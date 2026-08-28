//! One-shot BPF task-file iterator for sockets that predate RustNet startup.

use crate::SocketOwner;
use crate::linux::process::StartupSocketOwners;
use anyhow::{Context, Result, ensure};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Iter, IterOpts};
use std::io::Read;

mod socket_tracker_task_file {
    include!(concat!(
        env!("OUT_DIR"),
        "/socket_tracker_task_file.skel.rs"
    ));
}

use socket_tracker_task_file::*;

const TASK_COMM_LEN: usize = 16;
const OWNER_RECORD_SIZE: usize = 32;
const READ_BUFFER_SIZE: usize = 64 * 1024;

pub(in crate::linux) fn snapshot_task_file_owners() -> Result<StartupSocketOwners> {
    let skel_builder = SocketTrackerTaskFileSkelBuilder::default();
    let mut open_object = Box::new(std::mem::MaybeUninit::uninit());
    let open_skel = skel_builder
        .open(&mut open_object)
        .context("open task-file iterator skeleton")?;
    let skel = open_skel
        .load()
        .context("load task-file iterator BPF object")?;
    let link = skel
        .progs
        .snapshot_task_file_owners
        .attach_iter_with_opts(IterOpts::None)
        .context("attach task-file iterator")?;
    let mut iter = Iter::new(&link).context("create task-file iterator reader")?;

    read_owner_records(&mut iter)
}

fn read_owner_records(reader: &mut impl Read) -> Result<StartupSocketOwners> {
    let mut owners = StartupSocketOwners::default();
    let mut pending = Vec::with_capacity(READ_BUFFER_SIZE + OWNER_RECORD_SIZE);
    let mut buffer = [0_u8; READ_BUFFER_SIZE];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .context("read task-file iterator records")?;
        if bytes_read == 0 {
            break;
        }

        pending.extend_from_slice(&buffer[..bytes_read]);
        let complete_len = pending.len() / OWNER_RECORD_SIZE * OWNER_RECORD_SIZE;
        let (records, remainder) = pending[..complete_len].as_chunks::<OWNER_RECORD_SIZE>();
        debug_assert!(remainder.is_empty());
        for record in records {
            if let Some((inode, owner)) = decode_owner_record(record) {
                owners.insert(inode, owner);
            }
        }

        let remaining = pending.len() - complete_len;
        pending.copy_within(complete_len.., 0);
        pending.truncate(remaining);
    }

    ensure!(
        pending.is_empty(),
        "task-file iterator returned a truncated owner record"
    );
    Ok(owners)
}

fn decode_owner_record(record: &[u8]) -> Option<(u64, SocketOwner)> {
    if record.len() != OWNER_RECORD_SIZE {
        return None;
    }

    let inode = u64::from_ne_bytes(record[0..8].try_into().ok()?);
    let tgid = u32::from_ne_bytes(record[8..12].try_into().ok()?);
    let uid = u32::from_ne_bytes(record[12..16].try_into().ok()?);
    let comm_bytes = &record[16..16 + TASK_COMM_LEN];
    let comm_len = comm_bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(TASK_COMM_LEN);
    let comm = String::from_utf8_lossy(&comm_bytes[..comm_len]).to_string();

    if inode == 0 || tgid == 0 || comm.is_empty() {
        return None;
    }

    Some((inode, SocketOwner::new(tgid, comm, Some(uid))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;

    fn record(inode: u64, tgid: u32, uid: u32, comm: &str) -> [u8; OWNER_RECORD_SIZE] {
        let mut bytes = [0_u8; OWNER_RECORD_SIZE];
        bytes[0..8].copy_from_slice(&inode.to_ne_bytes());
        bytes[8..12].copy_from_slice(&tgid.to_ne_bytes());
        bytes[12..16].copy_from_slice(&uid.to_ne_bytes());
        let comm = comm.as_bytes();
        let len = comm.len().min(TASK_COMM_LEN - 1);
        bytes[16..16 + len].copy_from_slice(&comm[..len]);
        bytes
    }

    #[test]
    fn decodes_binary_owner_record() {
        let bytes = record(123, 456, 789, "nordvpnd");
        let (inode, owner) = decode_owner_record(&bytes).expect("record must decode");

        assert_eq!(inode, 123);
        assert_eq!(owner, SocketOwner::new(456, "nordvpnd", Some(789)));
    }

    #[test]
    fn reads_records_split_across_io_boundaries() {
        struct SplitReader {
            bytes: Cursor<Vec<u8>>,
            chunk_size: usize,
        }

        impl Read for SplitReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let len = buf.len().min(self.chunk_size);
                self.bytes.read(&mut buf[..len])
            }
        }

        let bytes = [record(1, 10, 100, "one"), record(2, 20, 200, "two")].concat();
        let mut reader = SplitReader {
            bytes: Cursor::new(bytes),
            chunk_size: 7,
        };

        let owners = read_owner_records(&mut reader).expect("records must decode");
        assert_eq!(owners.len(), 2);
    }

    #[test]
    fn rejects_truncated_stream() {
        let mut bytes = record(1, 10, 100, "one").to_vec();
        bytes.pop();

        let error = read_owner_records(&mut Cursor::new(bytes)).unwrap_err();
        assert!(error.to_string().contains("truncated owner record"));
    }

    #[test]
    #[ignore = "requires CAP_BPF, CAP_PERFMON, and a kernel with task-file iterators"]
    fn kernel_iterator_reports_current_process_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener must bind");
        let link = std::fs::read_link(format!("/proc/self/fd/{}", listener.as_raw_fd()))
            .expect("listener fd must resolve");
        let link = link.to_str().expect("socket link must be UTF-8");
        let inode = link
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
            .expect("socket link must contain an inode");

        let owners = snapshot_task_file_owners().expect("task-file iterator must load");
        let owner = owners.get(inode).expect("listener owner must be present");
        assert_eq!(owner.pid, std::process::id());
    }
}
