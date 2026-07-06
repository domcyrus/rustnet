use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SHB_TYPE: u32 = 0x0A0D_0D0A;
const IDB_TYPE: u32 = 0x0000_0001;
const EPB_TYPE: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const SHB_MAJOR: u16 = 1;
const SHB_MINOR: u16 = 0;
const SECTION_LENGTH_UNSPECIFIED: i64 = -1;
const OPT_ENDOFOPT: u16 = 0;
const OPT_COMMENT: u16 = 1;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_TSRESOL: u16 = 9;
const TSRESOL_MICROS: u8 = 6;

/// Minimal PCAPNG writer for RustNet's annotated packet export.
///
/// It writes one little-endian section, one interface, and Enhanced Packet
/// Blocks with optional packet comments. This intentionally supports only the
/// block and option shapes RustNet needs.
pub struct PcapngWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapngWriter<W> {
    pub fn new(
        mut writer: W,
        linktype: u16,
        snaplen: u32,
        if_name: Option<&str>,
    ) -> io::Result<Self> {
        write_section_header(&mut writer)?;
        write_interface_description(&mut writer, linktype, snaplen, if_name)?;
        Ok(Self { writer })
    }

    pub fn write_packet(
        &mut self,
        timestamp: SystemTime,
        data: &[u8],
        original_len: u32,
        comment: Option<&str>,
    ) -> io::Result<()> {
        write_enhanced_packet(&mut self.writer, timestamp, data, original_len, comment)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub fn timestamp_micros_since_epoch(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
}

pub fn linktype_to_u16(linktype: i32) -> u16 {
    u16::try_from(linktype).unwrap_or(1)
}

fn write_section_header<W: Write>(writer: &mut W) -> io::Result<()> {
    let mut body = Vec::with_capacity(32);
    write_u32(&mut body, BYTE_ORDER_MAGIC)?;
    write_u16(&mut body, SHB_MAJOR)?;
    write_u16(&mut body, SHB_MINOR)?;
    write_i64(&mut body, SECTION_LENGTH_UNSPECIFIED)?;
    write_option_string(
        &mut body,
        SHB_USERAPPL,
        concat!("rustnet ", env!("CARGO_PKG_VERSION")),
    )?;
    write_option_end(&mut body)?;
    write_block(writer, SHB_TYPE, &body)
}

fn write_interface_description<W: Write>(
    writer: &mut W,
    linktype: u16,
    snaplen: u32,
    if_name: Option<&str>,
) -> io::Result<()> {
    let mut body = Vec::with_capacity(32);
    write_u16(&mut body, linktype)?;
    write_u16(&mut body, 0)?;
    write_u32(&mut body, snaplen)?;
    if let Some(name) = if_name.filter(|s| !s.is_empty()) {
        write_option_string(&mut body, IF_NAME, name)?;
    }
    write_option_bytes(&mut body, IF_TSRESOL, &[TSRESOL_MICROS])?;
    write_option_end(&mut body)?;
    write_block(writer, IDB_TYPE, &body)
}

fn write_enhanced_packet<W: Write>(
    writer: &mut W,
    timestamp: SystemTime,
    data: &[u8],
    original_len: u32,
    comment: Option<&str>,
) -> io::Result<()> {
    let mut body = Vec::with_capacity(20 + padded_len(data.len()) + 128);
    let micros = timestamp_micros_since_epoch(timestamp);
    let captured_len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
    write_u32(&mut body, 0)?;
    write_u32(&mut body, (micros >> 32) as u32)?;
    write_u32(&mut body, (micros & 0xffff_ffff) as u32)?;
    write_u32(&mut body, captured_len)?;
    write_u32(&mut body, original_len.max(captured_len))?;
    body.write_all(data)?;
    write_padding(&mut body, data.len())?;
    if let Some(comment) = comment.filter(|s| !s.is_empty()) {
        write_option_string(&mut body, OPT_COMMENT, comment)?;
    }
    write_option_end(&mut body)?;
    write_block(writer, EPB_TYPE, &body)
}

fn write_block<W: Write>(writer: &mut W, block_type: u32, body: &[u8]) -> io::Result<()> {
    let total_len = u32::try_from(12 + body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pcapng block too large"))?;
    write_u32(writer, block_type)?;
    write_u32(writer, total_len)?;
    writer.write_all(body)?;
    write_u32(writer, total_len)
}

fn write_option_string<W: Write>(writer: &mut W, code: u16, value: &str) -> io::Result<()> {
    write_option_bytes(writer, code, value.as_bytes())
}

fn write_option_bytes<W: Write>(writer: &mut W, code: u16, value: &[u8]) -> io::Result<()> {
    let len = u16::try_from(value.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pcapng option too large"))?;
    write_u16(writer, code)?;
    write_u16(writer, len)?;
    writer.write_all(value)?;
    write_padding(writer, value.len())
}

fn write_option_end<W: Write>(writer: &mut W) -> io::Result<()> {
    write_u16(writer, OPT_ENDOFOPT)?;
    write_u16(writer, 0)
}

fn write_padding<W: Write>(writer: &mut W, len: usize) -> io::Result<()> {
    const ZERO_PAD: [u8; 3] = [0; 3];
    writer.write_all(&ZERO_PAD[..padding_len(len)])
}

fn padding_len(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

fn padded_len(len: usize) -> usize {
    len + padding_len(len)
}

fn write_u16<W: Write>(writer: &mut W, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_i64<W: Write>(writer: &mut W, value: i64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(buf: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
    }

    fn find_epb(buf: &[u8]) -> &[u8] {
        let mut offset = 0usize;
        while offset + 12 <= buf.len() {
            let block_type = read_u32(buf, offset);
            let block_len = read_u32(buf, offset + 4) as usize;
            if block_type == EPB_TYPE {
                return &buf[offset..offset + block_len];
            }
            offset += block_len;
        }
        panic!("EPB not found");
    }

    #[test]
    fn writes_valid_block_lengths_and_comment() {
        let mut out = Vec::new();
        let mut writer = PcapngWriter::new(&mut out, 1, 1514, Some("eth0")).unwrap();
        writer
            .write_packet(
                UNIX_EPOCH + Duration::from_micros(42),
                &[1, 2, 3],
                3,
                Some("rustnet pid=1"),
            )
            .unwrap();
        writer.flush().unwrap();

        let mut offset = 0usize;
        while offset + 12 <= out.len() {
            let block_len = read_u32(&out, offset + 4) as usize;
            assert!(block_len >= 12);
            assert_eq!(read_u32(&out, offset + block_len - 4), block_len as u32);
            offset += block_len;
        }
        assert_eq!(offset, out.len());

        let epb = find_epb(&out);
        let captured_len = read_u32(epb, 20) as usize;
        let original_len = read_u32(epb, 24) as usize;
        assert_eq!(captured_len, 3);
        assert_eq!(original_len, 3);
        let options_start = 28 + padded_len(captured_len);
        assert_eq!(
            u16::from_le_bytes(epb[options_start..options_start + 2].try_into().unwrap()),
            OPT_COMMENT
        );
        let comment_len = u16::from_le_bytes(
            epb[options_start + 2..options_start + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let comment =
            std::str::from_utf8(&epb[options_start + 4..options_start + 4 + comment_len]).unwrap();
        assert_eq!(comment, "rustnet pid=1");
    }

    #[test]
    fn timestamp_uses_microseconds() {
        let ts = UNIX_EPOCH + Duration::from_secs(2) + Duration::from_micros(7);
        assert_eq!(timestamp_micros_since_epoch(ts), 2_000_007);
    }

    #[test]
    fn packet_can_report_original_length_larger_than_capture() {
        let mut out = Vec::new();
        let mut writer = PcapngWriter::new(&mut out, 1, 3, None).unwrap();
        writer
            .write_packet(UNIX_EPOCH, &[1, 2, 3], 42, None)
            .unwrap();

        let epb = find_epb(&out);
        assert_eq!(read_u32(epb, 20), 3);
        assert_eq!(read_u32(epb, 24), 42);
    }
}
