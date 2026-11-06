#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define TASK_FILE_OWNER_SIZE 32

/* Binary record consumed by task_file.rs. */
struct task_file_owner
{
    __u64 inode;
    __u32 tgid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
};

_Static_assert(sizeof(struct task_file_owner) == TASK_FILE_OWNER_SIZE,
               "task-file owner ABI size changed");

/*
 * One-shot startup inventory for sockets that existed before the live
 * fentry/kprobe programs were attached. The kernel's task_file iterator skips
 * threads that share their group leader's file table, so normal thread groups
 * do not emit duplicate owners.
 */
SEC("iter/task_file")
int snapshot_task_file_owners(struct bpf_iter__task_file *ctx)
{
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;

    if (!task || !file || !bpf_sock_from_file(file))
        return 0;

    struct task_file_owner owner = {};
    owner.inode = BPF_CORE_READ(file, f_inode, i_ino);
    owner.tgid = BPF_CORE_READ(task, tgid);
    owner.uid = BPF_CORE_READ(task, cred, euid.val);

    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (!leader || owner.inode == 0 || owner.tgid == 0)
        return 0;

    if (BPF_CORE_READ_STR_INTO(&owner.comm, leader, comm) <= 0 ||
        owner.comm[0] == '\0')
        return 0;

    bpf_seq_write(ctx->meta->seq, &owner, sizeof(owner));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
