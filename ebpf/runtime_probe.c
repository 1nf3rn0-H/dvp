#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/mm_types.h>
#include <linux/uio.h>

#define ARGSIZE 128
#define FNAME_LEN 256
#define PROT_EXEC 4

enum event_type {
    EVENT_EXEC = 1,
    EVENT_CONNECT = 2,
    EVENT_MEMFD = 3,
    EVENT_MPROTECT = 4,
    EVENT_VM_WRITE = 5
};

/*
Shared event header
All event payloads begin with this
*/
struct common_t {
    u32 type;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

/*
EXEC EVENT
*/
struct exec_data_t {
    struct common_t common;
    char filename[FNAME_LEN];
    char arg[ARGSIZE];
};

/*
CONNECT EVENT
*/
struct connect_data_t {
    struct common_t common;
    u32 ip;
    u16 port;
    u16 _pad;
};

/*
MEMFD EVENT
*/
struct memfd_data_t {
    struct common_t common;
    char name[FNAME_LEN];
};

/*
MPROTECT EVENT
*/
struct mprotect_data_t {
    struct common_t common;
    u64 addr;
    u64 len;
    u32 prot;
    u32 _pad;
};

/*
PROCESS_VM_WRITE EVENT
*/
struct vm_write_data_t {
    struct common_t common;
    u32 target_pid;
    u32 _pad;
    u64 remote_addr;
    u64 local_addr;
    u64 bytes;
};

/*
Tracked container PID map
*/
BPF_HASH(tracked_pids, u32, u32);

/*
Target container cgroup
*/
BPF_ARRAY(target_cgroup, u64, 1);

/*
Unified ringbuffer
*/
BPF_RINGBUF_OUTPUT(events, 1024);


/*
Container membership check
*/
static __always_inline int is_tracked()
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (tracked_pids.lookup(&pid))
        return 1;

    int zero = 0;
    u64 *cgroup_ptr = target_cgroup.lookup(&zero);

    if (cgroup_ptr && *cgroup_ptr != 0)
    {
        if (bpf_get_current_cgroup_id() == *cgroup_ptr)
        {
            u32 val = 1;
            tracked_pids.update(&pid, &val);
            return 1;
        }
    }

    return 0;
}


/*
PID inheritance tracking
*/
TRACEPOINT_PROBE(sched, sched_process_fork)
{
    u32 parent_pid = args->parent_pid;
    u32 child_pid = args->child_pid;

    if (tracked_pids.lookup(&parent_pid))
    {
        u32 val = 1;
        tracked_pids.update(&child_pid, &val);
    }

    return 0;
}


/*
PID cleanup
*/
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    tracked_pids.delete(&pid);

    return 0;
}


/*
EXECVE TRACE
*/
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    if (!is_tracked())
        return 0;

    struct exec_data_t *data;

    data = events.ringbuf_reserve(sizeof(*data));
    if (!data)
        return 0;

    data->common.type = EVENT_EXEC;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&data->common.comm,
                         sizeof(data->common.comm));

    bpf_probe_read_user_str(&data->filename,
                            sizeof(data->filename),
                            args->filename);

    const char **argv =
        (const char **)(args->argv);

    const char *argp;

    bpf_probe_read_user(&argp,
                        sizeof(argp),
                        &argv[1]);

    if (argp)
    {
        bpf_probe_read_user_str(&data->arg,
                                sizeof(data->arg),
                                argp);
    }
    else
    {
        data->arg[0] = '\0';
    }

    events.ringbuf_submit(data, 0);

    return 0;
}


/*
CONNECT TRACE
*/
TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    if (!is_tracked())
        return 0;

    struct sockaddr_in addr = {};

    bpf_probe_read_user(&addr,
                        sizeof(addr),
                        args->uservaddr);

    if (addr.sin_family != AF_INET)
        return 0;

    struct connect_data_t *data;

    data = events.ringbuf_reserve(sizeof(*data));
    if (!data)
        return 0;

    data->common.type = EVENT_CONNECT;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&data->common.comm,
                         sizeof(data->common.comm));

    data->ip = addr.sin_addr.s_addr;
    data->port = addr.sin_port;

    events.ringbuf_submit(data, 0);

    return 0;
}


/*
MEMFD CREATE TRACE
*/
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create)
{
    if (!is_tracked())
        return 0;

    struct memfd_data_t *data;

    data = events.ringbuf_reserve(sizeof(*data));
    if (!data)
        return 0;

    data->common.type = EVENT_MEMFD;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&data->common.comm,
                         sizeof(data->common.comm));

    bpf_probe_read_user_str(&data->name,
                            sizeof(data->name),
                            args->uname);

    events.ringbuf_submit(data, 0);

    return 0;
}


/*
RW → RX transition detection
*/
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect)
{
    if (!(args->prot & PROT_EXEC))
        return 0;

    if (!is_tracked())
        return 0;

    struct mprotect_data_t *data;

    data = events.ringbuf_reserve(sizeof(*data));
    if (!data)
        return 0;

    data->common.type = EVENT_MPROTECT;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&data->common.comm,
                         sizeof(data->common.comm));

    data->addr = args->start;
    data->len = args->len;
    data->prot = args->prot;

    events.ringbuf_submit(data, 0);

    return 0;
}


/*
PROCESS MEMORY INJECTION TRACE
*/
TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_writev)
{
    if (!is_tracked())
        return 0;

    struct vm_write_data_t *data;

    data = events.ringbuf_reserve(sizeof(*data));
    if (!data)
        return 0;

    data->common.type = EVENT_VM_WRITE;
    data->common.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&data->common.comm,
                         sizeof(data->common.comm));

    data->target_pid = args->pid;

    struct iovec iov;

    bpf_probe_read_user(&iov,
                        sizeof(iov),
                        (void *)args->lvec);

    data->local_addr = (u64)iov.iov_base;

    bpf_probe_read_user(&iov,
                        sizeof(iov),
                        (void *)args->rvec);

    data->remote_addr = (u64)iov.iov_base;

    data->bytes = (u64)iov.iov_len;

    events.ringbuf_submit(data, 0);

    return 0;
}