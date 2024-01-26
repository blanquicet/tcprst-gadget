// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2023 The Inspektor Gadget authors

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <asm-generic/errno.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>
#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>

// Define here, because there are conflicts with include files
#define AF_INET 2
#define AF_INET6 10

// Taken from kernel:
// https://github.com/torvalds/linux/blob/052d534373b7ed33712a63d5e17b2b6cdbce84fd/include/linux/timer.h#L138-L139
#define from_timer(var, callback_timer, timer_fieldname) \
    container_of(callback_timer, typeof(*var), timer_fieldname)

enum callee {
    UNKOWN_CALLEE,
    FUNC_TCP_SEND_ACTIVE_RESET,
    FUNC_TCP_V4_SEND_RESET,
    FUNC_NF_SEND_RESET,
};

enum caller {
    UNKOWN_CALLER,

    // callee FUNC_TCP_SEND_ACTIVE_RESET:
    FUNC_TCP_DISCONNECT,
    FUNC_TCP_ABORT,
    FUNC_TCP_CLOSE,
    FUNC_TCP_KEEPALIVE_TIMER,
    FUNC_TCP_OUT_OF_RESOURCES,

    // callee FUNC_TCP_V4_SEND_RESET
    FUNC_TCP_V4_DO_RCV,
    FUNC_TCP_V4_RCV,
};

struct proc_ctx {
    __u64 mntns_id;
    __u32 netns_id;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u8 comm[TASK_COMM_LEN];
};

struct event {
    enum callee callee;
    enum caller caller;
    __u8 sk_state;

    // Info of process calling the function that led to the
    // tcp_send_active_reset/tcp_v4_send_reset call. This information is
    // retrieved using bpf_get_current_*() helpers.
    gadget_mntns_id mntns_id;
    __u32 netns_id;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u8 comm[TASK_COMM_LEN];

    // Info of process owning the socket. This information is retrieved
    // using the socket enricher.
    __u64 socket_mntns_id;
    __u32 socket_netns_id;
    __u32 socket_pid;
    __u32 socket_tid;
    __u32 socket_uid;
    __u32 socket_gid;
    __u8 socket_comm[TASK_COMM_LEN];

    struct gadget_l4endpoint_t src;
    struct gadget_l4endpoint_t dst;
};

static const struct event empty_event = {};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(tcprst, events, event);

struct pre_rst_event {
    enum caller caller;
    __u8 sk_state;
};

// pre_rst keeps track of process passing through all the functions that can
// lead to a tcp_send_active_reset or tcp_v4_send_reset call:
// tcp_send_active_reset:
// - tcp_disconnect
// - tcp_abort
// - tcp_close
// - tcp_keepalive_timer
// - tcp_out_of_resources
// tcp_v4_send_reset:
// - tcp_v4_do_rcv
// - tcp_v4_rcv
// Then, if a tcp_send_active_reset/tcp_v4_send_reset is called, we can check if
// the process is in the map, and if it is, we notify the user about the
// function that led to the call. In the value, we also store the state of the
// socket because in tcp_send_active_reset/tcp_v4_send_reset, most of the times,
// the status is already TCP_CLOSE.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    // key is the pid from get_current_pid(). It's the tid from userspace
    // point of view. There might be conflicts for the kernel threads as
    // they are all identified by 0.
    __type(key, __u32);
    __type(value, struct pre_rst_event);
} pre_rst SEC(".maps");

static __always_inline char *caller2str(enum caller caller)
{
    switch (caller) {
    case FUNC_TCP_DISCONNECT:
        return "tcp_disconnect";
    case FUNC_TCP_ABORT:
        return "tcp_abort";
    case FUNC_TCP_CLOSE:
        return "tcp_close";
    case FUNC_TCP_KEEPALIVE_TIMER:
        return "tcp_keepalive_timer";
    case FUNC_TCP_OUT_OF_RESOURCES:
        return "tcp_out_of_resources";
    case FUNC_TCP_V4_DO_RCV:
        return "tcp_v4_do_rcv";
    case FUNC_TCP_V4_RCV:
        return "tcp_v4_rcv";
    default:
        return "unknown";
    }
}

static __always_inline char *callee2str(enum callee callee)
{
    switch (callee) {
    case FUNC_TCP_SEND_ACTIVE_RESET:
        return "tcp_send_active_reset";
    case FUNC_TCP_V4_SEND_RESET:
        return "tcp_v4_send_reset";
    case FUNC_NF_SEND_RESET:
        return "nf_send_reset";
    default:
        return "unknown";
    }
}

static __always_inline __u32 get_current_pid()
{
    return (__u32)bpf_get_current_pid_tgid();
}

// Duplicating bpf_map_lookup_or_try_init from include/gadget/maps.bpf.h to add
// debug logs.
static __always_inline void *bpf_map_lookup_or_try_init(void *map,
                                                        const void *key,
                                                        const void *init,
                                                        enum caller caller,
                                                        enum callee callee)
{
    void *val;
    long err;
    __u32 current_pid = *((__u32 *)key);

    val = bpf_map_lookup_elem(map, key);
    if (val) {
        bpf_printk("WARN: %s - %s: tid %u already in pre_rst map. Overwriting!",
                   caller2str(caller), callee2str(callee), current_pid);
        return val;
    }

    err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    if (err && err != -EEXIST) {
        return 0;
    }

    return bpf_map_lookup_elem(map, key);
}

static __always_inline void get_socket_proc(struct proc_ctx *proc,
                                            const struct sock *sk)
{
    __u32 netns_id;
    struct sockets_value *skb_val;

    BPF_CORE_READ_INTO(&netns_id, sk, __sk_common.skc_net.net, ns.inum);
    skb_val = gadget_socket_lookup(sk, netns_id);
    if (!skb_val) {
        bpf_printk("WARN: socket %p and netns_id %u not found in "
                   "socket enricher",
                   sk, netns_id);
        return;
    }

    proc->pid = skb_val->pid_tgid >> 32;
    proc->tid = skb_val->pid_tgid;

    proc->gid = skb_val->uid_gid >> 32;
    proc->uid = skb_val->uid_gid;

    __builtin_memcpy(proc->comm, skb_val->task, sizeof(proc->comm));

    proc->mntns_id = skb_val->mntns;
    proc->netns_id = netns_id;
}

// This function could be useful for other gadgets. Consider moving it to some
// gadget helper library.
static __always_inline __u32 gadget_get_netns_id()
{
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
}

static __always_inline void get_current_proc(struct proc_ctx *proc)
{
    __u64 pid_tgid, uid_gid;

    pid_tgid = bpf_get_current_pid_tgid();
    proc->pid = pid_tgid >> 32;
    proc->tid = pid_tgid;

    uid_gid = bpf_get_current_uid_gid();
    proc->gid = uid_gid >> 32;
    proc->uid = uid_gid;

    bpf_get_current_comm(proc->comm, sizeof(proc->comm));

    proc->mntns_id = gadget_get_mntns_id();
    proc->netns_id = gadget_get_netns_id();
}

static __always_inline __u32 notify_event(void *ctx,
                                        const struct sock *sk,
                                        enum callee callee)
{
    struct pre_rst_event *pre_rst_event;
    struct event *event;

    // Filter by container
    if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
        return 0;

    // Even if we don't have track of the previous function, we still want to
    // notify the user about the function that led to send the reset.
    __u32 current_pid = get_current_pid();
    pre_rst_event = bpf_map_lookup_or_try_init(&pre_rst, &current_pid,
                                               &empty_event,
                                               UNKOWN_CALLER,
                                               callee);
    if (!pre_rst_event) {
        bpf_printk("ERROR: %u: call to %s without track of previous function and couldn't notify it",
                    current_pid, callee2str(callee));
        return 0;
    }

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

    // Set info captured in caller function
    event->caller = pre_rst_event->caller;
    event->sk_state = pre_rst_event->sk_state;

    // Set callee
    event->callee = callee;

    // Get process data from bpf helpers, which is the process calling the
    // function that led to the tcp_send_active_reset/tcp_v4_send_reset call
    // (action owner).
    struct proc_ctx current_proc = {};
    get_current_proc(&current_proc);
    event->pid = current_proc.pid;
    event->tid = current_proc.tid;
    event->uid = current_proc.uid;
    event->gid = current_proc.gid;
    event->mntns_id = current_proc.mntns_id;
    event->netns_id = current_proc.netns_id;
    __builtin_memcpy(event->comm, current_proc.comm, sizeof(event->comm));

    // Get process data from both socket enricher (socket owner).
    if (sk) {
        struct proc_ctx socket_proc = {};
        get_socket_proc(&socket_proc, sk);
        event->socket_pid = socket_proc.pid;
        event->socket_tid = socket_proc.tid;
        event->socket_uid = socket_proc.uid;
        event->socket_gid = socket_proc.gid;
        event->socket_mntns_id = socket_proc.mntns_id;
        event->socket_netns_id = socket_proc.netns_id;
        __builtin_memcpy(event->socket_comm, socket_proc.comm,
                        sizeof(event->socket_comm));
    }

    // Get IP data from the socket
    event->src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
    // Host expects data in host byte order
    event->dst.port =
        bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    event->src.proto = event->dst.proto = IPPROTO_TCP;
    unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET) {
        event->src.l3.version = event->dst.l3.version = 4;
        event->src.l3.addr.v4 =
            BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event->dst.l3.addr.v4 =
            BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else {
        event->src.l3.version = event->dst.l3.version = 6;
        BPF_CORE_READ_INTO(&event->src.l3.addr.v6, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&event->dst.l3.addr.v6, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_printk("DEBUG: %s->%s: reporting event for tid %u",
               caller2str(event->caller),
               callee2str(event->callee), current_pid);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

SEC("kprobe/tcp_send_active_reset")
int BPF_KPROBE(ig_tcp_tx_a_rst, struct sock *sk, gfp_t priority)
{
    return notify_event(ctx, sk, FUNC_TCP_SEND_ACTIVE_RESET);
}

SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(ig_tcp_tx_rst, const struct sock *sk, struct sk_buff *skb)
{
    return notify_event(ctx, sk, FUNC_TCP_V4_SEND_RESET);
}

// The kprobe in nf_send_reset is available only if nf_reject_ipv4 module is
// loaded. It's automatically loaded when adding a rule with iptables "-j REJECT
// --reject-with tcp-reset". However, if the module is not loaded, the kprobe
// won't be available and the program will fail to load and the gadget will
// crash. Given that we can't load the program conditionally, we need to exclude
// it at compile time.
#ifndef TRACE_NF_FUNC
SEC("kprobe/nf_send_reset")
int BPF_KPROBE(ig_nf_send_rst, struct sk_buff *oldskb, int hook)
{
    struct sock *sk = BPF_CORE_READ(oldskb, sk);
    return notify_event(ctx, sk, FUNC_NF_SEND_RESET);
}
#endif

static __always_inline int trace_pre_tcp_rst(void *ctx, const struct sock *sk,
                                             enum caller caller)
{
    struct pre_rst_event *pre_rst_event;

    // Filter by container
    if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
        return 0;

    // If the pid is already in the map, it means that the pid already
    // passed through one of the functions that can lead to a
    // tcp_send_active_reset/tcp_v4_send_reset call. In this case, overwrite
    // the previous event.
    __u32 current_pid = get_current_pid();
    pre_rst_event = bpf_map_lookup_or_try_init(&pre_rst, &current_pid,
                                               &empty_event,
                                               caller,
                                               UNKOWN_CALLEE);
    if (!pre_rst_event) {
        bpf_printk("ERROR: %s: couldn't add tid %u to pre_rst map",
                   caller2str(caller), current_pid);
        return 0;
    }

    pre_rst_event->caller = caller;
    BPF_CORE_READ_INTO(&pre_rst_event->sk_state, sk, __sk_common.skc_state);

    bpf_printk("DEBUG: %s: tid %u added to pre_rst map", caller2str(caller),
               current_pid);
    bpf_map_update_elem(&pre_rst, &current_pid, pre_rst_event, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_disconnect")
int BPF_KPROBE(ig_tcp_disc_e, struct sock *sk, int flags)
{
    return trace_pre_tcp_rst(ctx, sk, FUNC_TCP_DISCONNECT);
}

SEC("kprobe/tcp_abort")
int BPF_KPROBE(ig_tcp_abort_e, struct sock *sk, int err)
{
    return trace_pre_tcp_rst(ctx, sk, FUNC_TCP_ABORT);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(ig_tcp_close_e, struct sock *sk, long timeout)
{
    return trace_pre_tcp_rst(ctx, sk, FUNC_TCP_CLOSE);
}

SEC("kprobe/tcp_keepalive_timer")
int BPF_KPROBE(ig_tcp_katimer_e, struct timer_list *t)
{
    struct sock *sk = from_timer(sk, t, sk_timer);
    return trace_pre_tcp_rst(ctx, sk, FUNC_TCP_KEEPALIVE_TIMER);
}

SEC("kprobe/tcp_out_of_resources")
int BPF_KPROBE(ig_tcp_oor_e, struct sock *sk, bool do_reset)
{
    return trace_pre_tcp_rst(ctx, sk, FUNC_TCP_OUT_OF_RESOURCES);
}

SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(ig_tcp_do_rcv_e, struct sock *sk, struct sk_buff *skb)
{
    return trace_pre_tcp_rst(ctx, sk, FUNC_TCP_V4_DO_RCV);
}

SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(ig_tcp_rcv_e, struct sk_buff *skb)
{
    struct sock *sk = BPF_CORE_READ(skb, sk);
    return trace_pre_tcp_rst(ctx, sk, FUNC_TCP_V4_RCV);
}

static __always_inline int cleanup_pre_rst_map(enum caller caller)
{
    // Filter by container
    if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
        return 0;

    __u32 current_pid = get_current_pid();
    if (bpf_map_delete_elem(&pre_rst, &current_pid)) {
        bpf_printk("WARN: %s: couldn't delete tid %u from pre_rst map",
                   caller2str(caller), current_pid);
        return 0;
    }

    bpf_printk("DEBUG: %s: tid %u deleted from pre_rst map", caller2str(caller),
               current_pid);

    return 0;
}

SEC("kretprobe/tcp_disconnect")
int BPF_KRETPROBE(ig_tcp_disc_x)
{
    return cleanup_pre_rst_map(FUNC_TCP_DISCONNECT);
}

SEC("kretprobe/tcp_abort")
int BPF_KRETPROBE(ig_tcp_abort_x)
{
    return cleanup_pre_rst_map(FUNC_TCP_ABORT);
}

SEC("kretprobe/tcp_close")
int BPF_KRETPROBE(ig_tcp_close_x)
{
    return cleanup_pre_rst_map(FUNC_TCP_CLOSE);
}

SEC("kretprobe/tcp_keepalive_timer")
int BPF_KRETPROBE(ig_tcp_katimer_x)
{
    return cleanup_pre_rst_map(FUNC_TCP_KEEPALIVE_TIMER);
}

SEC("kretprobe/tcp_out_of_resources")
int BPF_KRETPROBE(ig_tcp_oor_x)
{
    return cleanup_pre_rst_map(FUNC_TCP_OUT_OF_RESOURCES);
}

SEC("kretprobe/tcp_v4_do_rcv")
int BPF_KRETPROBE(ig_tcp_do_rcv_x)
{
    return cleanup_pre_rst_map(FUNC_TCP_V4_DO_RCV);
}

SEC("kretprobe/tcp_v4_rcv")
int BPF_KRETPROBE(ig_tcp_rcv_x)
{
    return cleanup_pre_rst_map(FUNC_TCP_V4_RCV);
}

char LICENSE[] SEC("license") = "GPL";
