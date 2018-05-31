"""
This BCC script tracks calls to the `open` and `close` system calls and reports
possibly leaked file descriptors.

* usage: <pid> [-k]
    -k to get the userspace stacktrace

* this could have been implemented using the kernel's tracepoints
"""
import sys
import time

from bcc import BPF


text = """
#include <uapi/linux/ptrace.h>

DEFINES

struct info_t {
    u64 stack_id;
};

BPF_HASH(data, u32, struct info_t);
#ifdef FETCH_STACKS
BPF_STACK_TRACE(stacks, 1024);
#endif

int open_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid != FILTER_PID) {
        return 0;
    }
    int fd = PT_REGS_RC(ctx);

    struct info_t info = {};
    #ifdef FETCH_STACKS
    u64 key = stacks.get_stackid(ctx, BPF_F_USER_STACK);
    if (key >= 0 ) {
        info.stack_id = key;
    }
    #endif
    data.update(&fd, &info);
    return 0;
}

int close_enter(struct pt_regs *ctx, int fd) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid != FILTER_PID) {
        return 0;
    }

    struct info_t *info = data.lookup(&fd);
    if (info == 0) {
        // could be closing a fd whose `open` wasn't traced
        return 0;
    } else {
        // assuming `close` does not fail
        data.delete(&fd);
    }
    return 0;
}

// not in use atm. useful if checking for errors
int close_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid != FILTER_PID) {
        return 0;
    }

    return 0;
}
"""


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: <pid> [<-k>]")
        exit(1)

    # Super brittle parsing
    pid = int(sys.argv[1])
    stacks = True if len(sys.argv) > 2 and sys.argv[2] == '-k' else False

    b = BPF(text=text.
        replace('FILTER_PID', sys.argv[1]).
        replace('DEFINES', '#define FETCH_STACKS' if stacks else '')
    )
    # funnily enough, `sys_open` does not work
    b.attach_kretprobe(event="do_sys_open", fn_name="open_return")
    b.attach_kprobe(event="sys_close", fn_name="close_enter")

    print("Waiting for SIGINT to display results...")

    try:
        while True:
            time.sleep(30)
    except KeyboardInterrupt:
        print("%d possibly leaked fds:" % len(b["data"]))
        print()

        if stacks:
            stacks = b["stacks"]
            for fd, value in b["data"].items():
                print("=> fd=%d" % fd.value)
                print()


                try:
                    for addr in stacks.walk(value.stack_id):
                        print("{}".format(b.sym(
                            addr,
                            pid,
                            show_module=True,
                            show_offset=True,
                        )))
                except KeyError:
                    print("error while walking the stack", file=sys.stderr)
        else:
            print([fd.value for fd in b["data"].keys()])

        exit(0)
