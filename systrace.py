"""
Toy system call tracer. Inspired by `tools/syscount.py`
"""
import argparse
import ctypes as ct
import shlex
import subprocess

from bcc import BPF


SYSCALLS = subprocess.check_output(
    "ausyscall --dump | tail +2 | cut -f2", shell=True
).split(b'\n')


def syscall_name(id):
    try:
        return SYSCALLS[id].decode()
    except IndexError:
        return "(unknown syscall)"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?")
    parser.add_argument("-p", "--pid", type=int)
    parser.add_argument("-f", "--failed", action="store_true")
    parser.add_argument("-c", "--page-cnt", type=int, default=64)
    parser.add_argument("-k", "--stack-traces", action="store_true")
    return parser.parse_args()


def build_defines(args, pid):
    defines = []

    if pid is not None:
        defines.append("#define FILTER_PID {}".format(pid))

    if args.stack_traces:
        defines.append("#define FETCH_STACKS 1")

    if args.failed:
        defines.append("#define FILTER_FAILED")

    return '\n'.join(defines)


text = """
DEFINES

struct syscall {
    u32 pid;
    int id;
    int ret;
    u64 stack_id;
};

BPF_PERF_OUTPUT(events);
#ifdef FETCH_STACKS
BPF_STACK_TRACE(stack_traces, 1024);
#endif
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;

    #ifdef FILTER_PID
    if (pid != FILTER_PID) {
        return 0;
    }
    #endif

    struct syscall call = {
        .id = args->id,
    };
    // Cannot be placed in the struct init, because of
    // a BCC bug. See issue #1775
    call.pid = pid;
    call.ret = args->ret;

    #ifdef FETCH_STACKS
    u64 stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    if (stack_id >= 0) {
        u32 zero = 0;
        call.stack_id = stack_id;
    }
    #endif

    #ifdef FILTER_FAILED
    if (call.ret >= 0) {
        return 0;
    }
    #endif

    events.perf_submit(args, &call, sizeof(call));

    return 0;
}
"""


class Data(ct.Structure):
    _fields_ = [
        ('pid', ct.c_uint),
        ('id', ct.c_int),
        ('ret', ct.c_int),
        ('stack_id', ct.c_ulonglong),
    ]


def on_event(cpu, data, size, pid):
    event = ct.cast(data, ct.POINTER(Data)).contents
    # `ausyscall --dump | tail +2 | cut -f2 | wc -L`
    print("pid={:<6}\tsyscall={:<23}\tret={}".format(
        event.pid,
        syscall_name(event.id),
        event.ret
    ))

    if args.stack_traces:
        for addr in bpf["stack_traces"].walk(event.stack_id):
            print(bpf.sym(
                addr,
                pid,
                show_module=True,
                show_offset=True,
            ))


def run_tracee(binary):
  # This is pretty racy: the process will start before we start tracing it
  # We are not waiting for the child, either
  sub = subprocess.Popen(
      shlex.split(binary),
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
  )
  return sub.pid


if __name__ == "__main__":
    if SYSCALLS == []:
        print("No syscall table could be retrived")
        print("Make sure you have `ausyscall` installed")
        exit(1)

    args = parse_args()

    # gives priority to the `pid` flag
    tracee_pid = None
    if args.pid:
        tracee_pid = args.pid
    if args.binary:
        tracee_pid = run_tracee(args.binary)

    defines = build_defines(args, tracee_pid)

    bpf = BPF(text=text.replace('DEFINES', defines))
    bpf["events"].open_perf_buffer(
        lambda cpu, data, size: on_event(cpu, data, size, tracee_pid),
        page_cnt=args.page_cnt,
    )

    while True:
        bpf.perf_buffer_poll()
