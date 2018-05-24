"""
Toy system call tracer. Inspired by `tools/syscount.py`
"""
import argparse
import ctypes as ct
import subprocess

from bcc import BPF


SYSCALLS = subprocess.check_output(
    "ausyscall --dump | tail +2 | cut -f2", shell=True
).split(b'\n')


def syscall_name(id):
    try:
        return SYSCALLS[id]
    except KeyError:
        return "(unknown syscall)"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", type=int)
    parser.add_argument("-f", "--failed", action="store_true")
    return parser.parse_args()


def build_defines(args):
    defines = []

    if args.pid:
        defines.append("#define FILTER_PID {}".format(args.pid))

    if args.failed:
        defines.append("#define FILTER_FAILED")

    return '\n'.join(defines)


text = """
DEFINES

struct syscall {
    int id;
    int ret;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    #ifdef FILTER_PID
        u64 pid = bpf_get_current_pid_tgid() >> 32;
        if (pid != FILTER_PID) {
            return 0;
        }
    #endif

    struct syscall call = {
        .id = args->id,
        .ret = args->ret,
    };

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
        ('id', ct.c_int),
        ('ret', ct.c_int),
    ]


def on_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    # `ausyscall --dump | tail +2 | cut -f2 | wc -L`
    print("syscall={:<23}\tret={}".format(
        syscall_name(event.id).decode(),
        event.ret)
    )


if __name__ == "__main__":
    if SYSCALLS == []:
        print("No syscall table could be retrived")
        print("Make sure you have `ausyscall` installed")
        exit(1)

    args = parse_args()

    bpf = BPF(text=text.replace('DEFINES', build_defines(args)))
    bpf["events"].open_perf_buffer(
        on_event,
        page_cnt=64,
        #lost_cb=
    )

    while True:
        bpf.perf_buffer_poll()
