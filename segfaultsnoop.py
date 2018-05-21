import ctypes as ct
import signal
import sys

from bcc import BPF


DEADLY_SIGNALS = [signal.SIGILL.value, signal.SIGSEGV.value]
DEBUG = False
TASK_COMM_LEN = 16


def build_signal_filtering(signal_var, signals):
    if not signals:
        return ""

    conditions = [
        "{} != {}".format(signal_var, signal)
        for signal in signals
    ]

    return """if (%s) {
        return 0;
    }""" % "&&".join(conditions)


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct enter_info {
    u64 pid;
    int tpid;
    int sig;
    u64 frame;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(temp, u32, struct enter_info);
BPF_STACK_TRACE(stacks, 1024);
BPF_PERF_OUTPUT(events);

int complete_signal_handler(struct pt_regs *ctx, int sig, struct task_struct *p) {
    // Maybe store statistics on filtered signals
    SIGNAL_CONDS

    int pid = bpf_get_current_pid_tgid();
    u64 key = stacks.get_stackid(ctx, BPF_F_USER_STACK);
    if (key < 0) {
        // Maybe bump stats counter
        return 0;
    }

    // Can we fetch the IP?
    //int sp = p->thread.sp;
    //int ip = task_pt_regs(p->thread)->ip;

    struct enter_info value = {
        .pid = pid,
        .tpid = p->pid, // well...
        .sig = sig,
        .frame = key,
    };

    // This can fail
    bpf_get_current_comm(&value.comm, sizeof(value.comm));

    events.perf_submit(ctx, &value, sizeof(value));
    return 0;
}
"""


bpf_text_replaced = bpf_text.replace(
    "SIGNAL_CONDS", build_signal_filtering("sig", DEADLY_SIGNALS)
)

if DEBUG:
    print("BCC program:")
    print(bpf_text_replaced)


b = BPF(text=bpf_text_replaced)
b.attach_kprobe(event="complete_signal", fn_name="complete_signal_handler")


class Data(ct.Structure):
    _fields_ = [
            ("pid", ct.c_ulonglong),
            ("tpid", ct.c_int),
            ("sig", ct.c_int),
            ("frame", ct.c_ulonglong),
            ("comm", ct.c_char * TASK_COMM_LEN),
    ]


def receive_data(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("pid: {}, comm: {}, signal: {}".format(
        event.pid,
        event.comm,
        signal.Signals(event.sig).__repr__(),
    ))

    stacks = b["stacks"]

    try:
        for addr in stacks.walk(event.frame):
            print("{}".format(b.sym(
                addr,
                event.pid,
                show_module=True,
                show_offset=True,
            )))
    except KeyError:
        print("error while walking the stack", file=sys.stderr)


b["events"].open_perf_buffer(receive_data)

print("Running...")
while True:
    b.perf_buffer_poll()
