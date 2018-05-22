import sys

from bcc import BPF, USDT


GC_START_PROBE_NAME = {
    "ruby": "gc__sweep__begin",
    "python": "gc__start",
}


bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);

int gc_run(struct pt_regs *ctx) {
    // this is kinda shitty, but not sure how to notify
    // of an event without sending a payload
    char a = '_';
    events.perf_submit(ctx, &a, sizeof(a));
    return 0;
};
"""


def on_event(cpu, data, size):
    print("\a", end="")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[usage] python gb_beep.py <pid> <ruby|python>")
        exit(1)

    u = USDT(pid=int(sys.argv[1]))
    probe_name = GC_START_PROBE_NAME[sys.argv[2]]

    u.enable_probe(probe=probe_name, fn_name="gc_run")

    b = BPF(text=bpf_text, usdt_contexts=[u])

    print("Beeping on GC runs...")
    b["events"].open_perf_buffer(on_event)

    while True:
        b.perf_buffer_poll()
