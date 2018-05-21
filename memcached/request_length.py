import time
import sys

from bcc import BPF, USDT
import ctypes as ct


bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    int request_size;
};

BPF_HISTOGRAM(command_dist);

int command_start(struct pt_regs *ctx) {
    uint64_t addr;

    // TODO: figure out why not initializing `key`
    // makes the verifier complain
    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_usdt_readarg(3, ctx, &key.request_size);

    command_dist.increment(bpf_log2l(key.request_size));

    return 0;
};
"""


def display_stats(commands, update_interval):
    previous_stats = {}

    while True:
        stats = commands.items()

        # :shrug:
        if stats.__str__() != previous_stats.__str__():
            commands.print_log2_hist("command strlen")

        time.sleep(update_interval)
        previous_stats = stats


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: ... <memcached_pid> [<update_interval>]")
        sys.exit(1)

    memcached_pid = int(sys.argv[1])
    update_interval = float(sys.argv[2]) if len(sys.argv) >= 3 else 0.1

    u = USDT(pid=int(sys.argv[1]))
    u.enable_probe(probe='process__command__start', fn_name='command_start')

    b = BPF(text=bpf_text, usdt_contexts=[u])

    print('Waiting for commands...')
    display_stats(b.get_table('command_dist'), update_interval)
