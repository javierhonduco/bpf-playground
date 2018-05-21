import time
import sys

from bcc import BPF, USDT
import ctypes as ct


bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    // Big enough value, as we want to trace sent commands,
    // no matter if they are actually commands or they aren't
    char query[10];
};

// TODO: could use an array w/ predefined commands
BPF_HASH(commands, struct key_t);

int command_start(struct pt_regs *ctx) {
    uint64_t addr = 0;
    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_usdt_readarg(2, ctx, &addr);
    if (addr != 0) {
        bpf_probe_read(&key.query, sizeof(key.query), (void *)addr);
    }

    #pragma clang loop unroll(full)
    for(int i=0; i<sizeof(key.query); i++) {
        if (key.query[i] == ' ') {
            key.query[i] = '\\0';
            break;
        }
    }

    // bpf_trace_printk("%s\\n", key.query);

    val = commands.lookup_or_init(&key, &zero);
    (*val)++;

    return 0;
};
"""


def display_stats(commands, update_interval):
    previous_stats = {}

    while True:
        counts = commands.items()
        stats = {
            k.query.decode(): v.value
            for k, v in sorted(
                counts, 
                key=lambda counts: counts[1].value,
            )
        }

        if stats != previous_stats:
            print(stats)

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
    # b.trace_print(fmt="__{5}")
    display_stats(b.get_table('commands'), update_interval)
