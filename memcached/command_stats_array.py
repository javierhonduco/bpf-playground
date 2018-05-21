import time
import sys

from bcc import BPF, USDT
import ctypes as ct


MEMCACHED_CMD_INDEX = ["get", "set", "stats"]


bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    // Big enough value, as we want to trace sent commands,
    // no matter if they are actually commands or they aren't
    char query[10];
};

// Just track get, set, and stats right now
BPF_ARRAY(commands, u64, 3);

static void array_incr(int index) {
    u64 *leaf = commands.lookup(&index);
    if (leaf) {
       (*leaf)++;
    }
}

int command_start(struct pt_regs *ctx) {
    uint64_t addr = 0;
    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_usdt_readarg(2, ctx, &addr);
    if (addr != 0) {
        bpf_probe_read(&key.query, sizeof(key.query), (void *)addr);
    }

    // TODO: check cmd string length
    // TODO: support binary protocol
    if (key.query[0] == 'g' && key.query[1] == 'e' \
            && key.query[2] == 't') {
        array_incr(0);
    }

    if (key.query[0] == 's' && key.query[1] == 'e' \
            && key.query[2] == 't') {
        array_incr(1);
    }

    if (key.query[0] == 's' && key.query[1] == 't' \
            && key.query[2] == 'a' && key.query[3] == 't' \
            && key.query[4] == 's') {
        array_incr(2);
    }


    return 0;
};
"""


def display_stats(commands, update_interval):
    previous_stats = {}

    while True:
        counts = commands.items()
        stats = [
            (MEMCACHED_CMD_INDEX[i], count.value)
            for i, count in enumerate(commands.values())
        ]

        if stats != previous_stats:
            print(stats)

        previous_stats = stats
        time.sleep(update_interval)


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
