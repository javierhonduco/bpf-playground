"""
This doesn't work.

Memcached seems to be returning old data in this
USDT probe :(
"""
import time
import sys

from bcc import BPF, USDT
import ctypes as ct


bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    int hits;
    int misses;
    char query[50];
    int written_bytes;
};

BPF_HASH(commands, struct key_t);

int command_end(struct pt_regs *ctx) {
    uint64_t arg1 = 0;
    int32_t arg2 = 0;
    u64 zero = 0, *val;
    struct key_t key = {};

    bpf_usdt_readarg(2, ctx, &arg1);
    bpf_probe_read(&key.query, sizeof(key.query), (void *)arg1);

    bpf_usdt_readarg(3, ctx, &arg2);
    key.written_bytes = arg2;

    bpf_trace_printk("%s__%d\\n", key.query, key.written_bytes);

    //val = commands.lookup_or_init(&key, &zero);
    //(*val)++;
    return 0;
};
"""


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: ... <memcached_pid> [<update_interval>]")
        sys.exit(1)

    memcached_pid = int(sys.argv[1])

    u = USDT(pid=int(sys.argv[1]))
    u.enable_probe(probe='process__command__end', fn_name='command_end')

    b = BPF(text=bpf_text, usdt_contexts=[u])

    print('===========')
    while True:
        try:
            b.trace_print(fmt="__{5}")
        except ValueError:
            pass

        time.sleep(1)
