#!/usr/bin/env bash

if [ -z "$1" ]; then
    echo "usage: $0 PID"
    exit 1
fi

PID=$1
BPF_CMD=25 # BPF_MAP_LOOKUP_AND_DELETE_BATCH

SCRIPT=$(cat <<-END
// libbpf
uprobe:/proc/$PID/exe:bpf_map_lookup_and_delete_batch  {
    @in_libbpf = 1;
}

uretprobe:/proc/$PID/exe:bpf_map_lookup_and_delete_batch / @in_libbpf == 1 / {
    printf("return from libbpf %s with %d\n", ustack, retval);
     @in_libbpf = 0;
}

// BPF syscall
tracepoint:syscalls:sys_enter_bpf /args->cmd == $BPF_CMD/ {
    @sys_bpf = 1;
}

tracepoint:syscalls:sys_exit_bpf / @sys_bpf == 1 / {
    printf("return from BPF syscall %s with %d\n", ustack, args->ret);
    @sys_bpf = 0;
}
END
)

bpftrace -e "$SCRIPT"
