"""
Traces BPF using its tracepoints
"""
from bcc import BPF


BPF_TRACEPOINTS = """
bpf_map_delete_elem
bpf_map_lookup_elem
bpf_map_next_key
bpf_map_update_elem
bpf_obj_get_map
bpf_obj_get_prog
bpf_obj_pin_map
bpf_obj_pin_prog
bpf_prog_get_type
bpf_prog_load
bpf_prog_put_rcu
""".split()


tp_placeholder = """
TRACEPOINT_PROBE(bpf, TP_NAME) {
    bpf_trace_printk("TP_NAME\\n");
    return 0;
}
"""

text = "\n".join([
    tp_placeholder.replace("TP_NAME", tp)
    for tp in BPF_TRACEPOINTS
])


if __name__ == "__main__":
    bpf = BPF(text=text)

    print("Tracing BPF tracepoints:")
    print()
    while True:
        bpf.trace_print()
