#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Enable BSS.
int my_global_var = 0;

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(max_entries, 2);
  __type(key, int);
  __type(value, int);
} sock_redir_map SEC(".maps");

SEC("prog_parser")
int _prog_parser(struct __sk_buff *skb) { return skb->len; }

SEC("prog_verdict")
int _prog_verdict(struct __sk_buff *skb) {
  uint32_t idx = 0;
  return bpf_sk_redirect_map(skb, &sock_redir_map, idx, 0);
}