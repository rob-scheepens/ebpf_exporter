#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

extern int LINUX_KERNEL_VERSION __kconfig;

const volatile u64 kaddr_bpf_total_size_written = 0;

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u64);
} bpf_total_size_written SEC(".maps");

static __always_inline int trace_rq_start(struct request *rq)
{
  u32 zero_key = 0;

  if (bpf_core_field_exists(rq->__data_len))
     increment_map(&bpf_total_size_written, &zero_key, BPF_CORE_READ(rq, __data_len));

  return 0;
}

SEC("raw_tp/block_rq_issue")
int block_rq_issue(struct bpf_raw_tracepoint_args *ctx)
{
  /**
   * commit a54895fa (v5.11-rc1) changed tracepoint argument list
   * from TP_PROTO(struct request_queue *q, struct request *rq)
   * to TP_PROTO(struct request *rq)
   */
  if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0))
  {
    return trace_rq_start((void *)ctx->args[1]);
  }
  else
  {
    return trace_rq_start((void *)ctx->args[0]);
  }
}

char LICENSE[] SEC("license") = "GPL";

