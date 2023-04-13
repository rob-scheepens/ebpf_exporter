#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

extern int LINUX_KERNEL_VERSION __kconfig;

const volatile u64 kaddr_bpf_total_size_written = 0;

struct total_size
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, u64);
  __type(value, u64);
};

struct total_size bpf_total_size_written SEC(".maps");
struct total_size bpf_total_size_read SEC(".maps");
struct total_size bpf_total_size_discard SEC(".maps");
struct total_size bpf_total_size_none SEC(".maps");
struct total_size bpf_total_size_unknown SEC(".maps");

/*
  field:unsigned short common_type;	offset:0;	size:2;	signed:0;
  field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
  field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
  field:int common_pid;	offset:4;	size:4;	signed:1;

  field:dev_t dev;	offset:8;	size:4;	signed:0;
  field:sector_t sector;	offset:16;	size:8;	signed:0;
  field:unsigned int nr_sector;	offset:24;	size:4;	signed:0;
  field:unsigned int bytes;	offset:28;	size:4;	signed:0;
  field:char rwbs[8];	offset:32;	size:8;	signed:1;
  field:char comm[16];	offset:40;	size:16;	signed:1;
  field:__data_loc char[] cmd;	offset:56;	size:4;	signed:1;
*/
struct block_rq_issue_struct
{
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  dev_t dev;
  sector_t sector;
  unsigned int nr_sector;
  unsigned int bytes;
  char rwbs[8];
  char comm[16];
  char __data_loc[];
};

static __always_inline int trace_rq_start(struct block_rq_issue_struct *p)
{

  struct total_size *pMap = &bpf_total_size_unknown;

  switch (p->rwbs[0])
  {
  case 'R':
    pMap = &bpf_total_size_read;
    break;
  case 'W':
    pMap = &bpf_total_size_written;
    break;
  case 'D':
    pMap = &bpf_total_size_discard;
    break;
  case 'N':
    pMap = &bpf_total_size_none;
    break;
  }
  
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm) )
  
  increment_map(pMap, &comm, p->bytes);
  return 0;
}

SEC("tracepoint/block/block_rq_issue")
int block_rq_issue(struct block_rq_issue_struct *p)
{
  return trace_rq_start(p);
}

char LICENSE[] SEC("license") = "GPL";
