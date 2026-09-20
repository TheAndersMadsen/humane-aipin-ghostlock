#define _POSIX_C_SOURCE 200809L

#include "src/slide_supervisor.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum scenario {
  SCENARIO_SUCCESS,
  SCENARIO_EXIT_BEFORE_PACKET,
  SCENARIO_PARTIAL_PACKET,
  SCENARIO_CORRUPT_PACKET,
  SCENARIO_FULL_PACKET_THEN_HANG,
  SCENARIO_WRITER_HOLDER_AFTER_EXIT,
};

struct test_case {
  const char *name;
  enum scenario scenario;
  enum slide_supervisor_outcome expected;
  uint64_t timeout_ms;
};

static int failures;

static uint64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    perror("clock_gettime");
    exit(2);
  }
  return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void sleep_ms(unsigned int milliseconds) {
  struct timespec request;
  struct timespec remaining;

  request.tv_sec = (time_t)(milliseconds / 1000u);
  request.tv_nsec = (long)(milliseconds % 1000u) * 1000000L;
  while (nanosleep(&request, &remaining) != 0) {
    if (errno != EINTR) {
      perror("nanosleep");
      exit(2);
    }
    request = remaining;
  }
}

static int write_all(int fd, const void *buffer, size_t size) {
  const unsigned char *bytes = buffer;
  size_t used = 0;

  while (used < size) {
    ssize_t wrote = write(fd, bytes + used, size - used);
    if (wrote > 0) {
      used += (size_t)wrote;
      continue;
    }
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    return -1;
  }
  return 0;
}

static _Noreturn void hang_forever(void) {
  for (;;) {
    pause();
  }
}

static void child_scenario(enum scenario scenario, int write_fd) {
  static const uint64_t expected_value = UINT64_C(0x1122334455667788);
  struct slide_supervisor_result result;
  unsigned char invalid_frame[SLIDE_SUPERVISOR_FRAME_SIZE];

  result.code = 7;
  result.value = expected_value;
  memset(invalid_frame, 0xa5, sizeof(invalid_frame));

  switch (scenario) {
    case SCENARIO_SUCCESS:
      _exit(slide_supervisor_write_result(write_fd, &result) == 0 ? 0 : 70);

    case SCENARIO_EXIT_BEFORE_PACKET:
      _exit(23);

    case SCENARIO_PARTIAL_PACKET:
      if (write_all(write_fd, invalid_frame, 7) != 0) {
        _exit(71);
      }
      hang_forever();

    case SCENARIO_CORRUPT_PACKET:
      if (write_all(write_fd, invalid_frame, sizeof(invalid_frame)) != 0) {
        _exit(72);
      }
      hang_forever();

    case SCENARIO_FULL_PACKET_THEN_HANG:
      if (slide_supervisor_write_result(write_fd, &result) != 0) {
        _exit(73);
      }
      hang_forever();

    case SCENARIO_WRITER_HOLDER_AFTER_EXIT: {
      pid_t holder = fork();
      if (holder < 0) {
        _exit(74);
      }
      if (holder == 0) {
        hang_forever();
      }
      result.value = (uint64_t)holder;
      if (slide_supervisor_write_result(write_fd, &result) != 0) {
        _exit(75);
      }
      _exit(0);
    }
  }
  _exit(76);
}

static int process_group_is_gone(pid_t pgid) {
  uint64_t deadline = monotonic_ms() + 750u;

  for (;;) {
    if (kill(-pgid, 0) != 0 && errno == ESRCH) {
      return 1;
    }
    if (monotonic_ms() >= deadline) {
      return 0;
    }
    sleep_ms(5);
  }
}

static int no_direct_children(void) {
  int status;
  pid_t got = waitpid(-1, &status, WNOHANG);

  return got < 0 && errno == ECHILD;
}

static void report_failure(const char *name, const char *message) {
  fprintf(stderr, "FAIL %-31s %s\n", name, message);
  ++failures;
}

static void test_pipe_flags(void) {
  int fds[2];
  int read_fd_flags;
  int write_fd_flags;
  int read_status_flags;

  if (slide_supervisor_pipe(fds) != 0) {
    report_failure("pipe-flags", strerror(errno));
    return;
  }
  read_fd_flags = fcntl(fds[0], F_GETFD);
  write_fd_flags = fcntl(fds[1], F_GETFD);
  read_status_flags = fcntl(fds[0], F_GETFL);
  if (read_fd_flags < 0 || write_fd_flags < 0 || read_status_flags < 0 ||
      (read_fd_flags & FD_CLOEXEC) == 0 ||
      (write_fd_flags & FD_CLOEXEC) == 0 ||
      (read_status_flags & O_NONBLOCK) == 0) {
    report_failure("pipe-flags", "missing CLOEXEC or reader O_NONBLOCK");
  } else {
    printf("PASS %-31s CLOEXEC + reader O_NONBLOCK\n", "pipe-flags");
  }
  close(fds[0]);
  close(fds[1]);
}

static void run_case(const struct test_case *test) {
  static const uint64_t expected_value = UINT64_C(0x1122334455667788);
  int fds[2];
  pid_t child;
  struct timespec deadline;
  struct slide_supervisor_result result;
  enum slide_supervisor_outcome outcome;
  uint64_t started;
  uint64_t elapsed;
  int wait_status = -1;
  int saved_errno;

  if (slide_supervisor_pipe(fds) != 0) {
    report_failure(test->name, strerror(errno));
    return;
  }

  child = fork();
  if (child < 0) {
    close(fds[0]);
    close(fds[1]);
    report_failure(test->name, strerror(errno));
    return;
  }
  if (child == 0) {
    close(fds[0]);
    if (setpgid(0, 0) != 0) {
      _exit(69);
    }
    child_scenario(test->scenario, fds[1]);
  }

  close(fds[1]);
  if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    close(fds[0]);
    report_failure(test->name, "setpgid failed");
    return;
  }

  if (slide_supervisor_deadline_after_ms(&deadline, test->timeout_ms) != 0) {
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    close(fds[0]);
    report_failure(test->name, "deadline creation failed");
    return;
  }
  if (test->scenario == SCENARIO_WRITER_HOLDER_AFTER_EXIT) {
    /* Make the leader exit first while its child deliberately retains fd 1. */
    sleep_ms(40);
  }

  started = monotonic_ms();
  outcome = slide_supervisor_collect(
      child, fds[0], &deadline, &result, &wait_status);
  saved_errno = errno;
  elapsed = monotonic_ms() - started;

  if (outcome != test->expected) {
    char message[160];
    snprintf(message, sizeof(message), "got %s errno=%d expected %s",
             slide_supervisor_outcome_name(outcome), saved_errno,
             slide_supervisor_outcome_name(test->expected));
    report_failure(test->name, message);
  } else if (outcome == SLIDE_SUPERVISOR_OK &&
             test->scenario != SCENARIO_WRITER_HOLDER_AFTER_EXIT &&
             (result.code != 7 || result.value != expected_value)) {
    report_failure(test->name, "decoded result does not match frame");
  } else if (outcome == SLIDE_SUPERVISOR_OK &&
             test->scenario == SCENARIO_WRITER_HOLDER_AFTER_EXIT &&
             (result.code != 7 || result.value == 0)) {
    report_failure(test->name, "writer-holder pid was not decoded");
  } else if (elapsed > 1200u) {
    report_failure(test->name, "operation exceeded 1200 ms bound");
  } else if (!process_group_is_gone(child)) {
    report_failure(test->name, "dedicated process group survived cleanup");
  } else if (!no_direct_children()) {
    report_failure(test->name, "direct child survived or was not reaped");
  } else {
    printf("PASS %-31s outcome=%-14s elapsed=%llums\n", test->name,
           slide_supervisor_outcome_name(outcome),
           (unsigned long long)elapsed);
  }
}

int main(void) {
  static const struct test_case tests[] = {
      {"success", SCENARIO_SUCCESS, SLIDE_SUPERVISOR_OK, 500},
      {"exit-before-packet", SCENARIO_EXIT_BEFORE_PACKET,
       SLIDE_SUPERVISOR_CHILD_EXITED, 500},
      {"partial-packet", SCENARIO_PARTIAL_PACKET,
       SLIDE_SUPERVISOR_PROTOCOL_ERROR, 120},
      {"corrupt-packet", SCENARIO_CORRUPT_PACKET,
       SLIDE_SUPERVISOR_PROTOCOL_ERROR, 500},
      {"full-packet-then-hang", SCENARIO_FULL_PACKET_THEN_HANG,
       SLIDE_SUPERVISOR_OK, 500},
      {"writer-holder-after-target-exit",
       SCENARIO_WRITER_HOLDER_AFTER_EXIT, SLIDE_SUPERVISOR_OK, 500},
  };
  size_t i;

  signal(SIGPIPE, SIG_IGN);
  test_pipe_flags();
  for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
    run_case(&tests[i]);
  }

  if (failures != 0) {
    fprintf(stderr, "%d slide supervisor regression(s) failed\n", failures);
    return 1;
  }
  printf("All slide supervisor regressions passed; no child remains.\n");
  return 0;
}
