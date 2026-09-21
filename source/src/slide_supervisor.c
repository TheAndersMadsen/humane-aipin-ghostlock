#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "slide_supervisor.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define SLIDE_SUPERVISOR_MAGIC 0x52444c53u
#define SLIDE_SUPERVISOR_VERSION 1u
#define SLIDE_SUPERVISOR_PAYLOAD_SIZE 12u
#define SLIDE_SUPERVISOR_POLL_SLICE_MS 10
#define SLIDE_SUPERVISOR_REAP_GRACE_MS 500u

struct child_state {
  int reaped;
  int status_known;
  int status;
};

static void put_u16_le(unsigned char *dst, uint16_t value) {
  dst[0] = (unsigned char)(value & 0xffu);
  dst[1] = (unsigned char)((value >> 8) & 0xffu);
}

static void put_u32_le(unsigned char *dst, uint32_t value) {
  dst[0] = (unsigned char)(value & 0xffu);
  dst[1] = (unsigned char)((value >> 8) & 0xffu);
  dst[2] = (unsigned char)((value >> 16) & 0xffu);
  dst[3] = (unsigned char)((value >> 24) & 0xffu);
}

static void put_u64_le(unsigned char *dst, uint64_t value) {
  unsigned int i;
  for (i = 0; i < 8; ++i) {
    dst[i] = (unsigned char)((value >> (i * 8)) & 0xffu);
  }
}

static uint16_t get_u16_le(const unsigned char *src) {
  return (uint16_t)((uint16_t)src[0] | ((uint16_t)src[1] << 8));
}

static uint32_t get_u32_le(const unsigned char *src) {
  return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
         ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static uint64_t get_u64_le(const unsigned char *src) {
  uint64_t value = 0;
  unsigned int i;
  for (i = 0; i < 8; ++i) {
    value |= (uint64_t)src[i] << (i * 8);
  }
  return value;
}

static uint32_t frame_checksum(const unsigned char *frame, size_t size) {
  uint32_t hash = 2166136261u;
  size_t i;
  for (i = 0; i < size; ++i) {
    hash ^= (uint32_t)frame[i];
    hash *= 16777619u;
  }
  return hash;
}

static void encode_frame(
    unsigned char frame[SLIDE_SUPERVISOR_FRAME_SIZE],
    const struct slide_supervisor_result *result) {
  memset(frame, 0, SLIDE_SUPERVISOR_FRAME_SIZE);
  put_u32_le(frame + 0, SLIDE_SUPERVISOR_MAGIC);
  put_u16_le(frame + 4, SLIDE_SUPERVISOR_VERSION);
  put_u16_le(frame + 6, SLIDE_SUPERVISOR_FRAME_SIZE);
  put_u32_le(frame + 8, result->code);
  put_u32_le(frame + 12, 0);
  put_u64_le(frame + 16, result->value);
  put_u32_le(frame + 24, SLIDE_SUPERVISOR_PAYLOAD_SIZE);
  put_u32_le(frame + 28, frame_checksum(frame, 28));
}

static int decode_frame(
    const unsigned char frame[SLIDE_SUPERVISOR_FRAME_SIZE],
    struct slide_supervisor_result *result) {
  if (get_u32_le(frame + 0) != SLIDE_SUPERVISOR_MAGIC ||
      get_u16_le(frame + 4) != SLIDE_SUPERVISOR_VERSION ||
      get_u16_le(frame + 6) != SLIDE_SUPERVISOR_FRAME_SIZE ||
      get_u32_le(frame + 12) != 0 ||
      get_u32_le(frame + 24) != SLIDE_SUPERVISOR_PAYLOAD_SIZE ||
      get_u32_le(frame + 28) != frame_checksum(frame, 28)) {
    errno = EPROTO;
    return -1;
  }
  result->code = get_u32_le(frame + 8);
  result->value = get_u64_le(frame + 16);
  return 0;
}

static int set_cloexec(int fd) {
  int flags;
  do {
    flags = fcntl(fd, F_GETFD);
  } while (flags < 0 && errno == EINTR);
  if (flags < 0) {
    return -1;
  }
  if ((flags & FD_CLOEXEC) != 0) {
    return 0;
  }
  while (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
    if (errno != EINTR) {
      return -1;
    }
  }
  return 0;
}

static int set_nonblocking(int fd) {
  int flags;
  do {
    flags = fcntl(fd, F_GETFL);
  } while (flags < 0 && errno == EINTR);
  if (flags < 0) {
    return -1;
  }
  if ((flags & O_NONBLOCK) != 0) {
    return 0;
  }
  while (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    if (errno != EINTR) {
      return -1;
    }
  }
  return 0;
}

int slide_supervisor_pipe(int fds[2]) {
  int made = 0;
  int saved_errno;

  if (fds == NULL) {
    errno = EINVAL;
    return -1;
  }

#if defined(__linux__) || defined(__ANDROID__)
  if (pipe2(fds, O_CLOEXEC) == 0) {
    made = 1;
  } else if (errno != ENOSYS && errno != EINVAL) {
    return -1;
  }
#endif

  if (!made && pipe(fds) != 0) {
    return -1;
  }

  if (set_cloexec(fds[0]) != 0 || set_cloexec(fds[1]) != 0 ||
      set_nonblocking(fds[0]) != 0) {
    saved_errno = errno;
    close(fds[0]);
    close(fds[1]);
    errno = saved_errno;
    return -1;
  }
  return 0;
}

int slide_supervisor_write_result(
    int write_fd, const struct slide_supervisor_result *result) {
  unsigned char frame[SLIDE_SUPERVISOR_FRAME_SIZE];
  size_t used = 0;

  if (write_fd < 0 || result == NULL) {
    errno = EINVAL;
    return -1;
  }
  encode_frame(frame, result);

  while (used < sizeof(frame)) {
    ssize_t wrote = write(write_fd, frame + used, sizeof(frame) - used);
    if (wrote > 0) {
      used += (size_t)wrote;
      continue;
    }
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote == 0) {
      errno = EIO;
    }
    return -1;
  }
  return 0;
}

static int timespec_valid(const struct timespec *value) {
  return value != NULL && value->tv_sec >= 0 && value->tv_nsec >= 0 &&
         value->tv_nsec < 1000000000L;
}

static int remaining_ms_ceil(
    const struct timespec *deadline, const struct timespec *now) {
  int64_t seconds = (int64_t)deadline->tv_sec - (int64_t)now->tv_sec;
  int64_t nanoseconds = (int64_t)deadline->tv_nsec - (int64_t)now->tv_nsec;
  uint64_t milliseconds;

  if (nanoseconds < 0) {
    --seconds;
    nanoseconds += 1000000000LL;
  }
  if (seconds < 0 || (seconds == 0 && nanoseconds == 0)) {
    return 0;
  }
  if ((uint64_t)seconds > (uint64_t)INT_MAX / 1000u) {
    return INT_MAX;
  }
  milliseconds = (uint64_t)seconds * 1000u;
  milliseconds += ((uint64_t)nanoseconds + 999999u) / 1000000u;
  if (milliseconds > (uint64_t)INT_MAX) {
    return INT_MAX;
  }
  return (int)milliseconds;
}

int slide_supervisor_deadline_after_ms(
    struct timespec *deadline, uint64_t timeout_ms) {
  struct timespec now;
  uint64_t seconds;
  uint64_t nanoseconds;
  int64_t base_seconds;

  if (deadline == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return -1;
  }

  seconds = timeout_ms / 1000u;
  nanoseconds = (timeout_ms % 1000u) * 1000000u;
  base_seconds = (int64_t)now.tv_sec;
  if (seconds > (uint64_t)INT64_MAX ||
      base_seconds > INT64_MAX - (int64_t)seconds) {
    errno = EOVERFLOW;
    return -1;
  }

  deadline->tv_sec = (time_t)(base_seconds + (int64_t)seconds);
  deadline->tv_nsec = now.tv_nsec + (long)nanoseconds;
  if (deadline->tv_nsec >= 1000000000L) {
    ++deadline->tv_sec;
    deadline->tv_nsec -= 1000000000L;
  }
  return 0;
}

static int sample_child(pid_t child, struct child_state *state) {
  pid_t got;

  if (state->reaped) {
    return 0;
  }
  for (;;) {
    got = waitpid(child, &state->status, WNOHANG);
    if (got == child) {
      state->reaped = 1;
      state->status_known = 1;
      return 0;
    }
    if (got == 0) {
      return 0;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == ECHILD) {
      state->reaped = 1;
      state->status_known = 0;
      return 0;
    }
    return -1;
  }
}

static int signal_process_group(pid_t child) {
  if (kill(-child, SIGKILL) == 0) {
    return 0;
  }
  if (errno != ESRCH) {
    return -1;
  }
  /* The group may have disappeared before setpgid; still stop its leader. */
  if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
    return -1;
  }
  return 0;
}

static int poll_no_fds(int timeout_ms) {
  int rc;
  do {
    rc = poll(NULL, 0, timeout_ms);
  } while (rc < 0 && errno == EINTR);
  return rc;
}

static int reap_with_grace(pid_t child, struct child_state *state) {
  struct timespec deadline;

  if (state->reaped) {
    return 0;
  }
  if (slide_supervisor_deadline_after_ms(
          &deadline, SLIDE_SUPERVISOR_REAP_GRACE_MS) != 0) {
    return -1;
  }

  for (;;) {
    struct timespec now;
    int remaining;

    if (sample_child(child, state) != 0) {
      return -1;
    }
    if (state->reaped) {
      return 0;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      return -1;
    }
    remaining = remaining_ms_ceil(&deadline, &now);
    if (remaining == 0) {
      errno = ETIMEDOUT;
      return -1;
    }
    if (remaining > SLIDE_SUPERVISOR_POLL_SLICE_MS) {
      remaining = SLIDE_SUPERVISOR_POLL_SLICE_MS;
    }
    if (poll_no_fds(remaining) < 0) {
      return -1;
    }
  }
}

static int outcome_errno(enum slide_supervisor_outcome outcome) {
  switch (outcome) {
    case SLIDE_SUPERVISOR_OK:
      return 0;
    case SLIDE_SUPERVISOR_BAD_ARGUMENT:
      return EINVAL;
    case SLIDE_SUPERVISOR_TIMEOUT:
    case SLIDE_SUPERVISOR_REAP_TIMEOUT:
      return ETIMEDOUT;
    case SLIDE_SUPERVISOR_CHILD_EXITED:
      return ECHILD;
    case SLIDE_SUPERVISOR_PROTOCOL_ERROR:
      return EPROTO;
    case SLIDE_SUPERVISOR_SYSTEM_ERROR:
      return EIO;
  }
  return EIO;
}

enum slide_supervisor_outcome slide_supervisor_collect(
    pid_t child, int read_fd, const struct timespec *deadline,
    struct slide_supervisor_result *result, int *wait_status) {
  unsigned char frame[SLIDE_SUPERVISOR_FRAME_SIZE];
  struct child_state child_state;
  size_t used = 0;
  int saw_eof = 0;
  int terminal_errno = 0;
  int signal_errno = 0;
  enum slide_supervisor_outcome outcome = SLIDE_SUPERVISOR_SYSTEM_ERROR;

  memset(&child_state, 0, sizeof(child_state));
  if (wait_status != NULL) {
    *wait_status = -1;
  }
  if (child <= 0 || read_fd < 0 || !timespec_valid(deadline) ||
      result == NULL) {
    if (read_fd >= 0) {
      close(read_fd);
    }
    errno = EINVAL;
    return SLIDE_SUPERVISOR_BAD_ARGUMENT;
  }
  memset(result, 0, sizeof(*result));
  if (set_cloexec(read_fd) != 0 || set_nonblocking(read_fd) != 0) {
    terminal_errno = errno;
    outcome = SLIDE_SUPERVISOR_SYSTEM_ERROR;
    goto cleanup;
  }

  for (;;) {
    int read_error = 0;

    if (sample_child(child, &child_state) != 0) {
      terminal_errno = errno;
      outcome = SLIDE_SUPERVISOR_SYSTEM_ERROR;
      break;
    }

    while (used < sizeof(frame)) {
      ssize_t got = read(read_fd, frame + used, sizeof(frame) - used);
      if (got > 0) {
        used += (size_t)got;
        continue;
      }
      if (got == 0) {
        saw_eof = 1;
        break;
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      terminal_errno = errno;
      read_error = 1;
      break;
    }
    if (read_error) {
      outcome = SLIDE_SUPERVISOR_SYSTEM_ERROR;
      break;
    }

    if (used == sizeof(frame)) {
      if (decode_frame(frame, result) == 0) {
        outcome = SLIDE_SUPERVISOR_OK;
      } else {
        terminal_errno = errno;
        outcome = SLIDE_SUPERVISOR_PROTOCOL_ERROR;
      }
      break;
    }
    if (child_state.reaped || saw_eof) {
      outcome = used == 0 ? SLIDE_SUPERVISOR_CHILD_EXITED
                          : SLIDE_SUPERVISOR_PROTOCOL_ERROR;
      terminal_errno = outcome_errno(outcome);
      break;
    }

    {
      struct timespec now;
      struct pollfd descriptor;
      int timeout_ms;
      int poll_result;

      if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        terminal_errno = errno;
        outcome = SLIDE_SUPERVISOR_SYSTEM_ERROR;
        break;
      }
      timeout_ms = remaining_ms_ceil(deadline, &now);
      if (timeout_ms == 0) {
        outcome = used == 0 ? SLIDE_SUPERVISOR_TIMEOUT
                            : SLIDE_SUPERVISOR_PROTOCOL_ERROR;
        terminal_errno = outcome_errno(outcome);
        break;
      }
      if (timeout_ms > SLIDE_SUPERVISOR_POLL_SLICE_MS) {
        timeout_ms = SLIDE_SUPERVISOR_POLL_SLICE_MS;
      }

      descriptor.fd = read_fd;
      descriptor.events = POLLIN;
      descriptor.revents = 0;
      do {
        poll_result = poll(&descriptor, 1, timeout_ms);
      } while (poll_result < 0 && errno == EINTR);
      if (poll_result < 0) {
        terminal_errno = errno;
        outcome = SLIDE_SUPERVISOR_SYSTEM_ERROR;
        break;
      }
    }
  }

cleanup:
  if (signal_process_group(child) != 0) {
    signal_errno = errno;
  }
  if (reap_with_grace(child, &child_state) != 0) {
    terminal_errno = errno;
    outcome = terminal_errno == ETIMEDOUT ? SLIDE_SUPERVISOR_REAP_TIMEOUT
                                          : SLIDE_SUPERVISOR_SYSTEM_ERROR;
  } else if (signal_errno != 0) {
    int group_probe = kill(-child, 0);
    int group_errno = errno;

    /*
     * Darwin can report EPERM when the group leader becomes a zombie during
     * killpg.  It is benign only after the leader is reaped and the dedicated
     * group is proven gone.  Any surviving group remains a cleanup failure.
     */
    if (!(signal_errno == EPERM && group_probe != 0 &&
          group_errno == ESRCH)) {
      terminal_errno = signal_errno;
      outcome = SLIDE_SUPERVISOR_SYSTEM_ERROR;
    }
  }
  if (close(read_fd) != 0 && terminal_errno == 0) {
    terminal_errno = errno;
    outcome = SLIDE_SUPERVISOR_SYSTEM_ERROR;
  }
  if (wait_status != NULL && child_state.status_known) {
    *wait_status = child_state.status;
  }
  if (terminal_errno == 0) {
    terminal_errno = outcome_errno(outcome);
  }
  errno = terminal_errno;
  return outcome;
}

const char *slide_supervisor_outcome_name(
    enum slide_supervisor_outcome outcome) {
  switch (outcome) {
    case SLIDE_SUPERVISOR_OK:
      return "ok";
    case SLIDE_SUPERVISOR_BAD_ARGUMENT:
      return "bad-argument";
    case SLIDE_SUPERVISOR_SYSTEM_ERROR:
      return "system-error";
    case SLIDE_SUPERVISOR_TIMEOUT:
      return "timeout";
    case SLIDE_SUPERVISOR_CHILD_EXITED:
      return "child-exited";
    case SLIDE_SUPERVISOR_PROTOCOL_ERROR:
      return "protocol-error";
    case SLIDE_SUPERVISOR_REAP_TIMEOUT:
      return "reap-timeout";
  }
  return "unknown";
}
