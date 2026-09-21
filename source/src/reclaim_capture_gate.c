#define _POSIX_C_SOURCE 200809L

#include "reclaim_capture_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define GATE_TOKEN_CAP 65
#define GATE_COMMAND_CAP 160
#define GATE_STATUS_CAP 256
#define GATE_DEFAULT_TIMEOUT_MS 120000ULL
#define GATE_MAX_TIMEOUT_MS 240000ULL
#define GATE_POLL_NS 20000000L

struct capture_gate_state {
  int enabled;
  int control_fd;
  int status_fd;
  uint64_t timeout_ms;
  char token[GATE_TOKEN_CAP];
};

static struct capture_gate_state gate = {
    .control_fd = -1,
    .status_fd = -1,
};

static int token_valid(const char *token) {
  size_t length;
  if (!token) {
    return 0;
  }
  length = strlen(token);
  if (length < 8 || length >= GATE_TOKEN_CAP) {
    return 0;
  }
  for (const char *p = token; *p; ++p) {
    if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))) {
      return 0;
    }
  }
  return 1;
}

static int parse_timeout(const char *text, uint64_t *timeout_ms) {
  if (!text || !*text) {
    *timeout_ms = GATE_DEFAULT_TIMEOUT_MS;
    return 1;
  }
  errno = 0;
  char *end = NULL;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno || end == text || *end || value < 10 ||
      value > GATE_MAX_TIMEOUT_MS) {
    errno = EINVAL;
    return 0;
  }
  *timeout_ms = (uint64_t)value;
  return 1;
}

static int open_owned_regular(const char *path, int flags) {
  if (!path || path[0] != '/') {
    errno = EINVAL;
    return -1;
  }
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  int fd = open(path, flags | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
    int saved = errno ? errno : EPERM;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}

static int write_full(int fd, const char *data, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t n = write(fd, data + offset, length - offset);
    if (n > 0) {
      offset += (size_t)n;
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else {
      if (n == 0) {
        errno = EIO;
      }
      return 0;
    }
  }
  return 1;
}

static int write_status(const char *phase, uintptr_t page_base, int error) {
  char status[GATE_STATUS_CAP];
  int length = snprintf(
      status, sizeof(status),
      "phase=%s token=%s pid=%d base=%016llx errno=%d trigger=disabled\n",
      phase, gate.token, getpid(), (unsigned long long)page_base, error);
  if (length < 0 || length >= (int)sizeof(status)) {
    errno = EOVERFLOW;
    return 0;
  }
  if (ftruncate(gate.status_fd, 0) != 0 ||
      lseek(gate.status_fd, 0, SEEK_SET) < 0) {
    return 0;
  }
  return write_full(gate.status_fd, status, (size_t)length);
}

static int64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return -1;
  }
  return (int64_t)now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
}

static void poll_pause(void) {
  struct timespec request = {.tv_sec = 0, .tv_nsec = GATE_POLL_NS};
  struct timespec remain;
  while (nanosleep(&request, &remain) != 0 && errno == EINTR) {
    request = remain;
  }
}

void ghostlock_capture_gate_close(void) {
  if (gate.control_fd >= 0) {
    close(gate.control_fd);
  }
  if (gate.status_fd >= 0) {
    close(gate.status_fd);
  }
  memset(&gate, 0, sizeof(gate));
  gate.control_fd = -1;
  gate.status_fd = -1;
}

int ghostlock_capture_gate_init(void) {
  const char *control_path = getenv("AI_PIN_RECLAIM_GATE_CONTROL");
  const char *status_path = getenv("AI_PIN_RECLAIM_GATE_STATUS");
  const char *token = getenv("AI_PIN_RECLAIM_GATE_TOKEN");
  const char *timeout = getenv("AI_PIN_RECLAIM_GATE_TIMEOUT_MS");
  int configured = (control_path && *control_path) ||
                   (status_path && *status_path) || (token && *token) ||
                   (timeout && *timeout);

  ghostlock_capture_gate_close();
  if (!configured) {
    return 1;
  }
  if (!control_path || !*control_path || !status_path || !*status_path ||
      strcmp(control_path, status_path) == 0 || !token_valid(token) ||
      !parse_timeout(timeout, &gate.timeout_ms)) {
    errno = EINVAL;
    return 0;
  }

  gate.control_fd = open_owned_regular(control_path, O_RDONLY);
  if (gate.control_fd < 0) {
    return 0;
  }
  gate.status_fd = open_owned_regular(status_path, O_WRONLY);
  if (gate.status_fd < 0) {
    int saved = errno;
    ghostlock_capture_gate_close();
    errno = saved;
    return 0;
  }

  struct stat control_st;
  if (fstat(gate.control_fd, &control_st) != 0 || control_st.st_size != 0 ||
      ftruncate(gate.status_fd, 0) != 0) {
    int saved = errno ? errno : EBUSY;
    ghostlock_capture_gate_close();
    errno = saved;
    return 0;
  }

  memcpy(gate.token, token, strlen(token) + 1);
  gate.enabled = 1;
  return 1;
}

int ghostlock_capture_gate_enabled(void) {
  return gate.enabled;
}

const char *ghostlock_capture_gate_token(void) {
  return gate.enabled ? gate.token : "-";
}

int ghostlock_capture_gate_wait(uintptr_t page_base) {
  char expected_go[GATE_COMMAND_CAP];
  char expected_abort[GATE_COMMAND_CAP];
  char command[GATE_COMMAND_CAP];
  int64_t start_ms;

  if (!gate.enabled || gate.control_fd < 0 || gate.status_fd < 0) {
    errno = EINVAL;
    return 0;
  }
  int go_length = snprintf(expected_go, sizeof(expected_go), "go %s\n", gate.token);
  int abort_length =
      snprintf(expected_abort, sizeof(expected_abort), "abort %s\n", gate.token);
  if (go_length <= 0 || go_length >= (int)sizeof(expected_go) ||
      abort_length <= 0 || abort_length >= (int)sizeof(expected_abort) ||
      !write_status("waiting", page_base, 0)) {
    int saved = errno ? errno : EIO;
    ghostlock_capture_gate_close();
    errno = saved;
    return 0;
  }

  start_ms = monotonic_ms();
  if (start_ms < 0) {
    int saved = errno;
    (void)write_status("clock-error", page_base, saved);
    ghostlock_capture_gate_close();
    errno = saved;
    return 0;
  }

  for (;;) {
    ssize_t n;
    do {
      n = pread(gate.control_fd, command, sizeof(command) - 1, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
      int saved = errno;
      (void)write_status("read-error", page_base, saved);
      ghostlock_capture_gate_close();
      errno = saved;
      return 0;
    }
    if (n > 0) {
      command[n] = 0;
      if (!strchr(command, '\n')) {
        poll_pause();
        continue;
      }
      if (n == go_length && memcmp(command, expected_go, (size_t)n) == 0) {
        (void)write_status("released", page_base, 0);
        ghostlock_capture_gate_close();
        return 1;
      }
      if (n == abort_length &&
          memcmp(command, expected_abort, (size_t)n) == 0) {
        (void)write_status("aborted", page_base, ECANCELED);
        ghostlock_capture_gate_close();
        errno = ECANCELED;
        return 0;
      }
      (void)write_status("invalid-command", page_base, EPROTO);
      ghostlock_capture_gate_close();
      errno = EPROTO;
      return 0;
    }

    int64_t now_ms = monotonic_ms();
    if (now_ms < 0 || (uint64_t)(now_ms - start_ms) >= gate.timeout_ms) {
      int saved = now_ms < 0 ? errno : ETIMEDOUT;
      (void)write_status("timeout", page_base, saved);
      ghostlock_capture_gate_close();
      errno = saved;
      return 0;
    }
    poll_pause();
  }
}
