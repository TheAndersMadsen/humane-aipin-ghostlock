/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE

#include "perf_reclaim_gate.h"

#include "offset.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define GHOSTLOCK_TRACE_MM_PAGE_FREE 239ULL
#define GHOSTLOCK_TRACE_MM_PAGE_ALLOC 241ULL
#define GHOSTLOCK_FILTER_CAP 128

struct perf_gate_state {
  int free_fds[GHOSTLOCK_PERF_MAX_CANDIDATES];
  int alloc_fds[GHOSTLOCK_PERF_MAX_CANDIDATES];
  int pool_ready;
  struct ghostlock_perf_gate_result result;
};

static struct perf_gate_state gate = {
    .free_fds = {-1, -1, -1, -1, -1, -1, -1, -1},
    .alloc_fds = {-1, -1, -1, -1, -1, -1, -1, -1},
    .result = {.matched_index = SIZE_MAX},
};

static void initialize_fds(void) {
  for (size_t i = 0; i < GHOSTLOCK_PERF_MAX_CANDIDATES; ++i) {
    gate.free_fds[i] = -1;
    gate.alloc_fds[i] = -1;
  }
  gate.result.matched_index = SIZE_MAX;
}

static int perf_event_open_count(uint64_t id) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_TRACEPOINT;
  attr.size = sizeof(attr);
  attr.config = id;
  attr.disabled = 1;
  return (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1,
                      PERF_FLAG_FD_CLOEXEC);
}

static void close_pool(void) {
  for (size_t i = 0; i < GHOSTLOCK_PERF_MAX_CANDIDATES; ++i) {
    if (gate.free_fds[i] >= 0)
      close(gate.free_fds[i]);
    if (gate.alloc_fds[i] >= 0)
      close(gate.alloc_fds[i]);
    gate.free_fds[i] = -1;
    gate.alloc_fds[i] = -1;
  }
  gate.pool_ready = 0;
}

static int read_count(int fd, uint64_t *value) {
  uint8_t *cursor = (uint8_t *)value;
  size_t remaining = sizeof(*value);
  *value = 0;
  while (remaining) {
    ssize_t got = read(fd, cursor, remaining);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0) {
      if (got == 0)
        errno = EIO;
      return 0;
    }
    cursor += (size_t)got;
    remaining -= (size_t)got;
  }
  return 1;
}

static int disable_fd(int fd) {
  if (fd < 0)
    return 1;
  return ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) == 0;
}

static int reset_enable_fd(int fd) {
  return fd >= 0 && ioctl(fd, PERF_EVENT_IOC_RESET, 0) == 0 &&
         ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == 0;
}

static int parse_zoneinfo(uint64_t *start_pfn, uint64_t *end_pfn) {
  FILE *file = fopen("/proc/zoneinfo", "r");
  if (!file)
    return 0;

  char line[256];
  uint64_t current_start = 0;
  uint64_t current_spanned = 0;
  int have_start = 0;
  int have_spanned = 0;
  uint64_t minimum = UINT64_MAX;
  uint64_t maximum = 0;

  while (fgets(line, sizeof(line), file)) {
    if (strncmp(line, "Node ", 5) == 0) {
      if (have_start && have_spanned && current_spanned) {
        if (current_start < minimum)
          minimum = current_start;
        if (current_start + current_spanned > maximum)
          maximum = current_start + current_spanned;
      }
      current_start = 0;
      current_spanned = 0;
      have_start = 0;
      have_spanned = 0;
      continue;
    }

    char *field = strstr(line, "start_pfn:");
    if (field) {
      errno = 0;
      char *end = NULL;
      current_start = strtoull(field + strlen("start_pfn:"), &end, 10);
      if (errno || end == field + strlen("start_pfn:")) {
        fclose(file);
        errno = EINVAL;
        return 0;
      }
      have_start = 1;
      continue;
    }

    field = strstr(line, "spanned");
    if (field) {
      errno = 0;
      char *end = NULL;
      current_spanned = strtoull(field + strlen("spanned"), &end, 10);
      if (errno || end == field + strlen("spanned")) {
        fclose(file);
        errno = EINVAL;
        return 0;
      }
      have_spanned = 1;
    }
  }

  if (have_start && have_spanned && current_spanned) {
    if (current_start < minimum)
      minimum = current_start;
    if (current_start + current_spanned > maximum)
      maximum = current_start + current_spanned;
  }
  int close_rc = fclose(file);
  if (close_rc != 0)
    return 0;
  if (minimum == UINT64_MAX || maximum <= minimum) {
    errno = ERANGE;
    return 0;
  }
  *start_pfn = minimum;
  *end_pfn = maximum;
  return 1;
}

void ghostlock_perf_gate_close(void) {
  close_pool();
  memset(&gate, 0, sizeof(gate));
  initialize_fds();
}

int ghostlock_perf_gate_init(void) {
  const char *requested = getenv("AI_PIN_PERF_RECLAIM_GATE");
  ghostlock_perf_gate_close();
  if (!requested || !*requested)
    return 1;
  if (strcmp(requested, "1") != 0) {
    errno = EINVAL;
    return 0;
  }
  if (!parse_zoneinfo(&gate.result.zone_start_pfn,
                      &gate.result.zone_end_pfn))
    return 0;

  gate.result.enabled = 1;
  return 1;
}

int ghostlock_perf_gate_enabled(void) {
  return gate.result.enabled;
}

int ghostlock_perf_gate_prepare_attempt(void) {
  if (!gate.result.enabled)
    return 1;

  close_pool();
  gate.result.configured = 0;
  gate.result.free_started = 0;
  gate.result.capture_verified = 0;
  gate.result.candidate_count = 0;
  gate.result.matched_index = SIZE_MAX;
  gate.result.page_base = 0;
  gate.result.matched_pfn = 0;
  gate.result.matched_memstart = 0;
  gate.result.free_count = 0;
  gate.result.alloc_count = 0;
  memset(gate.result.candidates, 0, sizeof(gate.result.candidates));
  memset(gate.result.candidate_free_counts, 0,
         sizeof(gate.result.candidate_free_counts));

  for (size_t i = 0; i < GHOSTLOCK_PERF_MAX_CANDIDATES; ++i) {
    gate.free_fds[i] = perf_event_open_count(GHOSTLOCK_TRACE_MM_PAGE_FREE);
    if (gate.free_fds[i] < 0)
      goto fail;
    gate.alloc_fds[i] = perf_event_open_count(GHOSTLOCK_TRACE_MM_PAGE_ALLOC);
    if (gate.alloc_fds[i] < 0)
      goto fail;
  }
  gate.pool_ready = 1;
  return 1;

fail: {
    int saved_errno = errno;
    close_pool();
    errno = saved_errno;
    return 0;
  }
}

int ghostlock_perf_gate_configure(uintptr_t page_base) {
  if (!gate.result.enabled || !gate.pool_ready) {
    errno = EINVAL;
    return 0;
  }
  for (size_t i = 0; i < GHOSTLOCK_PERF_MAX_CANDIDATES; ++i) {
    (void)disable_fd(gate.free_fds[i]);
    (void)disable_fd(gate.alloc_fds[i]);
  }

  gate.result.configured = 0;
  gate.result.free_started = 0;
  gate.result.capture_verified = 0;
  gate.result.page_base = page_base;
  gate.result.matched_index = SIZE_MAX;
  gate.result.matched_pfn = 0;
  gate.result.matched_memstart = 0;
  gate.result.free_count = 0;
  gate.result.alloc_count = 0;
  memset(gate.result.candidate_free_counts, 0,
         sizeof(gate.result.candidate_free_counts));
  gate.result.candidate_count = ghostlock_perf_build_candidates(
      page_base, gate.result.zone_start_pfn, gate.result.zone_end_pfn,
      gate.result.candidates, GHOSTLOCK_PERF_MAX_CANDIDATES);
  if (gate.result.candidate_count == 0 ||
      gate.result.candidate_count > GHOSTLOCK_PERF_MAX_CANDIDATES) {
    errno = ERANGE;
    return 0;
  }

  for (size_t i = 0; i < gate.result.candidate_count; ++i) {
    char filter[GHOSTLOCK_FILTER_CAP];
    int length = snprintf(filter, sizeof(filter),
                          "order == 3 && pfn == %" PRIu64,
                          gate.result.candidates[i].pfn);
    if (length <= 0 || length >= (int)sizeof(filter)) {
      errno = EOVERFLOW;
      return 0;
    }
    if (ioctl(gate.free_fds[i], PERF_EVENT_IOC_SET_FILTER, filter) != 0 ||
        ioctl(gate.alloc_fds[i], PERF_EVENT_IOC_SET_FILTER, filter) != 0)
      return 0;
  }
  gate.result.configured = 1;
  return 1;
}

int ghostlock_perf_gate_begin_free(void) {
  if (!gate.result.enabled || !gate.result.configured) {
    errno = EINVAL;
    return 0;
  }
  gate.result.free_started = 0;
  for (size_t i = 0; i < gate.result.candidate_count; ++i) {
    if (!reset_enable_fd(gate.free_fds[i])) {
      int saved_errno = errno;
      for (size_t j = 0; j <= i; ++j)
        (void)disable_fd(gate.free_fds[j]);
      errno = saved_errno;
      return 0;
    }
  }
  gate.result.free_started = 1;
  return 1;
}

int ghostlock_perf_gate_finish_free_begin_alloc(void) {
  if (!gate.result.enabled || !gate.result.configured ||
      !gate.result.free_started) {
    errno = EINVAL;
    return 0;
  }

  for (size_t i = 0; i < gate.result.candidate_count; ++i) {
    if (!disable_fd(gate.free_fds[i]))
      return 0;
  }

  size_t matches = 0;
  size_t matched = SIZE_MAX;
  uint64_t matched_count = 0;
  for (size_t i = 0; i < gate.result.candidate_count; ++i) {
    uint64_t count = 0;
    if (!read_count(gate.free_fds[i], &count))
      return 0;
    gate.result.candidate_free_counts[i] = count;
    if (count) {
      ++matches;
      matched = i;
      matched_count = count;
    }
  }
  gate.result.free_started = 0;
  if (matches != 1 || matched_count != 1) {
    errno = EAGAIN;
    return 0;
  }

  gate.result.matched_index = matched;
  gate.result.matched_pfn = gate.result.candidates[matched].pfn;
  gate.result.matched_memstart = gate.result.candidates[matched].memstart;
  gate.result.free_count = matched_count;
  if (!reset_enable_fd(gate.alloc_fds[matched]))
    return 0;
  return 1;
}

int ghostlock_perf_gate_poll_alloc(void) {
  if (!gate.result.enabled || gate.result.matched_index == SIZE_MAX ||
      gate.result.matched_index >= gate.result.candidate_count) {
    errno = EINVAL;
    return -1;
  }

  uint64_t count = 0;
  if (!read_count(gate.alloc_fds[gate.result.matched_index], &count))
    return -1;
  gate.result.alloc_count = count;
  if (count == 0)
    return 0;
  if (count != 1) {
    errno = EOVERFLOW;
    return -1;
  }
  return 1;
}

int ghostlock_perf_gate_finish_alloc(void) {
  if (!gate.result.enabled || gate.result.matched_index == SIZE_MAX ||
      gate.result.matched_index >= gate.result.candidate_count) {
    errno = EINVAL;
    return 0;
  }
  int fd = gate.alloc_fds[gate.result.matched_index];
  if (!disable_fd(fd) || !read_count(fd, &gate.result.alloc_count))
    return 0;
  if (gate.result.alloc_count != 1) {
    errno = EAGAIN;
    return 0;
  }
  gate.result.capture_verified = 1;
  return 1;
}

const struct ghostlock_perf_gate_result *ghostlock_perf_gate_result(void) {
  return &gate.result;
}
