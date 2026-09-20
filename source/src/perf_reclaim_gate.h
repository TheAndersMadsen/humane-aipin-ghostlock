/* SPDX-License-Identifier: Apache-2.0 */
#ifndef GHOSTLOCK_PERF_RECLAIM_GATE_H
#define GHOSTLOCK_PERF_RECLAIM_GATE_H

#include <stddef.h>
#include <stdint.h>

#define GHOSTLOCK_PERF_MAX_CANDIDATES 8

struct ghostlock_perf_candidate {
  uint64_t pfn;
  uint64_t memstart;
};

struct ghostlock_perf_gate_result {
  int enabled;
  int configured;
  int free_started;
  int capture_verified;
  size_t candidate_count;
  size_t matched_index;
  uintptr_t page_base;
  uint64_t zone_start_pfn;
  uint64_t zone_end_pfn;
  uint64_t matched_pfn;
  uint64_t matched_memstart;
  uint64_t free_count;
  uint64_t alloc_count;
  struct ghostlock_perf_candidate
      candidates[GHOSTLOCK_PERF_MAX_CANDIDATES];
  uint64_t candidate_free_counts[GHOSTLOCK_PERF_MAX_CANDIDATES];
};

size_t ghostlock_perf_build_candidates(
    uintptr_t page_base, uint64_t zone_start_pfn, uint64_t zone_end_pfn,
    struct ghostlock_perf_candidate *candidates, size_t capacity);

int ghostlock_perf_gate_init(void);
int ghostlock_perf_gate_enabled(void);
int ghostlock_perf_gate_prepare_attempt(void);
int ghostlock_perf_gate_configure(uintptr_t page_base);
int ghostlock_perf_gate_begin_free(void);
int ghostlock_perf_gate_finish_free_begin_alloc(void);
/* Return 1 on capture, 0 while pending, and -1 on a counter error. */
int ghostlock_perf_gate_poll_alloc(void);
int ghostlock_perf_gate_finish_alloc(void);
const struct ghostlock_perf_gate_result *ghostlock_perf_gate_result(void);
void ghostlock_perf_gate_close(void);

#endif
