#include "perf_reclaim_gate.h"

#include <assert.h>
#include <stdint.h>

static void test_candidate_derivation(void) {
  struct ghostlock_perf_candidate candidates[GHOSTLOCK_PERF_MAX_CANDIDATES];
  size_t count = ghostlock_perf_build_candidates(
      0xffffffd1e1758000ULL, 0x80600ULL, 0x180000ULL,
      candidates, GHOSTLOCK_PERF_MAX_CANDIDATES);
  assert(count == 4);
  assert(candidates[0].pfn == 0x161758ULL);
  assert(candidates[0].memstart == 0xffffffef80000000ULL);
  assert(candidates[1].pfn == 0x121758ULL);
  assert(candidates[1].memstart == 0xffffffef40000000ULL);
  assert(candidates[2].pfn == 0xe1758ULL);
  assert(candidates[2].memstart == 0xffffffef00000000ULL);
  assert(candidates[3].pfn == 0xa1758ULL);
  assert(candidates[3].memstart == 0xffffffeec0000000ULL);
}

static void test_rejections_and_capacity(void) {
  struct ghostlock_perf_candidate candidates[GHOSTLOCK_PERF_MAX_CANDIDATES];
  assert(ghostlock_perf_build_candidates(
             0xffffffd1e1758001ULL, 0x80600ULL, 0x180000ULL,
             candidates, GHOSTLOCK_PERF_MAX_CANDIDATES) == 0);
  assert(ghostlock_perf_build_candidates(
             0xffffffd1e1758000ULL, 0x180000ULL, 0x80600ULL,
             candidates, GHOSTLOCK_PERF_MAX_CANDIDATES) == 0);
  assert(ghostlock_perf_build_candidates(
             0xffffffd1e1758000ULL, 0x80600ULL, 0x180000ULL,
             candidates, 2) == 3);
}

int main(void) {
  test_candidate_derivation();
  test_rejections_and_capacity();
  return 0;
}
