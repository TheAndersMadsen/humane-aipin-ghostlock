#include "perf_reclaim_gate.h"
#include "profile_geometry.h"

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

static void test_profile_geometry_binding(void) {
  assert(ghostlock_profile_mm_geometry_matches(
      PROFILE_MM_OBJECT_SIZE, PROFILE_MM_SLAB_SIZE, PROFILE_MM_ORDER,
      PROFILE_MM_OBJECTS_PER_SLAB, PROFILE_MM_CPU_PARTIAL));
  assert(!ghostlock_profile_mm_geometry_matches(
      PROFILE_MM_OBJECT_SIZE + 1, PROFILE_MM_SLAB_SIZE, PROFILE_MM_ORDER,
      PROFILE_MM_OBJECTS_PER_SLAB, PROFILE_MM_CPU_PARTIAL));
  assert(!ghostlock_profile_mm_geometry_matches(
      PROFILE_MM_OBJECT_SIZE, PROFILE_MM_SLAB_SIZE + 1, PROFILE_MM_ORDER,
      PROFILE_MM_OBJECTS_PER_SLAB, PROFILE_MM_CPU_PARTIAL));
  assert(!ghostlock_profile_mm_geometry_matches(
      PROFILE_MM_OBJECT_SIZE, PROFILE_MM_SLAB_SIZE, PROFILE_MM_ORDER + 1,
      PROFILE_MM_OBJECTS_PER_SLAB, PROFILE_MM_CPU_PARTIAL));
  assert(!ghostlock_profile_mm_geometry_matches(
      PROFILE_MM_OBJECT_SIZE, PROFILE_MM_SLAB_SIZE, PROFILE_MM_ORDER,
      PROFILE_MM_OBJECTS_PER_SLAB + 1, PROFILE_MM_CPU_PARTIAL));
  assert(!ghostlock_profile_mm_geometry_matches(
      PROFILE_MM_OBJECT_SIZE, PROFILE_MM_SLAB_SIZE, PROFILE_MM_ORDER,
      PROFILE_MM_OBJECTS_PER_SLAB, PROFILE_MM_CPU_PARTIAL + 1));
}

int main(void) {
  test_candidate_derivation();
  test_rejections_and_capacity();
  test_profile_geometry_binding();
  return 0;
}
