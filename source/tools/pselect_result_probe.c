#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PROBE_NFDS 320
#define PROBE_WORDS_PER_SET 5
#define PROBE_SENTINEL_FD 63
#define PROBE_HIGH_FD 512
#define PROBE_WAITER_WORDS 10

static void put_word(fd_set *set, int word, uint64_t value) {
  ((uint64_t *)(void *)set)[word] = value;
}

static uint64_t get_word(const fd_set *set, int word) {
  return ((const uint64_t *)(const void *)set)[word];
}

static int duplicate_selected(const fd_set *in, const fd_set *out,
                              const fd_set *ex, int ready_fd) {
  int opened = 0;
  for (int fd = 0; fd < PROBE_NFDS; fd++) {
    if (!FD_ISSET(fd, in) && !FD_ISSET(fd, out) && !FD_ISSET(fd, ex)) {
      continue;
    }
    if (dup2(ready_fd, fd) != fd) {
      return -1;
    }
    opened++;
  }

  /* Keep n=320 from being clamped if the selected pattern has a low max fd. */
  if (dup2(ready_fd, PROBE_NFDS - 1) != PROBE_NFDS - 1) {
    return -1;
  }
  return opened;
}

static int count_bits(const fd_set *set) {
  int total = 0;
  for (int word = 0; word < PROBE_WORDS_PER_SET; word++) {
    total += __builtin_popcountll(get_word(set, word));
  }
  return total;
}

int main(void) {
  if (FD_SETSIZE < PROBE_NFDS || sizeof(unsigned long) != sizeof(uint64_t)) {
    fprintf(stderr, "[pselect-probe] unsupported fdset=%d ulong=%zu\n",
            FD_SETSIZE, sizeof(unsigned long));
    return 2;
  }

  /* Mode-0-shaped values: five nonzero waiter words, all other words zero. */
  const uint64_t expected[PROBE_WAITER_WORDS] = {
      0xffffff8009de36f0ULL, 0, 0xffffff8009ec2098ULL, 0, 0,
      0, 0xffffffdbdb2f2380ULL, 0xffffffdbdb2f04d0ULL, 130, 0,
  };

  fd_set in;
  fd_set out;
  fd_set ex;
  FD_ZERO(&in);
  FD_ZERO(&out);
  FD_ZERO(&ex);

  /*
   * Retail .45.20 pselect6/core_sys_select stack geometry at nfds=320:
   *   res_in[1..4] -> waiter q0..q3
   *   res_out[0..4] -> waiter q4..q8
   *   res_ex[0] -> waiter q9
   */
  for (int i = 0; i < 4; i++) {
    put_word(&in, i + 1, expected[i]);
  }
  for (int i = 4; i < 9; i++) {
    put_word(&out, i - 4, expected[i]);
  }
  put_word(&ex, 0, expected[9]);
  FD_SET(PROBE_SENTINEL_FD, &in);

  int pair[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
    perror("socketpair");
    return 3;
  }
  int ready_fd = fcntl(pair[0], F_DUPFD_CLOEXEC, PROBE_HIGH_FD);
  int peer_fd = fcntl(pair[1], F_DUPFD_CLOEXEC,
                      ready_fd >= 0 ? ready_fd + 1 : PROBE_HIGH_FD + 1);
  if (ready_fd < 0 || peer_fd < 0) {
    perror("F_DUPFD_CLOEXEC");
    return 4;
  }
  close(pair[0]);
  close(pair[1]);

  const unsigned char byte = 0x5a;
  if (write(peer_fd, &byte, sizeof(byte)) != (ssize_t)sizeof(byte)) {
    perror("socket write");
    return 5;
  }

  int opened = duplicate_selected(&in, &out, &ex, ready_fd);
  if (opened < 0) {
    perror("dup2 selected");
    return 6;
  }

  int expected_ret = count_bits(&in) + count_bits(&out) + count_bits(&ex);
  struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
  errno = 0;
  long ret = syscall(SYS_pselect6, PROBE_NFDS, &in, &out, &ex,
                     &timeout, NULL);
  int saved_errno = errno;

  uint64_t observed[PROBE_WAITER_WORDS] = {0};
  for (int i = 0; i < 4; i++) {
    observed[i] = get_word(&in, i + 1);
  }
  for (int i = 4; i < 9; i++) {
    observed[i] = get_word(&out, i - 4);
  }
  observed[9] = get_word(&ex, 0);

  int exact = memcmp(expected, observed, sizeof(expected)) == 0;
  int sentinel = FD_ISSET(PROBE_SENTINEL_FD, &in);
  printf("[pselect-probe] ret=%ld expected_ret=%d errno=%d opened=%d "
         "sentinel=%d exact=%d\n",
         ret, expected_ret, saved_errno, opened, sentinel, exact);
  for (int i = 0; i < PROBE_WAITER_WORDS; i++) {
    printf("[pselect-probe] q%d expected=%016llx observed=%016llx\n",
           i, (unsigned long long)expected[i],
           (unsigned long long)observed[i]);
  }

  return ret == expected_ret && saved_errno == 0 && sentinel && exact ? 0 : 7;
}
