#define _GNU_SOURCE

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PROBE_WAIT_SECONDS 5
#define PROBE_SETTLE_USEC 200000
#define PROBE_DONE_TIMEOUT_MS 8000

struct probe_state {
  uint32_t wait_word;
  uint32_t target_word;
  uint32_t chain_word;

  atomic_int waiter_ready;
  atomic_int waiter_waiting;
  atomic_int waiter_returned;
  atomic_int waiter_done;
  atomic_int owner_started;
  atomic_int owner_chain_entered;
  atomic_int owner_chain_returned;
  atomic_int owner_done;

  atomic_int waiter_lock_ret;
  atomic_int waiter_lock_errno;
  atomic_int waiter_wait_ret;
  atomic_int waiter_wait_errno;
  atomic_int waiter_unlock_ret;
  atomic_int waiter_unlock_errno;
  atomic_int owner_target_ret;
  atomic_int owner_target_errno;
  atomic_int owner_chain_ret;
  atomic_int owner_chain_errno;
  atomic_int owner_chain_unlock_ret;
  atomic_int owner_chain_unlock_errno;
  atomic_int owner_target_unlock_ret;
  atomic_int owner_target_unlock_errno;
  atomic_int parent_requeue_ret;
  atomic_int parent_requeue_errno;
};

static struct probe_state state;

static long futex_call(uint32_t *uaddr, int op, uint32_t val,
                       const struct timespec *timeout, uint32_t *uaddr2,
                       uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static void raw_line(const char *line, size_t length) {
  while (length != 0) {
    long written = syscall(SYS_write, STDERR_FILENO, line, length);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return;
    }
    line += written;
    length -= (size_t)written;
  }
}

#define RAW_LINE(text) raw_line((text), sizeof(text) - 1)

static void spin_until(atomic_int *value) {
  while (!atomic_load_explicit(value, memory_order_acquire)) {
    syscall(SYS_sched_yield);
  }
}

static void *waiter_main(void *unused) {
  (void)unused;

  errno = 0;
  long ret = futex_call(&state.chain_word, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&state.waiter_lock_ret, (int)ret);
  atomic_store(&state.waiter_lock_errno, errno);
  if (ret != 0) {
    atomic_store(&state.waiter_done, 1);
    return NULL;
  }

  atomic_store_explicit(&state.waiter_ready, 1, memory_order_release);
  spin_until(&state.owner_started);

  struct timespec timeout;
  if (clock_gettime(CLOCK_MONOTONIC, &timeout) != 0) {
    atomic_store(&state.waiter_done, 1);
    return NULL;
  }
  timeout.tv_sec += PROBE_WAIT_SECONDS;

  atomic_store_explicit(&state.waiter_waiting, 1, memory_order_release);
  RAW_LINE("[futex-probe] waiter WAIT_REQUEUE_PI enter\n");
  errno = 0;
  ret = futex_call(&state.wait_word, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                   &state.target_word, 0);
  atomic_store(&state.waiter_wait_ret, (int)ret);
  atomic_store(&state.waiter_wait_errno, errno);
  atomic_store_explicit(&state.waiter_returned, 1, memory_order_release);
  RAW_LINE("[futex-probe] waiter WAIT_REQUEUE_PI returned\n");

  /*
   * Clean up immediately.  The exploit instead keeps this PI cycle alive,
   * reuses the returned syscall stack, and later asks the scheduler to walk
   * it.  This probe deliberately performs none of those actions.
   */
  errno = 0;
  ret = futex_call(&state.chain_word, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&state.waiter_unlock_ret, (int)ret);
  atomic_store(&state.waiter_unlock_errno, errno);
  RAW_LINE("[futex-probe] waiter immediate UNLOCK_PI returned\n");

  spin_until(&state.owner_done);
  atomic_store_explicit(&state.waiter_done, 1, memory_order_release);
  return NULL;
}

static void *owner_main(void *unused) {
  (void)unused;

  errno = 0;
  long ret = futex_call(&state.target_word, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&state.owner_target_ret, (int)ret);
  atomic_store(&state.owner_target_errno, errno);
  if (ret != 0) {
    atomic_store(&state.owner_done, 1);
    return NULL;
  }

  spin_until(&state.waiter_ready);
  atomic_store_explicit(&state.owner_started, 1, memory_order_release);
  atomic_store_explicit(&state.owner_chain_entered, 1, memory_order_release);
  RAW_LINE("[futex-probe] owner chain LOCK_PI enter\n");
  errno = 0;
  ret = futex_call(&state.chain_word, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&state.owner_chain_ret, (int)ret);
  atomic_store(&state.owner_chain_errno, errno);
  atomic_store_explicit(&state.owner_chain_returned, 1, memory_order_release);
  RAW_LINE("[futex-probe] owner chain LOCK_PI returned\n");

  if (ret == 0) {
    errno = 0;
    ret = futex_call(&state.chain_word, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&state.owner_chain_unlock_ret, (int)ret);
    atomic_store(&state.owner_chain_unlock_errno, errno);
  }

  errno = 0;
  ret = futex_call(&state.target_word, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&state.owner_target_unlock_ret, (int)ret);
  atomic_store(&state.owner_target_unlock_errno, errno);
  atomic_store_explicit(&state.owner_done, 1, memory_order_release);
  RAW_LINE("[futex-probe] owner cleanup complete\n");
  return NULL;
}

static int elapsed_ms(const struct timespec *start,
                      const struct timespec *now) {
  time_t seconds = now->tv_sec - start->tv_sec;
  long nanos = now->tv_nsec - start->tv_nsec;
  return (int)(seconds * 1000 + nanos / 1000000);
}

int main(void) {
  pthread_t waiter;
  pthread_t owner;

  memset(&state, 0, sizeof(state));
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  printf("[futex-probe] start pid=%d wait=%ds settle_us=%d pointers=disabled "
         "reclaim=disabled process_vm=disabled scheduler_trigger=disabled\n",
         getpid(), PROBE_WAIT_SECONDS, PROBE_SETTLE_USEC);

  int rc = pthread_create(&waiter, NULL, waiter_main, NULL);
  if (rc != 0) {
    fprintf(stderr, "[futex-probe] waiter pthread_create errno=%d\n", rc);
    return 2;
  }
  rc = pthread_create(&owner, NULL, owner_main, NULL);
  if (rc != 0) {
    fprintf(stderr, "[futex-probe] owner pthread_create errno=%d\n", rc);
    return 3;
  }

  while ((!atomic_load(&state.waiter_waiting) ||
          !atomic_load(&state.owner_chain_entered)) &&
         !atomic_load(&state.waiter_done) && !atomic_load(&state.owner_done)) {
    usleep(1000);
  }

  usleep(PROBE_SETTLE_USEC);
  RAW_LINE("[futex-probe] parent CMP_REQUEUE_PI enter\n");
  errno = 0;
  long requeue_ret = futex_call(&state.wait_word, FUTEX_CMP_REQUEUE_PI, 1,
                                (const struct timespec *)1,
                                &state.target_word, 0);
  atomic_store(&state.parent_requeue_ret, (int)requeue_ret);
  atomic_store(&state.parent_requeue_errno, errno);
  RAW_LINE("[futex-probe] parent CMP_REQUEUE_PI returned\n");

  struct timespec start;
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &start);
  do {
    if (atomic_load(&state.waiter_done) && atomic_load(&state.owner_done)) {
      break;
    }
    usleep(1000);
    clock_gettime(CLOCK_MONOTONIC, &now);
  } while (elapsed_ms(&start, &now) < PROBE_DONE_TIMEOUT_MS);

  int completed = atomic_load(&state.waiter_done) &&
                  atomic_load(&state.owner_done);
  if (completed) {
    pthread_join(waiter, NULL);
    pthread_join(owner, NULL);
  }

  printf("[futex-probe] result completed=%d requeue=%d/%d "
         "wait=%d/%d waiter_unlock=%d/%d owner_chain=%d/%d "
         "owner_chain_unlock=%d/%d owner_target_unlock=%d/%d\n",
         completed,
         atomic_load(&state.parent_requeue_ret),
         atomic_load(&state.parent_requeue_errno),
         atomic_load(&state.waiter_wait_ret),
         atomic_load(&state.waiter_wait_errno),
         atomic_load(&state.waiter_unlock_ret),
         atomic_load(&state.waiter_unlock_errno),
         atomic_load(&state.owner_chain_ret),
         atomic_load(&state.owner_chain_errno),
         atomic_load(&state.owner_chain_unlock_ret),
         atomic_load(&state.owner_chain_unlock_errno),
         atomic_load(&state.owner_target_unlock_ret),
         atomic_load(&state.owner_target_unlock_errno));

  int ok = completed &&
           atomic_load(&state.parent_requeue_ret) == -1 &&
           atomic_load(&state.parent_requeue_errno) == EDEADLK &&
           atomic_load(&state.waiter_wait_ret) == -1 &&
           atomic_load(&state.waiter_wait_errno) == ETIMEDOUT &&
           atomic_load(&state.waiter_unlock_ret) == 0 &&
           atomic_load(&state.owner_chain_ret) == 0 &&
           atomic_load(&state.owner_chain_unlock_ret) == 0 &&
           atomic_load(&state.owner_target_unlock_ret) == 0;
  printf("[futex-probe] verdict=%s\n", ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}
