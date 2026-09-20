/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AI_PIN_SLIDE_SUPERVISOR_H
#define AI_PIN_SLIDE_SUPERVISOR_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A fixed-size frame keeps the parent independent of pipe EOF.  The wire
 * representation is little-endian and includes a checksum; callers should
 * use slide_supervisor_write_result() rather than writing this frame directly.
 */
#define SLIDE_SUPERVISOR_FRAME_SIZE 32u

struct slide_supervisor_result {
  uint32_t code;
  uint64_t value;
};

enum slide_supervisor_outcome {
  SLIDE_SUPERVISOR_OK = 0,
  SLIDE_SUPERVISOR_BAD_ARGUMENT,
  SLIDE_SUPERVISOR_SYSTEM_ERROR,
  SLIDE_SUPERVISOR_TIMEOUT,
  SLIDE_SUPERVISOR_CHILD_EXITED,
  SLIDE_SUPERVISOR_PROTOCOL_ERROR,
  SLIDE_SUPERVISOR_REAP_TIMEOUT,
};

/*
 * Create a close-on-exec pipe.  The read end is nonblocking; the write end is
 * blocking so a small result frame cannot be silently dropped on EAGAIN.
 */
int slide_supervisor_pipe(int fds[2]);

/* Write one complete, checksummed result frame.  EINTR is handled internally. */
int slide_supervisor_write_result(
    int write_fd, const struct slide_supervisor_result *result);

/* Set deadline to CLOCK_MONOTONIC now plus timeout_ms. */
int slide_supervisor_deadline_after_ms(
    struct timespec *deadline, uint64_t timeout_ms);

/*
 * Collect one framed result before the absolute CLOCK_MONOTONIC deadline.
 *
 * The caller must put child in a dedicated process group whose pgid equals
 * child.  This function owns and closes read_fd.  It samples child state only
 * with waitpid(..., WNOHANG), never waits for pipe EOF, and always sends
 * SIGKILL to the dedicated group after a terminal result so inherited writers
 * cannot survive.  It then gives the group leader a fixed, bounded reap grace.
 * A valid frame is authoritative even if the leader has to be killed after
 * sending it.  If the leader was already reaped, wait_status receives its
 * status; otherwise it receives the status observed during cleanup.
 */
enum slide_supervisor_outcome slide_supervisor_collect(
    pid_t child, int read_fd, const struct timespec *deadline,
    struct slide_supervisor_result *result, int *wait_status);

const char *slide_supervisor_outcome_name(
    enum slide_supervisor_outcome outcome);

#ifdef __cplusplus
}
#endif

#endif
