#define _POSIX_C_SOURCE 200809L

#include "reclaim_capture_gate.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static char control_path[] = "/tmp/ghostlock-control.XXXXXX";
static char status_path[] = "/tmp/ghostlock-status.XXXXXX";

static void clear_env(void) {
  unsetenv("AI_PIN_RECLAIM_GATE_CONTROL");
  unsetenv("AI_PIN_RECLAIM_GATE_STATUS");
  unsetenv("AI_PIN_RECLAIM_GATE_TOKEN");
  unsetenv("AI_PIN_RECLAIM_GATE_TIMEOUT_MS");
  ghostlock_capture_gate_close();
}

static void reset_files(void) {
  int fd = open(control_path, O_WRONLY | O_TRUNC);
  assert(fd >= 0);
  assert(close(fd) == 0);
  fd = open(status_path, O_WRONLY | O_TRUNC);
  assert(fd >= 0);
  assert(close(fd) == 0);
}

static void configure(const char *timeout_ms) {
  assert(setenv("AI_PIN_RECLAIM_GATE_CONTROL", control_path, 1) == 0);
  assert(setenv("AI_PIN_RECLAIM_GATE_STATUS", status_path, 1) == 0);
  assert(setenv("AI_PIN_RECLAIM_GATE_TOKEN", "abc12345def67890", 1) == 0);
  assert(setenv("AI_PIN_RECLAIM_GATE_TIMEOUT_MS", timeout_ms, 1) == 0);
}

static void write_command_later(const char *command) {
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    usleep(40000);
    int fd = open(control_path, O_WRONLY | O_TRUNC);
    if (fd < 0 || write(fd, command, strlen(command)) != (ssize_t)strlen(command)) {
      _exit(2);
    }
    close(fd);
    _exit(0);
  }
}

static void reap_writer(void) {
  int status = 0;
  assert(wait(&status) > 0);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_disabled_and_partial_config(void) {
  clear_env();
  assert(ghostlock_capture_gate_init());
  assert(!ghostlock_capture_gate_enabled());

  assert(setenv("AI_PIN_RECLAIM_GATE_CONTROL", control_path, 1) == 0);
  errno = 0;
  assert(!ghostlock_capture_gate_init());
  assert(errno == EINVAL);
  clear_env();
}

static void test_go_and_abort(void) {
  reset_files();
  configure("1000");
  assert(ghostlock_capture_gate_init());
  assert(ghostlock_capture_gate_enabled());
  write_command_later("go abc12345def67890\n");
  assert(ghostlock_capture_gate_wait(0xfffffff817d70000ULL));
  reap_writer();
  assert(!ghostlock_capture_gate_enabled());

  reset_files();
  configure("1000");
  assert(ghostlock_capture_gate_init());
  write_command_later("abort abc12345def67890\n");
  errno = 0;
  assert(!ghostlock_capture_gate_wait(0xfffffff817d70000ULL));
  assert(errno == ECANCELED);
  reap_writer();
  clear_env();
}

static void test_invalid_stale_and_timeout(void) {
  reset_files();
  configure("1000");
  assert(ghostlock_capture_gate_init());
  write_command_later("go wrongtoken\n");
  errno = 0;
  assert(!ghostlock_capture_gate_wait(0xfffffff817d70000ULL));
  assert(errno == EPROTO);
  reap_writer();

  reset_files();
  int fd = open(control_path, O_WRONLY);
  assert(fd >= 0);
  assert(write(fd, "stale\n", 6) == 6);
  assert(close(fd) == 0);
  configure("1000");
  errno = 0;
  assert(!ghostlock_capture_gate_init());
  assert(errno == EBUSY);

  reset_files();
  configure("30");
  assert(ghostlock_capture_gate_init());
  errno = 0;
  assert(!ghostlock_capture_gate_wait(0xfffffff817d70000ULL));
  assert(errno == ETIMEDOUT);
  clear_env();
}

int main(void) {
  int control_fd = mkstemp(control_path);
  int status_fd = mkstemp(status_path);
  assert(control_fd >= 0 && status_fd >= 0);
  assert(close(control_fd) == 0);
  assert(close(status_fd) == 0);

  test_disabled_and_partial_config();
  test_go_and_abort();
  test_invalid_stale_and_timeout();

  assert(unlink(control_path) == 0);
  assert(unlink(status_path) == 0);
  return 0;
}
