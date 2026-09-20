/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Small boot-scoped command broker for GhostLock's AI Pin proof of concept.
 * The Unix socket accepts only kernel-authenticated UID 0 and AID_SHELL peers.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define GHOSTLOCK_SOCKET "/data/local/tmp/.ghostlock-su.sock"
#define AID_SHELL 2000
#define REQUEST_MAGIC UINT32_C(0x474c5351)
#define REPLY_MAGIC UINT32_C(0x474c5352)
#define PROTOCOL_VERSION UINT32_C(1)
#define MAX_COMMAND_BYTES 16384U

struct request_header {
  uint32_t magic;
  uint32_t version;
  uint32_t command_bytes;
};

struct reply_footer {
  uint32_t magic;
  uint32_t version;
  int32_t exit_code;
};

static int transfer_exact(int fd, void *buffer, size_t length, int writing) {
  unsigned char *cursor = buffer;
  while (length != 0) {
    ssize_t count = writing ? write(fd, cursor, length)
                            : read(fd, cursor, length);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return 0;
    }
    cursor += (size_t)count;
    length -= (size_t)count;
  }
  return 1;
}

static int write_exact(int fd, const void *buffer, size_t length) {
  return transfer_exact(fd, (void *)buffer, length, 1);
}

static int read_exact(int fd, void *buffer, size_t length) {
  return transfer_exact(fd, buffer, length, 0);
}

static socklen_t unix_address(struct sockaddr_un *address) {
  memset(address, 0, sizeof(*address));
  address->sun_family = AF_UNIX;
  snprintf(address->sun_path, sizeof(address->sun_path), "%s",
           GHOSTLOCK_SOCKET);
  return (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                     strlen(address->sun_path) + 1);
}

static int open_client_socket(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  struct sockaddr_un address;
  socklen_t length = unix_address(&address);
  if (connect(fd, (struct sockaddr *)&address, length) != 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  return fd;
}

static int emit_command_output(int socket_fd) {
  unsigned char trailing[sizeof(struct reply_footer)];
  size_t trailing_bytes = 0;
  unsigned char incoming[4096];

  for (;;) {
    ssize_t count = read(socket_fd, incoming, sizeof(incoming));
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      return 125;
    }
    if (count == 0) {
      break;
    }

    size_t fresh = (size_t)count;
    if (fresh >= sizeof(trailing)) {
      if (trailing_bytes != 0 &&
          !write_exact(STDOUT_FILENO, trailing, trailing_bytes)) {
        return 125;
      }
      size_t visible = fresh - sizeof(trailing);
      if (visible != 0 &&
          !write_exact(STDOUT_FILENO, incoming, visible)) {
        return 125;
      }
      memcpy(trailing, incoming + visible, sizeof(trailing));
      trailing_bytes = sizeof(trailing);
      continue;
    }

    size_t combined = trailing_bytes + fresh;
    if (combined > sizeof(trailing)) {
      size_t visible = combined - sizeof(trailing);
      if (!write_exact(STDOUT_FILENO, trailing, visible)) {
        return 125;
      }
      memmove(trailing, trailing + visible, trailing_bytes - visible);
      trailing_bytes -= visible;
    }
    memcpy(trailing + trailing_bytes, incoming, fresh);
    trailing_bytes += fresh;
  }

  if (trailing_bytes != sizeof(struct reply_footer)) {
    if (trailing_bytes != 0) {
      (void)write_exact(STDOUT_FILENO, trailing, trailing_bytes);
    }
    return 125;
  }

  struct reply_footer footer;
  memcpy(&footer, trailing, sizeof(footer));
  if (footer.magic != REPLY_MAGIC || footer.version != PROTOCOL_VERSION ||
      footer.exit_code < 0 || footer.exit_code > 255) {
    (void)write_exact(STDOUT_FILENO, trailing, trailing_bytes);
    return 125;
  }
  return footer.exit_code;
}

static int command_client(const char *command) {
  size_t command_bytes = strlen(command);
  if (command_bytes == 0 || command_bytes > MAX_COMMAND_BYTES) {
    fprintf(stderr, "su: command must contain 1..%u bytes\n",
            MAX_COMMAND_BYTES);
    return 2;
  }

  int fd = open_client_socket();
  if (fd < 0) {
    perror("su: connect");
    return 127;
  }
  struct request_header header = {
      .magic = REQUEST_MAGIC,
      .version = PROTOCOL_VERSION,
      .command_bytes = (uint32_t)command_bytes,
  };
  if (!write_exact(fd, &header, sizeof(header)) ||
      !write_exact(fd, command, command_bytes)) {
    close(fd);
    return 125;
  }
  (void)shutdown(fd, SHUT_WR);
  int result = emit_command_output(fd);
  close(fd);
  return result;
}

static void configure_root_process(void) {
  static const char path[] =
      "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
      "/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:"
      "/vendor/xbin";
  (void)setenv("PATH", path, 1);
  (void)setenv("HOME", "/data/local/tmp", 1);
  (void)setenv("USER", "root", 1);
  (void)setenv("LOGNAME", "root", 1);
  (void)umask(022);
  (void)chdir("/");
}

static int peer_is_allowed(int fd) {
  struct ucred credentials;
  socklen_t length = sizeof(credentials);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
      length != sizeof(credentials)) {
    return 0;
  }
  return credentials.pid > 0 &&
         (credentials.uid == 0 || credentials.uid == AID_SHELL);
}

static int wait_status_code(int status) {
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 125;
}

static void execute_request(int fd, char *command) {
  pid_t child = fork();
  if (child == 0) {
    (void)dup2(fd, STDIN_FILENO);
    (void)dup2(fd, STDOUT_FILENO);
    (void)dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO) {
      close(fd);
    }
    configure_root_process();
    if (setgroups(0, NULL) != 0 || setresgid(0, 0, 0) != 0 ||
        setresuid(0, 0, 0) != 0) {
      _exit(126);
    }
    execl("/system/bin/sh", "sh", "-c", command, (char *)NULL);
    _exit(127);
  }

  int status = 0;
  if (child < 0) {
    status = 125 << 8;
  } else {
    while (waitpid(child, &status, 0) < 0) {
      if (errno != EINTR) {
        status = 125 << 8;
        break;
      }
    }
  }
  struct reply_footer footer = {
      .magic = REPLY_MAGIC,
      .version = PROTOCOL_VERSION,
      .exit_code = wait_status_code(status),
  };
  (void)write_exact(fd, &footer, sizeof(footer));
}

static void service_connection(int fd) {
  if (!peer_is_allowed(fd)) {
    return;
  }

  struct request_header header;
  if (!read_exact(fd, &header, sizeof(header)) ||
      header.magic != REQUEST_MAGIC ||
      header.version != PROTOCOL_VERSION ||
      header.command_bytes == 0 ||
      header.command_bytes > MAX_COMMAND_BYTES) {
    return;
  }

  char *command = malloc((size_t)header.command_bytes + 1);
  if (command == NULL) {
    return;
  }
  if (!read_exact(fd, command, header.command_bytes) ||
      memchr(command, '\0', header.command_bytes) != NULL) {
    free(command);
    return;
  }
  command[header.command_bytes] = '\0';
  execute_request(fd, command);
  free(command);
}

static int daemon_main(void) {
  if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
    fprintf(stderr, "su: daemon requires complete root credentials\n");
    return 126;
  }
  configure_root_process();
  signal(SIGPIPE, SIG_IGN);

  int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (server < 0) {
    return 1;
  }
  (void)unlink(GHOSTLOCK_SOCKET);
  struct sockaddr_un address;
  socklen_t length = unix_address(&address);
  if (bind(server, (struct sockaddr *)&address, length) != 0 ||
      chown(GHOSTLOCK_SOCKET, 0, AID_SHELL) != 0 ||
      chmod(GHOSTLOCK_SOCKET, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) != 0 ||
      listen(server, 8) != 0) {
    close(server);
    (void)unlink(GHOSTLOCK_SOCKET);
    return 1;
  }

  for (;;) {
    int connection = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    if (connection < 0 && errno == EINTR) {
      continue;
    }
    if (connection < 0) {
      sleep(1);
      continue;
    }

    pid_t worker = fork();
    if (worker == 0) {
      close(server);
      service_connection(connection);
      close(connection);
      _exit(0);
    }
    close(connection);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
  }
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--daemon") == 0) {
    return daemon_main();
  }
  if (argc == 3 && strcmp(argv[1], "-c") == 0) {
    return command_client(argv[2]);
  }
  fprintf(stderr, "usage: su -c COMMAND\n");
  return 2;
}
