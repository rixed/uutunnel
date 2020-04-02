#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#define EXHAUST_BANNER "uutunnel, starting exhaust."
#define EXHAUST_BANNER_LEN strlen(EXHAUST_BANNER)

static char const *my_binary;

/*
 * Misc utilities
 */

static void close_ign(int fd)
{
  if (0 != close(fd))
    fprintf(stderr, "Cannot close %d: %s\n", fd, strerror(errno));
}

static ssize_t write_all(int fd, char const *buf, size_t sz)
{
  while (sz > 0) {
    ssize_t s = write(fd, buf, sz);
    if (s < 0) {
      if (EINTR == errno) continue;
      fprintf(stderr, "Cannot write: %s\n", strerror(errno));
      return -1;
    }
    sz -= s;
    buf += s;
  }

  return 0;
}

#define UPD_MAX_FD(fd) do { if (fd > max_fd) max_fd = fd; } while (0)
#define IS_SELECTABLE(fd) ((fd) >= 0 && (fd) <= max_fd)

/*
 * Forwarding data from user to shell and vice versa
 */

#define IO_BUF_SIZE 4096
static char buffer_from_clt[IO_BUF_SIZE];
static char buffer_from_srv[IO_BUF_SIZE];
static size_t from_clt_sz, from_srv_sz;
// Intermediary buffers with bytes encoded as to survive any terminal:
static char buffer_from_clt_enc[IO_BUF_SIZE];
static char buffer_from_srv_enc[IO_BUF_SIZE];
static size_t from_clt_enc_sz, from_srv_enc_sz;

#define IS_FULL(sz) ((sz) >= IO_BUF_SIZE)
#define IS_EMPTY(sz) (0 == (sz))

static int read_into(char *buf, size_t *sz, int *fd)
{
  assert(! IS_FULL(*sz));

  ssize_t rd = read(*fd, buf + *sz, IO_BUF_SIZE - *sz);
  if (rd < 0) {
    if (EINTR == errno) return 0;
    fprintf(stderr, "Cannot read from %d: %s\r\n", *fd, strerror(errno));
    close_ign(*fd);
    *fd = -1;
    return -1;
  }

  if (rd == 0) {
    close_ign(*fd);
    *fd = -1;
    return 0;
  }

  *sz += rd;
  return 0;
}

static void buffer_shift(char *buf, size_t *sz, size_t n)
{
  assert(*sz >= n);
  *sz -= n;
  memmove(buf, buf + n, *sz);
}

static void buffer_move(char *restrict src, size_t *restrict src_sz, char *restrict dst, size_t *restrict dst_sz)
{
  size_t s = *src_sz;
  if (s > IO_BUF_SIZE - *dst_sz) s = IO_BUF_SIZE - *dst_sz;
  memcpy(dst + *dst_sz, src, s);
  *dst_sz += s;
  buffer_shift(src, src_sz, s);
}

static int write_from(char *buf, size_t *sz, int *fd)
{
  assert(! IS_EMPTY(*sz));

  ssize_t wr = write(*fd, buf, *sz);
  if (wr < 0) {
    if (EINTR == errno) return 0;
    fprintf(stderr, "Cannot write into %d: %s\r\n", *fd, strerror(errno));
    close_ign(*fd);
    *fd = -1;
    return -1;
  }
  buffer_shift(buf, sz, wr);

  return 0;
}

/*
 * uuencoding/decoding
 */

static int encode_char(int c)
{
  return c ? (c & 077) + ' ' : '`';
}

static void encode(char *restrict src, size_t *restrict src_sz, char *restrict dst, size_t *restrict dst_sz)
{
  size_t i = 0;
  while (i < *src_sz) {
    // lines up to 45 chars in length
    size_t n = *src_sz - i;
    if (n > 45) n = 45;
    // for each 3 chars we output 4, +1 prefix and newline:
    if (1 + 4 * ((n + 2) / 3) + 1 > IO_BUF_SIZE - *dst_sz)
      break; // wait

    // Prefix:
    dst[(*dst_sz)++] = encode_char(n);

    for (size_t m = 0; m < n; m += 3) {
      // The padding is actually sent with the data before the new line:
      int c1 = src[i++];
      int c2 = m + 1 < n ? src[i++] : 0;
      int c3 = m + 2 < n ? src[i++] : 0;
      dst[(*dst_sz)++] = encode_char(c1 >> 2);
      dst[(*dst_sz)++] = encode_char(((c1 << 4) & 060) | ((c2 >> 4) & 017));
      dst[(*dst_sz)++] = encode_char(((c2 << 2) & 074) | ((c3 >> 6) & 03));
      dst[(*dst_sz)++] = encode_char(c3 & 077);
    }

    dst[(*dst_sz)++] = '\n';
  }

  buffer_shift(src, src_sz, i);
}

static char decode_char(int c)
{
  return (c - ' ') & 077;
}

static void decode(char *restrict src, size_t *restrict src_sz, char *restrict dst, size_t *restrict dst_sz)
{
  size_t i;
  for (i = 0; i < *src_sz; ) {
    // First char is the line length
    ssize_t n = decode_char(src[i]);
    assert(n > 0 && n <= 45);

    /* Since the padding is sent with the data, we must have that length after
     * the prefix, plus the newline: */
    size_t expected = 4 * ((n + 2) / 3);
    if (i + 1 + expected + 1 > *src_sz) break;
    i++;

    while (n > 0) {
      char c1 = decode_char(src[i]) << 2 | decode_char(src[i + 1]) >> 4;
      char c2 = decode_char(src[i + 1]) << 4 | decode_char(src[i + 2]) >> 2;
      char c3 = decode_char(src[i + 2]) << 6 | decode_char(src[i + 3]);

      dst[(*dst_sz)++] = c1;
      if (n > 1)
        dst[(*dst_sz)++] = c2;
      if (n > 2)
        dst[(*dst_sz)++] = c3;

      n -= 3;
      i += 4;
    }

    assert(src[i] == '\n');
    i++;
  }

  buffer_shift(src, src_sz, i);
}

/*
 * Terminal
 */

static int tty_raw(int fd)
{
  struct termios buf;

  if (tcgetattr(fd, &buf) < 0) {
    fprintf(stderr, "Cannot tcgetattr: %s\n", strerror(errno));
    return -1;
  }

  buf.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
  buf.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
  buf.c_cflag &= ~(CSIZE | PARENB);
  buf.c_cflag |= CS8;
  buf.c_oflag &= ~(OPOST);
  buf.c_cc[VMIN] = 1;
  buf.c_cc[VTIME] = 0;

  if (tcsetattr(fd, TCSAFLUSH, &buf) < 0) {
    fprintf(stderr, "Cannot tcsetattr: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

static int tty_noecho(int fd)
{
  struct termios t;
  if (tcgetattr(fd, &t) < 0) {
    fprintf(stderr, "Cannot tcgetattr: %s\r\n", strerror(errno));
    return -1;
  }

  t.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  t.c_oflag &= ~ONLCR;

  if (tcsetattr(fd, TCSANOW, &t) < 0) {
    fprintf(stderr, "Cannot tcsetattr: %s\r\n", strerror(errno));
    return -1;
  }

  return 0;
}

static int spawn_shell(int *retfd)
{
  /*
   * Prepare a pseudo-tty
   */

  struct termios termios;
  if (tcgetattr(STDIN_FILENO, &termios) < 0) {
    fprintf(stderr, "Cannot tcgetattr: %s\n", strerror(errno));
    return -1;
  }
  struct winsize winsize;
  if (ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize) < 0) {
    fprintf(stderr, "Cannot ioctl %d: %s\n", STDIN_FILENO, strerror(errno));
    return -1;
  }

  int ptmfd = posix_openpt(O_RDWR);
  if (ptmfd < 0) {
    fprintf(stderr, "Cannot posix_openpt: %s\n", strerror(errno));
    return -1;
  }

  if (grantpt(ptmfd) < 0) {
    fprintf(stderr, "Cannot grantpt: %s\n", strerror(errno));
err:
    close(ptmfd);
    return -1;
  }

  if (unlockpt(ptmfd) < 0) {
    fprintf(stderr, "Cannot unlockpt: %s\n", strerror(errno));
    goto err;
  }

  char *pts_name;
  if (NULL == (pts_name = ptsname(ptmfd))) {
    fprintf(stderr, "Cannot ptsname: %s\n", strerror(errno));
    goto err;
  }

  /*
   * Fork
   */

  int shell_pid = fork();

  if (shell_pid < 0) {
    fprintf(stderr, "Cannot fork: %s\n", strerror(errno));
    goto err;
  }

  if (0 == shell_pid) {
    if (setsid() < 0) {
      fprintf(stderr, "Cannot setsid: %s\n", strerror(errno));
errchld:
      exit(-1);
    }

    int ptsfd = open(pts_name, O_RDWR);
    if (ptsfd < 0) {
      fprintf(stderr, "Cannot open '%s': %s\n", pts_name, strerror(errno));
      goto errchld;
    }

    close_ign(ptmfd);

    if (tcsetattr(ptsfd, TCSANOW, &termios) < 0) {
      fprintf(stderr, "Cannot tcsetattr: %s\n", strerror(errno));
      goto errchld;
    }
    if (ioctl(ptsfd, TIOCSWINSZ, &winsize) < 0) {
      fprintf(stderr, "Cannot ioctl %d: %s\n", ptsfd, strerror(errno));
      goto errchld;
    }

    if (dup2(ptsfd, STDIN_FILENO) != STDIN_FILENO ||
        dup2(ptsfd, STDOUT_FILENO) != STDOUT_FILENO ||
        dup2(ptsfd, STDERR_FILENO) != STDERR_FILENO)
    {
      fprintf(stderr, "Cannot dup2: %s\n", strerror(errno));
      exit(-1);
    }
    if (ptsfd != STDIN_FILENO &&
        ptsfd != STDOUT_FILENO &&
        ptsfd != STDERR_FILENO)
      close_ign(ptsfd);

    char *shell = "/bin/sh";
    char *argv[] = { shell, "-i", NULL };
    char *envp[] = { NULL };

    if (0 != execve(shell, argv, envp)) {
      fprintf(stderr, "Cannot execve '%s': %s\n", shell, strerror(errno));
      exit(-1);
    }
    abort();
  } else {
    if (tty_raw(STDIN_FILENO) < 0) goto err;

    *retfd = ptmfd;
    return shell_pid;
  }
}

/*
 * Network intake
 */

static struct client {
  int fd;
  size_t from_clt_sz, from_srv_sz;
  size_t from_clt_enc_sz, from_srv_enc_sz;
  char from_clt[IO_BUF_SIZE];
  char from_srv[IO_BUF_SIZE];
  char from_clt_enc[IO_BUF_SIZE];
  char from_srv_enc[IO_BUF_SIZE];
} client;

static int intake_end(unsigned short port, int *ptmfd)
{
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    fprintf(stderr, "Cannot socket: %s\r\n", strerror(errno));
    return -1;
  }

  int one = 1;
  if (0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
    fprintf(stderr, "Cannot setsockopt(SO_REUSEADDR): %s\r\n", strerror(errno));
    return -1;
  }
  int flags = fcntl(sock, F_GETFL);
  if (flags == -1) {
    fprintf(stderr, "Cannot fcntl(F_GETFL): %s\r\n", strerror(errno));
    return -1;
  }
  if (-1 == fcntl(sock, F_SETFL, flags | O_NONBLOCK)) {
    fprintf(stderr, "Cannot fcntl(F_SETFL): %s\r\n", strerror(errno));
    return -1;
  }
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (0 != bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
    fprintf(stderr, "Cannot bind: %s\r\n", strerror(errno));
    return -1;
  }
  if (0 != listen(sock, 10)) {
    fprintf(stderr, "Cannot listen: %s\r\n", strerror(errno));
    return -1;
  }

  client.fd = -1;
  client.from_clt_sz = client.from_srv_sz = 0;
  client.from_clt_enc_sz = client.from_srv_enc_sz = 0;
  /* The client should get whatever is left on the global input buffer, that
   * the server might have written spontaneously before we even called
   * intake_end(): */
  if (! IS_EMPTY(from_srv_sz)) {
    // This has been encoded
    buffer_move(buffer_from_srv, &from_srv_sz, client.from_srv_enc, &client.from_srv_enc_sz);
  }

  // Event loop
  while (*ptmfd >= 0) {
    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    int max_fd = -1;

    if (sock >= 0 && client.fd < 0) {
      FD_SET(sock, &rset);
      UPD_MAX_FD(sock);
    }

    if (client.fd >= 0 && ! IS_FULL(client.from_clt_sz)) {
      FD_SET(client.fd, &rset);
      UPD_MAX_FD(client.fd);
    }
    if (client.fd >= 0 && ! IS_EMPTY(client.from_srv_sz)) {
      FD_SET(client.fd, &wset);
      UPD_MAX_FD(client.fd);
    }

    if (! IS_FULL(client.from_srv_enc_sz)) {
      FD_SET(*ptmfd, &rset);
      UPD_MAX_FD(*ptmfd);
    }
    if (! IS_EMPTY(client.from_clt_enc_sz)) {
      FD_SET(*ptmfd, &wset);
      UPD_MAX_FD(*ptmfd);
    }

    int num_fds = select(max_fd + 1, &rset, &wset, NULL, NULL);
    if (num_fds < 0) {
      if (EINTR == errno) continue;
      fprintf(stderr, "Cannot select: %s\r\n", strerror(errno));
      return -1;
    }

    if (0 == num_fds) continue;

    if (IS_SELECTABLE(client.fd) && FD_ISSET(client.fd, &rset)) {
      read_into(client.from_clt, &client.from_clt_sz, &client.fd);
    }
    if (IS_SELECTABLE(client.fd) && FD_ISSET(client.fd, &wset)) {
      write_from(client.from_srv, &client.from_srv_sz, &client.fd);
    }

    if (IS_SELECTABLE(*ptmfd) && FD_ISSET(*ptmfd, &rset)) {
      if (0 != read_into(client.from_srv_enc, &client.from_srv_enc_sz, ptmfd)) break;
    }
    if (IS_SELECTABLE(*ptmfd) && FD_ISSET(*ptmfd, &wset)) {
      if (0 != write_from(client.from_clt_enc, &client.from_clt_enc_sz, ptmfd)) break;
    }

    // Encode/decode
    if (! IS_EMPTY(client.from_srv_enc_sz) && ! IS_FULL(client.from_srv_sz))
      decode(client.from_srv_enc, &client.from_srv_enc_sz, client.from_srv, &client.from_srv_sz);
    if (! IS_EMPTY(client.from_clt_sz) && ! IS_FULL(client.from_clt_enc_sz))
      encode(client.from_clt, &client.from_clt_sz, client.from_clt_enc, &client.from_clt_enc_sz);

    // Must come after because client.fd may be changed:
    if (IS_SELECTABLE(sock) && FD_ISSET(sock, &rset)) {
      int fd = accept(sock, NULL, NULL);
      if (fd < 0) {
        fprintf(stderr, "Cannot accept: %s\r\n", strerror(errno));
        continue; // too bad
      }
      if (client.fd >= 0) {
        fprintf(stderr, "Cannot accept: unfortunately we are fully booked at the moment.\r\n");
        close_ign(fd);
        continue;
      }
      client.fd = fd;
      // We may already have content for her
      fprintf(stderr, "New client accepted (with %zu bytes of content already)!\r\n", client.from_srv_sz);
    }
  }

  return -1;
}

/*
 * Network exhaust
 */

static int exhaust_end(unsigned short port)
{
  // Where to connect to:
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  // All those may be closed by read_into/write_from:
  int fd = -1;  // reconnect on demand
  int stdin_fileno = STDIN_FILENO;
  int stdout_fileno = STDOUT_FILENO;

  while (true) {
    if (fd < 0) {
      fd = socket(PF_INET, SOCK_STREAM, 0);
      if (-1 == fd) {
        fprintf(stderr, "Cannot socket: %s\n", strerror(errno));
        return -1;
      }
      if (0 != connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
        fprintf(stderr, "Cannot connect: %s\n", strerror(errno));
        return -1;
      }
    }

    fd_set rset, wset;
    int max_fd = -1;
    FD_ZERO(&rset);
    FD_ZERO(&wset);

    if (fd >= 0 && ! IS_FULL(from_srv_sz)) {
      FD_SET(fd, &rset);
      UPD_MAX_FD(fd);
    }
    if (stdin_fileno >= 0 && ! IS_FULL(from_clt_enc_sz)) {
      FD_SET(stdin_fileno, &rset);
      UPD_MAX_FD(stdin_fileno);
    }
    if (fd >= 0 && ! IS_EMPTY(from_clt_sz)) {
      FD_SET(fd, &wset);
      UPD_MAX_FD(fd);
    }
    if (! IS_EMPTY(from_srv_enc_sz)) {
      FD_SET(stdout_fileno, &wset);
      UPD_MAX_FD(stdout_fileno);
    }

    assert(max_fd >= 0);

    int num_fds = select(max_fd + 1, &rset, &wset, NULL, NULL);
    if (num_fds < 0) {
      if (EINTR == errno) continue;
      fprintf(stderr, "Cannot select: %s\n", strerror(errno));
      return -1;
    }

    if (0 == num_fds) continue;

    if (IS_SELECTABLE(fd) && FD_ISSET(fd, &rset))
      if (0 != read_into(buffer_from_srv, &from_srv_sz, &fd)) break;
    if (IS_SELECTABLE(stdin_fileno) && FD_ISSET(stdin_fileno, &rset))
      if (0 != read_into(buffer_from_clt_enc, &from_clt_enc_sz, &stdin_fileno)) break;
    if (IS_SELECTABLE(fd) && FD_ISSET(fd, &wset))
      if (0 != write_from(buffer_from_clt, &from_clt_sz, &fd)) break;
    if (IS_SELECTABLE(stdout_fileno) && FD_ISSET(stdout_fileno, &wset))
      if (0 != write_from(buffer_from_srv_enc, &from_srv_enc_sz, &stdout_fileno)) break;

    // Encode/decode
    if (! IS_EMPTY(from_clt_enc_sz) && ! IS_FULL(from_clt_sz))
      decode(buffer_from_clt_enc, &from_clt_enc_sz, buffer_from_clt, &from_clt_sz);
    if (! IS_EMPTY(from_srv_sz) && ! IS_FULL(from_srv_enc_sz))
      encode(buffer_from_srv, &from_srv_sz, buffer_from_srv_enc, &from_srv_enc_sz);
  }

  return -1;
}

/*
 * Tunnelling
 */

static struct magic_seq {
  char const *text;
  size_t len;
  size_t matched;
  enum { ACTION_MENU, ACTION_START_SERVER } action;
  bool completed;
  // for debugging:
  int fd_copy;
} seq_from_clt = {
  .text = "\r!!",
  .len = 3,
  .matched = 0,
  .action = ACTION_MENU,
  .completed = false,
  -1
}, seq_from_srv = {
  .text = EXHAUST_BANNER "\r\n",
  .len = EXHAUST_BANNER_LEN + 2,
  .matched = 0,
  .action = ACTION_START_SERVER,
  .completed = false,
  -1
};

static void print_menu(void)
{
  fprintf(stderr,
    "\r\nuutunnel menu:\r\n"
    "h, ? : this help\r\n"
    "i, > : inject uutunnel uuencoded binary (%s)\r\n"
    "anything else returns to the shell\r\n",
    my_binary);
}

static int inject_binary(int ptmfd)
{
  int fd = open(my_binary, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Cannot open '%s': %s\r\n", my_binary, strerror(errno));
    return -1;
  }

  if (0 != write_all(ptmfd, "begin 755 uutunnel\n", 19)) {
err:
    close(fd);
    return -1;
  }

  char in[1000];
  char out[2000];
  size_t in_sz = 0;
  while (true) {
    ssize_t rs = read(fd, in + in_sz, sizeof(in) - in_sz);
    if (rs < 0) {
      if (EINTR == errno) continue;
      fprintf(stderr, "Cannot read '%s': %s\r\n", my_binary, strerror(errno));
      goto err;
    }

    if (0 == rs) {
      fprintf(stderr, "Done.\r\n");
      break;
    }

    in_sz += rs;
    size_t out_sz = 0;
    encode(in, &in_sz, out, &out_sz);
    if (0 != write_all(ptmfd, out, out_sz)) goto err;
  }

  if (0 != write_all(ptmfd, "`\nend\n", 6)) goto err;

  return 0;
}

static int write_and_scan_from(char *buf, size_t *sz, int *fd, struct magic_seq *seq)
{
  assert(! IS_EMPTY(*sz));

  if (seq) {
    if (seq->fd_copy >= 0) {
      write_all(seq->fd_copy, buf, *sz);
    }

    if (seq->matched >= seq->len) {
      if (seq->action == ACTION_MENU) {
        /* We are now expecting the command */
        switch (buf[0]) {
          case '?':
          case 'h':
          case 'H':
            buffer_shift(buf, sz, 1);
            print_menu();
            return 0;

          case '>':
          case 'i':
            buffer_shift(buf, sz, 1);
            inject_binary(*fd);
            return 0;

          default:
            seq->matched = 0;
            goto no_match;
        }
      } else {
        assert(seq->action == ACTION_START_SERVER);
      }
    } else {
      /* Is it the continuation of the magic sequence? */
      size_t i;
      for (i = 0; i < *sz && i + seq->matched < seq->len; i++) {
        if (buf[i] != seq->text[seq->matched + i]) {
          seq->matched = 0;
          goto no_match;
        }
      }
      seq->matched += i;
      if (seq->matched >= seq->len) {
        if (seq->action == ACTION_MENU) {
          print_menu();
        } else {
          seq->completed = true;
          buffer_shift(buf, sz, i);
          fprintf(stderr, "Peered! Forwarding port...\r\n");
          return 0;
        }
      }
    }
no_match:;
    if (seq->action == ACTION_MENU && seq->matched > 1) {
      /* Stop echoing the sequence at that point, but consume the input until
       * mismatch or completion of the sequence: */
      *sz = 0;
      return 0;
    }
  }

  return write_from(buf, sz, fd);
}

static int dig_tunnel(unsigned short port)
{
  // Debug copies:
  seq_from_srv.fd_copy =
    open("/tmp/from_srv.log", O_CREAT|O_TRUNC|O_WRONLY, 0640);
  if (seq_from_srv.fd_copy < 0) {
    fprintf(stderr, "Cannot open logfile: %s\n", strerror(errno));
    return -1;
  }

  seq_from_clt.fd_copy =
    open("/tmp/from_clt.log", O_CREAT|O_TRUNC|O_WRONLY, 0640);
  if (seq_from_clt.fd_copy < 0) {
    fprintf(stderr, "Cannot open logfile: %s\n", strerror(errno));
    return -1;
  }

  // All those may be closed by read_into/write_from:
  int ptmfd;
  int stdin_fileno = STDIN_FILENO;
  int stdout_fileno = STDOUT_FILENO;

  int shell_pid = spawn_shell(&ptmfd);
  if (shell_pid < 0) return -1;

  while (true) {
    fd_set rset, wset;
    int max_fd = -1;
    FD_ZERO(&rset);
    FD_ZERO(&wset);

    if (ptmfd >= 0 && ! IS_FULL(from_srv_sz)) {
      FD_SET(ptmfd, &rset);
      UPD_MAX_FD(ptmfd);
    }
    if (stdin_fileno >= 0 && ! IS_FULL(from_clt_sz)) {
      FD_SET(stdin_fileno, &rset);
      UPD_MAX_FD(stdin_fileno);
    }
    if (ptmfd >= 0 && ! IS_EMPTY(from_clt_sz)) {
      FD_SET(ptmfd, &wset);
      UPD_MAX_FD(ptmfd);
    }
    if (! IS_EMPTY(from_srv_sz)) {
      FD_SET(stdout_fileno, &wset);
      UPD_MAX_FD(stdout_fileno);
    }

    assert(max_fd >= 0);

    int num_fds = select(max_fd + 1, &rset, &wset, NULL, NULL);
    if (num_fds < 0) {
      if (EINTR == errno) continue;
      fprintf(stderr, "Cannot select: %s\n", strerror(errno));
      return -1;
    }

    if (0 == num_fds) continue;

    if (IS_SELECTABLE(ptmfd) && FD_ISSET(ptmfd, &rset))
      if (0 != read_into(buffer_from_srv, &from_srv_sz, &ptmfd)) break;
    if (IS_SELECTABLE(stdin_fileno) && FD_ISSET(stdin_fileno, &rset))
      if (0 != read_into(buffer_from_clt, &from_clt_sz, &stdin_fileno)) break;
    if (IS_SELECTABLE(ptmfd) && FD_ISSET(ptmfd, &wset))
      if (0 != write_and_scan_from(buffer_from_clt, &from_clt_sz, &ptmfd, &seq_from_clt)) break;
    if (IS_SELECTABLE(stdout_fileno) && FD_ISSET(stdout_fileno, &wset))
      if (0 != write_and_scan_from(buffer_from_srv, &from_srv_sz, &stdout_fileno, &seq_from_srv)) break;

    if (seq_from_srv.completed) {
      return intake_end(port, &ptmfd);
    }
  }

  return -1;
}

int main(int num_args, char const **args)
{
//#define TESTS

#ifdef TESTS
  {
    char const str[] =
      "La pluie nous a débués et lavés,\n"
      "Et le soleil desséchés et noircis.\n"
      "  Pies, corbeaux nous ont les yeux cavés,\n"
      "Et arraché la barbe et les sourcils.\n"
      "  Jamais nul temps nous ne sommes assis\n"
      "  Puis çà, puis là, comme le vent varie,\n"
      "A son plaisir sans cesser nous charrie,\n"
      "Plus becquetés d'oiseaux que dés à coudre.\n"
      "  Ne soyez donc de notre confrérie;\n"
      "Mais priez Dieu que tous nous veuille absoudre!\n";
    size_t buf0_sz = sizeof(str);
    char buf0[IO_BUF_SIZE];
    memcpy(buf0, str, buf0_sz);
    size_t buf1_sz = 0, buf2_sz = 0;
    char buf1[IO_BUF_SIZE];
    char buf2[IO_BUF_SIZE];

    // Visual check:
    printf("Source:\n%s\n", buf0);
    encode(buf0, &buf0_sz, buf1, &buf1_sz);
    assert(buf1_sz == 568);
    printf("Encoded:\n%s\n", buf1);
    decode(buf1, &buf1_sz, buf2, &buf2_sz);
    assert(buf2_sz == sizeof(str));
    printf("Decoded:\n%s\n", buf2);
    assert(0 == strncmp(str, buf2, buf2_sz));

    // Test all line lengths:
    size_t len;
    for (len = 1; len <= sizeof(str); len++) {
      buf0_sz = len;
      memcpy(buf0, str, buf0_sz);
      buf1_sz = buf2_sz = 0;
      encode(buf0, &buf0_sz, buf1, &buf1_sz);
      assert(buf0_sz == 0);
      decode(buf1, &buf1_sz, buf2, &buf2_sz);
      assert(buf2_sz == len);
      assert(0 == strncmp(str, buf2, buf2_sz));
    }
    printf("Line sizes from 1 to %zu OK\n", len);

    // Test filling encoded buffer:
    buf0_sz = buf1_sz = buf2_sz = 0;
    char seq_in = 0, seq_out = 0;
    for (int n = 0; n < 1000; n ++) {
      // Fill input:
      for (; buf0_sz < IO_BUF_SIZE; buf0_sz++) buf0[buf0_sz] = seq_in++;
      encode(buf0, &buf0_sz, buf1, &buf1_sz);
      assert(! IS_EMPTY(buf1_sz) && ! IS_FULL(buf0_sz));  // must have done something
      decode(buf1, &buf1_sz, buf2, &buf2_sz);
      assert(! IS_EMPTY(buf2_sz) && ! IS_FULL(buf1_sz));
      size_t i;
      for (i = 0; i < buf2_sz; i++) assert(buf2[i] == seq_out++);
      buffer_shift(buf2, &buf2_sz, i);
      assert(IS_EMPTY(buf2_sz));
    }
    printf("Fill test OK\n");
  }
  return 0;
#endif

  if (num_args != 3) {
syntax:
    assert(num_args > 0);
    fprintf(stderr, "%s [in|out] [address:]port\n", args[0]);
    return -1;
  }

  char *end;
  unsigned port = strtoul(args[2], &end, 10);
  if (*end != '\0' || 0 == port || port > 65535) {
    fprintf(stderr, "Cannot parse port ('%s').\n", args[2]);
    return -1;
  }

  my_binary = args[0];

  switch (args[1][0]) {
    case 'o':
    case 'O':
      printf(EXHAUST_BANNER "\n");
      tcdrain(STDOUT_FILENO);
      tty_noecho(STDIN_FILENO);
      return exhaust_end(port);

    case 'i':
    case 'I':
      return dig_tunnel(port);
  }

  goto syntax;
}
