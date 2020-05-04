#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SIZEOF_ARRAY(x) (sizeof(x) / sizeof(*(x)))

#define EXHAUST_BANNER "uutunnel, starting exhaust."
#define EXHAUST_BANNER_LEN strlen(EXHAUST_BANNER)

static bool const debug = false;

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

static char *now(void)
{
  struct timeval tv;
  if (0 != gettimeofday(&tv, NULL)) {
    fprintf(stderr, "Cannot gettimeofday: %s\r\n", strerror(errno));
    return "ERR: ";
  }
  struct tm *tm = localtime(&tv.tv_sec);
  static char c[] = "23:59:59.999: ";
  snprintf(c, sizeof(c), "%02d:%02d:%02d.%03d: ",
    tm->tm_hour, tm->tm_min, tm->tm_sec,
    (int)(tv.tv_usec / 1000));
  return c;
}

#define UPD_MAX_FD(fd) do { if (fd > max_fd) max_fd = fd; } while (0)
#define IS_SELECTABLE(fd) ((fd) >= 0 && (fd) <= max_fd)

/*
 * Forwarding data from user to shell and vice versa
 */

#define IO_BUF_SIZE (size_t)4096
static char buffer_from_clt[IO_BUF_SIZE];
static char buffer_from_srv[IO_BUF_SIZE];
static size_t from_clt_sz, from_srv_sz;
/* Intermediary buffers with frames of data from/to the servers, uu-encoded
 * to survive any terminal: */
static char buffer_from_clt_enc[IO_BUF_SIZE];
static char buffer_from_srv_enc[IO_BUF_SIZE];
static size_t from_clt_enc_sz, from_srv_enc_sz;

#define IS_EMPTY(sz) (0 == (sz))
#define HAS_ROOM_FOR(x, sz) ((sz) <= IO_BUF_SIZE - (x))
#define IS_FULL(sz) (! HAS_ROOM_FOR(1, sz))

static ssize_t read_into(char *buf, size_t *sz, int fd)
{
  assert(! IS_FULL(*sz));

  ssize_t rd = read(fd, buf + *sz, IO_BUF_SIZE - *sz);
  if (rd < 0) {
    if (EINTR == errno) return 0;
    fprintf(stderr, "Cannot read from %d: %s\r\n", fd, strerror(errno));
    return -1;
  }

  if (rd == 0) {
    return 0;
  }

  *sz += rd;
  return rd;
}

static void buffer_shift(char *buf, size_t *sz, size_t n)
{
  assert(*sz >= n);
  *sz -= n;
  memmove(buf, buf + n, *sz);
}

static int write_from(char *buf, size_t *sz, int fd)
{
  assert(! IS_EMPTY(*sz));

  ssize_t wr = write(fd, buf, *sz);
  if (wr < 0) {
    if (EINTR == errno) return 0;
    fprintf(stderr, "Cannot write into %d: %s\r\n", fd, strerror(errno));
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

#define UU_LINE_LEN (size_t)45  // must be divisible by 3 and less than 64

static void encode(char *restrict src, size_t *restrict src_sz, char *restrict dst, size_t *restrict dst_sz)
{
  size_t i = 0;
  while (i < *src_sz) {
    // lines up to UU_LINE_LEN chars in length
    size_t n = *src_sz - i;
    if (n > UU_LINE_LEN) n = UU_LINE_LEN;
    // for every 3 chars we output 4, +1 prefix and newline:
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

static void decode(
  char *restrict src, // source buffer
  size_t src_stop,  // do not decode past that point
  size_t *restrict src_sz,  // end of source buffer (>= src_stop)
  char *restrict dst,  // dst buffer
  size_t *restrict dst_sz)  // size of dest buffer
{
  size_t i;
  for (i = 0; i < src_stop; ) {
    // First char is the line length
    ssize_t n = decode_char(src[i]);
    assert(n > 0 && n <= (ssize_t)UU_LINE_LEN);

    if (*dst_sz + n > IO_BUF_SIZE) break;

    /* Since the padding is sent with the data, we must have that length after
     * the prefix, plus the newline: */
    size_t expected = 4 * ((n + 2) / 3);
    if (i + 1 + expected + 1 > src_stop) break;
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
 * Connections and frames
 */

#define NUM_MAX_CNXS 100  // must be below 65536

static struct cnx {
  int fd; // <= 0 if this cnx is free (thus statically initialized to free)
  size_t from_clt_sz, from_srv_sz;
  bool is_new;
  // Fins are signaled via an empty frame
  bool fin_clt, fin_srv, fin_clt_sent, fin_srv_sent;
  char from_clt[IO_BUF_SIZE];
  char from_srv[IO_BUF_SIZE];
} cnxs[NUM_MAX_CNXS];

static struct cnx *cnx_new(void)
{
  for (size_t i = 0; i < NUM_MAX_CNXS; i++) {
    struct cnx *cnx = cnxs + i;

    if (cnx->fd <= 0) {
      cnx->from_clt_sz = cnx->from_srv_sz = 0;
      cnx->is_new = true;
      cnx->fin_clt = cnx->fin_srv = cnx->fin_clt_sent = cnx->fin_srv_sent = false;
      return cnx;
    }
  }

  return NULL;
}

static void cnx_del(struct cnx *cnx)
{
  close_ign(cnx->fd);
  cnx->fd = -1;
}

static struct cnx *cnx_new_to_server(struct sockaddr_in *addr)
{
  struct cnx *cnx = cnx_new();
  if (! cnx) return NULL;

  int fd = socket(PF_INET, SOCK_STREAM, 0);
  if (-1 == fd) {
    fprintf(stderr, "Cannot socket: %s\n", strerror(errno));
    return NULL;
  }
  if (0 != connect(fd, (struct sockaddr *)addr, sizeof(*addr))) {
    fprintf(stderr, "Cannot connect: %s\n", strerror(errno));
    return NULL;
  }
  cnx->fd = fd;
  return cnx;
}

static struct cnx *cnx_new_from_client(int fd)
{
  struct cnx *cnx = cnx_new();
  cnx->fd = fd;
  return cnx;
}

// Assuming 4 chars can be read
static uint16_t peek_hex(char *src)
{
  uint16_t ret = 0;
  for (size_t i = 0; i < 4; i++) {
    ret <<= 4;
    if (src[i] >= 'A' && src[i] <= 'F') ret += 10 + src[i] - 'A';
    else ret += src[i] - '0';
  }
  return ret;
}

static void poke_hex(char *dst, uint16_t v)
{
  size_t i = 4;
  while (i--) {
    char c = v & 0xF;
    if (c < 10) dst[i] = '0' + c;
    else dst[i] = 'A' + (c - 10);
    v >>= 4;
  }
}

/* Frames have a header made of the length (excluding the header itself,
 * 16 bits) and the cnx number (16 bits) both encoded as hexadecimal, and
 * followed by a newline to flush even an empty frame. */
#define FRAME_HEAD_LEN 9

/* decode() will not write full lines unless at the end of the source buffer.
 * Therefore we must not start a frame unless we have enough room for a full
 * uu-encoded line, which is UU_LINE_LEN * 4 / 3 + 2. Also keeps the header
 * overhead small: */
#define MIN_FRAME_LEN (size_t)(UU_LINE_LEN * 4 / 3 + 2)

/* Encode as much as possible from src that will fit in the dst buffer once
 * uuencoded. Every single byte of input must go, but we wait until we have
 * enough room in the dst buffer before departure.
 * Actually, even 0 bytes from input must go (as an empty frame) to signal
 * opens and closes.
 * Return the size of the frame that was sent, or -1. */
static ssize_t try_encode_frame(
  size_t cnx_i, char *restrict src, size_t *restrict src_sz,
  char *restrict dst, size_t *restrict dst_sz)
{
  if (! HAS_ROOM_FOR(FRAME_HEAD_LEN + MIN_FRAME_LEN, *dst_sz)) return -1;

  assert(cnx_i <= NUM_MAX_CNXS);

  char *header = dst + *dst_sz;
  *dst_sz += FRAME_HEAD_LEN;
  size_t start_frame = *dst_sz;
  encode(src, src_sz, dst, dst_sz);
  size_t frame_sz = *dst_sz - start_frame;
  poke_hex(header, frame_sz);
  poke_hex(header+4, cnx_i);
  header[FRAME_HEAD_LEN-1] = '\n';

  return frame_sz;
}

// returns true if a frame was decoded
static bool try_decode_frame(char *src, size_t *restrict src_sz, size_t *restrict len, size_t *restrict recpt, bool from_clt)
{
  // Leave the header in the buffer until the whole frame can be read:
  if (*src_sz < FRAME_HEAD_LEN) return false;

  *len = peek_hex(src);
  *recpt = peek_hex(src + 4);
  assert(src[FRAME_HEAD_LEN-1] == '\n');
  assert(*recpt < NUM_MAX_CNXS);

  // Wait until the whole frame is available:
  if (*src_sz < FRAME_HEAD_LEN + *len) return false;

  struct cnx *cnx = cnxs + *recpt;

  if (cnx->fd <= 0) {
    // Drop the frame
    buffer_shift(src, src_sz, FRAME_HEAD_LEN + *len);
    return true;
  } else if (! HAS_ROOM_FOR(*len, from_clt ? cnx->from_clt_sz : cnx->from_srv_sz)) {
    // Have to wait some more
    return false;
  } else {
    buffer_shift(src, src_sz, FRAME_HEAD_LEN);
    // Decode not further than the end of the frame:
    size_t const src_sz_ = *src_sz - *len;
    if (from_clt)
      decode(src, *len, src_sz,
             cnx->from_clt, &cnx->from_clt_sz);
    else
      decode(src, *len, src_sz,
             cnx->from_srv, &cnx->from_srv_sz);
    assert(*src_sz == src_sz_);

    return true;
  }
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

static int intake(unsigned short port, int *ptmfd)
{
  // The global input buffer must be empty at this point:
  assert(IS_EMPTY(from_srv_sz));
  assert(IS_EMPTY(from_srv_enc_sz));

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

  // Event loop
  while (*ptmfd >= 0) {
    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    int max_fd = -1;

    /* Due to the intermediary buffers, the select can hang in two situations:
     * - any client from_clt buffer not empty, while buffer_from_clt_enc is
     *   empty, in which case the select will block until next reception, and
     * - buffer_from_srv_enc not empty while all client from_srv buffers are
     *   empty, in which case again the select will block until next reception.
     * To avoid the former case, we select the ttyp for writing as soon as any
     * client has a non empty from_clt. And to avoid the later we decode frames
     * into clients from_srv buffers last. */

    if (sock >= 0) {
      FD_SET(sock, &rset);
      UPD_MAX_FD(sock);
    }

    for (size_t i = 0; i < NUM_MAX_CNXS; i++) {
      struct cnx *client = cnxs + i;

      int fd = client->fd;
      if (fd <= 0) continue;

      if (client->fin_clt && !client->fin_clt_sent) {
        // Wait until all have been sent and then add an empty frame:
        if (IS_EMPTY(client->from_clt_sz)) {
          if (debug) fprintf(stderr, "%sPropagating FIN to server for client %zu.\r\n", now(), i);
          ssize_t frame_sz =
            try_encode_frame(i, client->from_clt, &client->from_clt_sz,
                                buffer_from_clt_enc, &from_clt_enc_sz);
          if (frame_sz == 0) client->fin_clt_sent = true;
        }
      }
      if (client->fin_srv && !client->fin_srv_sent) {
        if (IS_EMPTY(client->from_srv_sz)) {
          if (debug) fprintf(stderr, "%sPropaganting FIN to client %zu.\r\n", now(), i);
          if (0 != shutdown(client->fd, SHUT_WR)) {
            fprintf(stderr, "Cannot shutdown: %s.\r\n", strerror(errno));
            // So be it
          }
          client->fin_srv_sent = true;
        }
      }
      if (client->fin_clt_sent && client->fin_srv_sent) {
        if (debug) fprintf(stderr, "%sDisconnecting client %zu.\r\n", now(), i);
        cnx_del(client);
        continue;
      }

      // Avoid reading the EOF repeatedly, or anything else, when fin_clt:
      if (! IS_FULL(client->from_clt_sz) && ! client->fin_clt) {
        FD_SET(fd, &rset);
        UPD_MAX_FD(fd);
      }
      if (! IS_EMPTY(client->from_srv_sz) && ! client->fin_srv_sent) {
        FD_SET(fd, &wset);
        UPD_MAX_FD(fd);
      }
      /* For new clients we will want to write an empty frame (only when that
       * empty frame is encoded shall the is_new flag be cleared).
       * In addition, we want to write in ptmfd even if from_clt_enc is
       * currently empty as soon as at least one of the client from_clt is
       * not empty. */
      if (client->is_new || ! IS_EMPTY(client->from_clt_sz)) {
        FD_SET(*ptmfd, &wset);
        UPD_MAX_FD(*ptmfd);
      }
    }

    if (! IS_FULL(from_srv_enc_sz)) {
      FD_SET(*ptmfd, &rset);
      UPD_MAX_FD(*ptmfd);
    }
    if (! IS_EMPTY(from_clt_enc_sz)) {
      FD_SET(*ptmfd, &wset);
      UPD_MAX_FD(*ptmfd);
    }
    /* It is not possible that from_srv_enc to be not empty and the recipient
     * of the waiting frame to be empty (because we decode frames last).
     * Therefore we cannot hang in the select. */

    int num_fds = select(max_fd + 1, &rset, &wset, NULL, NULL);
    if (num_fds < 0) {
      if (EINTR == errno) continue;
      fprintf(stderr, "Cannot select: %s\r\n", strerror(errno));
      return -1;
    }

    if (0 == num_fds) continue;

    for (size_t i = 0; i < NUM_MAX_CNXS; i++) {
      struct cnx *client = cnxs + i;
      int fd = client->fd;

      if (fd <= 0) continue;

      if (client->is_new) {
        ssize_t frame_sz =
          try_encode_frame(i, client->from_clt, &client->from_clt_sz,
                              buffer_from_clt_enc, &from_clt_enc_sz);
        if (frame_sz < 0) break;
        client->is_new = false;
        if (debug) fprintf(stderr, "%sclient[%zd], wrote the initial empty frame.\r\n", now(), i);
      }

      if (! client->is_new && IS_SELECTABLE(fd) && FD_ISSET(fd, &rset)) {
        ssize_t rs = read_into(client->from_clt, &client->from_clt_sz, client->fd);
        if (debug) fprintf(stderr, "%sclient[%zd] received %zd bytes from client, from_clt_sz = %zu.\r\n", now(), i, rs, client->from_clt_sz);
        if (rs <= 0) client->fin_clt = true;
      }
      if (IS_SELECTABLE(fd) && FD_ISSET(fd, &wset)) {
        if (write_from(client->from_srv, &client->from_srv_sz, client->fd) < 0) {
          cnx_del(client);
          continue;
        }
        if (debug) fprintf(stderr, "%sclient[%zd] receiving from server, from_srv_sz = %zu.\r\n", now(), i, client->from_srv_sz);
      }

      // Encode (but wait for new clients to have queued the empty frame first)
      if (! client->is_new && ! IS_EMPTY(client->from_clt_sz)) {
        if (debug) fprintf(stderr, "%sclient[%zd], client->from_clt_sz = %zu, buffer_from_clt_enc_sz = %zu.\r\n", now(), i, client->from_clt_sz, from_clt_enc_sz);
        ssize_t frame_sz =
          try_encode_frame(i, client->from_clt, &client->from_clt_sz,
                              buffer_from_clt_enc, &from_clt_enc_sz);
        if (frame_sz < 0) break;
        client->is_new = false;
        if (debug) fprintf(stderr, "%sclient[%zd], wrote a frame of %zd bytes, from_clt_enc_sz = %zu.\r\n", now(), i, frame_sz, from_clt_enc_sz);
      }
    }

    // Write to tty:
    if (IS_SELECTABLE(*ptmfd) && FD_ISSET(*ptmfd, &wset)) {
      if (debug) fprintf(stderr, "%stty: is writable, from_clt_enc_sz = %zu.\r\n", now(), from_clt_enc_sz);
      if (write_from(buffer_from_clt_enc, &from_clt_enc_sz, *ptmfd) < 0) break;
      if (debug) fprintf(stderr, "%stty: writing, from_clt_enc_sz = %zu.\r\n", now(), from_clt_enc_sz);
    }

    // Read from tty:
    if (IS_SELECTABLE(*ptmfd) && FD_ISSET(*ptmfd, &rset)) {
      if (read_into(buffer_from_srv_enc, &from_srv_enc_sz, *ptmfd) <= 0) break;
      if (debug) fprintf(stderr, "%stty: reading, from_srv_enc_sz = %zu.\r\n", now(), from_srv_enc_sz);
    }

    // Decode:
    while (true) {
      size_t frame_sz, i;
      if (! try_decode_frame(buffer_from_srv_enc, &from_srv_enc_sz, &frame_sz, &i, false)) break;
      if (debug) fprintf(stderr, "%sDecoded a frame of %zu bytes for client %zu.\r\n", now(), frame_sz, i);
      assert(i < NUM_MAX_CNXS);
      if (frame_sz == 0) cnxs[i].fin_srv = true;
    }

    // Accept new connections:
    if (IS_SELECTABLE(sock) && FD_ISSET(sock, &rset)) {
      int fd = accept(sock, NULL, NULL);
      if (fd < 0) {
        fprintf(stderr, "Cannot accept: %s\r\n", strerror(errno));
        continue; // too bad
      }
      struct cnx *client = cnx_new_from_client(fd);
      if (! client) {
        fprintf(stderr, "Cannot accept: unfortunately we are fully booked at the moment.\r\n");
        close_ign(fd);
        continue;
      }
      // We may already have content for her
      fprintf(stderr, "%sNew client accepted!\r\n", now());
    }
  }

  return -1;
}

/*
 * Network exhaust
 */

static int exhaust(unsigned short port)
{
  FILE *log = NULL;
  if (debug) {
    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/tmp/uutunnel.%d.log", getpid());
    log = fopen(fname, "w+");
    if (! log) abort();
    fprintf(log, "UUTunnel, exhaust side, logging...\n");
  }

  // Where to connect to:
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  int stdin_fileno = STDIN_FILENO;
  int stdout_fileno = STDOUT_FILENO;

  while (true) {
    fd_set rset, wset;
    int max_fd = -1;
    FD_ZERO(&rset);
    FD_ZERO(&wset);

    /* Similarly to the intake case, we must not enter the select in any of
     * those two cases:
     * - buffer_from_clt_enc non empty but all clients from_clt buffers empty;
     * - some clients from_srv buffer non empty but buffer_from_srv_enc empty.
     * To avoid the former case we decode frames last. And to avoid the later
     * we select tty for writing as soon as a clients from_srv is not empty. */

    for (size_t i = 0; i < NUM_MAX_CNXS; i++) {
      struct cnx *cnx = cnxs + i;
      int fd = cnx->fd;
      if (fd <= 0) continue;

      if (cnx->fin_srv && !cnx->fin_srv_sent) {
        // Wait until all have been sent and then add an empty frame:
        if (IS_EMPTY(cnx->from_srv_sz)) {
          if (log) fprintf(log, "%sPropagating FIN to client for cnx %zu.\n", now(), i);
          ssize_t frame_sz =
            try_encode_frame(i, cnx->from_srv, &cnx->from_srv_sz,
                                buffer_from_srv_enc, &from_srv_enc_sz);
          if (frame_sz == 0) cnx->fin_srv_sent = true;
        }
      }

      if (cnx->fin_clt && !cnx->fin_clt_sent) {
        if (IS_EMPTY(cnx->from_clt_sz)) {
          if (log) fprintf(log, "%sPropagating FIN to server for cnx %zu.\n", now(), i);
          if (0 != shutdown(cnx->fd, SHUT_WR)) {
            if (log) fprintf(log, "%sCannot shutdown: %s.\n", now(), strerror(errno));
          }
          cnx->fin_clt_sent = true;
        }
      }

      /* Actual disconnection happens only when we have seen and propagated
       * both FINs.
       * Beware that if we have already sent the empty frame to the client, and
       * we just shutdown the connection to the server, then we are not going to
       * select anything from this client, so let's delete the cnx right here: */
      if (cnx->fin_srv_sent && cnx->fin_clt_sent && IS_EMPTY(cnx->from_srv_sz)) {
        if (log) fprintf(log, "%sDestroying connection %zu.\n", now(), i);
        cnx_del(cnx);
        continue;
      }

      // Avoids reading EOF repeatedly nor anything else once cnx->fin_srv:
      if (! IS_FULL(cnx->from_srv_sz) && !cnx->fin_srv) {
        FD_SET(fd, &rset);
        UPD_MAX_FD(fd);
      }
      if (! IS_EMPTY(cnx->from_clt_sz) && !cnx->fin_clt_sent) {
        FD_SET(fd, &wset);
        UPD_MAX_FD(fd);
      }
      if (! IS_EMPTY(cnx->from_srv_sz)) {
        FD_SET(stdout_fileno, &wset);
        UPD_MAX_FD(stdout_fileno);
      }
    }

    if (stdin_fileno >= 0 && ! IS_FULL(from_clt_enc_sz)) {
      FD_SET(stdin_fileno, &rset);
      UPD_MAX_FD(stdin_fileno);
    }
    if (! IS_EMPTY(from_srv_enc_sz)) {
      FD_SET(stdout_fileno, &wset);
      UPD_MAX_FD(stdout_fileno);
    }

    assert(max_fd >= 0);

    if (log) fflush(log);

    int num_fds = select(max_fd + 1, &rset, &wset, NULL, NULL);
    if (num_fds < 0) {
      if (EINTR == errno) continue;
      fprintf(stderr, "Cannot select: %s\n", strerror(errno));
      return -1;
    }

    if (0 == num_fds) continue;

    for (size_t i = 0; i < NUM_MAX_CNXS; i++) {
      struct cnx *cnx = cnxs + i;
      if (cnx->fd <= 0) continue;  // Important because 0 IS_SELECTABLE

      if (IS_SELECTABLE(cnx->fd) && FD_ISSET(cnx->fd, &rset)) {
        ssize_t rs = read_into(cnx->from_srv, &cnx->from_srv_sz, cnx->fd);
        if (log) fprintf(log, "%scnx[%zu] receiving, from_srv_sz = %zu.\n", now(), i, cnx->from_srv_sz);
        if (rs <= 0) cnx->fin_srv = true;
      }
      if (IS_SELECTABLE(cnx->fd) && FD_ISSET(cnx->fd, &wset)) {
        if (write_from(cnx->from_clt, &cnx->from_clt_sz, cnx->fd) < 0) break;
        if (log) fprintf(log, "%scnx[%zu] sending, from_srv_sz = %zu.\n", now(), i, cnx->from_srv_sz);
      }

      /* Encode. Notice first connections will starve later ones.
       * FIXME by iterating starting at a random offset. */
      if (! IS_EMPTY(cnx->from_srv_sz)) {
        if (log) fprintf(log, "%scnx[%zd], cnx->from_srv_sz = %zu, buffer_from_srv_enc_sz = %zu.\n", now(), i, cnx->from_srv_sz, from_srv_enc_sz);
        ssize_t frame_sz =
          try_encode_frame(i, cnx->from_srv, &cnx->from_srv_sz,
                              buffer_from_srv_enc, &from_srv_enc_sz);
        if (frame_sz < 0) break;
        if (log) fprintf(log, "%sWrote a frame of %zd bytes, from_srv_enc_sz = %zu.\r\n", now(), frame_sz, from_srv_enc_sz);
      }
    }

    // Write uu-encoded to stdout:
    if (IS_SELECTABLE(stdout_fileno) && FD_ISSET(stdout_fileno, &wset)) {
      if (write_from(buffer_from_srv_enc, &from_srv_enc_sz, stdout_fileno) < 0) break;
      if (log) fprintf(log, "%sWriting to stdout, from_srv_enc_sz = %zd.\n", now(), from_srv_enc_sz);
    }

    // Read uu-encoded data from stdin:
    if (IS_SELECTABLE(stdin_fileno) && FD_ISSET(stdin_fileno, &rset)) {
      if (log) fprintf(log, "%sStdint is selectable, from_clt_enc_sz = %zd.\n", now(), from_clt_enc_sz);
      if (read_into(buffer_from_clt_enc, &from_clt_enc_sz, stdin_fileno) <= 0) break;
      if (log) fprintf(log, "%sReading from stdin, from_clt_enc_sz = %zd.\n", now(), from_clt_enc_sz);
    }

    // Decode the next frame if it's complete:
    while (true) {
      if (log) fprintf(log, "%sTrying to decode a frame, from_clt_enc_sz = %zu.\n", now(), from_clt_enc_sz);
      if (log && from_clt_enc_sz >= FRAME_HEAD_LEN)
        fprintf(log, "%sHeader: '%.8s'\n", now(), buffer_from_clt_enc);
      size_t frame_sz, i;
      if (! try_decode_frame(buffer_from_clt_enc, &from_clt_enc_sz, &frame_sz, &i, true)) break;
      if (log) fprintf(log, "%sDecoded a frame of %zu bytes from client %zu.\n", now(), frame_sz, i);
      assert(i < NUM_MAX_CNXS);

      if (cnxs[i].fd <= 0) {
        assert(frame_sz == 0);
        (void)cnx_new_to_server(&addr);
        if (log) fprintf(log, "%sNew connection to localhost:%d\n", now(), port);
      } else if (frame_sz == 0) {
        cnxs[i].fin_clt = true;
      }
    }
  }

  if (log) fclose(log);

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
          fprintf(stderr, "%sPeered! Forwarding port...\r\n", now());
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

  return write_from(buf, sz, *fd);
}

static int dig_tunnel(unsigned short port)
{
  if (debug) {
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
  } else {
    seq_from_srv.fd_copy = seq_from_clt.fd_copy = -1;
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
      if (read_into(buffer_from_srv, &from_srv_sz, ptmfd) <= 0) break;
    if (IS_SELECTABLE(stdin_fileno) && FD_ISSET(stdin_fileno, &rset))
      if (read_into(buffer_from_clt, &from_clt_sz, stdin_fileno) <= 0) break;
    if (IS_SELECTABLE(ptmfd) && FD_ISSET(ptmfd, &wset))
      if (0 != write_and_scan_from(buffer_from_clt, &from_clt_sz, &ptmfd, &seq_from_clt)) break;
    if (IS_SELECTABLE(stdout_fileno) && FD_ISSET(stdout_fileno, &wset))
      if (0 != write_and_scan_from(buffer_from_srv, &from_srv_sz, &stdout_fileno, &seq_from_srv)) break;

    if (seq_from_srv.completed) {
      return intake(port, &ptmfd);
    }
  }

  return -1;
}

#ifdef TESTS
# include "tests.c"
#else
int main(int num_args, char const **args)
{
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
      return exhaust(port);

    case 'i':
    case 'I':
      return dig_tunnel(port);
  }

  goto syntax;
}
#endif
