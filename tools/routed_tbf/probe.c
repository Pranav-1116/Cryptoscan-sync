/* Guest-only fixed-address traffic fixture. Never a host/remote traffic tool.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define MAXPACKETS 1048576
static uint64_t ns(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    exit(70);
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void until(uint64_t t) {
  struct timespec s = {t / 1000000000ULL, t % 1000000000ULL};
  int e;
  do {
    e = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &s, 0);
  } while (e == EINTR);
  if (e)
    exit(70);
}
static struct sockaddr_in addr(const char *ip, int port) {
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
  if (inet_pton(AF_INET, ip, &a.sin_addr) != 1)
    exit(64);
  return a;
}
static int sock(int type, const char *ip, int port, int server) {
  int s = socket(AF_INET, type, 0);
  if (s < 0)
    exit(70);
  int v = 1048576;
  setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
  setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
  v = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v);
  struct sockaddr_in a = addr(ip, port);
  if (server) {
    if (bind(s, (void *)&a, sizeof a))
      exit(70);
  } else {
    struct timeval tv = {2, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(s, (void *)&a, sizeof a))
      exit(70);
  }
  if (fcntl(s, F_SETFL, O_NONBLOCK))
    exit(70);
  return s;
}
static int cmp(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return (x > y) - (x < y);
}
int main(int argc, char **argv) {
  if (geteuid() != 0 || access("/DISPOSABLE_TBF_VM", F_OK) || argc < 2)
    return 64;
  unsigned char packet[16384];
  memset(packet, 0x5a, sizeof packet);
  if (!strcmp(argv[1], "echo")) {
    if (argc != 3)
      return 64;
    int s = sock(SOCK_DGRAM, argv[2], 24175, 1);
    for (;;) {
      struct pollfd p = {s, POLLIN, 0};
      if (poll(&p, 1, 100) < 0 && errno != EINTR)
        return 70;
      struct sockaddr_in from;
      socklen_t len = sizeof from;
      ssize_t n = recvfrom(s, packet, sizeof packet, 0, (void *)&from, &len);
      if (n > 0)
        sendto(s, packet, n, 0, (void *)&from, len);
    }
  }
  if (!strcmp(argv[1], "latency")) {
    if (argc != 5)
      return 64;
    uint64_t start = strtoull(argv[3], 0, 10);
    int seconds = atoi(argv[4]);
    if (seconds < 1 || seconds > 240)
      return 64;
    int s = sock(SOCK_DGRAM, argv[2], 24175, 0), planned = seconds * 20,
        received = 0, sent = 0, missed = 0, errors = 0;
    double samples[4800];
    for (int i = 0; i < planned; i++) {
      uint64_t tick = start + (uint64_t)i * 50000000ULL;
      if (ns() > tick + 50000000ULL) {
        missed++;
        continue;
      }
      until(tick);
      uint64_t t = ns();
      memcpy(packet, &t, 8);
      memcpy(packet + 8, &i, 4);
      if (send(s, packet, 32, 0) != 32) {
        errors++;
        continue;
      }
      sent++;
      uint64_t deadline = t + 450000000ULL;
      int ok = 0;
      while (ns() < deadline) {
        struct pollfd p = {s, POLLIN, 0};
        if (poll(&p, 1, 5) < 0) {
          if (errno != EINTR)
            errors++;
          continue;
        }
        unsigned char b[64];
        ssize_t n = recv(s, b, sizeof b, 0);
        if (n == 32 && !memcmp(b, packet, 32)) {
          samples[received++] = (ns() - t) / 1e6;
          ok = 1;
          break;
        }
      }
      (void)ok;
    }
    qsort(samples, received, sizeof(double), cmp);
    double p95 = received ? samples[(received * 95 + 99) / 100 - 1] : 0,
           p99 = received ? samples[(received * 99 + 99) / 100 - 1] : 0;
    printf("{\"planned\":%d,\"sent\":%d,\"received\":%d,\"missed_schedule\":%d,"
           "\"errors\":%d,\"p95_ms\":%.6f,\"p99_ms\":%.6f}\n",
           planned, sent, received, missed, errors, p95, p99);
    return 0;
  }
  if (argc != 9)
    return 64;
  int tcp = !strcmp(argv[2], "tcp"), payload = atoi(argv[3]),
      flows = atoi(argv[4]), burst = atoi(argv[5]), seconds = atoi(argv[6]);
  uint64_t start = strtoull(argv[7], 0, 10), window = start + 1000000000ULL,
           end = window + (uint64_t)seconds * 1000000000ULL;
  const char *ip = argv[8];
  if (payload < 64 || payload > 1400 || flows < 1 || flows > 4 || burst < 1 ||
      burst > 16 || seconds != 10)
    return 64;
  if (!strcmp(argv[1], "receive")) {
    int s = sock(tcp ? SOCK_STREAM : SOCK_DGRAM, ip, 24173, 1);
    if (tcp && listen(s, 8))
      return 70;
    struct pollfd fds[5] = {{s, POLLIN, 0}};
    int nf = 1;
    uint64_t bytes = 0, packets = 0, total = 0, duplicates = 0, invalid = 0,
             errors = 0;
    unsigned char seen[MAXPACKETS / 8] = {0};
    while (ns() < end + 500000000ULL) {
      int ready = poll(fds, nf, 2);
      if (ready < 0) {
        if (errno != EINTR)
          errors++;
        continue;
      }
      if (tcp && fds[0].revents & POLLIN) {
        int c = accept4(s, 0, 0, SOCK_NONBLOCK);
        if (c >= 0 && nf < 5)
          fds[nf++] = (struct pollfd){c, POLLIN, 0};
        else if (c >= 0) {
          close(c);
          errors++;
        }
      }
      for (int i = tcp ? 1 : 0; i < nf; i++) {
        if (!(fds[i].revents & POLLIN))
          continue;
        for (int j = 0; j < 128; j++) {
          ssize_t n = recv(fds[i].fd, packet,
                           tcp ? sizeof packet : (size_t)payload + 1, 0);
          if (n <= 0) {
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                errno != EINTR)
              errors++;
            break;
          }
          uint64_t t = ns();
          if (tcp) {
            total += n;
            if (t >= window && t < end)
              bytes += n;
          } else {
            uint64_t seq, stamp;
            memcpy(&seq, packet, 8);
            memcpy(&stamp, packet + 8, 8);
            if (n != payload || seq >= MAXPACKETS || stamp < start ||
                stamp >= end) {
              invalid++;
              continue;
            }
            if (seen[seq / 8] & (1U << (seq % 8))) {
              duplicates++;
              continue;
            }
            seen[seq / 8] |= 1U << (seq % 8);
            total++;
            if (t >= window && t < end) {
              packets++;
              bytes += n;
            }
          }
        }
      }
    }
    printf("{\"bytes\":%llu,\"packets\":%llu,\"total_received\":%llu,"
           "\"duplicates\":%llu,\"invalid\":%llu,\"errors\":%llu,\"elapsed_"
           "ns\":%llu}\n",
           (unsigned long long)bytes, (unsigned long long)packets,
           (unsigned long long)total, (unsigned long long)duplicates,
           (unsigned long long)invalid, (unsigned long long)errors,
           (unsigned long long)seconds * 1000000000ULL);
    return 0;
  }
  if (strcmp(argv[1], "send"))
    return 64;
  int fds[4];
  uint64_t flowbytes[4] = {0}, sent = 0, bytes = 0, attempts = 0,
           backpressure = 0, errors = 0;
  for (int i = 0; i < flows; i++)
    fds[i] = sock(tcp ? SOCK_STREAM : SOCK_DGRAM, ip, 24173, 0);
  /* Each group is one microburst, offered at 48 payload Mbps; missed slots
   * never accumulate. */
  uint64_t tick = start,
           step = (uint64_t)payload * burst * 1000000000ULL / 6000000ULL;
  until(start);
  while (ns() < end) {
    for (int k = 0; k < burst && ns() < end; k++) {
      int i = attempts % flows;
      uint64_t t = ns();
      memcpy(packet, &sent, 8);
      memcpy(packet + 8, &t, 8);
      attempts++;
      ssize_t n = send(fds[i], packet, payload, MSG_NOSIGNAL);
      if (n > 0) {
        sent++;
        flowbytes[i] += n;
        if (t >= window)
          bytes += n;
      } else if (n < 0 &&
                 (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS))
        backpressure++;
      else
        errors++;
    }
    tick += step;
    if (tick < ns())
      tick = ns();
    until(tick);
  }
  unsigned retrans = 0;
  printf("{\"flow_bytes\":[");
  for (int i = 0; i < flows; i++) {
    if (i)
      printf(",");
    printf("%llu", (unsigned long long)flowbytes[i]);
    if (tcp) {
      struct tcp_info info;
      socklen_t l = sizeof info;
      if (getsockopt(fds[i], IPPROTO_TCP, TCP_INFO, &info, &l))
        errors++;
      else
        retrans += info.tcpi_total_retrans;
    }
    close(fds[i]);
  }
  printf("],\"successful_sends\":%llu,\"sent_bytes_window\":%llu,"
         "\"attempts\":%llu,\"backpressure\":%llu,\"errors\":%llu,\"tcp_total_"
         "retransmissions\":%u}\n",
         (unsigned long long)sent, (unsigned long long)bytes,
         (unsigned long long)attempts, (unsigned long long)backpressure,
         (unsigned long long)errors, retrans);
  return 0;
}
