/* Synthetic UDP payload accounting, guest loopback ONLY. Not a host traffic tool. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAYLOAD 1200
#define PORT 24173
static uint64_t ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(70);
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
int main(int argc, char **argv) {
    if (geteuid() != 0 || access("/DISPOSABLE_TBF_VM", F_OK) || argc != 2 || strlen(argv[1]) != 32) return 64;
    unsigned char token[16], packet[PAYLOAD], buffer[PAYLOAD + 1];
    for (int i = 0; i < 16; i++) {
        unsigned v; if (sscanf(argv[1] + i * 2, "%2x", &v) != 1) return 64;
        token[i] = v;
    }
    memset(packet, 0x5a, sizeof packet); memcpy(packet, token, sizeof token);
    int rx = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (rx < 0) return 70;
    int size = 65536;
    if (setsockopt(rx, SOL_SOCKET, SO_RCVBUF, &size, sizeof size)) return 70;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(PORT)};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(rx, (struct sockaddr *)&address, sizeof address)) return 70;
    uint64_t start = ns(), window = start + 1000000000ULL, end = window + 4000000000ULL;
    int fds[2]; if (pipe(fds)) return 70;
    pid_t sender = fork(); if (sender < 0) return 70;
    if (!sender) {
        close(rx); close(fds[0]);
        int tx = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (tx < 0) _exit(70);
        uint64_t counts[3] = {0, 0, 0}, tick = start;
        while (ns() < end) {
            /* Five 1200-byte datagrams per millisecond: at most 48 payload Mbps. */
            for (int i = 0; i < 5; i++) {
                ssize_t sent = sendto(tx, packet, sizeof packet, 0, (struct sockaddr *)&address, sizeof address);
                if (sent == PAYLOAD) counts[0]++;
                else if (sent < 0 && (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK)) counts[2]++;
                else counts[1]++;
            }
            tick += 1000000ULL;
            uint64_t now = ns();
            if (tick < now) tick = now; /* Do not accumulate and burst missed pacing slots. */
            struct timespec until = {.tv_sec = tick / 1000000000ULL, .tv_nsec = tick % 1000000000ULL};
            int status; do { status = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, NULL); } while (status == EINTR);
            if (status) _exit(70);
        }
        if (write(fds[1], counts, sizeof counts) != sizeof counts) _exit(70);
        close(tx); close(fds[1]); _exit(0);
    }
    close(fds[1]); uint64_t received = 0, invalid = 0, errors = 0;
    while (ns() < end) {
        struct pollfd p = {.fd = rx, .events = POLLIN};
        int ready = poll(&p, 1, 2);
        if (ready < 0) { if (errno != EINTR) { errors++; break; } continue; }
        if (!ready) continue;
        for (int i = 0; i < 64 && ns() < end; i++) {
            ssize_t length = recv(rx, buffer, sizeof buffer, 0);
            if (length < 0) { if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) errors++; break; }
            uint64_t now = ns();
            if (length != PAYLOAD || memcmp(buffer, token, sizeof token)) { invalid++; continue; }
            if (now >= window && now < end) received++;
        }
    }
    uint64_t finished = ns(), counts[3]; int status;
    if (read(fds[0], counts, sizeof counts) != sizeof counts || waitpid(sender, &status, 0) != sender
        || !WIFEXITED(status) || WEXITSTATUS(status)) return 70;
    close(fds[0]); close(rx);
    printf("{\"received_packets\":%llu,\"received_bytes\":%llu,\"elapsed_ns\":%llu,\"sent_packets_total\":%llu,\"send_errors\":%llu,\"send_backpressure\":%llu,\"attempted_packets_total\":%llu,\"receive_errors\":%llu,\"invalid_packets\":%llu,\"payload_bytes\":1200,\"warmup_seconds\":1}\n",
        (unsigned long long)received, (unsigned long long)(received * PAYLOAD),
        (unsigned long long)(finished - window), (unsigned long long)counts[0],
        (unsigned long long)counts[1], (unsigned long long)counts[2],
        (unsigned long long)(counts[0]+counts[1]+counts[2]), (unsigned long long)errors, (unsigned long long)invalid);
    return 0;
}
