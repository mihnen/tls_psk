/*
 * Reference / smoke test for the tls_psk engine: connect to a TLS 1.3 PSK
 * server, complete the handshake, send one line, print the echo.
 *
 *   tlspsk_smoke <host> <port> <psk-hex> <identity>
 *
 * Drives the memory-BIO engine over a plain POSIX TCP socket the same way the
 * Dart layer drives it over a dart:io Socket.
 */
#include "tls_psk.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int hex2bin(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t) v;
    }
    return (int) (n / 2);
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Push all queued ciphertext from the engine to the socket. */
static int pump_out(tlspsk_ctx *c, int fd)
{
    uint8_t buf[4096];
    int n;
    while ((n = tlspsk_extract(c, buf, sizeof buf)) > 0) {
        if (write(fd, buf, n) != n) return -1;
    }
    return n < 0 ? -1 : 0;
}

/* Read some ciphertext from the socket into the engine. */
static int pump_in(tlspsk_ctx *c, int fd)
{
    uint8_t buf[4096];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n <= 0) return -1;
    tlspsk_inject(c, buf, (size_t) n);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <host> <port> <psk-hex> <identity>\n", argv[0]);
        return 2;
    }
    printf("%s\n", tlspsk_version());

    uint8_t psk[64];
    int psk_len = hex2bin(argv[3], psk, sizeof psk);
    if (psk_len < 0) { fprintf(stderr, "bad psk hex\n"); return 2; }

    int fd = tcp_connect(argv[1], argv[2]);
    if (fd < 0) { fprintf(stderr, "tcp connect failed\n"); return 1; }

    tlspsk_ctx *c = tlspsk_client_new(psk, (size_t) psk_len,
                                      (const uint8_t *) argv[4], strlen(argv[4]), NULL);
    if (!c) { fprintf(stderr, "engine create failed\n"); return 1; }

    /* Handshake pump. */
    for (;;) {
        int rc = tlspsk_handshake(c);
        if (pump_out(c, fd) != 0) { fprintf(stderr, "socket write failed\n"); return 1; }
        if (rc == TLSPSK_OK) break;
        if (rc == TLSPSK_WANT_READ) {
            if (pump_in(c, fd) != 0) { fprintf(stderr, "socket read failed mid-handshake\n"); return 1; }
            continue;
        }
        char err[128];
        tlspsk_strerror(c, err, sizeof err);
        fprintf(stderr, "handshake failed: %s\n", err);
        return 1;
    }
    printf("HANDSHAKE OK (TLS 1.3 PSK)\n");

    /* Send a line. */
    const char *msg = "ping over tls-psk\n";
    tlspsk_write(c, (const uint8_t *) msg, strlen(msg));
    pump_out(c, fd);

    /* Read the echo. */
    uint8_t plain[512];
    for (int tries = 0; tries < 50; tries++) {
        int n = tlspsk_read(c, plain, sizeof plain);
        if (n > 0) { printf("ECHO: %.*s", n, plain); break; }
        if (n == TLSPSK_CLOSED) { printf("peer closed\n"); break; }
        if (n < 0) { fprintf(stderr, "read error\n"); return 1; }
        if (pump_in(c, fd) != 0) break;
    }

    tlspsk_close(c);
    pump_out(c, fd);
    tlspsk_free(c);
    close(fd);
    return 0;
}
