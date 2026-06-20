/*
 * tls_psk — a tiny C ABI exposing a TLS 1.3 pre-shared-key (PSK) client engine
 * to Dart/Flutter via FFI.
 *
 * The engine is transport-agnostic: it never touches a socket. Instead it runs
 * the TLS state machine over two in-memory buffers, so the *caller* owns the
 * socket (a fully async dart:io Socket on the Dart side) and just shuttles
 * ciphertext in and out:
 *
 *     create -> loop { handshake; drain outgoing -> socket; socket -> inject } until OK
 *     write(plaintext) -> drain outgoing -> socket
 *     socket -> inject -> read(plaintext)
 *
 * This is the same memory-BIO pattern dtls2 uses, but with mbedTLS (vendored,
 * built from source) instead of a system OpenSSL — so the package is fully
 * self-contained.
 *
 * The library is product-agnostic: it is a generic TLS-PSK socket engine.
 */
#ifndef TLS_PSK_H
#define TLS_PSK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  if defined(TLSPSK_BUILDING)
#    define TLSPSK_API __declspec(dllexport)
#  else
#    define TLSPSK_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__)
#  define TLSPSK_API __attribute__((visibility("default")))
#else
#  define TLSPSK_API
#endif

/* Result codes. Negative values are hard errors. */
typedef enum {
    TLSPSK_OK         =  0, /* operation complete */
    TLSPSK_WANT_READ  =  1, /* need more ciphertext from the peer (inject, retry) */
    TLSPSK_WANT_WRITE =  2, /* output is queued (extract it, send, retry) */
    TLSPSK_CLOSED     =  3, /* peer sent close_notify */
    TLSPSK_ERROR      = -1  /* fatal; see tlspsk_strerror */
} tlspsk_rc;

typedef struct tlspsk_ctx tlspsk_ctx;

/* Library version string ("tls_psk x.y.z / mbedTLS a.b.c"). */
TLSPSK_API const char *tlspsk_version(void);

/*
 * Create a TLS 1.3 PSK client engine.
 *   psk / psk_len             external pre-shared key (raw bytes; use >= 16)
 *   identity / identity_len   PSK identity (sent in the clear; may be empty)
 *   server_name               SNI hostname, or NULL for none
 * Returns NULL on allocation/setup failure.
 */
TLSPSK_API tlspsk_ctx *tlspsk_client_new(const uint8_t *psk, size_t psk_len,
                                         const uint8_t *identity, size_t identity_len,
                                         const char *server_name);

/* Advance the handshake. Returns TLSPSK_OK when established, TLSPSK_WANT_READ
 * when more peer data is needed, or TLSPSK_ERROR. Always drain tlspsk_extract
 * after calling (the handshake produces flights to send). */
TLSPSK_API int tlspsk_handshake(tlspsk_ctx *c);

/* Feed ciphertext received from the socket. Returns bytes accepted (may be less
 * than len if the input buffer is full — send the rest after extract/handshake),
 * or TLSPSK_ERROR. */
TLSPSK_API int tlspsk_inject(tlspsk_ctx *c, const uint8_t *buf, size_t len);

/* Copy out queued ciphertext to send to the socket. Returns bytes written
 * (0 if none), or TLSPSK_ERROR. */
TLSPSK_API int tlspsk_extract(tlspsk_ctx *c, uint8_t *buf, size_t cap);

/* Non-zero if there is queued outbound ciphertext waiting for tlspsk_extract. */
TLSPSK_API int tlspsk_pending_output(tlspsk_ctx *c);

/* Encrypt application data. The ciphertext is queued for tlspsk_extract.
 * Returns bytes consumed, TLSPSK_WANT_WRITE (drain and retry), or TLSPSK_ERROR. */
TLSPSK_API int tlspsk_write(tlspsk_ctx *c, const uint8_t *buf, size_t len);

/* Decrypt available application data into buf. Returns bytes read (0 if none
 * yet — inject more first), TLSPSK_CLOSED on close_notify, or TLSPSK_ERROR. */
TLSPSK_API int tlspsk_read(tlspsk_ctx *c, uint8_t *buf, size_t cap);

/* Queue a close_notify alert (extract + send it for a clean shutdown). */
TLSPSK_API void tlspsk_close(tlspsk_ctx *c);

/* Free the engine. Safe on NULL. */
TLSPSK_API void tlspsk_free(tlspsk_ctx *c);

/* Human-readable text for the last mbedTLS error on this engine. Writes a
 * NUL-terminated string into buf; returns its length (excluding NUL). */
TLSPSK_API int tlspsk_strerror(tlspsk_ctx *c, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* TLS_PSK_H */
