/*
 * tls_psk — TLS 1.3 PSK client engine over in-memory BIO buffers.
 * See tls_psk.h for the contract. mbedTLS does the crypto; the caller owns the
 * socket and shuttles ciphertext through tlspsk_inject / tlspsk_extract.
 */
#include "tls_psk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/version.h"
#include "psa/crypto.h"

/* One TLS record is at most 16 KB of plaintext plus expansion; size the
 * ciphertext staging buffers a little over that so a full record always fits. */
#define TLSPSK_BUF_CAP (18 * 1024)

struct tlspsk_ctx {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config  conf;

    /* Ciphertext received from the socket, waiting to be read by the TLS BIO. */
    uint8_t in_buf[TLSPSK_BUF_CAP];
    size_t  in_pos;   /* next byte the BIO will consume */
    size_t  in_len;   /* bytes valid in in_buf */

    /* Ciphertext produced by TLS, waiting to be sent to the socket. */
    uint8_t out_buf[TLSPSK_BUF_CAP];
    size_t  out_pos;  /* next byte tlspsk_extract will hand out */
    size_t  out_len;  /* bytes valid in out_buf */

    int last_err;     /* last mbedTLS error code (for tlspsk_strerror) */
};

/* PSA must be initialised once per process before any TLS 1.3 work. */
static int s_psa_ready = 0;

static int ensure_psa(void)
{
    if (s_psa_ready) {
        return 0;
    }
    if (psa_crypto_init() != PSA_SUCCESS) {
        return -1;
    }
    s_psa_ready = 1;
    return 0;
}

/* --- BIO: TLS reads ciphertext from in_buf, writes ciphertext to out_buf --- */

static int bio_recv(void *p, unsigned char *buf, size_t len)
{
    tlspsk_ctx *c = (tlspsk_ctx *) p;
    size_t avail = c->in_len - c->in_pos;
    if (avail == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    size_t n = len < avail ? len : avail;
    memcpy(buf, c->in_buf + c->in_pos, n);
    c->in_pos += n;
    if (c->in_pos == c->in_len) {
        c->in_pos = c->in_len = 0; /* fully drained — reset to the front */
    }
    return (int) n;
}

static int bio_send(void *p, const unsigned char *buf, size_t len)
{
    tlspsk_ctx *c = (tlspsk_ctx *) p;
    /* Compact any already-extracted prefix to make room. */
    if (c->out_pos > 0) {
        memmove(c->out_buf, c->out_buf + c->out_pos, c->out_len - c->out_pos);
        c->out_len -= c->out_pos;
        c->out_pos = 0;
    }
    size_t room = TLSPSK_BUF_CAP - c->out_len;
    if (room == 0) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    size_t n = len < room ? len : room;
    memcpy(c->out_buf + c->out_len, buf, n);
    c->out_len += n;
    return (int) n;
}

const char *tlspsk_version(void)
{
    static char buf[64];
    /* Keep the package version in sync with pubspec.yaml. */
    snprintf(buf, sizeof buf, "tls_psk 0.1.0 / mbedTLS %s", MBEDTLS_VERSION_STRING);
    return buf;
}

tlspsk_ctx *tlspsk_client_new(const uint8_t *psk, size_t psk_len,
                              const uint8_t *identity, size_t identity_len,
                              const char *server_name)
{
    if (psk == NULL || psk_len == 0 || ensure_psa() != 0) {
        return NULL;
    }

    tlspsk_ctx *c = calloc(1, sizeof *c);
    if (c == NULL) {
        return NULL;
    }

    mbedtls_ssl_init(&c->ssl);
    mbedtls_ssl_config_init(&c->conf);

    int rc = mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        goto fail;
    }

    /* TLS 1.3 only, with the PSK + ephemeral (EC)DHE key-exchange mode so every
     * session is forward-secret. The PSK is the mutual auth: no certificates. */
    mbedtls_ssl_conf_min_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_tls13_key_exchange_modes(
        &c->conf, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL);
    mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_NONE);
    /* mbedTLS 4.x draws all handshake randomness from the PSA RNG (initialised
     * in ensure_psa); there is no mbedtls_ssl_conf_rng to set. */

    const uint8_t empty = 0;
    rc = mbedtls_ssl_conf_psk(&c->conf, psk, psk_len,
                              identity ? identity : &empty, identity_len);
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ssl_setup(&c->ssl, &c->conf);
    if (rc != 0) {
        goto fail;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (server_name != NULL) {
        rc = mbedtls_ssl_set_hostname(&c->ssl, server_name);
        if (rc != 0) {
            goto fail;
        }
    }
#else
    /* SNI requires X.509 support, which a PSK-only build omits. With a shared
     * PSK and a single identity it is unnecessary, so ignore server_name. */
    (void) server_name;
#endif

    mbedtls_ssl_set_bio(&c->ssl, c, bio_send, bio_recv, NULL);
    return c;

fail:
    c->last_err = rc;
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->conf);
    free(c);
    return NULL;
}

static int map_rc(tlspsk_ctx *c, int rc)
{
    if (rc == 0) {
        return TLSPSK_OK;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
        return TLSPSK_WANT_READ;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return TLSPSK_WANT_WRITE;
    }
    c->last_err = rc;
    return TLSPSK_ERROR;
}

/* write() returns >=0 bytes on success; share the want/err mapping otherwise. */
static int map_rc_write(tlspsk_ctx *c, int rc)
{
    if (rc >= 0) {
        return rc;
    }
    return map_rc(c, rc);
}

int tlspsk_handshake(tlspsk_ctx *c)
{
    if (c == NULL) {
        return TLSPSK_ERROR;
    }
    return map_rc(c, mbedtls_ssl_handshake(&c->ssl));
}

int tlspsk_inject(tlspsk_ctx *c, const uint8_t *buf, size_t len)
{
    if (c == NULL || (buf == NULL && len)) {
        return TLSPSK_ERROR;
    }
    /* Compact consumed prefix, then append. */
    if (c->in_pos > 0) {
        memmove(c->in_buf, c->in_buf + c->in_pos, c->in_len - c->in_pos);
        c->in_len -= c->in_pos;
        c->in_pos = 0;
    }
    size_t room = TLSPSK_BUF_CAP - c->in_len;
    size_t n = len < room ? len : room;
    memcpy(c->in_buf + c->in_len, buf, n);
    c->in_len += n;
    return (int) n;
}

int tlspsk_extract(tlspsk_ctx *c, uint8_t *buf, size_t cap)
{
    if (c == NULL || buf == NULL) {
        return TLSPSK_ERROR;
    }
    size_t avail = c->out_len - c->out_pos;
    size_t n = cap < avail ? cap : avail;
    memcpy(buf, c->out_buf + c->out_pos, n);
    c->out_pos += n;
    if (c->out_pos == c->out_len) {
        c->out_pos = c->out_len = 0;
    }
    return (int) n;
}

int tlspsk_pending_output(tlspsk_ctx *c)
{
    return c != NULL && (c->out_len - c->out_pos) > 0;
}

int tlspsk_write(tlspsk_ctx *c, const uint8_t *buf, size_t len)
{
    if (c == NULL || (buf == NULL && len)) {
        return TLSPSK_ERROR;
    }
    return map_rc_write(c, mbedtls_ssl_write(&c->ssl, buf, len));
}

int tlspsk_read(tlspsk_ctx *c, uint8_t *buf, size_t cap)
{
    if (c == NULL || buf == NULL) {
        return TLSPSK_ERROR;
    }
    int rc = mbedtls_ssl_read(&c->ssl, buf, cap);
    if (rc >= 0) {
        return rc; /* bytes read (0 = none available right now) */
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0; /* nothing to hand back yet — caller injects more */
    }
    if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return TLSPSK_CLOSED;
    }
    c->last_err = rc;
    return TLSPSK_ERROR;
}

void tlspsk_close(tlspsk_ctx *c)
{
    if (c != NULL) {
        mbedtls_ssl_close_notify(&c->ssl);
    }
}

void tlspsk_free(tlspsk_ctx *c)
{
    if (c == NULL) {
        return;
    }
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->conf);
    free(c);
}

int tlspsk_strerror(tlspsk_ctx *c, char *buf, size_t cap)
{
    if (buf == NULL || cap == 0) {
        return 0;
    }
    int err = c ? c->last_err : 0;
    mbedtls_strerror(err, buf, cap);
    buf[cap - 1] = '\0';
    return (int) strlen(buf);
}
