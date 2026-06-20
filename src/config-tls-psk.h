/*
 * Mbed TLS (TLS-layer) configuration for the tls_psk Dart/Flutter plugin.
 *
 * TLS 1.3 only, client role, external pre-shared key with ephemeral key
 * agreement (psk_dhe_ke) so every session has forward secrecy. No X.509, no
 * certificates — the PSK is the mutual authentication.
 *
 * Pair with crypto-config-tls-psk.h (TF_PSA_CRYPTO_CONFIG_FILE).
 */
#ifndef CONFIG_TLS_PSK_H
#define CONFIG_TLS_PSK_H

/* --- Protocol: TLS 1.3 with PSK + ephemeral (EC)DHE key exchange ----------- */
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED

#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C

/* Required by the TLS 1.3 code path even when only PSK suites are used. */
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

#define MBEDTLS_SSL_OUT_CONTENT_LEN 16384
#define MBEDTLS_SSL_IN_CONTENT_LEN  16384

/* Randomness comes from the PSA RNG (seeded by the OS entropy source in the
 * crypto config). The DRBG/entropy modules themselves are configured there —
 * in mbedTLS 4.x they are internal to TF-PSA-Crypto and must not be set here. */

/* Human-readable error strings (tlspsk_strerror) + opt-in wire debug. */
#define MBEDTLS_ERROR_C
#define MBEDTLS_DEBUG_C

#endif /* CONFIG_TLS_PSK_H */
