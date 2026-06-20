/*
 * TF-PSA-Crypto configuration for the tls_psk Dart/Flutter plugin.
 *
 * Just enough PSA crypto for TLS 1.3 with an external PSK and ephemeral
 * (EC)DHE: AES-GCM AEAD, SHA-256/384, the HKDF key schedule, and ECDH on
 * X25519 + secp256r1. Built-in OS entropy (getrandom / getentropy /
 * CryptGenRandom) since this runs on a PC, not an MCU.
 *
 * Pair with config-tls-psk.h (MBEDTLS_CONFIG_FILE).
 */
#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

/* --- AEAD + hashes for the TLS 1.3 ciphersuites ---------------------------- */
#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_SHA_384                    1

/* --- TLS 1.3 key schedule (HKDF over HMAC) --------------------------------- */
#define PSA_WANT_ALG_HKDF                        1
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HMAC                       1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_DERIVE                1
#define PSA_WANT_KEY_TYPE_RAW_DATA              1

/* --- psk_dhe_ke: ephemeral ECDH on X25519 (preferred) + secp256r1 ---------- */
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ECC_MONTGOMERY_255             1
#define PSA_WANT_ECC_SECP_R1_256                1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1

#define MBEDTLS_PSA_CRYPTO_C

/* Performance / footprint knobs (host build). */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_ECP_NIST_OPTIM

/* DRBG used internally by the PSA RNG. */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C

/* PC host: pull entropy from the operating system. */
#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY

#endif /* PSA_CRYPTO_CONFIG_H */
