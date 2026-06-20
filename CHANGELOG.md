## 0.1.0

Initial release.

- TLS 1.3 external-PSK client sockets with forward secrecy (`psk_dhe_ke`).
- Async `TlsPskSocket` API (Dart owns a `dart:io` Socket; mbedTLS runs over
  in-memory BIO buffers — non-blocking).
- Self-contained: vendored mbedTLS v4.1.0, built from source per platform.
- Platforms: Linux (verified), Windows (wired), macOS (podspec, unverified).
