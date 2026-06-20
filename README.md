# tls_psk

**TLS 1.3 pre-shared-key (PSK) client sockets for Dart & Flutter** — with
forward secrecy (`psk_dhe_ke`), and no system OpenSSL to install.

Dart's built-in `SecureSocket` only speaks certificate TLS. When you want a
mutually-authenticated, encrypted channel keyed by a **shared secret** instead
of a certificate/PKI, there's no stdlib option. `tls_psk` fills that gap: it
drives a **vendored, statically-built [mbedTLS](https://www.trustedfirmware.org/projects/mbed-tls/)**
through `dart:ffi`, so the package is fully self-contained — `flutter pub add
tls_psk` and it just works.

> Unlike packages that dlopen a system OpenSSL, the crypto is built from source
> and bundled, so there's nothing for your users to install and no version skew
> across platforms.

## Features

- **TLS 1.3 external PSK** with ephemeral (EC)DHE — every session is forward-secret.
- **Async, non-blocking**: Dart owns a `dart:io` `Socket`; the native engine only
  does crypto on in-memory buffers, so the event loop never stalls.
- **Self-contained**: mbedTLS is vendored and built by the plugin per platform.
- **Mutual auth, no certificates, no CA.**

## Platforms

| Platform | Status |
|---|---|
| Linux   | ✅ built + tested (handshake & echo verified against OpenSSL) |
| Windows | ✅ CMake build wired (same shared build as Linux) |
| macOS   | ⚠️ podspec builds via CMake — not yet verified on Mac hardware |

Requires CMake on the build machine (Flutter desktop already needs it).

## Usage

```dart
import 'dart:convert';
import 'package:tls_psk/tls_psk.dart';

final sock = await TlsPskSocket.connect(
  'example.com', 4433,
  psk: myKeyBytes,                  // raw pre-shared key — use >= 16 random bytes
  identity: utf8.encode('device-42'),
);

sock.stream.listen((data) => print('recv ${data.length} bytes'));
sock.add(utf8.encode('hello'));
await sock.flush();
// ...
await sock.close();
```

### API

| Member | Description |
|---|---|
| `TlsPskSocket.connect(host, port, {psk, identity, serverName, timeout})` | Connect + complete the TLS 1.3 PSK handshake. `Future<TlsPskSocket>`. |
| `stream` | `Stream<Uint8List>` of decrypted inbound application data. |
| `add(List<int>)` | Encrypt and send application data. |
| `flush()` / `close()` | Flush buffered output / send close_notify and tear down. |
| `done` | Completes when fully closed. |
| `TlsPskSocket.version` | `"tls_psk x / mbedTLS y"`. |

Use a **high-entropy** PSK (16–32 random bytes). A human passphrase as a PSK is
offline-dictionary-attackable — generate and provision a real key instead.

## How it works

```
dart:io Socket  ⇄  TlsPskSocket  ⇄  [FFI]  ⇄  mbedTLS engine (memory BIO)
  (async I/O)       (event loop)                (TLS 1.3 crypto only)
```

The native engine never touches a socket — it reads/writes ciphertext through
two in-memory buffers (`inject`/`extract`). Dart shuttles those bytes to and
from an async socket, so all I/O stays on the Dart event loop.

## mbedTLS version & security updates

mbedTLS is pinned (git submodule) to an **LTS** release and bundled into the
published package. Updating is a one-line submodule bump + republish; an upstream
release watch (`.github/workflows/`) opens a notification when a new LTS lands, so
tracking CVEs is "merge a PR", not "remember to check".

## License

MIT (this package). Bundled mbedTLS is Apache-2.0 / GPL-2.0 dual-licensed; its
license applies to the `third_party/mbedtls` subtree.
