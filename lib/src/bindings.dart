// Low-level dart:ffi bindings to the tls_psk C ABI (src/tls_psk.h).
// Hand-written (no ffigen step required). The high-level async API in
// ../tls_psk.dart is what consumers use; this stays internal.
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

const String _libName = 'tls_psk';

/// Loads the bundled native library. A `TLS_PSK_LIB` environment variable
/// overrides the path (used by `dart test` / CLIs against a local build).
DynamicLibrary _open() {
  final override = Platform.environment['TLS_PSK_LIB'];
  if (override != null && override.isNotEmpty) {
    return DynamicLibrary.open(override);
  }
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.open('$_libName.framework/$_libName');
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('lib$_libName.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('$_libName.dll');
  }
  throw UnsupportedError('tls_psk: unsupported platform');
}

final DynamicLibrary _lib = _open();

// --- result codes (mirror tlspsk_rc in tls_psk.h) ---------------------------
const int tlspskOk = 0;
const int tlspskWantRead = 1;
const int tlspskWantWrite = 2;
const int tlspskClosed = 3;
const int tlspskError = -1;

final Pointer<Utf8> Function() tlspskVersion = _lib
    .lookup<NativeFunction<Pointer<Utf8> Function()>>('tlspsk_version')
    .asFunction();

final Pointer<Void> Function(
        Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Utf8>) tlspskClientNew =
    _lib
        .lookup<
            NativeFunction<
                Pointer<Void> Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>,
                    IntPtr, Pointer<Utf8>)>>('tlspsk_client_new')
        .asFunction();

final int Function(Pointer<Void>) tlspskHandshake = _lib
    .lookup<NativeFunction<Int32 Function(Pointer<Void>)>>('tlspsk_handshake')
    .asFunction();

final int Function(Pointer<Void>, Pointer<Uint8>, int) tlspskInject = _lib
    .lookup<NativeFunction<Int32 Function(Pointer<Void>, Pointer<Uint8>, IntPtr)>>(
        'tlspsk_inject')
    .asFunction();

final int Function(Pointer<Void>, Pointer<Uint8>, int) tlspskExtract = _lib
    .lookup<NativeFunction<Int32 Function(Pointer<Void>, Pointer<Uint8>, IntPtr)>>(
        'tlspsk_extract')
    .asFunction();

final int Function(Pointer<Void>) tlspskPendingOutput = _lib
    .lookup<NativeFunction<Int32 Function(Pointer<Void>)>>('tlspsk_pending_output')
    .asFunction();

final int Function(Pointer<Void>, Pointer<Uint8>, int) tlspskWrite = _lib
    .lookup<NativeFunction<Int32 Function(Pointer<Void>, Pointer<Uint8>, IntPtr)>>(
        'tlspsk_write')
    .asFunction();

final int Function(Pointer<Void>, Pointer<Uint8>, int) tlspskRead = _lib
    .lookup<NativeFunction<Int32 Function(Pointer<Void>, Pointer<Uint8>, IntPtr)>>(
        'tlspsk_read')
    .asFunction();

final void Function(Pointer<Void>) tlspskClose = _lib
    .lookup<NativeFunction<Void Function(Pointer<Void>)>>('tlspsk_close')
    .asFunction();

final void Function(Pointer<Void>) tlspskFree = _lib
    .lookup<NativeFunction<Void Function(Pointer<Void>)>>('tlspsk_free')
    .asFunction();

final int Function(Pointer<Void>, Pointer<Utf8>, int) tlspskStrerror = _lib
    .lookup<NativeFunction<Int32 Function(Pointer<Void>, Pointer<Utf8>, IntPtr)>>(
        'tlspsk_strerror')
    .asFunction();
