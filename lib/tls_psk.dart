/// A self-contained **TLS 1.3 pre-shared-key (PSK)** client socket for Dart and
/// Flutter, with forward secrecy (`psk_dhe_ke`).
///
/// Dart's built-in `SecureSocket` only does certificate TLS, so this package
/// drives a vendored, statically-built mbedTLS engine over `dart:ffi`. The Dart
/// side owns an async `dart:io` [Socket]; the native engine only does crypto on
/// in-memory buffers, so nothing blocks the event loop.
///
/// ```dart
/// final sock = await TlsPskSocket.connect(
///   'example.com', 4433,
///   psk: myKeyBytes,            // >= 16 random bytes
///   identity: utf8.encode('device-42'),
/// );
/// sock.stream.listen((data) => print('got ${data.length} bytes'));
/// sock.add(utf8.encode('hello'));
/// await sock.close();
/// ```
library;

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'src/bindings.dart' as b;

/// Thrown on connection or TLS errors.
class TlsPskException implements Exception {
  TlsPskException(this.message);
  final String message;
  @override
  String toString() => 'TlsPskException: $message';
}

/// A TLS 1.3 PSK connection. Decrypted inbound bytes arrive on [stream];
/// [add] sends application data.
class TlsPskSocket {
  TlsPskSocket._(this._socket, this._ctx);

  final Socket _socket;
  final Pointer<Void> _ctx;
  final StreamController<Uint8List> _controller =
      StreamController<Uint8List>();
  final Completer<void> _handshake = Completer<void>();
  bool _handshakeDone = false;
  bool _closed = false;
  StreamSubscription<Uint8List>? _sub;

  static const int _chunk = 16 * 1024;

  /// Library version, e.g. `"tls_psk 0.1.0 / mbedTLS 4.1.0"`.
  static String get version => b.tlspskVersion().toDartString();

  /// Connects to [host]:[port] and completes the TLS 1.3 PSK handshake.
  ///
  /// [psk] is the raw pre-shared key (use at least 16 random bytes). [identity]
  /// is the PSK identity sent in the clear (e.g. `utf8.encode('device-42')`).
  /// [serverName] sets SNI when the build supports it. Throws
  /// [TlsPskException] (or [SocketException]) on failure.
  static Future<TlsPskSocket> connect(
    String host,
    int port, {
    required List<int> psk,
    required List<int> identity,
    String? serverName,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (psk.isEmpty) throw TlsPskException('psk must not be empty');

    final socket = await Socket.connect(host, port, timeout: timeout);
    socket.setOption(SocketOption.tcpNoDelay, true);

    final pskBuf = _toNative(psk);
    final idBuf = _toNative(identity);
    final namePtr = serverName == null ? nullptr : serverName.toNativeUtf8();
    final Pointer<Void> ctx;
    try {
      ctx = b.tlspskClientNew(
          pskBuf, psk.length, idBuf, identity.length, namePtr.cast());
    } finally {
      malloc.free(pskBuf);
      malloc.free(idBuf);
      if (namePtr != nullptr) malloc.free(namePtr);
    }
    if (ctx == nullptr) {
      socket.destroy();
      throw TlsPskException('failed to create TLS-PSK engine: ${_initError()}');
    }

    final s = TlsPskSocket._(socket, ctx);
    s._start();
    try {
      await s._handshake.future.timeout(timeout);
    } catch (e) {
      await s.close();
      if (e is TlsPskException) rethrow;
      throw TlsPskException('handshake timed out');
    }
    return s;
  }

  /// Decrypted application data from the peer.
  Stream<Uint8List> get stream => _controller.stream;

  /// Completes when the connection is fully closed.
  Future<void> get done => _controller.done;

  /// True once the TLS handshake has completed.
  bool get isConnected => _handshakeDone && !_closed;

  /// Encrypts and sends application data.
  void add(List<int> data) {
    if (_closed) throw TlsPskException('socket is closed');
    if (!_handshakeDone) throw TlsPskException('handshake not complete');
    if (data.isEmpty) return;
    final buf = _toNative(data);
    try {
      var off = 0;
      while (off < data.length) {
        final n = b.tlspskWrite(
            _ctx, Pointer<Uint8>.fromAddress(buf.address + off), data.length - off);
        if (n > 0) {
          off += n;
          _drainOut();
        } else if (n == b.tlspskWantWrite) {
          _drainOut();
        } else {
          _fail('write');
          break;
        }
      }
    } finally {
      malloc.free(buf);
    }
  }

  /// Flushes buffered outbound data to the underlying socket.
  Future<void> flush() => _socket.flush();

  /// Sends close_notify, tears down the engine, and closes the socket.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      b.tlspskClose(_ctx);
      _drainOut();
      await _socket.flush();
    } catch (_) {/* best effort */}
    await _sub?.cancel();
    b.tlspskFree(_ctx);
    try {
      _socket.destroy();
    } catch (_) {}
    if (!_controller.isClosed) await _controller.close();
  }

  // --- internals -------------------------------------------------------------

  void _start() {
    _sub = _socket.listen(_onData,
        onError: _onError, onDone: _onSocketDone, cancelOnError: true);
    // TLS 1.3 clients speak first — kick the handshake to emit the ClientHello.
    _pump();
  }

  void _onData(Uint8List data) {
    _inject(data);
    _pump();
  }

  void _onError(Object e, StackTrace st) {
    if (!_handshake.isCompleted) {
      _handshake.completeError(TlsPskException('$e'));
    }
    if (!_controller.isClosed) _controller.addError(e, st);
  }

  void _onSocketDone() {
    if (!_handshake.isCompleted) {
      _handshake.completeError(TlsPskException('socket closed during handshake'));
    }
    close();
  }

  void _pump() {
    if (_closed) return;
    if (!_handshakeDone) {
      final rc = b.tlspskHandshake(_ctx);
      _drainOut();
      if (rc == b.tlspskOk) {
        _handshakeDone = true;
        if (!_handshake.isCompleted) _handshake.complete();
        _drainIn(); // app data may already be buffered
      } else if (rc == b.tlspskWantRead) {
        // await more socket data
      } else {
        _fail('handshake');
      }
    } else {
      _drainIn();
    }
  }

  void _drainIn() {
    final out = malloc<Uint8>(_chunk);
    try {
      while (!_closed) {
        final n = b.tlspskRead(_ctx, out, _chunk);
        if (n > 0) {
          _controller.add(Uint8List.fromList(out.asTypedList(n)));
        } else if (n == b.tlspskClosed) {
          close();
          break;
        } else if (n == 0) {
          break;
        } else {
          _fail('read');
          break;
        }
      }
    } finally {
      malloc.free(out);
    }
  }

  void _drainOut() {
    final out = malloc<Uint8>(_chunk);
    try {
      while (true) {
        final n = b.tlspskExtract(_ctx, out, _chunk);
        if (n <= 0) break;
        _socket.add(Uint8List.fromList(out.asTypedList(n)));
      }
    } finally {
      malloc.free(out);
    }
  }

  void _inject(Uint8List data) {
    if (data.isEmpty) return;
    final buf = _toNative(data);
    try {
      var off = 0;
      while (off < data.length) {
        final n = b.tlspskInject(
            _ctx, Pointer<Uint8>.fromAddress(buf.address + off), data.length - off);
        if (n <= 0) break;
        off += n;
      }
    } finally {
      malloc.free(buf);
    }
  }

  void _fail(String what) {
    final ex = TlsPskException('$what failed: ${_lastError()}');
    if (!_handshake.isCompleted) _handshake.completeError(ex);
    if (!_controller.isClosed) _controller.addError(ex);
    close();
  }

  String _lastError() {
    final buf = malloc<Uint8>(160);
    try {
      b.tlspskStrerror(_ctx, buf.cast<Utf8>(), 160);
      return buf.cast<Utf8>().toDartString();
    } finally {
      malloc.free(buf);
    }
  }

  // Why tlspsk_client_new returned null (engine setup failure).
  static String _initError() {
    final buf = malloc<Uint8>(160);
    try {
      b.tlspskStrerror(nullptr, buf.cast<Utf8>(), 160);
      return buf.cast<Utf8>().toDartString();
    } finally {
      malloc.free(buf);
    }
  }

  static Pointer<Uint8> _toNative(List<int> data) {
    final len = data.isEmpty ? 1 : data.length;
    final p = malloc<Uint8>(len);
    if (data.isNotEmpty) p.asTypedList(data.length).setAll(0, data);
    return p;
  }
}
