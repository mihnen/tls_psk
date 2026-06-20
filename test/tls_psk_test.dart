// Live test of the async TlsPskSocket API against an openssl TLS 1.3 PSK
// server. Run with the locally-built native lib:
//
//   (start a server)  openssl s_server -tls1_3 -psk <hex> \
//                        -psk_identity Client_identity -nocert -rev -accept 11999 -quiet &
//   TLS_PSK_LIB=build-host/libtls_psk.so flutter test test/tls_psk_test.dart
//
// The harness script test/run_live.sh wires this up.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:tls_psk/tls_psk.dart';

// Matches the server PSK hex "0123456789abcdef0123456789abcdef".
final Uint8List _psk = Uint8List.fromList(
    [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

void main() {
  test('version string', () {
    expect(TlsPskSocket.version, contains('mbedTLS'));
  });

  test('TLS 1.3 PSK handshake + encrypted echo', () async {
    final sock = await TlsPskSocket.connect(
      '127.0.0.1',
      11999,
      psk: _psk,
      identity: utf8.encode('Client_identity'),
    );
    expect(sock.isConnected, isTrue);

    final firstChunk = Completer<String>();
    sock.stream.listen((data) {
      if (!firstChunk.isCompleted) firstChunk.complete(utf8.decode(data));
    });

    sock.add(utf8.encode('ping over tls-psk\n'));
    final echo = await firstChunk.future.timeout(const Duration(seconds: 5));

    // The -rev server returns the line reversed.
    expect(echo.trim(), 'ksp-slt revo gnip');
    await sock.close();
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('wrong PSK fails the handshake', () async {
    expect(
      () => TlsPskSocket.connect(
        '127.0.0.1',
        11999,
        psk: Uint8List.fromList(List.filled(16, 0xAA)),
        identity: utf8.encode('Client_identity'),
        timeout: const Duration(seconds: 5),
      ),
      throwsA(isA<TlsPskException>()),
    );
  }, timeout: const Timeout(Duration(seconds: 20)));
}
