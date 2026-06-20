#!/usr/bin/env bash
# Run the live TLS 1.3 PSK tests against a local openssl echo server.
#   1. builds the native engine (cmake) if needed
#   2. starts `openssl s_server` in TLS 1.3 PSK echo (-rev) mode
#   3. runs `flutter test` with TLS_PSK_LIB pointing at the built lib
set -euo pipefail
cd "$(dirname "$0")/.."

PSK_HEX=0123456789abcdef0123456789abcdef
PORT=11999

[ -f build-host/libtls_psk.so ] || { cmake -S src -B build-host -DCMAKE_BUILD_TYPE=Release; cmake --build build-host -j; }

openssl s_server -tls1_3 -psk "$PSK_HEX" -psk_identity Client_identity \
  -nocert -accept "$PORT" -rev -quiet >/tmp/tls_psk_sserver.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 1

TLS_PSK_LIB="$(pwd)/build-host/libtls_psk.so" flutter test test/tls_psk_test.dart
