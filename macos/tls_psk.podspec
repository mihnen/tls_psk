#
# Flutter macOS FFI plugin podspec for tls_psk.
#
# CocoaPods can't drive mbedTLS's CMake build directly, so prepare_command runs
# CMake to produce libtls_psk.dylib, which is then vendored into the app. This
# requires CMake on the build machine (`brew install cmake`).
#
# NOTE: structured by analogy with the verified Linux build but not yet tested
# on macOS hardware.
#
Pod::Spec.new do |s|
  s.name             = 'tls_psk'
  s.version          = '0.1.0'
  s.summary          = 'TLS 1.3 PSK client sockets (mbedTLS) for Flutter.'
  s.description      = 'Self-contained TLS 1.3 pre-shared-key sockets via vendored mbedTLS.'
  s.homepage         = 'https://github.com/mihnen/tls_psk'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = { 'tls_psk' => 'noreply@example.com' }
  s.platform         = :osx, '10.13'
  s.source           = { :path => '.' }
  s.dependency 'FlutterMacOS'

  # Build libtls_psk.dylib from the shared CMake build before pod install.
  s.prepare_command = <<-CMD
    set -e
    ROOT="$(cd "$(dirname "$0")/.." && pwd)"
    BUILD="$ROOT/macos/Libs"
    cmake -S "$ROOT/src" -B "$BUILD/build" -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"
    cmake --build "$BUILD/build" --config Release
    mkdir -p "$BUILD"
    cp "$BUILD/build/libtls_psk.dylib" "$BUILD/libtls_psk.dylib"
  CMD

  s.vendored_libraries = 'Libs/libtls_psk.dylib'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
  }
end
