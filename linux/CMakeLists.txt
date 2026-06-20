# Flutter Linux FFI-plugin entry point — delegates to the shared native build.
cmake_minimum_required(VERSION 3.10)
project(tls_psk_library VERSION 0.1.0 LANGUAGES C)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../src"
                 "${CMAKE_CURRENT_BINARY_DIR}/shared")

# Tell the Flutter tooling which artifact(s) to bundle with the app.
set(tls_psk_bundled_libraries
    "$<TARGET_FILE:tls_psk>"
    PARENT_SCOPE)
