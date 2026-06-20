# Builds the tls_psk native engine (mbedTLS + the C shim) for every platform.
# The Flutter platform folders (linux/, windows/, macos/, ios/, android/) all
# include THIS file so there is exactly one description of the native build.
#
# Stand-alone (host) build, for development/tests:
#   cmake -S src -B build && cmake --build build
cmake_minimum_required(VERSION 3.16)
project(tls_psk C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Path to the package root (this file lives in <root>/src).
get_filename_component(TLSPSK_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(MBEDTLS_DIR "${TLSPSK_ROOT}/third_party/mbedtls")

if(NOT EXISTS "${MBEDTLS_DIR}/CMakeLists.txt")
  message(FATAL_ERROR
    "third_party/mbedtls is empty — run: git submodule update --init --recursive")
endif()

# --- Vendored mbedTLS (TLS 1.3 PSK only), built static into our shared lib ----
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(MBEDTLS_CONFIG_FILE
    "${CMAKE_CURRENT_LIST_DIR}/config-tls-psk.h" CACHE FILEPATH "" FORCE)
set(TF_PSA_CRYPTO_CONFIG_FILE
    "${CMAKE_CURRENT_LIST_DIR}/crypto-config-tls-psk.h" CACHE FILEPATH "" FORCE)

add_subdirectory("${MBEDTLS_DIR}" "${CMAKE_BINARY_DIR}/mbedtls" EXCLUDE_FROM_ALL)

# --- The tls_psk shared library (this is what Dart's DynamicLibrary loads) -----
add_library(tls_psk SHARED tls_psk.c)
set_target_properties(tls_psk PROPERTIES
    C_VISIBILITY_PRESET hidden
    OUTPUT_NAME tls_psk)
target_compile_definitions(tls_psk PRIVATE TLSPSK_BUILDING TLSPSK_SHARED)
target_include_directories(tls_psk PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_link_libraries(tls_psk PRIVATE
    MbedTLS::mbedtls TF-PSA-Crypto::tfpsacrypto)

# The platform folders (linux/, windows/, …) reference $<TARGET_FILE:tls_psk>
# and set <plugin>_bundled_libraries in their own scope for the Flutter tooling.
