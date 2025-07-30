project(nitrosecp256k1)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME nitrosecp256k1)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# Configure libsodium build options (minimal build for HMAC-SHA512 only)
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "Disable libsodium tests")
set(SODIUM_MINIMAL ON CACHE BOOL "Enable minimal libsodium build - only essential crypto functions")

# Add libsodium as a subdirectory (will be built as static lib)
add_subdirectory(${CMAKE_SOURCE_DIR}/../cpp/libsodium_cmake libsodium_cmake)

# Configure secp256k1 build options
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "Enable secp256k1 recovery module")
set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "Enable secp256k1 ECDH module")
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "Enable secp256k1 Schnorr signature module")
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "Build secp256k1 tests")
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "Build secp256k1 benchmark")
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "Build secp256k1 examples")
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "Disable shared library to avoid conflicts")
set(SECP256K1_INSTALL OFF CACHE BOOL "Disable installation")

# Add secp256k1 as a subdirectory (will be built as static lib)
add_subdirectory(${CMAKE_SOURCE_DIR}/../cpp/secp256k1 secp256k1)

# Define C++ library and add all sources
add_library(${PACKAGE_NAME} SHARED 
    src/main/cpp/cpp-adapter.cpp
    ../cpp/HybridNitroSecp256k1.cpp
    ../cpp/keccak-tiny.c
)

# Add Nitrogen specs :)
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/nitrosecp256k1+autolinking.cmake)

# Set up local includes
include_directories("src/main/cpp" "../cpp" "../cpp/secp256k1/include" "../cpp/secp256k1/src" "../cpp/libsodium_cmake/libsodium/src/libsodium/include")

find_library(LOG_LIB log)

# Link all libraries together
target_link_libraries(
        ${PACKAGE_NAME}
        secp256k1
        sodium
        ${LOG_LIB}
        android # <-- Android core
)
