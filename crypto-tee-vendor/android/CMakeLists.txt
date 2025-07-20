# CMake configuration for building CryptoTEE vendor library for Android

cmake_minimum_required(VERSION 3.10.2)
project("crypto_tee_vendor")

# Rust library configuration
set(RUST_LIBRARY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../../target")
set(RUST_TARGET "aarch64-linux-android")

# Build Rust library
add_custom_command(
    OUTPUT "${RUST_LIBRARY_PATH}/${RUST_TARGET}/release/libcrypto_tee_vendor.so"
    COMMAND cargo build --release --target ${RUST_TARGET} --features samsung
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
    COMMENT "Building Rust library for Android"
)

# Create custom target
add_custom_target(
    rust_build ALL
    DEPENDS "${RUST_LIBRARY_PATH}/${RUST_TARGET}/release/libcrypto_tee_vendor.so"
)

# Import the built library
add_library(crypto_tee_vendor SHARED IMPORTED)
set_target_properties(
    crypto_tee_vendor
    PROPERTIES IMPORTED_LOCATION
    "${RUST_LIBRARY_PATH}/${RUST_TARGET}/release/libcrypto_tee_vendor.so"
)

# Copy library to JNI libs directory
add_custom_command(
    TARGET rust_build POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}"
    COMMAND ${CMAKE_COMMAND} -E copy
            "${RUST_LIBRARY_PATH}/${RUST_TARGET}/release/libcrypto_tee_vendor.so"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libcrypto_tee_vendor.so"
)