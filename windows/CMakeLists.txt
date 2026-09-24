cmake_minimum_required(VERSION 3.24)
project(vphone_windows_backend LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(ENABLE_TEST OFF CACHE BOOL "" FORCE)
set(ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(ENABLE_TAR OFF CACHE BOOL "" FORCE)
set(ENABLE_CPIO OFF CACHE BOOL "" FORCE)
set(ENABLE_CAT OFF CACHE BOOL "" FORCE)
set(ENABLE_UNZIP OFF CACHE BOOL "" FORCE)
set(ENABLE_OPENSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_MBEDTLS OFF CACHE BOOL "" FORCE)
set(ENABLE_NETTLE OFF CACHE BOOL "" FORCE)
set(ENABLE_LIBB2 OFF CACHE BOOL "" FORCE)
set(ENABLE_LZ4 OFF CACHE BOOL "" FORCE)
set(ENABLE_LZO OFF CACHE BOOL "" FORCE)
set(ENABLE_LZMA OFF CACHE BOOL "" FORCE)
set(ENABLE_ZSTD OFF CACHE BOOL "" FORCE)
set(ENABLE_ZLIB OFF CACHE BOOL "" FORCE)
set(ENABLE_BZip2 OFF CACHE BOOL "" FORCE)
set(ENABLE_LIBXML2 OFF CACHE BOOL "" FORCE)
set(ENABLE_EXPAT OFF CACHE BOOL "" FORCE)
set(ENABLE_WIN32_XMLLITE OFF CACHE BOOL "" FORCE)
set(ENABLE_PCREPOSIX OFF CACHE BOOL "" FORCE)
set(ENABLE_PCRE2POSIX OFF CACHE BOOL "" FORCE)
set(ENABLE_LIBGCC OFF CACHE BOOL "" FORCE)
set(POSIX_REGEX_LIB "NONE" CACHE STRING "" FORCE)
set(ENABLE_CNG OFF CACHE BOOL "" FORCE)
set(ENABLE_XATTR OFF CACHE BOOL "" FORCE)
set(ENABLE_ACL OFF CACHE BOOL "" FORCE)
set(ENABLE_ICONV OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    libarchive
    GIT_REPOSITORY https://github.com/libarchive/libarchive.git
    GIT_TAG v3.8.9
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(libarchive)

FetchContent_Declare(
    zlib
    GIT_REPOSITORY https://github.com/madler/zlib.git
    GIT_TAG v1.3.2
    GIT_SHALLOW TRUE
)
set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZLIB_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zlib)

FetchContent_Declare(
    xz
    GIT_REPOSITORY https://github.com/tukaani-project/xz.git
    GIT_TAG v5.8.4
    GIT_SHALLOW TRUE
)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(XZ_NLS OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_XZ OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_XZDEC OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_LZMADEC OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_LZMAINFO OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_SCRIPTS OFF CACHE BOOL "" FORCE)
set(XZ_DOC OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(xz)

FetchContent_Declare(
    zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG v1.5.7
    GIT_SHALLOW TRUE
    SOURCE_SUBDIR build/cmake
)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZSTD_BUILD_DICTBUILDER OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)


add_library(vphone_backend STATIC src/backend_stub.cpp)
target_include_directories(vphone_backend PUBLIC include)

add_library(vphone_backend_protocol STATIC src/backend_protocol.cpp)
target_include_directories(vphone_backend_protocol PUBLIC include)

add_library(vphone_cli_core STATIC src/cli_core.cpp)
target_include_directories(vphone_cli_core PUBLIC include)
target_link_libraries(vphone_cli_core PUBLIC vphone_backend_protocol)

add_executable(vphone-cli-win src/cli_main.cpp)
target_link_libraries(vphone-cli-win PRIVATE vphone_cli_core)

add_executable(vphone-vm-win src/main.cpp)
target_link_libraries(vphone-vm-win PRIVATE vphone_backend vphone_backend_protocol)

add_executable(vphone_backend_contract_test tests/backend_contract_test.cpp)
target_link_libraries(vphone_backend_contract_test PRIVATE vphone_backend)

add_executable(vphone_backend_protocol_test tests/backend_protocol_test.cpp)
target_link_libraries(vphone_backend_protocol_test PRIVATE vphone_backend_protocol)

add_executable(vphone_native_cli_core_test tests/native_cli_core_test.cpp)
target_link_libraries(vphone_native_cli_core_test PRIVATE vphone_cli_core)

add_library(vphone_archive_portable STATIC src/archive_portable.c)
target_include_directories(vphone_archive_portable PUBLIC include)
target_compile_definitions(vphone_archive_portable PRIVATE LIBARCHIVE_STATIC)
target_link_libraries(vphone_archive_portable PUBLIC archive_static)
if(WIN32)
    target_link_libraries(vphone_archive_portable PUBLIC bcrypt)
endif()

add_executable(vphone_archive_roundtrip_test tests/archive_roundtrip_test.c)
target_link_libraries(vphone_archive_roundtrip_test PRIVATE vphone_archive_portable)

add_library(vphone_bundle_portable STATIC src/bundle_portable.c)
target_include_directories(vphone_bundle_portable PUBLIC include)
target_compile_definitions(vphone_bundle_portable PRIVATE LIBARCHIVE_STATIC)
target_link_libraries(vphone_bundle_portable PUBLIC archive_static)
if(WIN32)
    target_link_libraries(vphone_bundle_portable PUBLIC bcrypt)
endif()

add_executable(vphone_bundle_validation_test tests/bundle_validation_test.c)
target_link_libraries(vphone_bundle_validation_test PRIVATE
    vphone_archive_portable
    vphone_bundle_portable
)

add_library(vphone_compression_portable STATIC src/compression_portable.c)
target_include_directories(vphone_compression_portable
    PUBLIC include
    PRIVATE "${xz_SOURCE_DIR}/src/liblzma/api"
)
target_link_libraries(vphone_compression_portable PUBLIC
    ZLIB::ZLIBSTATIC
    liblzma
    libzstd_static
)

add_executable(vphone_compression_roundtrip_test tests/compression_roundtrip_test.c)
target_link_libraries(vphone_compression_roundtrip_test PRIVATE
    vphone_archive_portable
    vphone_bundle_portable
    vphone_compression_portable
)

if(WIN32)
    add_executable(vphone_windows_hardlink_identity_test tests/windows_hardlink_identity_test.cpp)
endif()

# Phase 1 upstream-derived portability proof.
set(VPHONE_MOBILE_RESTORE_ROOT
    "${CMAKE_CURRENT_SOURCE_DIR}/../VPhoneExecutable/VPhoneCommand/VPhoneRestore/MobileRestoreCore"
)
add_library(vphone_upstream_ftab STATIC
    "${VPHONE_MOBILE_RESTORE_ROOT}/Firmware/Containers/ftab.c"
)
target_include_directories(vphone_upstream_ftab PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/compat/mobile_restore"
    "${VPHONE_MOBILE_RESTORE_ROOT}"
    "${VPHONE_MOBILE_RESTORE_ROOT}/Firmware/Containers"
)

add_executable(vphone_upstream_ftab_test tests/upstream_ftab_test.c)
target_include_directories(vphone_upstream_ftab_test PRIVATE
    "${VPHONE_MOBILE_RESTORE_ROOT}"
    "${VPHONE_MOBILE_RESTORE_ROOT}/Firmware/Containers"
)
target_link_libraries(vphone_upstream_ftab_test PRIVATE vphone_upstream_ftab)

add_library(vphone_upstream_mbn STATIC
    "${VPHONE_MOBILE_RESTORE_ROOT}/Firmware/Containers/mbn.c"
)
target_include_directories(vphone_upstream_mbn PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/compat/mobile_restore"
    "${VPHONE_MOBILE_RESTORE_ROOT}"
    "${VPHONE_MOBILE_RESTORE_ROOT}/Firmware/Containers"
)

add_executable(vphone_upstream_mbn_test tests/upstream_mbn_test.c)
target_include_directories(vphone_upstream_mbn_test PRIVATE
    "${VPHONE_MOBILE_RESTORE_ROOT}/Firmware/Containers"
)
target_link_libraries(vphone_upstream_mbn_test PRIVATE vphone_upstream_mbn)

set(VPHONE_PROTOCOL_FIXTURE
    "${CMAKE_CURRENT_SOURCE_DIR}/../protocol/fixtures/backend_request_v1_boot.json"
)

enable_testing()

add_test(NAME backend_contract COMMAND vphone_backend_contract_test)

add_test(NAME native_cli_core COMMAND vphone_native_cli_core_test)

add_test(NAME native_cli_help COMMAND vphone-cli-win --help)
set_tests_properties(native_cli_help PROPERTIES
    PASS_REGULAR_EXPRESSION "vphone-cli-win vm launch"
)

add_test(NAME native_cli_protocol_version COMMAND vphone-cli-win protocol-version)
set_tests_properties(native_cli_protocol_version PROPERTIES
    PASS_REGULAR_EXPRESSION "^1"
)

add_test(NAME native_cli_firmware_capabilities COMMAND vphone-cli-win firmware-capabilities)
set_tests_properties(native_cli_firmware_capabilities PROPERTIES
    PASS_REGULAR_EXPRESSION "\"mbn\": \"supported\""
)

add_test(NAME native_cli_archive_capabilities COMMAND vphone-cli-win archive-capabilities)
set_tests_properties(native_cli_archive_capabilities PROPERTIES
    PASS_REGULAR_EXPRESSION "\"gnutar_uncompressed\": \"supported\""
)

add_test(
    NAME archive_gnutar_roundtrip
    COMMAND vphone_archive_roundtrip_test "${CMAKE_CURRENT_BINARY_DIR}/archive_gnutar_roundtrip.tar"
)

add_test(
    NAME bundle_manifest_validation
    COMMAND vphone_bundle_validation_test "${CMAKE_CURRENT_BINARY_DIR}/bundle_validation.tar"
)

if(WIN32)
    add_test(
        NAME windows_hardlink_identity
        COMMAND vphone_windows_hardlink_identity_test "${CMAKE_CURRENT_BINARY_DIR}"
    )
endif()

add_test(
    NAME compression_transport_roundtrip
    COMMAND vphone_compression_roundtrip_test
        "${CMAKE_CURRENT_BINARY_DIR}/compression_source.tar"
        "${CMAKE_CURRENT_BINARY_DIR}/compression_restored.tar"
)

add_test(
    NAME native_cli_dry_run
    COMMAND vphone-cli-win vm launch
        --config /tmp/vphone/demo/config.plist
        --headless
        --api-listen 127.0.0.1:8765
        --kernel-debug-port 62000
        --dry-run
)
set_tests_properties(native_cli_dry_run PROPERTIES
    PASS_REGULAR_EXPRESSION "\"protocol_version\": 1"
)

add_test(
    NAME backend_protocol_v1
    COMMAND vphone_backend_protocol_test "${VPHONE_PROTOCOL_FIXTURE}"
)

add_test(NAME cli_capability_probe COMMAND vphone-vm-win --capabilities)
set_tests_properties(cli_capability_probe PROPERTIES
    PASS_REGULAR_EXPRESSION "\"backend\": \"windows-research-stub\""
)

add_test(NAME cli_help COMMAND vphone-vm-win --help)
set_tests_properties(cli_help PROPERTIES
    PASS_REGULAR_EXPRESSION "usage: vphone-vm-win"
)

add_test(NAME cli_protocol_version COMMAND vphone-vm-win protocol-version)
set_tests_properties(cli_protocol_version PROPERTIES
    PASS_REGULAR_EXPRESSION "^1"
)

add_test(
    NAME cli_validate_protocol_request
    COMMAND vphone-vm-win validate-request "${VPHONE_PROTOCOL_FIXTURE}"
)
set_tests_properties(cli_validate_protocol_request PROPERTIES
    PASS_REGULAR_EXPRESSION "\"protocol_version\": 1"
)

add_test(NAME upstream_ftab_roundtrip COMMAND vphone_upstream_ftab_test)
add_test(NAME upstream_mbn_stitch COMMAND vphone_upstream_mbn_test)
