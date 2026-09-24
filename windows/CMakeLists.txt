cmake_minimum_required(VERSION 3.24)
project(vphone_windows_backend LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
