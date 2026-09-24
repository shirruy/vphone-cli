cmake_minimum_required(VERSION 3.24)
project(vphone_windows_backend LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(vphone_backend STATIC src/backend_stub.cpp)
target_include_directories(vphone_backend PUBLIC include)

add_executable(vphone-vm-win src/main.cpp)
target_link_libraries(vphone-vm-win PRIVATE vphone_backend)

add_executable(vphone_backend_contract_test tests/backend_contract_test.cpp)
target_link_libraries(vphone_backend_contract_test PRIVATE vphone_backend)

# Phase 1 upstream-derived portability proof.
# This builds real upstream MobileRestoreCore FTAB code under MSVC with only a
# narrow logging compatibility header. The source itself remains the authority.
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

enable_testing()

add_test(NAME backend_contract COMMAND vphone_backend_contract_test)

add_test(NAME cli_capability_probe COMMAND vphone-vm-win --capabilities)
set_tests_properties(cli_capability_probe PROPERTIES
    PASS_REGULAR_EXPRESSION "\"backend\": \"windows-research-stub\""
)

add_test(NAME cli_help COMMAND vphone-vm-win --help)
set_tests_properties(cli_help PROPERTIES
    PASS_REGULAR_EXPRESSION "usage: vphone-vm-win"
)

add_test(NAME upstream_ftab_roundtrip COMMAND vphone_upstream_ftab_test)
