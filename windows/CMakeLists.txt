cmake_minimum_required(VERSION 3.24)
project(vphone_windows_backend LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(vphone_backend STATIC src/backend_stub.cpp)
target_include_directories(vphone_backend PUBLIC include)

add_executable(vphone-vm-win src/main.cpp)
target_link_libraries(vphone-vm-win PRIVATE vphone_backend)

add_executable(vphone_backend_contract_test tests/backend_contract_test.cpp)
target_link_libraries(vphone_backend_contract_test PRIVATE vphone_backend)

enable_testing()
add_test(NAME backend_contract COMMAND vphone_backend_contract_test)
