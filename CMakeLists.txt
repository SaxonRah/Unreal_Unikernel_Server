cmake_minimum_required(VERSION 3.16)
project(ue5_574_nanos_endpoint_v2 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_STATIC "Build static ELF where supported" ON)

add_library(ue574_common
    src/udp_util.cpp
    src/crypto_sha1_hmac.cpp
    src/ue57_protocol.cpp
)

target_compile_options(ue574_common PRIVATE -Wall -Wextra -Wpedantic -fno-exceptions)

add_executable(ue574_endpoint src/main.cpp)
target_link_libraries(ue574_endpoint PRIVATE ue574_common)
target_compile_options(ue574_endpoint PRIVATE -Wall -Wextra -Wpedantic -fno-exceptions)

add_executable(ue574_temp_client src/temp_client.cpp)
target_link_libraries(ue574_temp_client PRIVATE ue574_common)
target_compile_options(ue574_temp_client PRIVATE -Wall -Wextra -Wpedantic -fno-exceptions)

if(BUILD_STATIC)
    target_link_options(ue574_endpoint PRIVATE -static)
    target_link_options(ue574_temp_client PRIVATE -static)
endif()
