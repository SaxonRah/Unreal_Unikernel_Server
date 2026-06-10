cmake_minimum_required(VERSION 3.16)
project(ue5_574_nanos_endpoint_v9 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_STATIC "Build static ELF where supported" ON)

add_library(ue574_common
    src/udp_util.cpp
    src/crypto_sha1_hmac.cpp
    src/bit_io.cpp
    src/ue57_protocol.cpp
    src/control_channel_probe.cpp
    src/control_channel_writer.cpp
)

add_executable(ue574_endpoint src/main.cpp)
target_link_libraries(ue574_endpoint PRIVATE ue574_common)

add_executable(ue574_temp_client src/temp_client.cpp)
target_link_libraries(ue574_temp_client PRIVATE ue574_common)

add_executable(ue574_probe_client src/ue574_probe_client.cpp)
target_link_libraries(ue574_probe_client PRIVATE ue574_common)

add_executable(ue574_binlog_dump src/binlog_dump.cpp)

set(UE574_TARGETS ue574_common ue574_endpoint ue574_temp_client ue574_probe_client ue574_binlog_dump)

foreach(tgt IN LISTS UE574_TARGETS)
    if(MSVC)
        target_compile_options(${tgt} PRIVATE /W4 /permissive-)
        target_compile_definitions(${tgt} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
    else()
        target_compile_options(${tgt} PRIVATE -Wall -Wextra -Wpedantic -fno-exceptions)
    endif()
endforeach()

if(WIN32)
    target_link_libraries(ue574_common PUBLIC ws2_32)
    target_link_libraries(ue574_binlog_dump PRIVATE ws2_32)
endif()

# NanoS target is Linux ELF. Static linking is useful there, but MSVC does not
# understand GNU-style -static.
if(BUILD_STATIC AND NOT MSVC)
    target_link_options(ue574_endpoint PRIVATE -static)
    target_link_options(ue574_temp_client PRIVATE -static)
    target_link_options(ue574_probe_client PRIVATE -static)
    target_link_options(ue574_binlog_dump PRIVATE -static)
endif()
