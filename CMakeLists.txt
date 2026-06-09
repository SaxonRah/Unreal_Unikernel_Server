cmake_minimum_required(VERSION 3.16)
project(ue5_nanos_handshake_relay_starter CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ue5relay src/main.cpp)

target_compile_options(ue5relay PRIVATE
    -Wall -Wextra -Wpedantic
    -fno-exceptions
)

# For small static Linux binaries. NanoS can run dynamic ELF too, but static
# makes early experiments simpler.
option(BUILD_STATIC "Build static ELF where supported" ON)
if(BUILD_STATIC)
    target_link_options(ue5relay PRIVATE -static)
endif()
