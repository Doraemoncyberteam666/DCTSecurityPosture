cmake_minimum_required(VERSION 3.22.1)

project(dctnative LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(dctnative SHARED
    native_checks.cpp
)

target_compile_options(dctnative PRIVATE
    -fvisibility=hidden
    -fno-rtti
    -fno-exceptions
    -Os
    -ffunction-sections
    -fdata-sections
    -Wall
)

target_link_options(dctnative PRIVATE
    -Wl,--gc-sections
    -Wl,-z,noexecstack
    -Wl,-z,relro
    -Wl,-z,now
)

find_library(log-lib log)

target_link_libraries(dctnative
    ${log-lib}
)
