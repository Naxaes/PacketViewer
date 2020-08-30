cmake_minimum_required(VERSION 3.17)
project(ted)

set(COMPILER_FLAGS "-Werror -pedantic -pedantic-errors -std=c++14")
set(COMPILER_FLAGS_SLOW "-O0 -g")
set(COMPILER_FLAGS_FAST "-O2")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(COMPILER_FLAGS "${COMPILER_FLAGS} ${COMPILER_FLAGS_FAST}")
    message(STATUS "Building debug...")
else()
    set(COMPILER_FLAGS "${COMPILER_FLAGS} ${COMPILER_FLAGS_FAST}")
    message(STATUS "Building release...")
endif()

set(CMAKE_CXX_FLAGS  "${COMPILER_FLAGS}")
add_executable(ted source/main.cpp)
