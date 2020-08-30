#!/usr/bin/env bash
clear

IGNORED_WARNINGS=
COMPILER_FLAGS="-Werror -pedantic -pedantic-errors -std=c++14"
COMPILER_FLAGS_SLOW="-O0 -g"
COMPILER_FLAGS_FAST="-O2"


if [ "$1" = "debug" ]; then
    COMPILER_FLAGS="${COMPILER_FLAGS} ${COMPILER_FLAGS_SLOW}"
else
    COMPILER_FLAGS="${COMPILER_FLAGS} ${COMPILER_FLAGS_FAST}"
fi


clang++ ${COMPILER_FLAGS} ${IGNORED_WARNINGS} "./source/main.cpp" -o ./build/ted

