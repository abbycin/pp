cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(code LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CURRENT_SOURCE_DIR ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_compile_options(-fpie)
string(TOLOWER "${CMAKE_BUILD_TYPE}" cmake_build_type)
if (NOT (${cmake_build_type} OR ${cmake_build_type} STREQUAL release))
    set(ASAN_OPTIONS
        -fsanitize=address
        -fsanitize=pointer-compare
        -fsanitize=pointer-subtract
        -fsanitize=leak
        -fsanitize=undefined
        -fsanitize-recover=all
        -fcf-protection=full
        -fstack-protector-all
        )
    add_compile_options(${ASAN_OPTIONS})
    add_link_options(${ASAN_OPTIONS})
endif()

add_compile_options(-Wall -Wextra -Wunused)
add_link_options(-pie)

add_executable(initiator initiator.c pool.h hdr.h pool.c)
target_link_libraries(initiator ibverbs rdmacm)

add_executable(target target.c pool.h hdr.h pool.c)
target_link_libraries(target ibverbs rdmacm)
