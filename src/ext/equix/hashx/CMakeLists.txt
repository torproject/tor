# Copyright (c) 2020 tevador <tevador@gmail.com>
# See LICENSE for licensing information

cmake_minimum_required(VERSION 2.8.8)

set(HASHX_VERSION 1)
set(HASHX_VERSION_MINOR 0)
set(HASHX_VERSION_PATCH 0)
set(HASHX_VERSION_STR "${HASHX_VERSION}.${HASHX_VERSION_MINOR}.${HASHX_VERSION_PATCH}")

project(hashx)

set(hashx_sources
src/blake2.c
src/compiler.c
src/compiler_a64.c
src/compiler_x86.c
src/context.c
src/hashx.c
src/program.c
src/program_exec.c
src/siphash.c
src/siphash_rng.c
src/virtual_memory.c)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
  message(STATUS "Setting default build type: ${CMAKE_BUILD_TYPE}")
endif()

option(HASHX_BLOCK_MODE "Hash function for block mode" OFF)

if(HASHX_BLOCK_MODE)
  add_definitions(-DHASHX_BLOCK_MODE)
endif()

set(HASHX_SIZE CACHE STRING "Hash function output size in bytes")

if(HASHX_SIZE)
  if(HASHX_SIZE GREATER 32)
    message(SEND_ERROR "The maximum hash size is 32 bytes")
  else()
    add_definitions(-DHASHX_SIZE=${HASHX_SIZE})
  endif()
endif()

set(HASHX_SALT CACHE STRING "Implementation-specific salt value")

if(HASHX_SALT)
  string(LENGTH ${HASHX_SALT} HASHX_SALT_LENGTH)
  if(HASHX_SALT_LENGTH GREATER 15)
    message(SEND_ERROR "The maximum salt length is 15 characters")
  else()
    add_definitions(-DHASHX_SALT=${HASHX_SALT})
  endif()
endif()

include_directories(include/)

add_library(hashx SHARED ${hashx_sources})
set_property(TARGET hashx PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET hashx PROPERTY PUBLIC_HEADER include/hashx.h)
target_compile_definitions(hashx PRIVATE HASHX_SHARED)
set_target_properties(hashx PROPERTIES VERSION ${HASHX_VERSION_STR}
                                       SOVERSION ${HASHX_VERSION})

add_library(hashx_static STATIC ${hashx_sources})
set_property(TARGET hashx_static PROPERTY POSITION_INDEPENDENT_CODE ON)
set_target_properties(hashx_static PROPERTIES OUTPUT_NAME hashx)

include(GNUInstallDirs)
install(TARGETS hashx hashx_static
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

add_executable(hashx-tests
  src/tests.c)
target_compile_definitions(hashx-tests PRIVATE HASHX_STATIC)
target_link_libraries(hashx-tests
  PRIVATE hashx_static)

if(NOT Threads_FOUND AND UNIX AND NOT APPLE)
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads)
endif()

add_executable(hashx-bench
  src/bench.c
  src/hashx_thread.c
  src/hashx_time.c)
target_compile_definitions(hashx-bench PRIVATE HASHX_STATIC)
target_link_libraries(hashx-bench
  PRIVATE hashx_static
  PRIVATE ${CMAKE_THREAD_LIBS_INIT})
