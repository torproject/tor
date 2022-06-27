/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#ifndef COMPILER_H
#define COMPILER_H

#include <stdint.h>
#include <stdbool.h>
#include <hashx.h>
#include "virtual_memory.h"
#include "program.h"

HASHX_PRIVATE void hashx_compile_x86(const hashx_program* program, uint8_t* code);

HASHX_PRIVATE void hashx_compile_a64(const hashx_program* program, uint8_t* code);

#if defined(_M_X64) || defined(__x86_64__)
#define HASHX_COMPILER 1
#define HASHX_COMPILER_X86
#define hashx_compile hashx_compile_x86
#elif defined(__aarch64__)
#define HASHX_COMPILER 1
#define HASHX_COMPILER_A64
#define hashx_compile hashx_compile_a64
#else
#define HASHX_COMPILER 0
#define hashx_compile
#endif

HASHX_PRIVATE bool hashx_compiler_init(hashx_ctx* compiler);
HASHX_PRIVATE void hashx_compiler_destroy(hashx_ctx* compiler);

#define COMP_PAGE_SIZE 4096
#define COMP_RESERVE_SIZE 1024
#define COMP_AVG_INSTR_SIZE 5
#define COMP_CODE_SIZE                                                        \
	ALIGN_SIZE(                                                               \
		HASHX_PROGRAM_MAX_SIZE * COMP_AVG_INSTR_SIZE + COMP_RESERVE_SIZE,     \
	COMP_PAGE_SIZE)

#endif
