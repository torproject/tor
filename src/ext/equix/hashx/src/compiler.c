/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#include <stdbool.h>

#include "compiler.h"
#include "virtual_memory.h"
#include "program.h"
#include "context.h"

bool hashx_compiler_init(hashx_ctx* ctx) {
	ctx->code = hashx_vm_alloc(COMP_CODE_SIZE);
	return ctx->code != NULL;
}

void hashx_compiler_destroy(hashx_ctx* ctx) {
	hashx_vm_free(ctx->code, COMP_CODE_SIZE);
}
