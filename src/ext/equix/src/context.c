/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#include <stdlib.h>
#include <equix.h>
#include <virtual_memory.h>
#include "context.h"
#include "solver_heap.h"

equix_ctx* equix_alloc(equix_ctx_flags flags) {
	equix_ctx* ctx_failure = NULL;
	equix_ctx* ctx = malloc(sizeof(equix_ctx));
	if (ctx == NULL) {
		goto failure;
	}
	ctx->flags = flags & EQUIX_CTX_COMPILE;
	ctx->hash_func = hashx_alloc(flags & EQUIX_CTX_COMPILE ?
		HASHX_COMPILED : HASHX_INTERPRETED);
	if (ctx->hash_func == NULL) {
		goto failure;
	}
	if (ctx->hash_func == HASHX_NOTSUPP) {
		ctx_failure = EQUIX_NOTSUPP;
		goto failure;
	}
	if (flags & EQUIX_CTX_SOLVE) {
		if (flags & EQUIX_CTX_HUGEPAGES) {
			ctx->heap = hashx_vm_alloc_huge(sizeof(solver_heap));
		}
		else {
			ctx->heap = malloc(sizeof(solver_heap));
		}
		if (ctx->heap == NULL) {
			goto failure;
		}
	}
	ctx->flags = flags;
	return ctx;
failure:
	equix_free(ctx);
	return ctx_failure;
}

void equix_free(equix_ctx* ctx) {
	if (ctx != NULL && ctx != EQUIX_NOTSUPP) {
		if (ctx->flags & EQUIX_CTX_SOLVE) {
			if (ctx->flags & EQUIX_CTX_HUGEPAGES) {
				hashx_vm_free(ctx->heap, sizeof(solver_heap));
			}
			else {
				free(ctx->heap);
			}
		}
		hashx_free(ctx->hash_func);
		free(ctx);
	}
}
