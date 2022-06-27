/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <equix.h>
#include <hashx.h>
#include "context.h"
#include "solver.h"
#include <hashx_endian.h>

static bool verify_order(const equix_solution* solution) {
	return
		tree_cmp4(&solution->idx[0], &solution->idx[4]) &
		tree_cmp2(&solution->idx[0], &solution->idx[2]) &
		tree_cmp2(&solution->idx[4], &solution->idx[6]) &
		tree_cmp1(&solution->idx[0], &solution->idx[1]) &
		tree_cmp1(&solution->idx[2], &solution->idx[3]) &
		tree_cmp1(&solution->idx[4], &solution->idx[5]) &
		tree_cmp1(&solution->idx[6], &solution->idx[7]);
}

static uint64_t sum_pair(hashx_ctx* hash_func, equix_idx left, equix_idx right) {
	uint8_t hash_left[HASHX_SIZE];
	uint8_t hash_right[HASHX_SIZE];
	hashx_exec(hash_func, left, hash_left);
	hashx_exec(hash_func, right, hash_right);
	return load64(hash_left) + load64(hash_right);
}

static equix_result verify_internal(hashx_ctx* hash_func, const equix_solution* solution) {
	uint64_t pair0 = sum_pair(hash_func, solution->idx[0], solution->idx[1]);
	if (pair0 & EQUIX_STAGE1_MASK) {
		return EQUIX_PARTIAL_SUM;
	}
	uint64_t pair1 = sum_pair(hash_func, solution->idx[2], solution->idx[3]);
	if (pair1 & EQUIX_STAGE1_MASK) {
		return EQUIX_PARTIAL_SUM;
	}
	uint64_t pair4 = pair0 + pair1;
	if (pair4 & EQUIX_STAGE2_MASK) {
		return EQUIX_PARTIAL_SUM;
	}
	uint64_t pair2 = sum_pair(hash_func, solution->idx[4], solution->idx[5]);
	if (pair2 & EQUIX_STAGE1_MASK) {
		return EQUIX_PARTIAL_SUM;
	}
	uint64_t pair3 = sum_pair(hash_func, solution->idx[6], solution->idx[7]);
	if (pair3 & EQUIX_STAGE1_MASK) {
		return EQUIX_PARTIAL_SUM;
	}
	uint64_t pair5 = pair2 + pair3;
	if (pair5 & EQUIX_STAGE2_MASK) {
		return EQUIX_PARTIAL_SUM;
	}
	uint64_t pair6 = pair4 + pair5;
	if (pair6 & EQUIX_FULL_MASK) {
		return EQUIX_FINAL_SUM;
	}
	return EQUIX_OK;
}

int equix_solve(
	equix_ctx* ctx,
	const void* challenge,
	size_t challenge_size,
	equix_solution output[EQUIX_MAX_SOLS])
{
	if ((ctx->flags & EQUIX_CTX_SOLVE) == 0) {
		return 0;
	}

	if (!hashx_make(ctx->hash_func, challenge, challenge_size)) {
		return 0;
	}

	return equix_solver_solve(ctx->hash_func, ctx->heap, output);
}


equix_result equix_verify(
	equix_ctx* ctx,
	const void* challenge,
	size_t challenge_size,
	const equix_solution* solution)
{
	if (!verify_order(solution)) {
		return EQUIX_ORDER;
	}
	if (!hashx_make(ctx->hash_func, challenge, challenge_size)) {
		return EQUIX_CHALLENGE;
	}
	return verify_internal(ctx->hash_func, solution);
}
