/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <equix.h>
#include <stdbool.h>
#include <stdio.h>

typedef bool test_func();

static equix_ctx* ctx = NULL;
static equix_solution solution[EQUIX_MAX_SOLS];
static int nonce;
static int valid_count = 0;
static int test_no = 0;

#define SWAP_IDX(a, b)      \
    do {                    \
        equix_idx temp = a; \
        a = b;              \
        b = temp;           \
    } while(0)

static bool test_alloc() {
	ctx = equix_alloc(EQUIX_CTX_SOLVE);
	assert(ctx != NULL && ctx != EQUIX_NOTSUPP);
	return true;
}

static bool test_free() {
	equix_free(ctx);
	return true;
}

static bool test_solve() {
	int num_solutions = 0;
	for (nonce = 0; num_solutions == 0 && nonce < 20; ++nonce) {
		num_solutions = equix_solve(ctx, &nonce, sizeof(nonce), solution);
	}
	--nonce;
	assert(num_solutions > 0);
	return true;
}

static bool test_verify1() {
	equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &solution[0]);
	assert(result == EQUIX_OK);
	return true;
}

static bool test_verify2() {
	SWAP_IDX(solution[0].idx[0], solution[0].idx[1]);
	equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &solution[0]);
	assert(result == EQUIX_ORDER);
	return true;
}

static bool test_verify3() {
	SWAP_IDX(solution[0].idx[0], solution[0].idx[4]);
	SWAP_IDX(solution[0].idx[1], solution[0].idx[5]);
	SWAP_IDX(solution[0].idx[2], solution[0].idx[6]);
	SWAP_IDX(solution[0].idx[3], solution[0].idx[7]);
	equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &solution[0]);
	assert(result == EQUIX_ORDER);
	SWAP_IDX(solution[0].idx[0], solution[0].idx[4]);
	SWAP_IDX(solution[0].idx[1], solution[0].idx[5]);
	SWAP_IDX(solution[0].idx[2], solution[0].idx[6]);
	SWAP_IDX(solution[0].idx[3], solution[0].idx[7]);
	return true;
}

static bool test_verify4() {
	SWAP_IDX(solution[0].idx[1], solution[0].idx[2]);
	equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &solution[0]);
	assert(result == EQUIX_PARTIAL_SUM);
	SWAP_IDX(solution[0].idx[1], solution[0].idx[2]);
	return true;
}

static void permute_idx(int start) {
	if (start == EQUIX_NUM_IDX - 1) {
		equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &solution[0]);
		valid_count += result == EQUIX_OK;
	}
	else {
		for (int i = start; i < EQUIX_NUM_IDX; ++i)	{
			SWAP_IDX(solution[0].idx[start], solution[0].idx[i]);
			permute_idx(start + 1);
			SWAP_IDX(solution[0].idx[start], solution[0].idx[i]);
		}
	}
}

static bool test_permutations() {
    permute_idx(0);
    assert(valid_count == 1); /* check that only one of the 40320 possible
                                 permutations of indices is a valid solution */
    return true;
}

#define RUN_TEST(x) run_test(#x, &x)

static void run_test(const char* name, test_func* func) {
	printf("[%2i] %-40s ... ", ++test_no, name);
	printf(func() ? "PASSED\n" : "SKIPPED\n");
}

int main() {
	RUN_TEST(test_alloc);
	RUN_TEST(test_solve);
	RUN_TEST(test_verify1);
	RUN_TEST(test_verify2);
	RUN_TEST(test_verify3);
	RUN_TEST(test_verify4);
	RUN_TEST(test_permutations);
	RUN_TEST(test_free);

	printf("\nAll tests were successful\n");
	return 0;
}
