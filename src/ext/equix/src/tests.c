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
static equix_solutions_buffer output;
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
	ctx = equix_alloc(EQUIX_CTX_SOLVE | EQUIX_CTX_TRY_COMPILE);
	assert(ctx != NULL);
	return true;
}

static bool test_free() {
	equix_free(ctx);
	return true;
}

static bool test_solve() {
	output.count = 0;
	for (nonce = 0; output.count == 0 && nonce < 20; ++nonce) {
		equix_result result = equix_solve(ctx, &nonce, sizeof(nonce), &output);
		assert(result == EQUIX_OK);
	}
	--nonce;
	assert(output.count > 0);
	assert(output.flags == EQUIX_SOLVER_DID_USE_COMPILER || output.flags == 0);
	printf("(using %s HashX) ",
		(EQUIX_SOLVER_DID_USE_COMPILER & output.flags)
		? "compiled" : "interpreted");
	return true;
}

static bool test_verify1() {
	equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &output.sols[0]);
	assert(result == EQUIX_OK);
	return true;
}

static bool test_verify2() {
	SWAP_IDX(output.sols[0].idx[0], output.sols[0].idx[1]);
	equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &output.sols[0]);
	assert(result == EQUIX_FAIL_ORDER);
	return true;
}

static bool test_verify3() {
	SWAP_IDX(output.sols[0].idx[0], output.sols[0].idx[4]);
	SWAP_IDX(output.sols[0].idx[1], output.sols[0].idx[5]);
	SWAP_IDX(output.sols[0].idx[2], output.sols[0].idx[6]);
	SWAP_IDX(output.sols[0].idx[3], output.sols[0].idx[7]);
	equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &output.sols[0]);
	assert(result == EQUIX_FAIL_ORDER);
	SWAP_IDX(output.sols[0].idx[0], output.sols[0].idx[4]);
	SWAP_IDX(output.sols[0].idx[1], output.sols[0].idx[5]);
	SWAP_IDX(output.sols[0].idx[2], output.sols[0].idx[6]);
	SWAP_IDX(output.sols[0].idx[3], output.sols[0].idx[7]);
	return true;
}

static bool test_verify4() {
	SWAP_IDX(output.sols[0].idx[1], output.sols[0].idx[2]);
	equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &output.sols[0]);
	assert(result == EQUIX_FAIL_PARTIAL_SUM);
	SWAP_IDX(output.sols[0].idx[1], output.sols[0].idx[2]);
	return true;
}

static void permute_idx(int start) {
	if (start == EQUIX_NUM_IDX - 1) {
		equix_result result = equix_verify(ctx, &nonce, sizeof(nonce), &output.sols[0]);
		valid_count += result == EQUIX_OK;
	}
	else {
		for (int i = start; i < EQUIX_NUM_IDX; ++i)	{
			SWAP_IDX(output.sols[0].idx[start], output.sols[0].idx[i]);
			permute_idx(start + 1);
			SWAP_IDX(output.sols[0].idx[start], output.sols[0].idx[i]);
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
