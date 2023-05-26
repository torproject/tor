/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include "test_utils.h"

typedef bool test_func();

static int test_no = 0;

static hashx_ctx* ctx_int = NULL;
static hashx_ctx* ctx_cmp = NULL;
static hashx_ctx* ctx_auto = NULL;

static const char seed1[] = "This is a test";
static const char seed2[] = "Lorem ipsum dolor sit amet";

static const uint64_t counter1 = 0;
static const uint64_t counter2 = 123456;
static const uint64_t counter3 = 987654321123456789;

#ifdef HASHX_BLOCK_MODE
static const unsigned char long_input[] = {
	0x0b, 0x0b, 0x98, 0xbe, 0xa7, 0xe8, 0x05, 0xe0, 0x01, 0x0a, 0x21, 0x26,
	0xd2, 0x87, 0xa2, 0xa0, 0xcc, 0x83, 0x3d, 0x31, 0x2c, 0xb7, 0x86, 0x38,
	0x5a, 0x7c, 0x2f, 0x9d, 0xe6, 0x9d, 0x25, 0x53, 0x7f, 0x58, 0x4a, 0x9b,
	0xc9, 0x97, 0x7b, 0x00, 0x00, 0x00, 0x00, 0x66, 0x6f, 0xd8, 0x75, 0x3b,
	0xf6, 0x1a, 0x86, 0x31, 0xf1, 0x29, 0x84, 0xe3, 0xfd, 0x44, 0xf4, 0x01,
	0x4e, 0xca, 0x62, 0x92, 0x76, 0x81, 0x7b, 0x56, 0xf3, 0x2e, 0x9b, 0x68,
	0xbd, 0x82, 0xf4, 0x16
};
#endif

#define RUN_TEST(x) run_test(#x, &x)

static void run_test(const char* name, test_func* func) {
	printf("[%2i] %-40s ... ", ++test_no, name);
	printf(func() ? "PASSED\n" : "SKIPPED\n");
}

static bool test_alloc() {
	ctx_int = hashx_alloc(HASHX_TYPE_INTERPRETED);
	assert(ctx_int != NULL);
	return true;
}

static bool test_free() {
	hashx_free(ctx_int);
	hashx_free(ctx_cmp);
	hashx_free(ctx_auto);
	return true;
}

static bool test_make1() {
	hashx_result result = hashx_make(ctx_int, seed1, sizeof(seed1));
	assert(result == HASHX_OK);
	return true;
}

static bool test_hash_ctr1() {
#ifdef HASHX_SALT
	return false;
#endif
#ifndef HASHX_BLOCK_MODE
	char hash[HASHX_SIZE];
	hashx_result result = hashx_exec(ctx_int, counter2, hash);
	assert(result == HASHX_OK);
	/* printf("\n");
	output_hex(hash, HASHX_SIZE);
	printf("\n"); */
	assert(equals_hex(hash, "aebdd50aa67c93afb82a4c534603b65e46decd584c55161c526ebc099415ccf1"));
	return true;
#else
	return false;
#endif
}

static bool test_hash_ctr2() {
#ifdef HASHX_SALT
	return false;
#endif
#ifndef HASHX_BLOCK_MODE
	char hash[HASHX_SIZE];
	hashx_result result = hashx_exec(ctx_int, counter1, hash);
	assert(result == HASHX_OK);
	assert(equals_hex(hash, "2b2f54567dcbea98fdb5d5e5ce9a65983c4a4e35ab1464b1efb61e83b7074bb2"));
	return true;
#else
	return false;
#endif
}

static bool test_make2() {
	hashx_result result = hashx_make(ctx_int, seed2, sizeof(seed2));
	assert(result == HASHX_OK);
	return true;
}

static bool test_hash_ctr3() {
#ifdef HASHX_SALT
	return false;
#endif
#ifndef HASHX_BLOCK_MODE
	char hash[HASHX_SIZE];
	hashx_result result = hashx_exec(ctx_int, counter2, hash);
	assert(result == HASHX_OK);
	assert(equals_hex(hash, "ab3d155bf4bbb0aa3a71b7801089826186e44300e6932e6ffd287cf302bbb0ba"));
	return true;
#else
	return false;
#endif
}

static bool test_hash_ctr4() {
#ifdef HASHX_SALT
	return false;
#endif
#ifndef HASHX_BLOCK_MODE
	char hash[HASHX_SIZE];
	hashx_result result = hashx_exec(ctx_int, counter3, hash);
	assert(result == HASHX_OK);
	assert(equals_hex(hash, "8dfef0497c323274a60d1d93292b68d9a0496379ba407b4341cf868a14d30113"));
	return true;
#else
	return false;
#endif
}

static bool test_hash_block1() {
#ifdef HASHX_SALT
	return false;
#endif
#ifndef HASHX_BLOCK_MODE
	return false;
#else
	char hash[HASHX_SIZE];
	hashx_result result = hashx_exec(ctx_int, long_input, sizeof(long_input), hash);
	assert(result == HASHX_OK);
	assert(equals_hex(hash, "d0b232b832459501ca1ac9dc0429fd931414ead7624a457e375a43ea3e5e737a"));
	return true;
#endif
}

static bool test_alloc_compiler() {
	ctx_cmp = hashx_alloc(HASHX_TYPE_COMPILED);
	assert(ctx_cmp != NULL);
	return true;
}

static bool test_make3() {
	hashx_result result = hashx_make(ctx_cmp, seed2, sizeof(seed2));
	if (result == HASHX_FAIL_COMPILE) {
		return false;
	}
	assert(result == HASHX_OK);
	return true;
}

static bool test_compiler_ctr1() {
#ifndef HASHX_BLOCK_MODE
	hashx_result result;
	char hash1[HASHX_SIZE];
	char hash2[HASHX_SIZE];
	result = hashx_exec(ctx_int, counter2, hash1);
	assert(result == HASHX_OK);
	result = hashx_exec(ctx_cmp, counter2, hash2);
	if (result == HASHX_FAIL_UNPREPARED) {
		return false;
	}
	assert(result == HASHX_OK);
	assert(hashes_equal(hash1, hash2));
	return true;
#else
	return false;
#endif
}

static bool test_compiler_ctr2() {
#ifndef HASHX_BLOCK_MODE
	hashx_result result;
	char hash1[HASHX_SIZE];
	char hash2[HASHX_SIZE];
	result = hashx_exec(ctx_int, counter1, hash1);
	assert(result == HASHX_OK);
	result = hashx_exec(ctx_cmp, counter1, hash2);
	if (result == HASHX_FAIL_UNPREPARED) {
		return false;
	}
	assert(result == HASHX_OK);
	assert(hashes_equal(hash1, hash2));
	return true;
#else
	return false;
#endif
}

static bool test_compiler_block1() {
#ifndef HASHX_BLOCK_MODE
	return false;
#else
	hashx_result result;
	char hash1[HASHX_SIZE];
	char hash2[HASHX_SIZE];
	result = hashx_exec(ctx_int, long_input, sizeof(long_input), hash1);
	assert(result == HASHX_OK);
	result = hashx_exec(ctx_cmp, long_input, sizeof(long_input), hash2);
	if (result == HASHX_FAIL_UNPREPARED) {
		return false;
	}
	assert(result == HASHX_OK);
	assert(hashes_equal(hash1, hash2));
	return true;
#endif
}

static bool test_alloc_automatic() {
	ctx_auto = hashx_alloc(HASHX_TRY_COMPILE);
	assert(ctx_auto != NULL);
	return true;
}

static bool test_auto_fallback() {
	hashx_result result = hashx_make(ctx_auto, seed2, sizeof(seed2));
	assert(result == HASHX_OK);
	hashx_type actual_type = (hashx_type)-1;
	result = hashx_query_type(ctx_auto, &actual_type);
	assert(result == HASHX_OK);
	assert(actual_type == HASHX_TYPE_INTERPRETED ||
	       actual_type == HASHX_TYPE_COMPILED);
	return actual_type == HASHX_TYPE_INTERPRETED;
}

static bool test_bad_seeds() {
#ifdef HASHX_SALT
	return false;
#else
	hashx_result result;
	result = hashx_make(ctx_auto, "\xf8\x05\x00\x00", 4);
	assert(result == HASHX_OK);
	result = hashx_make(ctx_auto, "\xf9\x05\x00\x00", 4);
	assert(result == HASHX_FAIL_SEED);
	result = hashx_make(ctx_auto, "\x5d\x93\x02\x00", 4);
	assert(result == HASHX_FAIL_SEED);
	result = hashx_make(ctx_auto, "\x5e\x93\x02\x00", 4);
	assert(result == HASHX_OK);
	return true;
#endif
}

int main() {
	RUN_TEST(test_alloc);
	RUN_TEST(test_make1);
	RUN_TEST(test_hash_ctr1);
	RUN_TEST(test_hash_ctr2);
	RUN_TEST(test_make2);
	RUN_TEST(test_hash_ctr3);
	RUN_TEST(test_hash_ctr4);
	RUN_TEST(test_alloc_compiler);
	RUN_TEST(test_make3);
	RUN_TEST(test_compiler_ctr1);
	RUN_TEST(test_compiler_ctr2);
	RUN_TEST(test_hash_block1);
	RUN_TEST(test_compiler_block1);
	RUN_TEST(test_alloc_automatic);
	RUN_TEST(test_auto_fallback);
	RUN_TEST(test_bad_seeds);
	RUN_TEST(test_free);

	printf("\nAll tests were successful\n");
	return 0;
}
