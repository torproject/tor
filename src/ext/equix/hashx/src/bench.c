/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#include "test_utils.h"
#include "hashx_thread.h"
#include "hashx_endian.h"
#include "hashx_time.h"
#include <assert.h>
#include <limits.h>
#include <inttypes.h>

typedef struct worker_job {
	int id;
	hashx_thread thread;
	hashx_ctx* ctx;
	int64_t total_hashes;
	uint64_t best_hash;
	uint64_t threshold;
	int start;
	int step;
	int end;
	int nonces;
} worker_job;

static hashx_thread_retval worker(void* args) {
	worker_job* job = (worker_job*)args;
	job->total_hashes = 0;
	job->best_hash = UINT64_MAX;
	for (int seed = job->start; seed < job->end; seed += job->step) {
		{
			hashx_result result = hashx_make(job->ctx, &seed, sizeof(seed));
			if (result == HASHX_FAIL_SEED) {
				continue;
			}
			if (result == HASHX_FAIL_COMPILE) {
				printf("Error: not supported. Try with --interpret\n");
			}
			assert(result == HASHX_OK);
			if (result != HASHX_OK)
				break;
		}
		for (int nonce = 0; nonce < job->nonces; ++nonce) {
			uint8_t hash[HASHX_SIZE] = { 0 };
			{
#ifndef HASHX_BLOCK_MODE
				hashx_result result = hashx_exec(job->ctx, nonce, hash);
#else
				hashx_result result = hashx_exec(job->ctx,
					&nonce, sizeof(nonce), hash);
#endif
				assert(result == HASHX_OK);
				if (result != HASHX_OK)
					break;
			}
			uint64_t hashval = load64(hash);
			if (hashval < job->best_hash) {
				job->best_hash = hashval;
			}
			if (hashval < job->threshold) {
				printf("[thread %2i] Hash (%5i, %5i) below threshold:"
					" ...%02x%02x%02x%02x%02x%02x%02x%02x\n",
					job->id,
					seed,
					nonce,
					hash[0],
					hash[1],
					hash[2],
					hash[3],
					hash[4],
					hash[5],
					hash[6],
					hash[7]);
			}
		}
		job->total_hashes += job->nonces;
	}
	return HASHX_THREAD_SUCCESS;
}

int main(int argc, char** argv) {
	int nonces, seeds, start, diff, threads;
	bool interpret;
	read_int_option("--diff", argc, argv, &diff, INT_MAX);
	read_int_option("--start", argc, argv, &start, 0);
	read_int_option("--seeds", argc, argv, &seeds, 500);
	read_int_option("--nonces", argc, argv, &nonces, 65536);
	read_int_option("--threads", argc, argv, &threads, 1);
	read_option("--interpret", argc, argv, &interpret);
	hashx_type ctx_type = HASHX_TYPE_INTERPRETED;
	if (!interpret) {
		ctx_type = HASHX_TYPE_COMPILED;
	}
	uint64_t best_hash = UINT64_MAX;
	uint64_t diff_ex = (uint64_t)diff * 1000ULL;
	uint64_t threshold = UINT64_MAX / diff_ex;
	int seeds_end = seeds + start;
	int64_t total_hashes = 0;
	printf("Interpret: %i, Target diff.: %" PRIu64 ", Threads: %i\n", interpret, diff_ex, threads);
	printf("Testing seeds %i-%i with %i nonces each ...\n", start, seeds_end - 1, nonces);
	double time_start, time_end;
	worker_job* jobs = malloc(sizeof(worker_job) * threads);
	if (jobs == NULL) {
		printf("Error: memory allocation failure\n");
		return 1;
	}
	for (int thd = 0; thd < threads; ++thd) {
		jobs[thd].ctx = hashx_alloc(ctx_type);
		if (jobs[thd].ctx == NULL) {
			printf("Error: memory allocation failure\n");
			return 1;
		}
		jobs[thd].id = thd;
		jobs[thd].start = start + thd;
		jobs[thd].step = threads;
		jobs[thd].end = seeds_end;
		jobs[thd].nonces = nonces;
		jobs[thd].threshold = threshold;
	}
	time_start = hashx_time();
	if (threads > 1) {
		for (int thd = 0; thd < threads; ++thd) {
			jobs[thd].thread = hashx_thread_create(&worker, &jobs[thd]);
		}
		for (int thd = 0; thd < threads; ++thd) {
			hashx_thread_join(jobs[thd].thread);
		}
	}
	else {
		worker(jobs);
	}
	time_end = hashx_time();
	for (int thd = 0; thd < threads; ++thd) {
		total_hashes += jobs[thd].total_hashes;
		if (jobs[thd].best_hash < best_hash) {
			best_hash = jobs[thd].best_hash;
		}
	}
	double elapsed = time_end - time_start;
	printf("Total hashes: %" PRIi64 "\n", total_hashes);
	printf("%f hashes/sec.\n", total_hashes / elapsed);
	printf("%f seeds/sec.\n", seeds / elapsed);
	printf("Best hash: ...");
	output_hex((char*)&best_hash, sizeof(best_hash));
	printf(" (diff: %" PRIu64 ")\n", UINT64_MAX / best_hash);
	free(jobs);
	return 0;
}
