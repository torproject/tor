/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

/*
 * HashX is an algorithm designed for client puzzles and proof-of-work schemes.
 * While traditional cryptographic hash functions use a fixed one-way
 * compression function, each HashX instance represents a unique pseudorandomly
 * generated one-way function.
 *
 * Example of usage:
 *
    #include <hashx.h>
    #include <stdio.h>

    int main() {
        char seed[] = "this is a seed that will generate a hash function";
        char hash[HASHX_SIZE];
        hashx_ctx* ctx = hashx_alloc(HASHX_COMPILED);
        if (ctx == HASHX_NOTSUPP)
            ctx = hashx_alloc(HASHX_INTERPRETED);
        if (ctx == NULL)
            return 1;
        if (!hashx_make(ctx, seed, sizeof(seed)))
            return 1;
        hashx_exec(ctx, 123456789, hash);
        hashx_free(ctx);
        for (unsigned i = 0; i < HASHX_SIZE; ++i)
            printf("%02x", hash[i] & 0xff);
        printf("\n");
        return 0;
    }
 *
 */

#ifndef HASHX_H
#define HASHX_H

#include <stdint.h>
#include <stddef.h>

/*
 * Input of the hash function.
 *
 * Counter mode (default): a 64-bit unsigned integer
 * Block mode: pointer to a buffer and the number of bytes to be hashed
*/
#ifndef HASHX_BLOCK_MODE
#define HASHX_INPUT uint64_t input
#else
#define HASHX_INPUT const void* input, size_t size
#endif

/* The default (and maximum) hash size is 32 bytes */
#ifndef HASHX_SIZE
#define HASHX_SIZE 32
#endif

/* Opaque struct representing a HashX instance */
typedef struct hashx_ctx hashx_ctx;

/* Type of hash function */
typedef enum hashx_type {
    HASHX_INTERPRETED,
    HASHX_COMPILED
} hashx_type;

/* Sentinel value used to indicate unsupported type */
#define HASHX_NOTSUPP ((hashx_ctx*)-1)

#if defined(_WIN32) || defined(__CYGWIN__)
#define HASHX_WIN
#endif

/* Shared/static library definitions */
#ifdef HASHX_WIN
    #ifdef HASHX_SHARED
        #define HASHX_API __declspec(dllexport)
    #elif !defined(HASHX_STATIC)
        #define HASHX_API __declspec(dllimport)
    #else
        #define HASHX_API
    #endif
    #define HASHX_PRIVATE
#else
    #ifdef HASHX_SHARED
        #define HASHX_API __attribute__ ((visibility ("default")))
    #else
        #define HASHX_API __attribute__ ((visibility ("hidden")))
    #endif
    #define HASHX_PRIVATE __attribute__ ((visibility ("hidden")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Allocate a HashX instance.
 *
 * @param type is the type of instance to be created.
 *
 * @return pointer to a new HashX instance. Returns NULL on memory allocation 
 *         failure and HASHX_NOTSUPP if the requested type is not supported.
*/
HASHX_API hashx_ctx* hashx_alloc(hashx_type type);

/*
 * Create a new HashX function from seed.
 *
 * @param ctx is pointer to a HashX instance.
 * @param seed is a pointer to the seed value.
 * @param size is the size of the seed.
 *
 * @return 1 on success, 0 on failure.                                         
*/
HASHX_API int hashx_make(hashx_ctx* ctx, const void* seed, size_t size);

/*
 * Execute the HashX function.
 *
 * @param ctx is pointer to a HashX instance. A HashX function must have
 *        been previously created by calling hashx_make.
 * @param HASHX_INPUT is the input to be hashed (see definition above).
 * @param output is a pointer to the result buffer. HASHX_SIZE bytes will be
 *        written.
 s*/
HASHX_API void hashx_exec(const hashx_ctx* ctx, HASHX_INPUT, void* output);

/*
 * Free a HashX instance.
 *
 * @param ctx is pointer to a HashX instance.
*/
HASHX_API void hashx_free(hashx_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif
