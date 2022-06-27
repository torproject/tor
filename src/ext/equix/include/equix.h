/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#ifndef EQUIX_H
#define EQUIX_H

#include <stdint.h>
#include <stddef.h>

/*
 * The solver will return at most this many solutions.
 */
#define EQUIX_MAX_SOLS 8

/*
 * The number of indices.
 */
#define EQUIX_NUM_IDX 8

/*
 * 16-bit index.
 */
typedef uint16_t equix_idx;

/*
 *  The solution.
 */
typedef struct equix_solution {
    equix_idx idx[EQUIX_NUM_IDX];
} equix_solution;

/*
 * Solution verification results
 */
typedef enum equix_result {
    EQUIX_OK,               /* Solution is valid */
    EQUIX_CHALLENGE,        /* The challenge is invalid (the internal hash
                               function doesn't pass validation). */
    EQUIX_ORDER,            /* Indices are not in the correct order. */
    EQUIX_PARTIAL_SUM,      /* The partial sums of the hash values don't
                               have the required number of trailing zeroes. */
    EQUIX_FINAL_SUM         /* The hash values don't sum to zero. */
} equix_result;

/*
 * Opaque struct that holds the Equi-X context
 */
typedef struct equix_ctx equix_ctx;

/*
 * Flags for context creation
*/
typedef enum equix_ctx_flags {
    EQUIX_CTX_VERIFY = 0,       /* Context for verification */
    EQUIX_CTX_SOLVE = 1,        /* Context for solving */
    EQUIX_CTX_COMPILE = 2,      /* Compile internal hash function */
    EQUIX_CTX_HUGEPAGES = 4,    /* Allocate solver memory using HugePages */
} equix_ctx_flags;

/* Sentinel value used to indicate unsupported type */
#define EQUIX_NOTSUPP ((equix_ctx*)-1)

#if defined(_WIN32) || defined(__CYGWIN__)
#define EQUIX_WIN
#endif

/* Shared/static library definitions */
#ifdef EQUIX_WIN
    #ifdef EQUIX_SHARED
        #define EQUIX_API __declspec(dllexport)
    #elif !defined(EQUIX_STATIC)
        #define EQUIX_API __declspec(dllimport)
    #else
        #define EQUIX_API
    #endif
    #define EQUIX_PRIVATE
#else
    #ifdef EQUIX_SHARED
        #define EQUIX_API __attribute__ ((visibility ("default")))
    #else
        #define EQUIX_API __attribute__ ((visibility ("hidden")))
    #endif
    #define EQUIX_PRIVATE __attribute__ ((visibility ("hidden")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Allocate an Equi-X context.
 *
 * @param flags is the type of context to be created
 *
 * @return pointer to a newly created context. Returns NULL on memory
 *         allocation failure and EQUIX_NOTSUPP if the requested type
 *         is not supported.
 */
EQUIX_API equix_ctx* equix_alloc(equix_ctx_flags flags);

/*
* Free an Equi-X a context.
*
* @param ctx is a pointer to the context
*/
EQUIX_API void equix_free(equix_ctx* ctx);

/*
 * Find Equi-X solutions for the given challenge.
 *
 * @param ctx             pointer to an Equi-X context
 * @param challenge       pointer to the challenge data
 * @param challenge_size  size of the challenge
 * @param output          pointer to the output array where solutions will be
 *                        stored
 *
 * @return the number of solutions found
 */
EQUIX_API int equix_solve(
    equix_ctx* ctx,
    const void* challenge,
    size_t challenge_size,
    equix_solution output[EQUIX_MAX_SOLS]);

/*
 * Verify an Equi-X solution.
 *
 * @param ctx             pointer to an Equi-X context
 * @param challenge       pointer to the challenge data
 * @param challenge_size  size of the challenge
 * @param solution        pointer to the solution to be verified
 *
 * @return verification result
*/
EQUIX_API equix_result equix_verify(
    equix_ctx* ctx,
    const void* challenge,
    size_t challenge_size,
    const equix_solution* solution);

#ifdef __cplusplus
}
#endif

#endif
