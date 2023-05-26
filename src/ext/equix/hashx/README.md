# HashX

HashX is an algorithm designed for client puzzles and proof-of-work schemes.
While traditional cryptographic hash functions use a fixed one-way compression
function, each HashX instance represents a unique pseudorandomly generated
one-way function.

HashX functions are generated as a carefully crafted sequence of integer
operations to fully saturate a 3-way superscalar CPU pipeline (modeled after
the Intel Ivy Bridge architecture). Extra care is taken to avoid optimizations
and to ensure that each function takes exactly the same number of CPU cycles
(currently 512 instructions over 192 cycles).

## API

The API consists of 5 functions and is documented in the public header file
[hashx.h](include/hashx.h).

Example of usage:

```c
#include <hashx.h>
#include <stdio.h>

int main() {
    char seed[] = "this is a seed that will generate a hash function";
    char hash[HASHX_SIZE];
    hashx_type func_type;
    hashx_ctx* ctx = hashx_alloc(HASHX_TRY_COMPILE);
    if (ctx == NULL)
        return 1;
    /* generate a hash function */
    if (hashx_make(ctx, seed, sizeof(seed)) != HASHX_OK)
        return 1;
    if (hashx_query_type(ctx, &func_type) == HASHX_OK && func_type == HASHX_TYPE_COMPILED)
        printf("Using the compiled implementation of HashX\n");
    hashx_exec(ctx, 123456789, hash); /* calculate the hash of a nonce value */
    hashx_free(ctx);
    for (unsigned i = 0; i < HASHX_SIZE; ++i)
        printf("%02x", hash[i] & 0xff);
    printf("\n");
    return 0;
}
```

## Build

A C99-compatible compiler and `cmake` are required.

```
git clone https://github.com/tevador/hashx.git
cd hashx
mkdir build
cd build
cmake .. [-DHASHX_BLOCK_MODE=ON] [-DHASHX_SIZE=<1-32>] [-DHASHX_SALT="my custom hash"]
make
```

### Block mode (default: off)

Because HashX is meant to be used in proof-of-work schemes and client puzzles,
the input is a 64-bit counter value. If you need to hash arbitrary data, build
with `-DHASHX_BLOCK_MODE=ON`. This will change the API to accept `const void*, size_t` instead of `uint64_t`.
However, it is strongly recommended to use the counter mode, which is almost twice faster for short inputs.

### Hash size (default: 32)

The default hash output size is 32 bytes (256 bits). If you want to reduce the output
size, build with, for example, `-DHASHX_SIZE=20`. Output sizes in the range of 1-32 bytes
are supported. Shorter output sizes are formed by simply truncating the full 256-bit hash.

### Generator salt (default: "HashX v1")

An implementation-specific salt value may be specified when building, for example: `-DHASHX_SALT="my custom hash"`.
This value is used as a salt when generating hash instances. The maximum supported
salt size is 15 characters.

## Performance

HashX was designed for fast verification. Generating a hash function from seed
takes about 50 μs and a 64-bit nonce can be hashed in under 100 ns (in compiled
mode) or in about 1-2 μs (in interpreted mode).

A benchmark executable is included:
```
./hashx-bench --seeds 500
```

## Error fallback

The compiled implementation of HashX is much faster (very roughly 20x) so it
should be used whenever possible. It may be necessary to use the interpreter
for multiple reasons: either the platform is not supported at compile time,
or various runtime policies disallow the memory protection changes that are
necessary to do just-in-time compilation. Failures may be detected late, so
the library provides a built-in mechanism to fall back from the compiled
implementation to interpreted quickly without duplicating the whole context.

The `hashx_query_type()` function is optional, provided for users of the
`HASHX_TRY_COMPILE` context who need to know which implementation was
ultimately used.

The actual hash function, `hashx_exec()`, returns an error code for
completeness in reporting programming errors, but if a caller has invoked
`hashx_make()` successfully it can be considered infallible.

It is always possible for `hashx_make()` to fail. In addition to the
OS-specific failures you may see when forcing HashX to use the compiled
implementation with `hashx_alloc(HASHX_TYPE_COMPILED)`, it's always possible
for `hashx_make` to fail unpredictably for a particular seed value. These
seeds should be discarded and a new one attempted by the caller when
`hashx_make` returns `HASHX_FAIL_SEED`.

## Security

HashX should provide strong preimage resistance. No other security guarantees are made. About
 99% of HashX instances pass [SMHasher](https://github.com/tevador/smhasher),
 but using HashX as a generic hash function is not recommended.

Known vulnerabilities that should not affect intended use cases:

1. HashX is not collision resistant. Around 0.2% of seeds produce "weak" hash functions for
which hash collisions are plentiful.
2. Secret values should not be used as inputs to HashX because the generated instructions
include data-dependent branches by design.

## Protocols based on HashX

Here are two examples of how HashX can be used in practice:

### Interactive client puzzle

Client puzzles are protocols designed to protect server resources from abuse.
A client requesting a resource from a server may be asked to solve a puzzle
before the request is accepted.

One of the first proposed client puzzles is [Hashcash](https://en.wikipedia.org/wiki/Hashcash),
which requires the client to find a partial SHA-1 hash inversion. However,
because of the static nature of cryptographic hash functions, an attacker can
offload hashing to a GPU or FPGA to gain a significant advantage over legitimate
clients equipped only with a CPU.

In a HashX-based interactive client puzzle, the server sends each client
a 256-bit challenge used to generate a unique HashX function. The client then
has to find a 64-bit nonce value such that the resulting hash has a predefined
number of leading zeroes. An attacker cannot easily parallelize the workload
because each request would require a new GPU kernel or FPGA bistream.

### Non-interactive proof-of-work

In the absence of a central authority handing out challenges (for example in
a cryptocurrency), the client takes some public information `T` (for example
a block template) and combines it with a chosen 64-bit nonce `N1`.
The resulting string `X = T||N1` is then used to generate a HashX function
<code>H<sub>X</sub></code>. The client then tries to find a 16-bit nonce `N2`
such that <code>r = H<sub>X</sub>(N2)</code> meets the difficulty target of
the protocol. If no `N2` value is successful, the client increments `N1` and
tries with a different hash function.

In this protocol, each HashX function provides only 65536 attempts before it
must be discarded. This limits the parallelization advantage of GPUs and FPGAs.
A CPU core will be able to test about 200 different hash functions per second.
