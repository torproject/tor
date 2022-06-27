# DoS protection for onion services: from RandomX to Equi-X

In early May 2020, I was contacted by two Tor developers to help them with their denial-of-service (DoS) mitigation proposal. Onion services have been plagued by DoS for many years and there are no easy solutions due to the anonymous nature of the Tor network. The vulnerability stems from the fact that the service has to perform a series of expensive operations for each connecting client, so an attacker can simply flood the service with connection requests, which are comparatively cheap to make.

## Proof of work

One of the strategies that can be used against such attacks are client puzzles, which require the client to prove that they performed certain amount of computational work before the request is accepted. This is not a new idea – using a client puzzle to combat email spam was first proposed in 1997 [[1](https://cypherpunks.venona.com/date/1997/03/msg00774.html)] and there have been proposals to add a client puzzle to the TLS protocol that we all use every day to browse the web [[2](https://tools.ietf.org/html/draft-nygren-tls-client-puzzles-02)].

The goal of the current Tor proposal [[3](https://lists.torproject.org/pipermail/tor-dev/2020-April/014215.html)] is to integrate some kind of client puzzle as part of the protocol used to connect to onion services. The client would download the hidden service descriptor, find that the service is protected by a client puzzle, calculate the solution and send it as part of the connection request. The service would give the request a priority value based on the "difficulty" of the puzzle solution.

The main issue is to find a suitable puzzle. There are three main requirements that the algorithm must meet:

1. The solution proof must be smaller than about 200 bytes.
2. Solution verification must be fast.
3. GPUs and FPGAs should not provide a large advantage for solving the puzzle.

The first requirement is due to the limited space in the message that the client sends to the hidden service to negotiate a connection. This doesn't pose a big problem in practice.

The second requirement is needed to prevent the client puzzle from becoming a DoS vector on its own. The service must be able to quickly verify if a proof provided by a client is valid or not, otherwise the attacker could just flood the service with invalid proofs.

The third requirement is the most important one. Users of the Tor browser are equipped with an ordinary general-purpose CPU and an attacker must not be able to use similarly priced hardware that offers a much higher performance for solving the puzzle – otherwise it would be easy for an attacker to simulate many legitimate clients connecting to the service.

It should be noted that the puzzle does not need to be resistant to speed-up by specialized fixed-function hardware (ASIC). This is called "ASIC resistance" and there are two main reasons why it's not strictly required in this case:

1. The cost to produce a specialized chip for a given algorithm exceeds USD $1 million for the 28 nm process [[4](https://www.electronicdesign.com/technologies/embedded-revolution/article/21808278/the-economics-of-asics-at-what-point-does-a-custom-soc-become-viable)]. This is in contrast with the current state when bringing down an onion service requires very little resources [[5](https://www.reddit.com/r/darknet/comments/b3qvbq/this_ddos_is_massive_its_gotta_be_multiple/ej1jwzc/)].
2. If an ASIC for the client puzzle is developed, the algorithm can be quickly changed with a simple patch, rendering the attacker's investment useless. This is in contrast with cryptocurrencies, which have complex consensus protocols and can take months or years to change their proof of work algorithm [[6](https://ethereum-magicians.org/t/eip-progpow-a-programmatic-proof-of-work/272)].

Therefore the client puzzle algorithm must be CPU-friendly and minimize the advantage of programmable hardware such as GPUs and FPGAs.

## RandomX

In 2019, we developed a new CPU-friendly proof of work algorithm called RandomX to be used by Monero [[7](https://web.getmonero.org/resources/moneropedia/randomx.html)]. It has been audited and field tested, which makes it a good candidate to be considered for a Tor client puzzle.

However, during the development of RandomX, we focused mainly on the "CPU-friendliness" of the algorithm to minimize the advantage of specialized hardware. Other aspects such as verification performance and memory requirements were secondary and only had upper limits. The result is that RandomX has quite high solution verification demands – over 2 GiB of memory and around 2 milliseconds to verify a hash. Alternatively, it is possible to use only 256 MiB of memory, but then verification takes around 15 ms. This is way too slow to be used as a client puzzle.

So I began slimming down RandomX to make it less demanding for verification. I halved the memory requirements and reduced the number of rounds from 8 to 2, which is the minimum that can be considered safe from optimizations. The result is RandomX-Tor [[8](https://github.com/tevador/RandomX/tree/tor-pow)], which takes around 0.5 ms to verify with slightly over 1 GiB of memory. GPUs perform very poorly when running RandomX-Tor – similar to full RandomX.

However, I see two main problems with RandomX-Tor:

1. 2000 verifications per second still may not be fast enough to prevent flooding attacks on the service, especially since each connection request to an onion service requires very little network bandwidth (512 bytes).
1. The 1 GB memory requirement is too high. Onion services would have to allocate over 2 GB just to verify puzzles because two different puzzles may be active at a given moment to allow for network synchronization delays.

So I decided to continue my quest and look for a better puzzle.

## Alternatives

I briefly tested Argon2 [[9](https://github.com/p-h-c/phc-winner-argon2)] and Yespower [[10](https://www.openwall.com/yespower/)], which are password hashing algorithms claiming to be "GPU-resistant". However, both have slower verification performance than RandomX-Tor and both run faster on GPUs, so they are not suitable. See Appendix for details.

Then I researched Equihash, which is an asymmetric client puzzle offering very fast solution verification [[11](https://eprint.iacr.org/2015/946.pdf)]. The main problem with Equihash is that GPUs perform up to 100x faster than CPUs, so it is unusable as a puzzle for CPU-based clients.

## HashX

I was ready to give up when I remembered SuperscalarHash, which is a part of RandomX that's used only to initialize the DAG [[12](https://github.com/tevador/RandomX/blob/master/doc/specs.md#6-superscalarhash)]. It could be considered a lightweight version of RandomX with only integer operations and no memory accesses. I began refactoring the code with the goal of creating a fast GPU-resistant hash function. The main idea is that each instance of the hash function would use a completely different randomly generated sequence of instructions. I managed to optimized the SuperscalarHash generator and reduce the time to generate a random program from 250 μs to 50 μs, which could mean up to 20000 verifications per second – ten times faster than RandomX-Tor.

I named the new algorithm "HashX" and in the course of the next week, I made several other changes compared to the old SuperscalarHash:

* improved code generator that can fully saturate the simulated 3-way superscalar pipeline
* removed reciprocal multiplication, which was sometimes causing front-end stalls
* implemented a more optimized JIT compiler for x86-64
* added input-dependent branches to further hinder GPU performance

I also made a few tweaks to the hash finalizer to pass SMHasher [[13](https://github.com/rurban/smhasher)]. The result is a CPU-friendly algorithm suitable to be used as a partial hash inversion client puzzle.

## Equi-X

I still felt a bit uneasy about HashX using no memory. This means that logic-only FPGAs could be a viable option to run HashX. Additionally, introducing the right amount of memory-hardness could affect GPUs more than CPUs. I remembered Equihash, which is a memory-hard algorithm, but still allows for fast solution verification. I could simply replace the Blake2b hash in the default implementation with HashX. Each solution attempt would then use a different randomly generated HashX instance.

Equihash has two main parameters that determine the difficulty of the generalized birthday problem: `n` is the hash size in bits and <code>2<sup>k</sup></code> is the number of hashes that need to XOR to zero. The memory hardness is proportional to <code>2<sup>n/(k+1)</sup></code>. To get fast verification and a small proof size, `k` should be as low as possible. I chose `k=3`, which means the goal would be to find preimages to 8 hashes that XOR to zero.

I first tried with `n=96`, which would require about 2 GB of memory for an efficient solver. However, the problem is that each HashX instance would be used for <code>2<sup>25</sup></code> hashes, which could make it feasible for GPUs to compile an optimized kernel for each new solution attempt. Additionally, GPUs are much better at the sorting phase of Equihash than CPUs due to their higher memory bandwidth.

After some more benchmarking, I estimated that <code>2<sup>16</sup></code> hashes per solution attempt would be the sweet spot for CPUs because one solution attempt would take roughly 6-8 ms, the HashX compilation overhead would still be under 1% and the expected memory usage would be under 2 MiB. This can fit entirely into the CPU cache, which is the only case when CPUs can compete with GPUs in memory bandwidth. The optimal Equihash parameters are then `n=60` and `k=3`. I call this algorithm "Equi-X" (portmanteau of **Equi**hash and Hash**X**). The exact memory requirements for Equi-X are 1.81 MiB with negligible solution discarding. It could be reduced to a minimum of 1 MiB with perfect bit packing and around 25% of discarded solutions, although this is viable only for custom hardware.

However, when testing Equi-X, I discovered a fatal flaw: the generalized birthday problem, as used by Equihash, requires a collision resistant hash function. While HashX is preimage-resistant, it is not collision resistant. Some small fraction of HashX instances produce a significant number of hash collisions. With a 2<sup>k</sup>-XOR, finding 2<sup>k-1</sup> pairs of colliding hashes automatically produces a valid solution because equal values XOR to zero. But it gets worse. If the number of colliding hashes is higher than 2<sup>k</sup>, the number of valid solutions grows exponentially. For example, with `k=3` and 100 colliding hashes, it is possible to produce more than 180 billion valid solutions! Finding such a multicollision takes only a few minutes for HashX.

Some modifications of HashX reduced the number of collisions, but I could not completely eliminate them, so I needed another solution. I began researching the generalized birthday problem and I found this paragraph in the seminal paper by David Wagner [[14](https://people.eecs.berkeley.edu/~daw/papers/genbday.html)]:

![genbday](https://i.imgur.com/I7TAfTQ.png)

The advantage of 2<sup>k</sup>-SUM compared to 2<sup>k</sup>-XOR is that identical hashes no longer produce valid solutions (except for `0x000000000000000` and `0x800000000000000`, but these are very rare). There are two additional advantages:

1. While XOR and addition have the same performance in CPUs, XOR is much faster in custom hardware. This means, for example, that an FPGA-based solver will have to use slightly more resources to calculate the modular additions.
1. With 2<sup>k</sup>-SUM, we can eliminate checking for duplicate indices, which simplifies both the solver and the verifier [[15](https://github.com/tevador/equix/issues/1)].

With this modification, an Equi-X solution for nonce `X` is a set of eight 16-bit indices <code>i<sub>0</sub>, ..., i<sub>7</sub></code> such that:

<code>H<sub>X</sub>(i<sub>0</sub>) + H<sub>X</sub>(i<sub>1</sub>) + H<sub>X</sub>(i<sub>2</sub>) + H<sub>X</sub>(i<sub>3</sub>) + H<sub>X</sub>(i<sub>4</sub>) + H<sub>X</sub>(i<sub>5</sub>) + H<sub>X</sub>(i<sub>6</sub>) + H<sub>X</sub>(i<sub>7</sub>) = 0 (mod 2<sup>60</sup>)</code>

where <code>H<sub>X</sub></code> is a HashX function generated for nonce `X`.

Example of a solution:

```
H(0x6c31) = 0xcfa5375c0a7f5d7 \
                              (+) = 0xa73d9777f110000 \
H(0x8803) = 0xd798601be690a29 /                        |
                                                      (+) = 0xefdaadb00000000 \
H(0x80c2) = 0xcabd8974bbee8d5 \                        |                       |
                              (+) = 0x489d16380ef0000 /                        |
H(0xa1db) = 0x7ddf8cc3530172b /                                                |
                                                                              (+) = 0
H(0x6592) = 0x348a96fd685dcba \                                                |
                              (+) = 0x357120e8ffb8000 \                        |
H(0x76b7) = 0x00e689eb975a346 /                        |                       |
                                                      (+) = 0x102552500000000 /
H(0x74a6) = 0xacccc4ad2d06bcd \                        |
                              (+) = 0xdab431670048000 /
H(0xe259) = 0x2de76cb9d341433 /
```

The following table compares Equi-X with the most common variants of Equihash:

|Algorithm |n  |k  |memory|solution size|verification <sup>1</sup>|CPU perf. <sup>2</sup>|GPU perf. <sup>3</sup>|
|----------|---|---|-------|-------------|------------|-----------|----------|
|**Equi-X**|60 |3  |1.8 MiB|16 bytes     |~50 μs      |2400 Sol/s|     ?    |
|Zcash     |200|9  |144 MiB|1344 bytes   |>150 μs     |30 Sol/s  |~400 Sol/s <sup>4</sup>|
|BTG       |144|5  |2.5 GiB|100 bytes    |~10 μs      |1 Sol/s   |~45 Sol/s <sup>5</sup>|

1. Using AMD Ryzen 1700 with 1 thread.
1. Using AMD Ryzen 1700 with 16 threads.
1. Using NVIDIA GTX 1660 Ti.
1. Estimated from http://www.zcashbenchmarks.info/ (GTX 1070)
1. Estimated from https://miniz.ch/features/

## References

[1] https://cypherpunks.venona.com/date/1997/03/msg00774.html

[2] https://tools.ietf.org/html/draft-nygren-tls-client-puzzles-02

[3] https://lists.torproject.org/pipermail/tor-dev/2020-April/014215.html

[4] https://www.electronicdesign.com/technologies/embedded-revolution/article/21808278/the-economics-of-asics-at-what-point-does-a-custom-soc-become-viable

[5] https://www.reddit.com/r/darknet/comments/b3qvbq/this_ddos_is_massive_its_gotta_be_multiple/ej1jwzc/

[6] https://ethereum-magicians.org/t/eip-progpow-a-programmatic-proof-of-work/272

[7] https://web.getmonero.org/resources/moneropedia/randomx.html

[8] https://github.com/tevador/RandomX/tree/tor-pow

[9] https://github.com/p-h-c/phc-winner-argon2

[10] https://www.openwall.com/yespower/

[11] https://eprint.iacr.org/2015/946.pdf

[12] https://github.com/tevador/RandomX/blob/master/doc/specs.md#6-superscalarhash

[13] https://github.com/rurban/smhasher

[14] https://people.eecs.berkeley.edu/~daw/papers/genbday.html

[15] https://github.com/tevador/equix/issues/1

## Appendix: Comparison of GPU-resistant client puzzles

|Algorithm|GPU speed <sup>6</sup>|Solver memory|Verifier memory|Verif./sec. <sup>11</sup>|Solution size <sup>12</sup>|
|------------|---------|-------------|---------------|---------------|-------------|
|**Equi-X** <sup>1</sup>|<50% <sup>7</sup>|1.81 MiB|< 20 KiB|19600| 32 bytes|
|**HashX** <sup>2</sup>|<50% <sup>7</sup>|< 20 KiB|< 20 KiB|19700|16 bytes|
|RandomX-Tor <sup>3</sup>|10% <sup>8</sup>|  1041 MiB|1041 MiB|2200|16 bytes|
|Argon2 <sup>4</sup>|~300% <sup>9</sup>|2.00 MiB|2.00 MiB|1020|16 bytes|
|Yespower <sup>5</sup>|~200% <sup>10</sup>|2.00 MiB|2.00 MiB|780|16 bytes|

1. https://github.com/tevador/equix
1. https://github.com/tevador/hashx
1. https://github.com/tevador/RandomX/tree/tor-pow
1. https://github.com/p-h-c/phc-winner-argon2
1. https://www.openwall.com/yespower/
1. Performance of NVIDIA GTX 1660 Ti compared to AMD Ryzen 1700
1. No GPU implementation exists; upper bound based on RandomX performance
1. Benchmarked using https://github.com/SChernykh/RandomX_CUDA
1. Estimated from https://github.com/WebDollar/argon2-gpu
1. Estimated from https://nlpool.nl/bench?algo=yescrypt
1. Benchmarked on AMD Ryzen 1700 @ 3.3 GHz using 1 thread
1. Including a 16-byte nonce.
