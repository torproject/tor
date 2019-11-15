@dir /lib/container
@brief lib/container: Hash tables, dynamic arrays, bit arrays, etc.

### Smartlists: Neither lists, nor especially smart.

For historical reasons, we call our dynamic-allocated array type
`smartlist_t`.  It can grow or shrink as elements are added and removed.

All smartlists hold an array of `void *`.  Whenever you expose a smartlist
in an API you *must* document which types its pointers actually hold.

<!-- It would be neat to fix that, wouldn't it? -NM  -->

Smartlists are created empty with `smartlist_new()` and freed with
`smartlist_free()`.  See the `containers.h` header documentation for more
information; there are many convenience functions for commonly needed
operations.

For low-level operations on smartlists, see also
\refdir{lib/smartlist_core}.

<!-- TODO: WRITE more about what you can do with smartlists. -->

### Digest maps, string maps, and more.

Tor makes frequent use of maps from 160-bit digests, 256-bit digests,
or nul-terminated strings to `void *`. These types are `digestmap_t`,
`digest256map_t`, and `strmap_t` respectively.  See the containers.h
module documentation for more information.

### Intrusive lists and hashtables

For performance-sensitive cases, we sometimes want to use "intrusive"
collections: ones where the bookkeeping pointers are stuck inside the
structures that belong to the collection.  If you've used the
BSD-style sys/queue.h macros, you'll be familiar with these.

Unfortunately, the `sys/queue.h` macros vary significantly between the
platforms that have them, so we provide our own variants in
`ext/tor_queue.h`.

We also provide an intrusive hashtable implementation in `ext/ht.h`.
When you're using it, you'll need to define your own hash
functions. If attacker-induced collisions are a worry here, use the
cryptographic siphash24g function to extract hashes.

<!-- TODO: WRITE about bloom filters, namemaps, bit-arrays, order functions.
-->

