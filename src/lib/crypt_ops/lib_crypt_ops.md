@dir /lib/crypt_ops
@brief lib/crypt_ops: Cryptographic operations.

This module contains wrappers around the cryptographic libraries that we
support, and implementations for some higher-level cryptographic
constructions that we use.

It wraps our two major cryptographic backends (OpenSSL or NSS, as configured
by the user), and also wraps other cryptographic code in src/ext.

Generally speaking, Tor code shouldn't be calling OpenSSL or NSS
(or any other crypto library) directly.  Instead, we should indirect through
one of the functions in this directory, or through \refdir{lib/tls}.

Cryptography functionality that's available is described below.

### RNG facilities ###

The most basic RNG capability in Tor is the crypto_rand() family of
functions. These currently use OpenSSL's RAND_() backend, but may use
something faster in the future.

In addition to crypto_rand(), which fills in a buffer with random
bytes, we also have functions to produce random integers in certain
ranges; to produce random hostnames; to produce random doubles, etc.

When you're creating a long-term cryptographic secret, you might want
to use crypto_strongest_rand() instead of crypto_rand().  It takes the
operating system's entropy source and combines it with output from
crypto_rand().  This is a pure paranoia measure, but it might help us
someday.

You can use smartlist_choose() to pick a random element from a smartlist
and smartlist_shuffle() to randomize the order of a smartlist.  Both are
potentially a bit slow.

### Cryptographic digests and related functions ###

We treat digests as separate types based on the length of their
outputs.  We support one 160-bit digest (SHA1), two 256-bit digests
(SHA256 and SHA3-256), and two 512-bit digests (SHA512 and SHA3-512).

You should not use SHA1 for anything new.

The crypto_digest\*() family of functions manipulates digests.  You
can either compute a digest of a chunk of memory all at once using
crypto_digest(), crypto_digest256(), or crypto_digest512().  Or you
can create a crypto_digest_t object with
crypto_digest{,256,512}_new(), feed information to it in chunks using
crypto_digest_add_bytes(), and then extract the final digest using
crypto_digest_get_digest().  You can copy the state of one of these
objects using crypto_digest_dup() or crypto_digest_assign().

We support the HMAC hash-based message authentication code
instantiated using SHA256. See crypto_hmac_sha256.  (You should not
add any HMAC users with SHA1, and HMAC is not necessary with SHA3.)

We also support the SHA3 cousins, SHAKE128 and SHAKE256.  Unlike
digests, these are extendable output functions (or XOFs) where you can
get any amount of output.  Use the crypto_xof_\*() functions to access
these.

We have several ways to derive keys from cryptographically strong secret
inputs (like diffie-hellman outputs). The old
crypto_expand_key_material_TAP() performs an ad-hoc KDF based on SHA1 -- you
shouldn't use it for implementing anything but old versions of the Tor
protocol.  You can use HKDF-SHA256 (as defined in RFC5869) for more modern
protocols.  Also consider SHAKE256.

If your input is potentially weak, like a password or passphrase, use a salt
along with the secret_to_key() functions as defined in crypto_s2k.c.  Prefer
scrypt over other hashing methods when possible.  If you're using a password
to encrypt something, see the "boxed file storage" section below.

Finally, in order to store objects in hash tables, Tor includes the
randomized SipHash 2-4 function.  Call it via the siphash24g() function in
src/ext/siphash.h whenever you're creating a hashtable whose keys may be
manipulated by an attacker in order to DoS you with collisions.


### Stream ciphers ###

You can create instances of a stream cipher using crypto_cipher_new().
These are stateful objects of type crypto_cipher_t.  Note that these
objects only support AES-128 right now; a future version should add
support for AES-128 and/or ChaCha20.

You can encrypt/decrypt with crypto_cipher_encrypt or
crypto_cipher_decrypt. The crypto_cipher_crypt_inplace function performs
an encryption without a copy.

Note that sensible people should not use raw stream ciphers; they should
probably be using some kind of AEAD. Sorry.

### Public key functionality ###

We support four public key algorithms: DH1024, RSA, Curve25519, and
Ed25519.

We support DH1024 over two prime groups.  You access these via the
crypto_dh_\*() family of functions.

We support RSA in many bit sizes for signing and encryption.  You access
it via the crypto_pk_*() family of functions.  Note that a crypto_pk_t
may or may not include a private key.  See the crypto_pk_* functions in
crypto.c for a full list of functions here.

For Curve25519 functionality, see the functions and types in
crypto_curve25519.c. Curve25519 is generally suitable for when you need
a secure fast elliptic-curve diffie hellman implementation. When
designing new protocols, prefer it over DH in Z_p.

For Ed25519 functionality, see the functions and types in
crypto_ed25519.c. Ed25519 is a generally suitable as a secure fast
elliptic curve signature method. For new protocols, prefer it over RSA
signatures.

### Metaformats for storage ###

When OpenSSL manages the storage of some object, we use whatever format
OpenSSL provides -- typically, some kind of PEM-wrapped base 64 encoding
that starts with "----- BEGIN CRYPTOGRAPHIC OBJECT ----".

When we manage the storage of some cryptographic object, we prefix the
object with 32-byte NUL-padded prefix in order to avoid accidental
object confusion; see the crypto_read_tagged_contents_from_file() and
crypto_write_tagged_contents_to_file() functions for manipulating
these. The prefix is "== type: tag ==", where type describes the object
and its encoding, and tag indicates which one it is.

### Boxed-file storage ###

When managing keys, you frequently want to have some way to write a
secret object to disk, encrypted with a passphrase.  The crypto_pwbox
and crypto_unpwbox functions do so in a way that's likely to be
readable by future versions of Tor.

