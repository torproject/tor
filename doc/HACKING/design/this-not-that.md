
Don't use memcmp.  Use {tor,fast}_{memeq,memneq,memcmp}.

Don't use assert.  Use tor_assert or tor_assert_nonfatal or BUG.  Prefer
nonfatal assertions or BUG()s.

Don't use sprintf or snprintf.  Use tor_asprintf or tor_snprintf.

Don't write hand-written binary parsers.  Use trunnel.

Don't use malloc, realloc, calloc, free, strdup, etc. Use tor_malloc,
tor_realloc, tor_calloc, tor_free, tor_strdup, etc.

Don't use tor_realloc(x, y\*z). Use tor_reallocarray(x, y, z);

Don't say "if (x) foo_free(x)".  Just foo_free(x) and make sure that
foo_free(NULL) is a no-op.

Don't use toupper or tolower; use TOR_TOUPPER and TOR_TOLOWER.

Don't use isalpha, isalnum, etc.  Instead use TOR_ISALPHA, TOR_ISALNUM, etc.

Don't use strcat, strcpy, strncat, or strncpy. Use strlcat and strlcpy
instead.

Don't use tor_asprintf then smartlist_add; use smartlist_add_asprintf.

Don't use any of these functions: they aren't portable. Use the
version prefixed with `tor_` instead: strtok_r, memmem, memstr,
asprintf, localtime_r, gmtime_r, inet_aton, inet_ntop, inet_pton,
getpass, ntohll, htonll, strdup,   (This list is incomplete.)

Don't create or close sockets directly. Instead use the wrappers in
compat.h.

When creating new APIs, only use 'char \*' to represent 'pointer to a
nul-terminated string'.  Represent 'pointer to a chunk of memory' as
'uint8_t \*'.  (Many older Tor APIs ignore this rule.)

Don't encode/decode u32, u64, or u16 to byte arrays by casting
pointers. That can crash if the pointers aren't aligned, and can cause
endianness problems.  Instead say something more like set_uint32(ptr,
htonl(foo)) to encode, and ntohl(get_uint32(ptr)) to decode.

Don't declare a 0-argument function with "void foo()".  That's C++
syntax. In C you say "void foo(void)".

When creating new APIs, use const everywhere you reasonably can.

Sockets should have type tor_socket_t, not int.

