@dir /lib/memarea
@brief lib/memarea: A fast arena-style allocator.

This module has a fast "arena" style allocator, where memory is freed all at
once.  This kind of allocation is very fast and avoids fragmentation, at the
expense of requiring all the data to be freed at the same time.  We use this
for parsing and diff calculations.

It's often handy to allocate a large number of tiny objects, all of which
need to disappear at the same time.  You can do this in tor using the
memarea.c abstraction, which uses a set of grow-only buffers for allocation,
and only supports a single "free" operation at the end.

Using memareas also helps you avoid memory fragmentation.  You see, some libc
malloc implementations perform badly on the case where a large number of
small temporary objects are allocated at the same time as a few long-lived
objects of similar size.  But if you use tor_malloc() for the long-lived ones
and a memarea for the temporary object, the malloc implementation is likelier
to do better.

To create a new memarea, use `memarea_new()`.  To drop all the storage from a
memarea, and invalidate its pointers, use `memarea_drop_all()`.

The allocation functions `memarea_alloc()`, `memarea_alloc_zero()`,
`memarea_memdup()`, `memarea_strdup()`, and `memarea_strndup()` are analogous
to the similarly-named malloc() functions.  There is intentionally no
`memarea_free()` or `memarea_realloc()`.

