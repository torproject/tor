
## Memory management

### Heap-allocation functions

Tor imposes a few light wrappers over C's native malloc and free
functions, to improve convenience, and to allow wholescale replacement
of malloc and free as needed.

You should never use 'malloc', 'calloc', 'realloc, or 'free' on their
own; always use the variants prefixed with 'tor_'.
They are the same as the standard C functions, with the following
exceptions:

   * tor_free(NULL) is a no-op.
   * tor_free() is a macro that takes an lvalue as an argument and sets it to
     NULL after freeing it.  To avoid this behavior, you can use tor_free_()
     instead.
   * tor_malloc() and friends fail with an assertion if they are asked to
     allocate a value so large that it is probably an underflow.
   * It is always safe to tor_malloc(0), regardless of whether your libc
     allows it.
   * tor_malloc(), tor_realloc(), and friends are never allowed to fail.
     Instead, Tor will die with an assertion.  This means that you never
     need to check their return values.  See the next subsection for
     information on why we think this is a good idea.

We define additional general-purpose memory allocation functions as well:

   * tor_malloc_zero(x) behaves as calloc(1, x), except the it makes clear
     the intent to allocate a single zeroed-out value.
   * tor_reallocarray(x,y) behaves as the OpenBSD reallocarray function.
     Use it for cases when you need to realloc() in a multiplication-safe
     way.

And specific-purpose functions as well:

   * tor_strdup() and tor_strndup() behaves as the underlying libc functions,
     but use tor_malloc() instead of the underlying function.
   * tor_memdup() copies a chunk of memory of a given size.
   * tor_memdup_nulterm() copies a chunk of memory of a given size, then
     NUL-terminates it just to be safe.

#### Why assert on failure?

Why don't we allow tor_malloc() and its allies to return NULL?

First, it's error-prone.  Many programmers forget to check for NULL return
values, and testing for malloc() failures is a major pain.

Second, it's not necessarily a great way to handle OOM conditions. It's
probably better (we think) to have a memory target where we dynamically free
things ahead of time in order to stay under the target.  Trying to respond to
an OOM at the point of tor_malloc() failure, on the other hand, would involve
a rare operation invoked from deep in the call stack.  (Again, that's
error-prone and hard to debug.)

Third, thanks to the rise of Linux and other operating systems that allow
memory to be overcommitted, you can't actually ever rely on getting a NULL
from malloc() when you're out of memory; instead you have to use an approach
closer to tracking the total memory usage.

#### Conventions for your own allocation functions.

Whenever you create a new type, the convention is to give it a pair of
x_new() and x_free() functions, named after the type.

Calling x_free(NULL) should always be a no-op.


### Grow-only memory allocation: memarea.c

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

To create a new memarea, use memarea_new().  To drop all the storage from a
memarea, and invalidate its pointers, use memarea_drop_all().

The allocation functions memarea_alloc(), memarea_alloc_zero(),
memarea_memdup(), memarea_strdup(), and memarea_strndup() are analogous to
the similarly-named malloc() functions.  There is intentionally no
memarea_free() or memarea_realloc().


