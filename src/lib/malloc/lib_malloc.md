@dir /lib/malloc
@brief lib/malloc: Wrappers and utilities for memory management.


Tor imposes a few light wrappers over C's native malloc and free
functions, to improve convenience, and to allow wholescale replacement
of malloc and free as needed.

You should never use 'malloc', 'calloc', 'realloc, or 'free' on their
own; always use the variants prefixed with 'tor_'.
They are the same as the standard C functions, with the following
exceptions:

   * `tor_free(NULL)` is a no-op.
   * `tor_free()` is a macro that takes an lvalue as an argument and sets it to
     NULL after freeing it.  To avoid this behavior, you can use `tor_free_()`
     instead.
   * tor_malloc() and friends fail with an assertion if they are asked to
     allocate a value so large that it is probably an underflow.
   * It is always safe to `tor_malloc(0)`, regardless of whether your libc
     allows it.
   * `tor_malloc()`, `tor_realloc()`, and friends are never allowed to fail.
     Instead, Tor will die with an assertion.  This means that you never
     need to check their return values.  See the next subsection for
     information on why we think this is a good idea.

We define additional general-purpose memory allocation functions as well:

   * `tor_malloc_zero(x)` behaves as `calloc(1, x)`, except the it makes clear
     the intent to allocate a single zeroed-out value.
   * `tor_reallocarray(x,y)` behaves as the OpenBSD reallocarray function.
     Use it for cases when you need to realloc() in a multiplication-safe
     way.

And specific-purpose functions as well:

   * `tor_strdup()` and `tor_strndup()` behaves as the underlying libc
     functions, but use `tor_malloc()` instead of the underlying function.
   * `tor_memdup()` copies a chunk of memory of a given size.
   * `tor_memdup_nulterm()` copies a chunk of memory of a given size, then
     NUL-terminates it just to be safe.

#### Why assert on allocation failure?

Why don't we allow `tor_malloc()` and its allies to return NULL?

First, it's error-prone.  Many programmers forget to check for NULL return
values, and testing for `malloc()` failures is a major pain.

Second, it's not necessarily a great way to handle OOM conditions. It's
probably better (we think) to have a memory target where we dynamically free
things ahead of time in order to stay under the target.  Trying to respond to
an OOM at the point of `tor_malloc()` failure, on the other hand, would involve
a rare operation invoked from deep in the call stack.  (Again, that's
error-prone and hard to debug.)

Third, thanks to the rise of Linux and other operating systems that allow
memory to be overcommitted, you can't actually ever rely on getting a NULL
from `malloc()` when you're out of memory; instead you have to use an approach
closer to tracking the total memory usage.

#### Conventions for your own allocation functions.

Whenever you create a new type, the convention is to give it a pair of
`x_new()` and `x_free_()` functions, named after the type.

Calling `x_free(NULL)` should always be a no-op.

There should additionally be an `x_free()` macro, defined in terms of
`x_free_()`.  This macro should set its lvalue to NULL.  You can define it
using the FREE_AND_NULL macro, as follows:

```
#define x_free(ptr) FREE_AND_NULL(x_t, x_free_, (ptr))
```

