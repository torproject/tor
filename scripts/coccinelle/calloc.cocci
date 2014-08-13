// Use calloc or realloc as appropriate instead of multiply-and-alloc

@malloc_to_calloc@
expression a,b;
@@
- tor_malloc(a * b)
+ tor_calloc(a, b)

@malloc_zero_to_calloc@
expression a, b;
@@
- tor_malloc_zero(a * b)
+ tor_calloc(a, b)

@realloc_to_reallocarray@
expression a, b;
expression p;
@@
- tor_realloc(p, a * b)
+ tor_reallocarray(p, a, b)
