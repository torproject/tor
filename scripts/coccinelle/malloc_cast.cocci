@cast_malloc@
expression e;
type T;
@@
- (T *)tor_malloc(e)
+ tor_malloc(e)

@cast_malloc_zero@
expression e;
type T;
identifier func;
@@
- (T *)tor_malloc_zero(e)
+ tor_malloc_zero(e)

@cast_calloc@
expression a, b;
type T;
identifier func;
@@
- (T *)tor_calloc(a, b)
+ tor_calloc(a, b)

@cast_realloc@
expression e;
expression p;
type T;
@@
- (T *)tor_realloc(p, e)
+ tor_realloc(p, e)

@cast_reallocarray@
expression a,b;
expression p;
type T;
@@
- (T *)tor_reallocarray(p, a, b)
+ tor_reallocarray(p, a, b)
