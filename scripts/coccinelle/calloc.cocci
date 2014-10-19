// Use calloc or realloc as appropriate instead of multiply-and-alloc

@malloc_to_calloc@
identifier f =~ "(tor_malloc|tor_malloc_zero)";
expression a;
constant b;
@@
- f(a * b)
+ tor_calloc(a, b)

@calloc_arg_order@
expression a;
type t;
@@
- tor_calloc(sizeof(t), a)
+ tor_calloc(a, sizeof(t))

@realloc_to_reallocarray@
expression a, b;
expression p;
@@
- tor_realloc(p, a * b)
+ tor_reallocarray(p, a, b)
