
@@
expression a;
@@
- tor_calloc(1, a)
+ tor_malloc_zero(a)

@@
expression a;
@@
- tor_calloc(a, 1)
+ tor_malloc_zero(a)

