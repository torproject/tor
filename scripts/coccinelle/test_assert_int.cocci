@@
int e;
constant c;
@@

(
- tt_assert(e == c)
+ tt_int_op(e, OP_EQ, c)
|
- tt_assert(e != c)
+ tt_int_op(e, OP_NE, c)
|
- tt_assert(e < c)
+ tt_int_op(e, OP_LT, c)
|
- tt_assert(e <= c)
+ tt_int_op(e, OP_LE, c)
|
- tt_assert(e > c)
+ tt_int_op(e, OP_GT, c)
|
- tt_assert(e >= c)
+ tt_int_op(e, OP_GE, c)
)

@@
unsigned int e;
constant c;
@@

(
- tt_assert(e == c)
+ tt_uint_op(e, OP_EQ, c)
|
- tt_assert(e != c)
+ tt_uint_op(e, OP_NE, c)
|
- tt_assert(e < c)
+ tt_uint_op(e, OP_LT, c)
|
- tt_assert(e <= c)
+ tt_uint_op(e, OP_LE, c)
|
- tt_assert(e > c)
+ tt_uint_op(e, OP_GT, c)
|
- tt_assert(e >= c)
+ tt_uint_op(e, OP_GE, c)
)
