@@
expression * e;
@@

(
- tt_assert(e != NULL)
+ tt_ptr_op(e, OP_NE, NULL)
|
- tt_assert(e == NULL)
+ tt_ptr_op(e, OP_EQ, NULL)
)
