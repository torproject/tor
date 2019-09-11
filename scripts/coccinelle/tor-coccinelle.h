#define MOCK_IMPL(a, b, c) a b c
#define CHECK_PRINTF(a, b)
#define STATIC static

#define STMT_BEGIN do {
#define STMT_END } while (0)

#define BUG(x) (x)
#define IF_BUG_ONCE(x) if (x)

#define ATTR_NORETURN
#define ATTR_UNUSED
#define ATTR_CONST
#define ATTR_MALLOC
#define ATTR_WUR

#define HT_ENTRY(x) void *
#define HT_HEAD(a,b) struct ht_head
#define HT_INITIALIZER { }
#define X509 struct x509_st
#define STACK_OF(x) struct foo_stack_t
