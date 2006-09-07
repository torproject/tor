
#include "orconfig.h"
#define DNS_USE_OPENSSL_FOR_ID
#ifndef HAVE_UINT
typedef unsigned int uint;
#endif
#ifndef HAVE_U_CHAR
typedef unsigned char u_char;
#endif
#ifdef MS_WINDOWS
#define inline __inline
#endif

