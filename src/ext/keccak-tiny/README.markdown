# libkeccak-tiny

An implementation of the FIPS-202-defined SHA-3 and SHAKE functions
in 120 cloc (156 lines). One C file, one header.

The `Keccak-f[1600]` permutation is fully unrolled; it's nearly as fast
as the Keccak team's optimized permutation.

## Building

    > clang -O3 -march=native -std=c11 -Wextra -dynamic -shared keccak-tiny.c -o libkeccak-tiny.dylib

If you don't have a modern libc that includes the `memset_s` function,
you can just add `-D"memset_s(W,WL,V,OL)=memset(W,V,OL)` to the command
line.

## Using

Build the library, include the header, and do, e.g.,

    shake256(out, 256, in, inlen);

That's it.

(Note: You can request less output from the fixed-output-length
functions, but not more.)

## TweetShake

The relevant tweets:

```C
// @hashbreaker Inspired by TweetNaCl!
// Keccak and SHA-3 are supposedly hard to implement. So, how many tweets does it take to get to the center of a sponge...?
#define decshake(bits) int shake##bits(unsigned char* o, unsigned long, unsigned char*, unsigned long);                   /*begin keccak.h*/
#define decsha3(bits) int sha3_##bits(unsigned char*,unsigned long,unsigned char*,unsigned long);
decshake(128) decshake(256) decsha3(224) decsha3(256) decsha3(384) decsha3(512)                                             /*end keccak.h*/
#define K static const /* Keccak constants: rho rotations, pi lanes, and iota RCs */                                      /*begin keccak.c*/
typedef unsigned char byte;typedef byte*bytes;typedef unsigned long z;typedef unsigned long long u8;K u8 V=1ULL<<63;K u8 W=1ULL<<31;/*!gcc*/
#define V (1ULL<<63)
#define W (1ULL<31)
K byte rho[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};K u8 RC[24]={1,0x8082,V|0x808a,V|W|0x8000,0x808b,W|1,V|W
|0x8081,V|0x8009,138,136,W|0x8009,W|10,W|0x808b,V|0x8b,V|0x8089,V|0x8003,V|0x8002,V|0x80,0x800a,V|W|0xa,V|W|0x8081,V|0x8080,W|1,V|W|0x8008};
K byte pi[25]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1}; /**helpers:*/static inline z min(z a,z b){return (a<b)?a:b;}
#define ROL(x, s) /* rotary shift */ (((x) << s) | ((x) >> (64-s)))              /**macros to fully unroll the Keccak-f[1600] permutation:*/
#define R24(e) /* repeat 24 times */ e e e e e e e e e e e e e e e e e e e e e e e e
#define L5(v,s,e) /* 5-unroll a loop */ v=0; e; v+=s; e; v+=s; e; v+=s; e; v+=s; e; v+=s;                              /**the permutation:*/
static inline void keccakf(u8* a){u8 b[5]={0};u8 t=0;byte x,y,i=0; /*24 rounds:*/R24( L5(x,1,b[x]=0;L5(y,5, /*parity*/ b[x] ^= a[x+y]))
L5(x,1,L5(y,5,/*theta*/a[y+x] ^= b[(x+4)%5] ^ ROL(b[(x+1)%5],1))) t=a[1];x=0;R24(b[0]=a[pi[x]];/*rho*/a[pi[x]]=ROL(t, rho[x]);t=b[0];x++;)
L5(y,5,L5(x,1, /*chi*/ b[x] = a[y+x]) L5(x,1, a[y+x] = b[x] ^ ~b[(x+1)%5] & b[(x+2)%5])) /*iota*/ a[0] ^= RC[i]; i++; )}     /**keccak-f!**/
#define FOR(i, ST, L, S) /*obvious*/ do { for (z i = 0; i < L; i += ST) { S; } } while (0)   /**now, the sponge construction in hash mode**/
#define appl(NAME, S) /*macro to define array comprehensions*/ static inline void NAME(bytes dst, bytes src, z len) { FOR(i, 1, len, S); }
/*helpers:*/ static inline void clear(bytes a) { FOR(i,1,200,a[i]=0); } appl(xorin, dst[i] ^= src[i])  appl(set, src[i] = dst[i])
#define foldP(I, L, F) /* macro to fold app P F */ while (L >= r) { /*apply F*/ F(a, I, r); /*permute*/ keccakf(A); I += r; L -= r; }
static inline int hash(bytes o,z olen,bytes in,z ilen,z r,byte D){ if((o == (void*)0)||((in == (void*)0)&&ilen != 0)||(r >= 200))return -1;
/*absorb*/u8 A[25]={0};bytes a=(bytes)A;/*full blocks*/foldP(in,ilen,xorin);/*last block*/xorin(a,in,ilen);/**ds+padstart*/a[ilen]^=D;
/*padend:*/a[r-1]^=0x80; /**permute**/keccakf(A); /**squeeze:**/foldP(o,olen,set);/*last bytes*/set(a,o,olen);/*done!*/clear(a);return 0;}
#define defshake(bits) int shake##bits(bytes o, z olen, bytes in, z ilen) {return hash(o,olen,in,ilen,200-(bits/4),0x1f);}
#define defsha3(bits) int sha3_##bits(bytes o,z olen,bytes in,z ilen) {return hash(o,min(olen,200-(bits/4)),in,ilen,200-(bits/4),0x06);}
/*define the SHA3 and SHAKE instances:*/defshake(128) defshake(256) defsha3(224) defsha3(256) defsha3(384) defsha3(512)/*end keccak.c*/
// ...chomp. 24 kinda legible tweets (3232 bytes). And a simple interface: shake256(digest, digestlen, in, inlen)
// Clang recommended. GCC users will need to insert "#define V (1ULL<<63)" and "#define W (1ULL<31)" at the point marked "/*!gcc*/"
// If you're using as a prefix MAC, you MUST replace the body of "clear" with "memset_s(a, 200, 0, 200)" to avoid misoptimization.
// @everyone_who_is_still_using_sha1 Please stop using SHA-1.
// Oh, one more thing: a C11-threaded, memmapped shake256sum in 10 tweets. (Your libc may need a shim for C11 thread support.)
// echo -n string stdio stdint fcntl sys/mman sys/stat sys/types unistd threads|tr ' ' \\n|xargs -n1 -I_ echo '#include <_.h>'
#include "kcksum_tweet.h"
#define E(LABEL, MSG) if (err != 0) { strerror_r(err, serr, 1024); fprintf(stderr, "%s: '%s' %s\n", serr, fn, MSG); goto LABEL;}
static mtx_t iomtx;void h(void* v);void h(void* v){char* fn=(char*)v;int err=0;char serr[1024]={0};/*open file*/int fd=open(fn, O_RDONLY);
err=!fd;E(ret,"couldn't be opened.");/*stat it*/struct stat stat;err=fstat(fd,&stat);E(close,"doesn't exist.");err=!!(stat.st_mode&S_IFDIR);
E(close,"not a regular file.");z length=(size_t)stat.st_size;/*mmap the file*/bytes in=length?mmap(0,length,PROT_READ,MAP_SHARED,fd,0):NULL;
if(length&&(in==MAP_FAILED)){E(close,"mmap-ing failed.");}byte out[64]={0};/*hash it*/shake256(out,64,in,length);length&&munmap(in,length);
/*lock io*/mtx_lock(&iomtx);printf("SHAKE256('%s') = ", fn);FOR(i,1,64,printf("%02x",out[i]));printf("\n");mtx_unlock(&iomtx);/*unlock io*/
close:close(fd);ret:thrd_exit(err);}int main(int argc,char** argv){int err=0; mtx_init(&iomtx, mtx_plain); thrd_t t[4]; int res[4],i,j,k;
for(i=1;i<argc;i+=4){for(j=0;j<4;j++){if((j+i)==argc){/*out of files*/goto join;} /*spawn*/ thrd_create(t + j,h,argv[i + j]);}
join: for (k = 0; k < j; k++) { /*wait*/ err |= thrd_join(t[k], res + k); err |= res[k];} } mtx_destroy(&iomtx); return err; } /* done! */
```


## License

[CC0](http://creativecommons.org/publicdomain/zero/1.0/)
