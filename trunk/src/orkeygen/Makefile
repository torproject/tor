SRC=orkeygen.c
OBJ=${SRC:.c=.o}
PROGS=orkeygen
LIB=-L/usr/local/ssl/lib
LIBS=-lcrypto
INCLUDE=-I/usr/local/ssl/include

CFLAGS= $(INCLUDE)
LDFLAGS = $(LIB) ${LIBS}

all:	${PROGS}

clean:
	rm -f *.o ${PROGS}

depend:
	makedepend -- ${CFLAGS} -- ${SRC}

${PROGS}:	${OBJ}
	$(LINK.c) -o $@ $(OBJ)

# DO NOT DELETE


orkeygen.o: /usr/include/alloca.h /usr/include/asm/errno.h
orkeygen.o: /usr/include/bits/endian.h /usr/include/bits/errno.h
orkeygen.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
orkeygen.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
orkeygen.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
orkeygen.o: /usr/include/bits/types.h /usr/include/bits/waitflags.h
orkeygen.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
orkeygen.o: /usr/include/endian.h /usr/include/errno.h /usr/include/features.h
orkeygen.o: /usr/include/_G_config.h /usr/include/gconv.h
orkeygen.o: /usr/include/gnu/stubs.h /usr/include/libio.h
orkeygen.o: /usr/include/linux/errno.h /usr/include/openssl/asn1.h
orkeygen.o: /usr/include/openssl/bio.h /usr/include/openssl/blowfish.h
orkeygen.o: /usr/include/openssl/bn.h /usr/include/openssl/buffer.h
orkeygen.o: /usr/include/openssl/cast.h /usr/include/openssl/crypto.h
orkeygen.o: /usr/include/openssl/des.h /usr/include/openssl/dh.h
orkeygen.o: /usr/include/openssl/dsa.h /usr/include/openssl/e_os2.h
orkeygen.o: /usr/include/openssl/err.h /usr/include/openssl/evp.h
orkeygen.o: /usr/include/openssl/lhash.h /usr/include/openssl/md2.h
orkeygen.o: /usr/include/openssl/md4.h /usr/include/openssl/md5.h
orkeygen.o: /usr/include/openssl/objects.h /usr/include/openssl/obj_mac.h
orkeygen.o: /usr/include/openssl/opensslconf.h /usr/include/openssl/opensslv.h
orkeygen.o: /usr/include/openssl/pem2.h /usr/include/openssl/pem.h
orkeygen.o: /usr/include/openssl/pkcs7.h /usr/include/openssl/rc2.h
orkeygen.o: /usr/include/openssl/rc4.h /usr/include/openssl/ripemd.h
orkeygen.o: /usr/include/openssl/rsa.h /usr/include/openssl/safestack.h
orkeygen.o: /usr/include/openssl/sha.h /usr/include/openssl/stack.h
orkeygen.o: /usr/include/openssl/symhacks.h /usr/include/openssl/x509.h
orkeygen.o: /usr/include/openssl/x509_vfy.h /usr/include/stdio.h
orkeygen.o: /usr/include/stdlib.h /usr/include/sys/cdefs.h
orkeygen.o: /usr/include/sys/select.h /usr/include/sys/sysmacros.h
orkeygen.o: /usr/include/sys/types.h /usr/include/time.h /usr/include/wchar.h
orkeygen.o: /usr/include/xlocale.h
orkeygen.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
orkeygen.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
