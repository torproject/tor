SRC=args.c config.c op.c routers.c auth.c ss.c buffers.c crypto.c
OBJ=${SRC:.c=.o}
PROGS=op
LIB=-L/usr/local/ssl/lib
LIBS=-lcrypto
INCLUDE = -I/usr/local/ssl/include

CFLAGS= $(INCLUDE) -Wall -Wpointer-arith -O2 -ggdb
LDFLAGS = $(LIB) $(LIBS)

all:	${PROGS}

clean:
	rm -f *.o ${PROGS}

depend:
	makedepend -- ${CFLAGS} -- ${SRC}

${PROGS}:	${OBJ}
	$(LINK.c) -o $@ $(OBJ) ../common/log.o ../common/config.o ../common/onion.o ../common/utils.o ../common/cell.o ../common/scheduler.o -lpopt

# DO NOT DELETE


args.o: args.h ../common/log.h /usr/include/alloca.h
args.o: /usr/include/bits/confname.h /usr/include/bits/endian.h
args.o: /usr/include/bits/environments.h /usr/include/bits/posix_opt.h
args.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
args.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
args.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
args.o: /usr/include/bits/types.h /usr/include/bits/waitflags.h
args.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
args.o: /usr/include/bits/wordsize.h /usr/include/ctype.h
args.o: /usr/include/endian.h /usr/include/features.h /usr/include/_G_config.h
args.o: /usr/include/gconv.h /usr/include/getopt.h /usr/include/gnu/stubs.h
args.o: /usr/include/libio.h /usr/include/stdio.h /usr/include/stdlib.h
args.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
args.o: /usr/include/sys/select.h /usr/include/sys/syslog.h
args.o: /usr/include/sys/sysmacros.h /usr/include/sys/types.h
args.o: /usr/include/time.h /usr/include/unistd.h /usr/include/wchar.h
args.o: /usr/include/xlocale.h
args.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
args.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
auth.o: auth.h ../common/log.h /usr/include/alloca.h /usr/include/asm/socket.h
auth.o: /usr/include/asm/sockios.h /usr/include/bits/byteswap.h
auth.o: /usr/include/bits/confname.h /usr/include/bits/endian.h
auth.o: /usr/include/bits/environments.h /usr/include/bits/in.h
auth.o: /usr/include/bits/local_lim.h /usr/include/bits/posix1_lim.h
auth.o: /usr/include/bits/posix2_lim.h /usr/include/bits/posix_opt.h
auth.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
auth.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
auth.o: /usr/include/bits/sockaddr.h /usr/include/bits/socket.h
auth.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
auth.o: /usr/include/bits/types.h /usr/include/bits/uio.h
auth.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
auth.o: /usr/include/bits/wchar.h /usr/include/bits/wordsize.h
auth.o: /usr/include/bits/xopen_lim.h /usr/include/endian.h
auth.o: /usr/include/features.h /usr/include/_G_config.h /usr/include/gconv.h
auth.o: /usr/include/getopt.h /usr/include/gnu/stubs.h /usr/include/libio.h
auth.o: /usr/include/limits.h /usr/include/linux/limits.h
auth.o: /usr/include/netinet/in.h /usr/include/openssl/bio.h
auth.o: /usr/include/openssl/bn.h /usr/include/openssl/crypto.h
auth.o: /usr/include/openssl/opensslconf.h /usr/include/openssl/opensslv.h
auth.o: /usr/include/openssl/rand.h /usr/include/openssl/rsa.h
auth.o: /usr/include/openssl/safestack.h /usr/include/openssl/stack.h
auth.o: /usr/include/openssl/symhacks.h /usr/include/stdint.h
auth.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h
auth.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
auth.o: /usr/include/sys/select.h /usr/include/sys/socket.h
auth.o: /usr/include/sys/syslog.h /usr/include/sys/sysmacros.h
auth.o: /usr/include/sys/types.h /usr/include/sys/uio.h /usr/include/time.h
auth.o: /usr/include/unistd.h /usr/include/wchar.h /usr/include/xlocale.h
auth.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
auth.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
auth.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
auth.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h
buffers.o: buffers.h ../common/cell.h ../common/log.h ../common/onion.h
buffers.o: ../common/routent.h ../common/version.h crypto.h op.h
buffers.o: /usr/include/alloca.h /usr/include/bits/confname.h
buffers.o: /usr/include/bits/endian.h /usr/include/bits/environments.h
buffers.o: /usr/include/bits/posix_opt.h /usr/include/bits/pthreadtypes.h
buffers.o: /usr/include/bits/sched.h /usr/include/bits/select.h
buffers.o: /usr/include/bits/sigset.h /usr/include/bits/stdio_lim.h
buffers.o: /usr/include/bits/time.h /usr/include/bits/types.h
buffers.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
buffers.o: /usr/include/bits/wchar.h /usr/include/bits/wordsize.h
buffers.o: /usr/include/endian.h /usr/include/features.h
buffers.o: /usr/include/_G_config.h /usr/include/gconv.h /usr/include/getopt.h
buffers.o: /usr/include/gnu/stubs.h /usr/include/libio.h
buffers.o: /usr/include/openssl/asn1.h /usr/include/openssl/bio.h
buffers.o: /usr/include/openssl/blowfish.h /usr/include/openssl/bn.h
buffers.o: /usr/include/openssl/cast.h /usr/include/openssl/crypto.h
buffers.o: /usr/include/openssl/des.h /usr/include/openssl/dh.h
buffers.o: /usr/include/openssl/dsa.h /usr/include/openssl/e_os2.h
buffers.o: /usr/include/openssl/evp.h /usr/include/openssl/md2.h
buffers.o: /usr/include/openssl/md4.h /usr/include/openssl/md5.h
buffers.o: /usr/include/openssl/objects.h /usr/include/openssl/obj_mac.h
buffers.o: /usr/include/openssl/opensslconf.h /usr/include/openssl/opensslv.h
buffers.o: /usr/include/openssl/rc2.h /usr/include/openssl/rc4.h
buffers.o: /usr/include/openssl/ripemd.h /usr/include/openssl/rsa.h
buffers.o: /usr/include/openssl/safestack.h /usr/include/openssl/sha.h
buffers.o: /usr/include/openssl/stack.h /usr/include/openssl/symhacks.h
buffers.o: /usr/include/stdint.h /usr/include/stdio.h /usr/include/stdlib.h
buffers.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
buffers.o: /usr/include/sys/select.h /usr/include/sys/syslog.h
buffers.o: /usr/include/sys/sysmacros.h /usr/include/sys/timeb.h
buffers.o: /usr/include/sys/time.h /usr/include/sys/types.h
buffers.o: /usr/include/time.h /usr/include/unistd.h /usr/include/wchar.h
buffers.o: /usr/include/xlocale.h
buffers.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
buffers.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
config.o: ../common/config.h ../common/log.h config.h
config.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
config.o: /usr/include/bits/stdio_lim.h /usr/include/bits/types.h
config.o: /usr/include/bits/wchar.h /usr/include/features.h
config.o: /usr/include/_G_config.h /usr/include/gconv.h
config.o: /usr/include/gnu/stubs.h /usr/include/libio.h /usr/include/stdio.h
config.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
config.o: /usr/include/sys/syslog.h /usr/include/wchar.h
config.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
config.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
crypto.o: ../common/cell.h ../common/log.h ../common/onion.h
crypto.o: ../common/routent.h ../common/version.h crypto.h
crypto.o: /usr/include/alloca.h /usr/include/asm/errno.h
crypto.o: /usr/include/bits/confname.h /usr/include/bits/endian.h
crypto.o: /usr/include/bits/environments.h /usr/include/bits/errno.h
crypto.o: /usr/include/bits/posix_opt.h /usr/include/bits/pthreadtypes.h
crypto.o: /usr/include/bits/sched.h /usr/include/bits/select.h
crypto.o: /usr/include/bits/sigset.h /usr/include/bits/stdio_lim.h
crypto.o: /usr/include/bits/time.h /usr/include/bits/types.h
crypto.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
crypto.o: /usr/include/bits/wchar.h /usr/include/bits/wordsize.h
crypto.o: /usr/include/endian.h /usr/include/errno.h /usr/include/features.h
crypto.o: /usr/include/_G_config.h /usr/include/gconv.h /usr/include/getopt.h
crypto.o: /usr/include/gnu/stubs.h /usr/include/libio.h
crypto.o: /usr/include/linux/errno.h /usr/include/malloc.h
crypto.o: /usr/include/openssl/asn1.h /usr/include/openssl/bio.h
crypto.o: /usr/include/openssl/blowfish.h /usr/include/openssl/bn.h
crypto.o: /usr/include/openssl/cast.h /usr/include/openssl/crypto.h
crypto.o: /usr/include/openssl/des.h /usr/include/openssl/dh.h
crypto.o: /usr/include/openssl/dsa.h /usr/include/openssl/e_os2.h
crypto.o: /usr/include/openssl/err.h /usr/include/openssl/evp.h
crypto.o: /usr/include/openssl/lhash.h /usr/include/openssl/md2.h
crypto.o: /usr/include/openssl/md4.h /usr/include/openssl/md5.h
crypto.o: /usr/include/openssl/objects.h /usr/include/openssl/obj_mac.h
crypto.o: /usr/include/openssl/opensslconf.h /usr/include/openssl/opensslv.h
crypto.o: /usr/include/openssl/rc2.h /usr/include/openssl/rc4.h
crypto.o: /usr/include/openssl/ripemd.h /usr/include/openssl/rsa.h
crypto.o: /usr/include/openssl/safestack.h /usr/include/openssl/sha.h
crypto.o: /usr/include/openssl/stack.h /usr/include/openssl/symhacks.h
crypto.o: /usr/include/stdint.h /usr/include/stdio.h /usr/include/stdlib.h
crypto.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
crypto.o: /usr/include/sys/select.h /usr/include/sys/syslog.h
crypto.o: /usr/include/sys/sysmacros.h /usr/include/sys/timeb.h
crypto.o: /usr/include/sys/time.h /usr/include/sys/types.h /usr/include/time.h
crypto.o: /usr/include/unistd.h /usr/include/wchar.h /usr/include/xlocale.h
crypto.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
crypto.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
op.o: args.h auth.h buffers.h ../common/cell.h ../common/config.h
op.o: ../common/log.h ../common/onion.h ../common/routent.h
op.o: ../common/scheduler.h ../common/ss.h ../common/utils.h
op.o: ../common/version.h config.h crypto.h op.h routers.h ss.h
op.o: /usr/include/alloca.h /usr/include/arpa/inet.h /usr/include/asm/errno.h
op.o: /usr/include/asm/sigcontext.h /usr/include/asm/socket.h
op.o: /usr/include/asm/sockios.h /usr/include/bits/byteswap.h
op.o: /usr/include/bits/confname.h /usr/include/bits/endian.h
op.o: /usr/include/bits/environments.h /usr/include/bits/errno.h
op.o: /usr/include/bits/in.h /usr/include/bits/local_lim.h
op.o: /usr/include/bits/netdb.h /usr/include/bits/posix1_lim.h
op.o: /usr/include/bits/posix2_lim.h /usr/include/bits/posix_opt.h
op.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/resource.h
op.o: /usr/include/bits/sched.h /usr/include/bits/select.h
op.o: /usr/include/bits/sigaction.h /usr/include/bits/sigcontext.h
op.o: /usr/include/bits/siginfo.h /usr/include/bits/signum.h
op.o: /usr/include/bits/sigset.h /usr/include/bits/sigstack.h
op.o: /usr/include/bits/sigthread.h /usr/include/bits/sockaddr.h
op.o: /usr/include/bits/socket.h /usr/include/bits/stdio_lim.h
op.o: /usr/include/bits/time.h /usr/include/bits/types.h
op.o: /usr/include/bits/uio.h /usr/include/bits/waitflags.h
op.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
op.o: /usr/include/bits/wordsize.h /usr/include/bits/xopen_lim.h
op.o: /usr/include/ctype.h /usr/include/endian.h /usr/include/errno.h
op.o: /usr/include/features.h /usr/include/_G_config.h /usr/include/gconv.h
op.o: /usr/include/getopt.h /usr/include/gnu/stubs.h /usr/include/libio.h
op.o: /usr/include/limits.h /usr/include/linux/errno.h
op.o: /usr/include/linux/limits.h /usr/include/netdb.h
op.o: /usr/include/netinet/in.h /usr/include/openssl/asn1.h
op.o: /usr/include/openssl/bio.h /usr/include/openssl/blowfish.h
op.o: /usr/include/openssl/bn.h /usr/include/openssl/buffer.h
op.o: /usr/include/openssl/cast.h /usr/include/openssl/crypto.h
op.o: /usr/include/openssl/des.h /usr/include/openssl/dh.h
op.o: /usr/include/openssl/dsa.h /usr/include/openssl/e_os2.h
op.o: /usr/include/openssl/err.h /usr/include/openssl/evp.h
op.o: /usr/include/openssl/lhash.h /usr/include/openssl/md2.h
op.o: /usr/include/openssl/md4.h /usr/include/openssl/md5.h
op.o: /usr/include/openssl/objects.h /usr/include/openssl/obj_mac.h
op.o: /usr/include/openssl/opensslconf.h /usr/include/openssl/opensslv.h
op.o: /usr/include/openssl/pem2.h /usr/include/openssl/pem.h
op.o: /usr/include/openssl/pkcs7.h /usr/include/openssl/rand.h
op.o: /usr/include/openssl/rc2.h /usr/include/openssl/rc4.h
op.o: /usr/include/openssl/ripemd.h /usr/include/openssl/rsa.h
op.o: /usr/include/openssl/safestack.h /usr/include/openssl/sha.h
op.o: /usr/include/openssl/stack.h /usr/include/openssl/symhacks.h
op.o: /usr/include/openssl/x509.h /usr/include/openssl/x509_vfy.h
op.o: /usr/include/rpc/netdb.h /usr/include/signal.h /usr/include/stdint.h
op.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h
op.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
op.o: /usr/include/sys/resource.h /usr/include/sys/select.h
op.o: /usr/include/sys/socket.h /usr/include/sys/syslog.h
op.o: /usr/include/sys/sysmacros.h /usr/include/sys/timeb.h
op.o: /usr/include/sys/time.h /usr/include/sys/types.h
op.o: /usr/include/sys/ucontext.h /usr/include/sys/uio.h /usr/include/sys/un.h
op.o: /usr/include/sys/wait.h /usr/include/time.h /usr/include/ucontext.h
op.o: /usr/include/unistd.h /usr/include/wait.h /usr/include/wchar.h
op.o: /usr/include/xlocale.h
op.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
op.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
op.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
op.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h
routers.o: ../common/cell.h ../common/config.h ../common/log.h
routers.o: ../common/routent.h ../common/utils.h routers.h
routers.o: /usr/include/alloca.h /usr/include/asm/errno.h
routers.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
routers.o: /usr/include/bits/byteswap.h /usr/include/bits/confname.h
routers.o: /usr/include/bits/endian.h /usr/include/bits/environments.h
routers.o: /usr/include/bits/errno.h /usr/include/bits/in.h
routers.o: /usr/include/bits/local_lim.h /usr/include/bits/netdb.h
routers.o: /usr/include/bits/posix1_lim.h /usr/include/bits/posix2_lim.h
routers.o: /usr/include/bits/posix_opt.h /usr/include/bits/pthreadtypes.h
routers.o: /usr/include/bits/sched.h /usr/include/bits/select.h
routers.o: /usr/include/bits/siginfo.h /usr/include/bits/sigset.h
routers.o: /usr/include/bits/sockaddr.h /usr/include/bits/socket.h
routers.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
routers.o: /usr/include/bits/types.h /usr/include/bits/waitflags.h
routers.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
routers.o: /usr/include/bits/wordsize.h /usr/include/bits/xopen_lim.h
routers.o: /usr/include/endian.h /usr/include/errno.h /usr/include/features.h
routers.o: /usr/include/_G_config.h /usr/include/gconv.h /usr/include/getopt.h
routers.o: /usr/include/gnu/stubs.h /usr/include/libio.h /usr/include/limits.h
routers.o: /usr/include/linux/errno.h /usr/include/linux/limits.h
routers.o: /usr/include/netdb.h /usr/include/netinet/in.h
routers.o: /usr/include/openssl/asn1.h /usr/include/openssl/bio.h
routers.o: /usr/include/openssl/blowfish.h /usr/include/openssl/bn.h
routers.o: /usr/include/openssl/buffer.h /usr/include/openssl/cast.h
routers.o: /usr/include/openssl/crypto.h /usr/include/openssl/des.h
routers.o: /usr/include/openssl/dh.h /usr/include/openssl/dsa.h
routers.o: /usr/include/openssl/e_os2.h /usr/include/openssl/err.h
routers.o: /usr/include/openssl/evp.h /usr/include/openssl/lhash.h
routers.o: /usr/include/openssl/md2.h /usr/include/openssl/md4.h
routers.o: /usr/include/openssl/md5.h /usr/include/openssl/objects.h
routers.o: /usr/include/openssl/obj_mac.h /usr/include/openssl/opensslconf.h
routers.o: /usr/include/openssl/opensslv.h /usr/include/openssl/pem2.h
routers.o: /usr/include/openssl/pem.h /usr/include/openssl/pkcs7.h
routers.o: /usr/include/openssl/rc2.h /usr/include/openssl/rc4.h
routers.o: /usr/include/openssl/ripemd.h /usr/include/openssl/rsa.h
routers.o: /usr/include/openssl/safestack.h /usr/include/openssl/sha.h
routers.o: /usr/include/openssl/stack.h /usr/include/openssl/symhacks.h
routers.o: /usr/include/openssl/x509.h /usr/include/openssl/x509_vfy.h
routers.o: /usr/include/rpc/netdb.h /usr/include/stdint.h /usr/include/stdio.h
routers.o: /usr/include/stdlib.h /usr/include/string.h
routers.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
routers.o: /usr/include/sys/select.h /usr/include/sys/syslog.h
routers.o: /usr/include/sys/sysmacros.h /usr/include/sys/timeb.h
routers.o: /usr/include/sys/time.h /usr/include/sys/types.h
routers.o: /usr/include/sys/un.h /usr/include/time.h /usr/include/unistd.h
routers.o: /usr/include/wchar.h /usr/include/xlocale.h
routers.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
routers.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
routers.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
routers.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h
ss.o: ../common/log.h ../common/ss.h ../common/utils.h ../common/version.h
ss.o: ss.h /usr/include/bits/confname.h /usr/include/bits/endian.h
ss.o: /usr/include/bits/environments.h /usr/include/bits/posix_opt.h
ss.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
ss.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
ss.o: /usr/include/bits/sockaddr.h /usr/include/bits/time.h
ss.o: /usr/include/bits/types.h /usr/include/bits/wordsize.h
ss.o: /usr/include/endian.h /usr/include/features.h /usr/include/getopt.h
ss.o: /usr/include/gnu/stubs.h /usr/include/malloc.h /usr/include/string.h
ss.o: /usr/include/sys/cdefs.h /usr/include/syslog.h /usr/include/sys/select.h
ss.o: /usr/include/sys/syslog.h /usr/include/sys/sysmacros.h
ss.o: /usr/include/sys/time.h /usr/include/sys/types.h /usr/include/sys/un.h
ss.o: /usr/include/time.h /usr/include/unistd.h /usr/include/xlocale.h
ss.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
ss.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
