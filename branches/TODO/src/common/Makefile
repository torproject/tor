SRC=log.c config.c utils.c key.c onion.c cell.c routent.c scheduler.c
OBJ=${SRC:.c=.o}
INCLUDE=-I/usr/local/ssl/include

CFLAGS=${INCLUDE} -Wall -Wpointer-arith -O2

all:	${OBJ}

clean:
	rm -f $(OBJ)

depend:
	makedepend -- $(CFLAGS) -- $(SRC)

# DO NOT DELETE


cell.o: cell.h log.h /usr/include/alloca.h /usr/include/asm/socket.h
cell.o: /usr/include/asm/sockios.h /usr/include/bits/byteswap.h
cell.o: /usr/include/bits/confname.h /usr/include/bits/endian.h
cell.o: /usr/include/bits/environments.h /usr/include/bits/in.h
cell.o: /usr/include/bits/local_lim.h /usr/include/bits/posix1_lim.h
cell.o: /usr/include/bits/posix2_lim.h /usr/include/bits/posix_opt.h
cell.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
cell.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
cell.o: /usr/include/bits/sockaddr.h /usr/include/bits/socket.h
cell.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
cell.o: /usr/include/bits/types.h /usr/include/bits/waitflags.h
cell.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
cell.o: /usr/include/bits/wordsize.h /usr/include/bits/xopen_lim.h
cell.o: /usr/include/endian.h /usr/include/features.h /usr/include/getopt.h
cell.o: /usr/include/gnu/stubs.h /usr/include/limits.h
cell.o: /usr/include/linux/limits.h /usr/include/netinet/in.h
cell.o: /usr/include/openssl/rand.h /usr/include/stdint.h
cell.o: /usr/include/stdlib.h /usr/include/string.h /usr/include/sys/cdefs.h
cell.o: /usr/include/syslog.h /usr/include/sys/select.h
cell.o: /usr/include/sys/syslog.h /usr/include/sys/sysmacros.h
cell.o: /usr/include/sys/types.h /usr/include/time.h /usr/include/unistd.h
cell.o: /usr/include/xlocale.h
cell.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
cell.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
cell.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
cell.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h
config.o: config.h log.h /usr/include/alloca.h /usr/include/asm/errno.h
config.o: /usr/include/bits/endian.h /usr/include/bits/errno.h
config.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
config.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
config.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
config.o: /usr/include/bits/types.h /usr/include/bits/waitflags.h
config.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
config.o: /usr/include/ctype.h /usr/include/endian.h /usr/include/errno.h
config.o: /usr/include/features.h /usr/include/_G_config.h
config.o: /usr/include/gconv.h /usr/include/gnu/stubs.h /usr/include/libio.h
config.o: /usr/include/linux/errno.h /usr/include/stdio.h
config.o: /usr/include/stdlib.h /usr/include/string.h /usr/include/sys/cdefs.h
config.o: /usr/include/syslog.h /usr/include/sys/select.h
config.o: /usr/include/sys/syslog.h /usr/include/sys/sysmacros.h
config.o: /usr/include/sys/types.h /usr/include/time.h /usr/include/wchar.h
config.o: /usr/include/xlocale.h
config.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
config.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
key.o: config.h key.h log.h /usr/include/alloca.h /usr/include/asm/errno.h
key.o: /usr/include/bits/endian.h /usr/include/bits/errno.h
key.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
key.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
key.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
key.o: /usr/include/bits/types.h /usr/include/bits/waitflags.h
key.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
key.o: /usr/include/endian.h /usr/include/errno.h /usr/include/features.h
key.o: /usr/include/_G_config.h /usr/include/gconv.h /usr/include/gnu/stubs.h
key.o: /usr/include/libio.h /usr/include/linux/errno.h
key.o: /usr/include/openssl/asn1.h /usr/include/openssl/bio.h
key.o: /usr/include/openssl/blowfish.h /usr/include/openssl/bn.h
key.o: /usr/include/openssl/buffer.h /usr/include/openssl/cast.h
key.o: /usr/include/openssl/crypto.h /usr/include/openssl/des.h
key.o: /usr/include/openssl/dh.h /usr/include/openssl/dsa.h
key.o: /usr/include/openssl/e_os2.h /usr/include/openssl/err.h
key.o: /usr/include/openssl/evp.h /usr/include/openssl/lhash.h
key.o: /usr/include/openssl/md2.h /usr/include/openssl/md4.h
key.o: /usr/include/openssl/md5.h /usr/include/openssl/objects.h
key.o: /usr/include/openssl/obj_mac.h /usr/include/openssl/opensslconf.h
key.o: /usr/include/openssl/opensslv.h /usr/include/openssl/pem2.h
key.o: /usr/include/openssl/pem.h /usr/include/openssl/pkcs7.h
key.o: /usr/include/openssl/rc2.h /usr/include/openssl/rc4.h
key.o: /usr/include/openssl/ripemd.h /usr/include/openssl/rsa.h
key.o: /usr/include/openssl/safestack.h /usr/include/openssl/sha.h
key.o: /usr/include/openssl/stack.h /usr/include/openssl/symhacks.h
key.o: /usr/include/openssl/x509.h /usr/include/openssl/x509_vfy.h
key.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h
key.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
key.o: /usr/include/sys/select.h /usr/include/sys/syslog.h
key.o: /usr/include/sys/sysmacros.h /usr/include/sys/types.h
key.o: /usr/include/time.h /usr/include/wchar.h /usr/include/xlocale.h
key.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
key.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
log.o: log.h /usr/include/asm/errno.h /usr/include/bits/errno.h
log.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
log.o: /usr/include/bits/stdio_lim.h /usr/include/bits/types.h
log.o: /usr/include/bits/wchar.h /usr/include/errno.h /usr/include/features.h
log.o: /usr/include/_G_config.h /usr/include/gconv.h /usr/include/gnu/stubs.h
log.o: /usr/include/libio.h /usr/include/linux/errno.h /usr/include/stdio.h
log.o: /usr/include/string.h /usr/include/sys/cdefs.h /usr/include/syslog.h
log.o: /usr/include/sys/syslog.h /usr/include/wchar.h /usr/include/xlocale.h
log.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
log.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
onion.o: cell.h log.h onion.h routent.h /usr/include/alloca.h
onion.o: /usr/include/arpa/inet.h /usr/include/asm/errno.h
onion.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
onion.o: /usr/include/bits/byteswap.h /usr/include/bits/confname.h
onion.o: /usr/include/bits/endian.h /usr/include/bits/environments.h
onion.o: /usr/include/bits/errno.h /usr/include/bits/in.h
onion.o: /usr/include/bits/local_lim.h /usr/include/bits/posix1_lim.h
onion.o: /usr/include/bits/posix2_lim.h /usr/include/bits/posix_opt.h
onion.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
onion.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
onion.o: /usr/include/bits/sockaddr.h /usr/include/bits/socket.h
onion.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
onion.o: /usr/include/bits/types.h /usr/include/bits/uio.h
onion.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
onion.o: /usr/include/bits/wchar.h /usr/include/bits/wordsize.h
onion.o: /usr/include/bits/xopen_lim.h /usr/include/endian.h
onion.o: /usr/include/errno.h /usr/include/features.h /usr/include/_G_config.h
onion.o: /usr/include/gconv.h /usr/include/getopt.h /usr/include/gnu/stubs.h
onion.o: /usr/include/libio.h /usr/include/limits.h /usr/include/linux/errno.h
onion.o: /usr/include/linux/limits.h /usr/include/netinet/in.h
onion.o: /usr/include/openssl/asn1.h /usr/include/openssl/bio.h
onion.o: /usr/include/openssl/blowfish.h /usr/include/openssl/bn.h
onion.o: /usr/include/openssl/cast.h /usr/include/openssl/crypto.h
onion.o: /usr/include/openssl/des.h /usr/include/openssl/dh.h
onion.o: /usr/include/openssl/dsa.h /usr/include/openssl/e_os2.h
onion.o: /usr/include/openssl/err.h /usr/include/openssl/evp.h
onion.o: /usr/include/openssl/lhash.h /usr/include/openssl/md2.h
onion.o: /usr/include/openssl/md4.h /usr/include/openssl/md5.h
onion.o: /usr/include/openssl/objects.h /usr/include/openssl/obj_mac.h
onion.o: /usr/include/openssl/opensslconf.h /usr/include/openssl/opensslv.h
onion.o: /usr/include/openssl/rand.h /usr/include/openssl/rc2.h
onion.o: /usr/include/openssl/rc4.h /usr/include/openssl/ripemd.h
onion.o: /usr/include/openssl/rsa.h /usr/include/openssl/safestack.h
onion.o: /usr/include/openssl/sha.h /usr/include/openssl/stack.h
onion.o: /usr/include/openssl/symhacks.h /usr/include/stdint.h
onion.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h
onion.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
onion.o: /usr/include/sys/select.h /usr/include/sys/socket.h
onion.o: /usr/include/sys/syslog.h /usr/include/sys/sysmacros.h
onion.o: /usr/include/sys/timeb.h /usr/include/sys/time.h
onion.o: /usr/include/sys/types.h /usr/include/sys/uio.h /usr/include/time.h
onion.o: /usr/include/unistd.h /usr/include/wchar.h /usr/include/xlocale.h
onion.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
onion.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
onion.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
onion.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h version.h
routent.o: cell.h routent.h /usr/include/alloca.h /usr/include/bits/confname.h
routent.o: /usr/include/bits/endian.h /usr/include/bits/environments.h
routent.o: /usr/include/bits/posix_opt.h /usr/include/bits/pthreadtypes.h
routent.o: /usr/include/bits/sched.h /usr/include/bits/select.h
routent.o: /usr/include/bits/sigset.h /usr/include/bits/stdio_lim.h
routent.o: /usr/include/bits/time.h /usr/include/bits/types.h
routent.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
routent.o: /usr/include/bits/wchar.h /usr/include/bits/wordsize.h
routent.o: /usr/include/endian.h /usr/include/features.h
routent.o: /usr/include/_G_config.h /usr/include/gconv.h /usr/include/getopt.h
routent.o: /usr/include/gnu/stubs.h /usr/include/libio.h
routent.o: /usr/include/openssl/asn1.h /usr/include/openssl/bio.h
routent.o: /usr/include/openssl/blowfish.h /usr/include/openssl/bn.h
routent.o: /usr/include/openssl/cast.h /usr/include/openssl/crypto.h
routent.o: /usr/include/openssl/des.h /usr/include/openssl/dh.h
routent.o: /usr/include/openssl/dsa.h /usr/include/openssl/e_os2.h
routent.o: /usr/include/openssl/evp.h /usr/include/openssl/md2.h
routent.o: /usr/include/openssl/md4.h /usr/include/openssl/md5.h
routent.o: /usr/include/openssl/objects.h /usr/include/openssl/obj_mac.h
routent.o: /usr/include/openssl/opensslconf.h /usr/include/openssl/opensslv.h
routent.o: /usr/include/openssl/rc2.h /usr/include/openssl/rc4.h
routent.o: /usr/include/openssl/ripemd.h /usr/include/openssl/rsa.h
routent.o: /usr/include/openssl/safestack.h /usr/include/openssl/sha.h
routent.o: /usr/include/openssl/stack.h /usr/include/openssl/symhacks.h
routent.o: /usr/include/stdint.h /usr/include/stdio.h /usr/include/stdlib.h
routent.o: /usr/include/sys/cdefs.h /usr/include/sys/select.h
routent.o: /usr/include/sys/sysmacros.h /usr/include/sys/timeb.h
routent.o: /usr/include/sys/time.h /usr/include/sys/types.h
routent.o: /usr/include/time.h /usr/include/unistd.h /usr/include/wchar.h
routent.o: /usr/include/xlocale.h
routent.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
routent.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
scheduler.o: log.h scheduler.h /usr/include/bits/confname.h
scheduler.o: /usr/include/bits/environments.h /usr/include/bits/posix_opt.h
scheduler.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
scheduler.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
scheduler.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
scheduler.o: /usr/include/bits/types.h /usr/include/bits/wchar.h
scheduler.o: /usr/include/bits/wordsize.h /usr/include/features.h
scheduler.o: /usr/include/_G_config.h /usr/include/gconv.h
scheduler.o: /usr/include/getopt.h /usr/include/gnu/stubs.h
scheduler.o: /usr/include/libio.h /usr/include/malloc.h /usr/include/stdio.h
scheduler.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
scheduler.o: /usr/include/sys/select.h /usr/include/sys/syslog.h
scheduler.o: /usr/include/sys/time.h /usr/include/time.h /usr/include/unistd.h
scheduler.o: /usr/include/wchar.h
scheduler.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
scheduler.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
utils.o: log.h /usr/include/alloca.h /usr/include/asm/errno.h
utils.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
utils.o: /usr/include/bits/confname.h /usr/include/bits/endian.h
utils.o: /usr/include/bits/environments.h /usr/include/bits/errno.h
utils.o: /usr/include/bits/local_lim.h /usr/include/bits/posix1_lim.h
utils.o: /usr/include/bits/posix2_lim.h /usr/include/bits/posix_opt.h
utils.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/sched.h
utils.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
utils.o: /usr/include/bits/sockaddr.h /usr/include/bits/socket.h
utils.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
utils.o: /usr/include/bits/types.h /usr/include/bits/uio.h
utils.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
utils.o: /usr/include/bits/wchar.h /usr/include/bits/wordsize.h
utils.o: /usr/include/bits/xopen_lim.h /usr/include/ctype.h
utils.o: /usr/include/endian.h /usr/include/errno.h /usr/include/features.h
utils.o: /usr/include/_G_config.h /usr/include/gconv.h /usr/include/getopt.h
utils.o: /usr/include/gnu/stubs.h /usr/include/libio.h /usr/include/limits.h
utils.o: /usr/include/linux/errno.h /usr/include/linux/limits.h
utils.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h
utils.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
utils.o: /usr/include/sys/select.h /usr/include/sys/socket.h
utils.o: /usr/include/sys/syslog.h /usr/include/sys/sysmacros.h
utils.o: /usr/include/sys/time.h /usr/include/sys/types.h
utils.o: /usr/include/sys/uio.h /usr/include/sys/un.h /usr/include/time.h
utils.o: /usr/include/unistd.h /usr/include/wchar.h /usr/include/xlocale.h
utils.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
utils.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
utils.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
utils.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h utils.h
