SRC=httpap.c http.c
OBJ=${SRC:.c=.o}
PROGS=httpap
LIB=
LIBS=
INCLUDE =

CFLAGS= $(INCLUDE) -Wall -Wpointer-arith -O2 -ggdb
LDFLAGS = $(LIB) $(LIBS)

all:	${PROGS}

clean:
	rm -f *.o ${PROGS}

depend:
	makedepend -- ${CFLAGS} -- ${SRC}

httpap:	${OBJ}
	$(LINK.c) -o $@ $(OBJ) ../common/log.o ../common/config.o ../common/utils.o -lpopt

# DO NOT DELETE


httpap.o: ../common/config.h ../common/log.h ../common/ss.h ../common/utils.h
httpap.o: ../common/version.h httpap.h http.h /usr/include/alloca.h
httpap.o: /usr/include/arpa/inet.h /usr/include/asm/errno.h
httpap.o: /usr/include/asm/sigcontext.h /usr/include/asm/socket.h
httpap.o: /usr/include/asm/sockios.h /usr/include/bits/byteswap.h
httpap.o: /usr/include/bits/confname.h /usr/include/bits/endian.h
httpap.o: /usr/include/bits/environments.h /usr/include/bits/errno.h
httpap.o: /usr/include/bits/in.h /usr/include/bits/local_lim.h
httpap.o: /usr/include/bits/netdb.h /usr/include/bits/posix1_lim.h
httpap.o: /usr/include/bits/posix2_lim.h /usr/include/bits/posix_opt.h
httpap.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/resource.h
httpap.o: /usr/include/bits/sched.h /usr/include/bits/select.h
httpap.o: /usr/include/bits/sigaction.h /usr/include/bits/sigcontext.h
httpap.o: /usr/include/bits/siginfo.h /usr/include/bits/signum.h
httpap.o: /usr/include/bits/sigset.h /usr/include/bits/sigstack.h
httpap.o: /usr/include/bits/sigthread.h /usr/include/bits/sockaddr.h
httpap.o: /usr/include/bits/socket.h /usr/include/bits/stdio_lim.h
httpap.o: /usr/include/bits/time.h /usr/include/bits/types.h
httpap.o: /usr/include/bits/uio.h /usr/include/bits/waitflags.h
httpap.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
httpap.o: /usr/include/bits/wordsize.h /usr/include/bits/xopen_lim.h
httpap.o: /usr/include/ctype.h /usr/include/endian.h /usr/include/errno.h
httpap.o: /usr/include/features.h /usr/include/_G_config.h
httpap.o: /usr/include/gconv.h /usr/include/getopt.h /usr/include/gnu/stubs.h
httpap.o: /usr/include/libio.h /usr/include/limits.h
httpap.o: /usr/include/linux/errno.h /usr/include/linux/limits.h
httpap.o: /usr/include/netdb.h /usr/include/netinet/in.h
httpap.o: /usr/include/rpc/netdb.h /usr/include/signal.h /usr/include/stdint.h
httpap.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h
httpap.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
httpap.o: /usr/include/sys/resource.h /usr/include/sys/select.h
httpap.o: /usr/include/sys/socket.h /usr/include/sys/syslog.h
httpap.o: /usr/include/sys/sysmacros.h /usr/include/sys/time.h
httpap.o: /usr/include/sys/types.h /usr/include/sys/ucontext.h
httpap.o: /usr/include/sys/uio.h /usr/include/sys/un.h /usr/include/sys/wait.h
httpap.o: /usr/include/time.h /usr/include/ucontext.h /usr/include/unistd.h
httpap.o: /usr/include/wait.h /usr/include/wchar.h /usr/include/xlocale.h
httpap.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
httpap.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
httpap.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
httpap.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h
http.o: ../common/log.h ../common/utils.h http.h /usr/include/alloca.h
http.o: /usr/include/arpa/inet.h /usr/include/asm/errno.h
http.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
http.o: /usr/include/bits/byteswap.h /usr/include/bits/confname.h
http.o: /usr/include/bits/endian.h /usr/include/bits/environments.h
http.o: /usr/include/bits/errno.h /usr/include/bits/in.h
http.o: /usr/include/bits/local_lim.h /usr/include/bits/netdb.h
http.o: /usr/include/bits/posix1_lim.h /usr/include/bits/posix2_lim.h
http.o: /usr/include/bits/posix_opt.h /usr/include/bits/pthreadtypes.h
http.o: /usr/include/bits/sched.h /usr/include/bits/select.h
http.o: /usr/include/bits/siginfo.h /usr/include/bits/sigset.h
http.o: /usr/include/bits/sockaddr.h /usr/include/bits/socket.h
http.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
http.o: /usr/include/bits/types.h /usr/include/bits/uio.h
http.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
http.o: /usr/include/bits/wchar.h /usr/include/bits/wordsize.h
http.o: /usr/include/bits/xopen_lim.h /usr/include/ctype.h
http.o: /usr/include/endian.h /usr/include/errno.h /usr/include/features.h
http.o: /usr/include/_G_config.h /usr/include/gconv.h /usr/include/getopt.h
http.o: /usr/include/gnu/stubs.h /usr/include/libio.h /usr/include/limits.h
http.o: /usr/include/linux/errno.h /usr/include/linux/limits.h
http.o: /usr/include/netdb.h /usr/include/netinet/in.h
http.o: /usr/include/rpc/netdb.h /usr/include/stdint.h /usr/include/stdio.h
http.o: /usr/include/stdlib.h /usr/include/string.h /usr/include/sys/cdefs.h
http.o: /usr/include/syslog.h /usr/include/sys/select.h
http.o: /usr/include/sys/socket.h /usr/include/sys/syslog.h
http.o: /usr/include/sys/sysmacros.h /usr/include/sys/time.h
http.o: /usr/include/sys/types.h /usr/include/sys/uio.h /usr/include/sys/un.h
http.o: /usr/include/time.h /usr/include/unistd.h /usr/include/wchar.h
http.o: /usr/include/xlocale.h
http.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
http.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
http.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
http.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h
