SRC=smtpap.c io.c
OBJ=${SRC:.c=.o}
PROGS=smtpap
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

${PROGS}:	${OBJ}
	$(LINK.c) -o $@ $(OBJ) ../common/log.o ../common/config.o ../common/utils.o -lpopt

# DO NOT DELETE


io.o: ../common/log.h ../common/utils.h io.h smtpap.h
io.o: /usr/include/bits/endian.h /usr/include/bits/pthreadtypes.h
io.o: /usr/include/bits/sched.h /usr/include/bits/select.h
io.o: /usr/include/bits/sigset.h /usr/include/bits/sockaddr.h
io.o: /usr/include/bits/stdio_lim.h /usr/include/bits/time.h
io.o: /usr/include/bits/types.h /usr/include/bits/wchar.h
io.o: /usr/include/endian.h /usr/include/features.h /usr/include/_G_config.h
io.o: /usr/include/gconv.h /usr/include/gnu/stubs.h /usr/include/libio.h
io.o: /usr/include/malloc.h /usr/include/stdio.h /usr/include/string.h
io.o: /usr/include/sys/cdefs.h /usr/include/syslog.h /usr/include/sys/select.h
io.o: /usr/include/sys/syslog.h /usr/include/sys/sysmacros.h
io.o: /usr/include/sys/time.h /usr/include/sys/types.h /usr/include/sys/un.h
io.o: /usr/include/time.h /usr/include/wchar.h /usr/include/xlocale.h
io.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
io.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
smtpap.o: ../common/config.h ../common/log.h ../common/ss.h ../common/utils.h
smtpap.o: ../common/version.h io.h smtpap.h /usr/include/alloca.h
smtpap.o: /usr/include/arpa/inet.h /usr/include/asm/errno.h
smtpap.o: /usr/include/asm/sigcontext.h /usr/include/asm/socket.h
smtpap.o: /usr/include/asm/sockios.h /usr/include/bits/byteswap.h
smtpap.o: /usr/include/bits/confname.h /usr/include/bits/endian.h
smtpap.o: /usr/include/bits/environments.h /usr/include/bits/errno.h
smtpap.o: /usr/include/bits/in.h /usr/include/bits/local_lim.h
smtpap.o: /usr/include/bits/netdb.h /usr/include/bits/posix1_lim.h
smtpap.o: /usr/include/bits/posix2_lim.h /usr/include/bits/posix_opt.h
smtpap.o: /usr/include/bits/pthreadtypes.h /usr/include/bits/resource.h
smtpap.o: /usr/include/bits/sched.h /usr/include/bits/select.h
smtpap.o: /usr/include/bits/sigaction.h /usr/include/bits/sigcontext.h
smtpap.o: /usr/include/bits/siginfo.h /usr/include/bits/signum.h
smtpap.o: /usr/include/bits/sigset.h /usr/include/bits/sigstack.h
smtpap.o: /usr/include/bits/sigthread.h /usr/include/bits/sockaddr.h
smtpap.o: /usr/include/bits/socket.h /usr/include/bits/stdio_lim.h
smtpap.o: /usr/include/bits/time.h /usr/include/bits/types.h
smtpap.o: /usr/include/bits/uio.h /usr/include/bits/waitflags.h
smtpap.o: /usr/include/bits/waitstatus.h /usr/include/bits/wchar.h
smtpap.o: /usr/include/bits/wordsize.h /usr/include/bits/xopen_lim.h
smtpap.o: /usr/include/ctype.h /usr/include/endian.h /usr/include/errno.h
smtpap.o: /usr/include/features.h /usr/include/_G_config.h
smtpap.o: /usr/include/gconv.h /usr/include/getopt.h /usr/include/gnu/stubs.h
smtpap.o: /usr/include/libio.h /usr/include/limits.h
smtpap.o: /usr/include/linux/errno.h /usr/include/linux/limits.h
smtpap.o: /usr/include/netdb.h /usr/include/netinet/in.h
smtpap.o: /usr/include/rpc/netdb.h /usr/include/signal.h /usr/include/stdint.h
smtpap.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h
smtpap.o: /usr/include/sys/cdefs.h /usr/include/syslog.h
smtpap.o: /usr/include/sys/resource.h /usr/include/sys/select.h
smtpap.o: /usr/include/sys/socket.h /usr/include/sys/syslog.h
smtpap.o: /usr/include/sys/sysmacros.h /usr/include/sys/time.h
smtpap.o: /usr/include/sys/types.h /usr/include/sys/ucontext.h
smtpap.o: /usr/include/sys/uio.h /usr/include/sys/un.h /usr/include/sys/wait.h
smtpap.o: /usr/include/time.h /usr/include/ucontext.h /usr/include/unistd.h
smtpap.o: /usr/include/wait.h /usr/include/wchar.h /usr/include/xlocale.h
smtpap.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/limits.h
smtpap.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stdarg.h
smtpap.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/stddef.h
smtpap.o: /usr/lib/gcc-lib/i386-redhat-linux/2.96/include/syslimits.h
