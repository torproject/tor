SRC=args.c buffers.c cell.c circuit.c command.c connection.c connection_app.c connection_op.c connection_or.c config.c main.c onion.c routers.c
OBJ=${SRC:.c=.o}
PROGS=or
LIB=
LIBS=
INCLUDE = -I/usr/local/ssl/include

CFLAGS=  $(INCLUDE) -Wall -Wpointer-arith -ggdb
LDFLAGS = $(LIB) $(LIBS)

all:	${OBJ} ${PROGS}

or:	${OBJ}
	gcc -o or $(CFLAGS) *.o ../common/*.o -lcrypto -lpopt

clean:
	rm -f *.o ${PROGS}

