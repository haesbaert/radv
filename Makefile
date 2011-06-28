PREFIX?=/usr/local
BINDIR=${PREFIX}/bin
MANDIR= ${PREFIX}/man/cat

PROG=	radv
SRCS=	radv.c

#MAN=	mdnsd.8

CFLAGS+= -g -Wall -I${.CURDIR} -I../
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
#LDADD+= -levent -lutil
#DPADD+= ${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
.include <bsd.man.mk>
