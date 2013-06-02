CC = gcc
DEBUG=no
AMD64=no
OBJECTSSRC = zeppoo.c hash.c md5.c memory.c mem.c kmem.c version.c symbols.c tasks.c syscalls.c idt.c vfs.c binaries.c 
OBJECTSLIB = zeppoo.o hash.o md5.o memory.o mem.o kmem.o version.o symbols.o tasks.o syscalls.o idt.o vfs.o binaries.o

ifeq ($(DEBUG),yes)
	export FLAGSDEBUG=-D_DEBUG_
endif

ifeq ($(AMD64),yes)
	export FLAGSAMD64=-D_AMD64_
endif

export CFLAGS=-Wall $(FLAGSDEBUG) $(FLAGSAMD64) -c -fPIC

libzeppoo.so: ${OBJECTSLIB}
	${CC} -o libzeppoo.so -shared ${OBJECTSLIB}
	
zeppoo.o: zeppoo.c
	${CC} ${CFLAGS} zeppoo.c

memory.o: memory.c
	${CC} ${CFLAGS} memory.c
	
mem.o: mem.c
	${CC} ${CFLAGS} mem.c

kmem.o: kmem.c
	${CC} ${CFLAGS} kmem.c

hash.o: hash.c
	${CC} ${CFLAGS} hash.c

md5.o: md5.c
	${CC} ${CFLAGS} md5.c
	
version.o: version.c
	${CC} ${CFLAGS} version.c

symbols.o: symbols.c
	${CC} ${CFLAGS} symbols.c

tasks.o: tasks.c
	${CC} ${CFLAGS} tasks.c

syscalls.o: syscalls.c
	${CC} ${CFLAGS} syscalls.c

idt.o: idt.c
	${CC} ${CFLAGS} idt.c

vfs.o: vfs.c
	${CC} ${CFLAGS} vfs.c

binaries.o: binaries.c
	${CC} ${CFLAGS} binaries.c

static: ${OBJECTSLIB}
	ar -q libzeppoo.a ${OBJECTSLIB}
	
#install:
#	cp -f libzeppoo.so /usr/lib/

#uninstall:
#	rm /usr/lib/libzeppoo.so

clean: 
	rm -f *.o
	rm -f *.a
	rm -f *.so
