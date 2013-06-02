CC = gcc
DEBUG=no
AMD64=no
MYFLAGS =
LIB_DIR=libzeppoo
OBJECTSSRC = main.c tasks.c syscalls.c idt.c symbols.c vfs.c binaries.c fingerprints.c
OBJECTS = main.o tasks.o syscalls.o idt.o symbols.o vfs.o binaries.o fingerprints.o

ifeq ($(DEBUG),yes)
	export FLAGSDEBUG=-D_DEBUG_
endif

ifeq ($(AMD64),yes)
	export FLAGSAMD64=-D_AMD64_
endif


export CFLAGS=-Wall $(FLAGSDEBUG) $(FLAGSAMD64) -c

all: lib zeppoo

lib: 
	@(cd $(LIB_DIR) && $(MAKE))

zeppoo: ${OBJECTS}
	${CC} -o zeppoo ${OBJECTS} libzeppoo/libzeppoo.so
	
main.o: main.c
	${CC} ${CFLAGS} main.c

tasks.o: tasks.c
	${CC} ${CFLAGS} tasks.c

syscalls.o: syscalls.c
	${CC} ${CFLAGS} syscalls.c

idt.o: idt.c
	${CC} ${CFLAGS} idt.c

symbols.o: symbols.c
	${CC} ${CFLAGS} symbols.c

vfs.o: vfs.c
	${CC} ${CFLAGS} vfs.c

binaries.o: binaries.c
	${CC} ${CFLAGS} binaries.c

fingerprints.o: fingerprints.c
	${CC} ${CFLAGS} fingerprints.c

static: ${OBJECTS}
	@(cd $(LIB_DIR) && $(MAKE) static)
	${CC} -o zeppoo ${OBJECTSSRC} libzeppoo/libzeppoo.a
	
clean: 
	@(cd $(LIB_DIR) && $(MAKE) clean)
	rm -f *.o
	rm -f zeppoo 
