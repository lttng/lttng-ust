#all: libbasic.so prog libbasic-noscript.so prog_noscript
all: libbasic.so prog

libbasic.so: basic_lib.o
	gcc -g $(LDFLAGS) -fPIC -o libbasic.so -shared -lust basic_lib.o
libbasic-noscript.so: basic_lib_noscript.o
	gcc -g $(LDFLAGS) -fPIC -o libbasic-noscript.so -shared basic_lib_noscript.o /usr/local/lib/libust.so.0 /usr/local/lib/libust-initializer.o

basic_lib.o: basic_lib.c
	gcc -g $(CFLAGS) -DCONFIG_UST_GDB_INTEGRATION -fPIC -c basic_lib.c
basic_lib_noscript.o: basic_lib.c
	gcc -g -DCONFIG_UST_GDB_INTEGRATION -fPIC -o basic_lib_noscript.o -c basic_lib.c

prog: prog.c
	gcc -g -DCONFIG_UST_GDB_INTEGRATION $(CFLAGS) $(LDFLAGS) -o prog -L . -lbasic -lust prog.c
prog_noscript: prog.c
	gcc -g -DCONFIG_UST_GDB_INTEGRATION -o prog_noscript -L . -lbasic-noscript prog.c /usr/local/lib/libust.so.0 /usr/local/lib/libust-initializer.o

.PHONY: clean
clean:
	rm -f basic_lib.o libbasic.so prog basic_lib_noscript.o libbasic-noscript.so
