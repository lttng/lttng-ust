all: libmallocwrap.so

libmallocwrap.so: mallocwrap.c
	gcc -shared -fPIC -g -I../share -I../libmarkers -I../libtracing -I../libtracectl -L../libmarkers -L../libtracing -L../libtracectl $(CFLAGS) -ldl -lmarkers -o libmallocwrap.so mallocwrap.c

.PHONY: libmallocwrap.so
