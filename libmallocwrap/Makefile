all: libmallocwrap.so

libmallocwrap.so: mallocwrap.c
	gcc -shared -fPIC -g -ldl -o libmallocwrap.so mallocwrap.c
