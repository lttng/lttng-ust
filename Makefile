CFLAGS="-I ../../../../urcu -I ../../../../libkcompat -Wl,-rpath ../../../../urcu"

all:
	CFLAGS=${CFLAGS} make -C libmarkers
	CFLAGS=${CFLAGS} make -C libtracing
	CFLAGS=${CFLAGS} make -C libtracectl
	CFLAGS=${CFLAGS} make -C hello
	CFLAGS=${CFLAGS} make -C libmallocwrap

.PHONY: all
