all: hello

hello: hello.c
#dynamic version
	gcc -g -I../libmarkers -I../share -I../libtracing -L../libmarkers -lmarkers -L../libtracectl -ltracectl -L../libtracing -ltracing $(CFLAGS) -Wl,-rpath ../../../../urcu -o hello hello.c marker-control.c serialize.c
	# -Wl,--print-map

clean:
	rm -rf hello *.o

.PHONY: all hello clean
