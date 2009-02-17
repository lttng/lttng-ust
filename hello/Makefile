all: hello

hello: hello.c
#dynamic version
	gcc -g -Wl,--print-map -I../libmarkers -I../share -I../libtracing -L../libmarkers -lmarkers -L../libtracectl -ltracectl -L../libtracing -ltracing -o hello hello.c marker-control.c serialize.c
#static version
#	gcc -g -I../libmarkers -I../share -I../libtracing -L../libmarkers -o hello hello.c marker-control.c serialize.c ../libtracing/*.c ../libmarkers/*.c ../libtracectl/*.c ../share/*.c

clean:
	rm -rf hello *.o

.PHONY: all hello clean
