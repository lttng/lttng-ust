all: hello

hello: hello.c
	gcc -g -I../libmarkers -I../share -I../libtracing -L../libmarkers -lmarkers -L../libtracectl -ltracectl -L../libtracing -ltracing -o hello hello.c serialize.c

clean:
	rm -rf hello *.o

.PHONY: all hello clean
