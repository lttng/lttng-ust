all: hello

hello: hello.c
	gcc -g -L../libtracectl -ltracectl -o hello hello.c

clean:
	rm -rf hello *.o
