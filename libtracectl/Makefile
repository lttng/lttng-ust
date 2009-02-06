all: libtracectl.so

libtracectl.so: tracectl.c
	gcc -g -shared -fPIC -o libtracectl.so tracectl.c

clean:
	rm -rf *.so *.o
