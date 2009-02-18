all: libtracectl.so

libtracectl.so: tracectl.c
	gcc -g -shared -fPIC -I../libmarkers -I../share $(CFLAGS) -o libtracectl.so tracectl.c

clean:
	rm -rf *.so *.o
