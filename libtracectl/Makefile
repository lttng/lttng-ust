all: libtracectl.so

libtracectl.so: tracectl.c
	gcc -g -shared -fPIC -I../libmarkers -I../libtracing -I../share -I../libustcomm -I. $(CFLAGS) -o libtracectl.so tracectl.c marker-control.c ../share/usterr.c ../libustcomm/ustcomm.c

clean:
	rm -rf *.so *.o

.PHONY: libtracectl.so
