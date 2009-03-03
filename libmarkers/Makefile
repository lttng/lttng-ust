all: libmarkers.so

libmarkers.so: marker.c *.c *.h
	gcc -g -fPIC -I../share -I../libtracing -I. -shared -o libmarkers.so -L../../../../urcu -I../../../../urcu $(CFLAGS) -lurcu marker.c tracepoint.c ../share/kref.c ../libtracing/channels.c

.PHONY: libmarkers.so all
