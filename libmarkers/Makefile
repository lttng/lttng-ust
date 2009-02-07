all: libmarkers.so

libmarkers.so: marker.c *.c *.h
	gcc -g -fPIC -I../share -I../libtracing -shared -o libmarkers.so marker.c
