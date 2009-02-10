all: libtracing.so

libtracing.so: *.c *.h
	gcc -g -fPIC -I../share -I../libtracing -shared -o libtracing.so *.c

.PHONY: libtracing.so all
