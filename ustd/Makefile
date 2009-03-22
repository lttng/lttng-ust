CFLAGS="-g -Wall"

all: ustd

lowlevel.o: lowlevel.c
	gcc -g -Wall -I ../libustcomm -I. -I ../../../../libkcompat -I ../libtracing -I ../share -I ../../../../urcu -I ../libmarkers -lpthread -c lowlevel.c

ustd.o: ustd.c
	gcc -g -Wall -I ../libustcomm -I. -I ../../../../libkcompat -lpthread -c ustd.c

ustcomm.o: ../libustcomm/ustcomm.c
	gcc -g -Wall -I ../share ../libustcomm/ustcomm.c

ustd: ustd.o lowlevel.o ustcomm.o
	gcc -g -Wall -lpthread -o ustd ustd.o lowlevel.o ustcomm.o

.PHONY: ustd
