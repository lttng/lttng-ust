all: ustd

ustd: ustd.c
	gcc -g -Wall -I ../libustcomm -I. -I ../../../../libkcompat -lpthread -o ustd ustd.c ../libustcomm/ustcomm.c

.PHONY: ustd
