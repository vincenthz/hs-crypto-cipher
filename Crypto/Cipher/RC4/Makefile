# Makefile for the C files supporting Haskell RC4

.c.o :
	cc -std=c99 -O4 -c $<

RC4CLib.o: RC4H.hs

all: RC4CLib.o

clean:
	rm RC4H.hs RC4CLib.o
