CC=gcc
CFLAGS=-I.
DEPS = mydump.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

mydump: mydump.o
	gcc -lpcap -o mydump mydump.o -I.

clean:
	rm -f *.o mydump