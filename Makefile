CFLAGS= -Wall -Wextra -Werror -ggdb -Wno-unused-function -DMU_DEBUG

prog = revlookup
objects = revlookup.o mu.o
headers = xpthread.h mu.h uthash.h

all: $(prog)

revlookup: revlookup.o mu.o
	$(CC) -o $@ $^ -pthread

$(objects) : %.o : %.c $(headers)
	$(CC) -c -o $@ $(CFLAGS) $<

clean:
	rm -rf $(prog) $(objects)

.PHONY: all clean