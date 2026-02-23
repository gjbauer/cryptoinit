CC = clang
CFLAGS = -Wall -W -O3 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE

all:
	$(CC) $(CFLAGS) -o cryptoinit *.c

clean:
	rm -f cryptoinit

.PHONY: clean