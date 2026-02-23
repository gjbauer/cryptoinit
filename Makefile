CC = gcc
CFLAGS = -Wall -W -O3 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE

GOAL = cryptosift
OBJ  = main.o aes.o

all: $(GOAL)

cross: CC = i386-mingw32-gcc
cross: STRIP= i386-mingw32-strip
cross: EXT = .exe
cross: $(GOAL).exe

cryptosift.exe: $(OBJ)
	$(CC) $(CFLAGS) -o cryptosift.exe $(OBJ)
	$(STRIP) cryptosift.exe

cryptosift: $(OBJ)
	$(CC) $(CFLAGS) -o cryptosift $(OBJ)

nice:
	rm -f *~

clean: nice
	rm -f $(GOAL) $(GOAL).exe $(OBJ)

DESTDIR = $(GOAL)-1.2

package: clean cross
	rm -rf $(DESTDIR) $(DESTDIR).zip
	mkdir $(DESTDIR)
	cp main.c aes.c aes.h Makefile findaes.exe $(DESTDIR)
	zip -r9 $(DESTDIR).zip $(DESTDIR)
	rm -rf $(DESTDIR)
