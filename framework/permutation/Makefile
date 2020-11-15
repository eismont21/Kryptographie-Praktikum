LIBOBJ = encrypt.o decrypt.o permio.o
ENOBJ = enmain.o libperm.a
DEOBJ = demain.o libperm.a
AOBJ = attacke.o libperm.a

CC = gcc
CFLAGS = -O1 -g -Wall

all: encrypt decrypt attacke

clean:
	rm -f *.o *~ *% libperm.a encrypt decrypt attacke

encrypt: $(ENOBJ)
	$(CC) -o $@ $(ENOBJ) $(LDFLAGS)

decrypt: $(DEOBJ)
	$(CC) -o $@ $(DEOBJ) $(LDFLAGS)

attacke: $(AOBJ)
	$(CC) -o $@ $(AOBJ) $(LDFLAGS)

enmain.o: endemain.c libperm.h
	$(CC) $(CFLAGS) -DENCRYPT -c endemain.c
	mv -f endemain.o enmain.o

demain.o: endemain.c libperm.h
	$(CC) $(CFLAGS) -DDECRYPT -c endemain.c
	mv -f endemain.o demain.o

encrypt.o: endecrypt.c
	$(CC) $(CFLAGS) -DENCRYPT -c endecrypt.c
	mv -f endecrypt.o encrypt.o

decrypt.o: endecrypt.c
	$(CC) $(CFLAGS) -DDECRYPT -c endecrypt.c
	mv -f endecrypt.o decrypt.o

libperm.a: $(LIBOBJ)
	rm -f $@
	ar rv $@ $(LIBOBJ)
	ranlib $@

$(LIBOBJ): libperm.h
