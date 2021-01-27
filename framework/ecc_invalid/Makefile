#
#         Europäisches Institut für Systemsicherheit
#   Praktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch: ECC Invalid Points
#
#-------------------------------------------------------------
#

include ../include/Makefile.Settings

SOURCE	= ecc_client.c protocol.c
HEADER	= protocol.h
OBJ	= $(SOURCE:%.c=%.o)
CFLAGS  += -g -I.
LDFLAGS  += -lgmp

BINS	= ecc_client


all:	$(BINS)

ecc_client:	ecc_client.o protocol.o invalid_curves.o
	$(CC) -o $@ $^ $(LDFLAGS)

ecc_client.o:	ecc_client.c	protocol.h
protocol.o:	protocol.c	protocol.h

#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
