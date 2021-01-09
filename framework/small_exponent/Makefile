#
#         Europäisches Institut für Systemsicherheit
#   Praktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch: Small Exponent
#
#-------------------------------------------------------------
#

include ../include/Makefile.Settings

SOURCE	= client.c
HEADER	= protocol.h
OBJ	= $(SOURCE:%.c=%.o)
CFLAGS  += -g -I.
LDFLAGS  += -lgmp

BINS	= client


all:	$(BINS)

client:	client.o
	$(CC) -o $@ $^ $(LDFLAGS)

client.o:	client.c	protocol.h


#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
