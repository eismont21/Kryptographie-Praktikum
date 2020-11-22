#
#         Europäisches Institut für Systemsicherheit
#   Praktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch: EC Pin
#
#-------------------------------------------------------------
#

include ../include/Makefile.Settings

CC = gcc
CFLAGS = -O1 -g -Wall

OBJECTS=	pin.o clientlib.o

pin: ${OBJECTS}
	cc  -o pin ${OBJECTS} ${LDFLAGS}

clean:
	rm -f ${OBJECTS} core *.core pin

pin.o: pin.h
clientlib.o: pin.h
