VPATH=../src:../tests

DEBUG=-DDEBUG -g
CFLAGS=-Wall -O3 $(DEBUG)
LDFLAGS=
CC=gcc
CXX=g++

OBJECTS= \
  fileio.o \
  macho.o

default: $(OBJECTS)
	$(CC) -o ../print_macho ../src/print_macho.c $(OBJECTS) \
	  $(CFLAGS) $(LDFLAGS)

%.o: %.c %.h
	$(CC) -c $< -o $*.o $(CFLAGS)

