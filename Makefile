
IDIR = ./include
SDIR = ./src
ODIR = ./obj

CC = gcc
CFLAGS = -I$(IDIR) -g -Wall -Wpedantic -pthread

_DEPS = dhcp.h monitor.h checksum.h sniffer.h

DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = main.o monitor.o checksum.o sniffer.o

OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

all: main

$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean run

run: main
	./main

clean:
	rm -f $(ODIR)/*.o
	rm -f main
