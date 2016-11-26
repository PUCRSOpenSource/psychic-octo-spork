
IDIR = ./include
SDIR = ./src
ODIR = ./obj

CC = gcc
CFLAGS = -I$(IDIR) -g -Wall -Wpedantic

_DEPS = dhcp.h monitor.h

DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = dhcp.o main.o monitor.o

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
