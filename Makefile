prefix ?= /usr
bindir ?= $(prefix)/bin

DESTDIR ?= 

TARGET = dmcryptfile
LIBS = -lm
CC = gcc
CFLAGS = -g -Wall

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

install: $(TARGET)
	install -d $(DESTDIR)$(bindir)
	install -m 0755 $^ $(DESTDIR)$(bindir)

clean:
	-rm -f *.o
	-rm -f $(TARGET)

