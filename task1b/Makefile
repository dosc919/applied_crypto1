CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=aes.c aes_test.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=aes_test

all: run
	$(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

run: $(EXECUTABLE)
	./$(EXECUTABLE)

.PHONY: all run

clean:
	rm -rf $(EXECUTABLE) $(OBJECTS)