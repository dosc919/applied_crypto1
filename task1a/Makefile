CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=des_test.c des.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=des_test

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