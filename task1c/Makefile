CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=keccak_mac.c
OBJECTS=build/$(SOURCES:.c=.o)
EXECUTABLE=build/keccak_mac

all: run
	$(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

build/%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

run: $(EXECUTABLE)
	./$(EXECUTABLE)

.PHONY: all run

clean:
	rm -rf $(EXECUTABLE) $(OBJECTS)