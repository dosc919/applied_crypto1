CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=des_test.c des.c
OBJECTS=build/$(SOURCES:.c=.o)
EXECUTABLE=build/des_test

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