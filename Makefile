
CC=gcc
CFLAGS=-g -O2 -W -Wall -Wextra -pedantic -std=c99
LDLIBS=-lsodium -lm

SOURCES:=$(wildcard src/**/*.c src/*.c)
HEADERS:=$(wildcard src/**/*.h src/*.h)
OBJECTS:=$(patsubst %.c, build/%.o, $(notdir $(SOURCES)))

vpath % src
vpath % src/ecc
vpath % src/kdf
vpath % tests

TEST_SOURCES:=$(wildcard tests/*.c)
TEST_EXES:=$(basename $(patsubst %, build/%, $(TEST_SOURCES)))
TEST_HEADER:=tests/minunit.h

.PHONY: all test clean build

all: $(OBJECTS)
test: $(TEST_EXES)

build/tests/%: tests/%.c $(TEST_HEADER) $(OBJECTS)
	$(CC) $(CFLAGS) $(LDLIBS) -o $@ $< $(OBJECTS)

build/%.o: %.c $(HEADERS) | build
	$(CC) -c $(CFLAGS) -o $@ $<

build:
	@mkdir -p build/tests

clean:
	rm -rf ./build


