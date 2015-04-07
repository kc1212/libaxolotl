
CC=gcc
CFLAGS=-g -W -Wall -Wextra -pedantic -std=c99
LDLIBS=-lsodium -lm

SOURCES:=$(wildcard src/*.c)
HEADERS:=$(wildcard src/*.h)
OBJECTS:=$(patsubst %.c, build/%.o, $(notdir $(SOURCES)))

REF10_SOURCES:=$(wildcard ref10/ed25519/additions/*.c ref10/ed25519/nacl_sha512/*.c ref10/ed25519/*.c)
REF10_HEADERS:=$(wildcard ref10/ed25519/**/*.h ref10/ed25519/*.h)
REF10_OBJECTS:=$(patsubst %.c, build/ref10/%.o, $(notdir $(REF10_SOURCES)))
REF10_FLAGS:=-Iref10/ed25519/nacl_includes -Iref10/ed25519/additions -Iref10/ed25519

# TODO we need an option to set to 32 or 64
# the axolotl branch should be used for curve25519-donna
CURVE_SOURCE:=curve25519-donna/curve25519-donna-c64.c
CURVE_HEADER:=src/curve25519-donna.h
CURVE_OBJECT:=build/curve25519-donna/curve25519-donna-c64.o

TEST_SOURCES:=$(wildcard tests/*.c)
TEST_EXES:=$(basename $(patsubst %, build/%, $(TEST_SOURCES)))
TEST_HEADER:=tests/minunit.h

vpath % src
vpath % ref10/ed25519
vpath % ref10/ed25519/additions
vpath % ref10/ed25519/nacl_sha512
# vpath % ref10/ed25519/main
vpath % tests

.PHONY: all test clean build ref10

all: $(OBJECTS)
ref10: $(REF10_OBJECTS)
curve: $(CURVE_OBJECT)
test: $(TEST_EXES)
	./run_all_tests.sh

build/%.o: src/%.c $(HEADERS) $(REF10_OBJECTS) $(CURVE_OBJECT)| build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

build/ref10/%.o: ref10/ed25519/%.c $(REF10_HEADERS) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

build/ref10/%.o: ref10/ed25519/additions/%.c $(REF10_HEADERS) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

build/ref10/%.o: ref10/ed25519/nacl_sha512/%.c $(REF10_HEADERS) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

$(CURVE_OBJECT) : $(CURVE_SOURCE) $(CURVE_HEADER) | build
	$(CC) -c $(CFLAGS) -o $@ $<

build/tests/%: tests/%.c $(TEST_HEADER) $(OBJECTS)
	$(CC) $(CFLAGS) $(LDLIBS) $(REF10_FLAGS) -o $@ $< $(OBJECTS) $(REF10_OBJECTS) $(CURVE_OBJECT)

build:
	@mkdir -p build/tests
	@mkdir -p build/ref10
	@mkdir -p build/curve25519-donna

clean:
	rm -rf ./build


