
CC=gcc
CFLAGS=-g -O2 -W -Wall -Wextra -pedantic -std=c99
CFLAGS32=-m32
LDLIBS=-lsodium -lm

SOURCES:=$(wildcard src/**/*.c src/*.c)
HEADERS:=$(wildcard src/**/*.h src/*.h)
OBJECTS:=$(patsubst %.c, build/%.o, $(notdir $(SOURCES)))

REF10_SOURCES:=$(wildcard ref10/ed25519/**/.c ref10/ed25519/*.c)
REF10_HEADERS:=$(wildcard ref10/ed25519/**/.h ref10/ed25519/*.h)
REF10_OBJECTS:=$(patsubst %.c, build/ref10/%.o, $(notdir $(REF10_SOURCES)))
REF10_FLAGS:=-Iref10/ed25519/nacl_includes -Iref10/ed25519/additions -Ied25519

CURVE_SOURCE:=curve25519-donna/curve25519-donna.c
CURVE_HEADER:=src/common/curve25519-donna.h
CURVE_OBJECT:=build/curve25519-donna/curve25519-donna.o

TEST_SOURCES:=$(wildcard tests/*.c)
TEST_EXES:=$(basename $(patsubst %, build/%, $(TEST_SOURCES)))
TEST_HEADER:=tests/minunit.h

vpath % src
vpath % src/ecc
vpath % src/kdf
vpath % ref10/ed25519
vpath % ref10/ed25519/additions
vpath % ref10/ed25519/nacl_includes
vpath % ref10/ed25519/nacl_sha512
vpath % curve25519-donna
# vpath % ref10/ed25519/main
vpath % tests

.PHONY: all test clean build

all: $(OBJECTS)
ref10: $(REF10_OBJECTS)
curve: $(CURVE_OBJECT)
test: $(TEST_EXES)
	./run_all_tests.sh

build/%.o: %.c $(HEADERS) $(REF10_OBJECTS) $(CURVE_OBJECT) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

build/ref10/%.o: ref10/ed25519/%.c $(REF10_HEADERS) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

$(CURVE_OBJECT) : $(CURVE_SOURCE) $(CURVE_HEADER) | build
	$(CC) -c $(CFLAGS) $(CFLAGS32) -o $@ $<

build/tests/%: tests/%.c $(TEST_HEADER) $(OBJECTS)
	$(CC) $(CFLAGS) $(LDLIBS) -o $@ $< $(OBJECTS)

build:
	@mkdir -p build/tests
	@mkdir -p build/ref10
	@mkdir -p build/curve25519-donna

clean:
	rm -rf ./build


