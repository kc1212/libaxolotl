
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
test: $(TEST_EXES)
	./run_all_tests.sh

build/%.o: src/%.c $(HEADERS) $(REF10_OBJECTS) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

build/ref10/%.o: ref10/ed25519/%.c $(REF10_HEADERS) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

build/ref10/%.o: ref10/ed25519/additions/%.c $(REF10_HEADERS) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

build/ref10/%.o: ref10/ed25519/nacl_sha512/%.c $(REF10_HEADERS) | build
	$(CC) -c $(CFLAGS) $(REF10_FLAGS) -o $@ $<

build/tests/%: tests/%.c $(TEST_HEADER) $(OBJECTS)
	$(CC) $(CFLAGS) $(LDLIBS) $(REF10_FLAGS) -o $@ $< $(OBJECTS) $(REF10_OBJECTS)

build:
	@mkdir -p build/tests
	@mkdir -p build/ref10

clean:
	rm -rf ./build


