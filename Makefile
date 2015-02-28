CC=gcc
CFLAGS=-g -O2 -W -Wall -Wextra -pedantic -std=c99
# CFLAGS=-g -O2 -std=c99
LDLIBS=-lsodium -lm

SOURCES:=$(wildcard src/**/*.c src/*.c)
OBJECTS:=$(patsubst %.c, build/%.o, $(notdir $(SOURCES)))

TEST_SOURCES:=$(wildcard tests/*.c)
TEST_EXES:=$(basename $(patsubst %, build/%, $(TEST_SOURCES)))
TEST_HEADER:=tests/minunit.h

.PHONY: all tests clean build

all : $(OBJECTS)

test: $(TEST_EXES)

$(TEST_EXES): $(TEST_SOURCES) $(TEST_HEADER) $(OBJECTS) | build
	$(CC) $(CFLAGS) $(LDLIBS) -o $@ $^

$(OBJECTS) : $(SOURCES) | build
	$(CC) -c $(CFLAGS) -o $@ $^

build:
	@mkdir -p build/tests

clean:
	rm -rf ./build


