CFLAGS := -std=c99 -Wall -W
ifneq ($(shell uname),Darwin)
CFLAGS += -static
endif

CPPFLAGS := -D_GNU_SOURCE

ifdef DEBUG
CFLAGS += -g -O0
else
CFLAGS += -O -fomit-frame-pointer
endif

ifndef NOMUSL
CC := musl-gcc
endif

all: uutunnel
ifndef DEBUG
	strip $<
	upx -qqq $<
endif

clean:
	$(RM) uutunnel tests *.o

tests: uutunnel.c tests.c
	cc -DTESTS=1 -Wno-unused-function -g -O0 $(CPPFLAGS) $< -o $@

check: tests
	./tests
