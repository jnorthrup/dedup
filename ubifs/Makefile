# Userspace BTRFS library — btrfs-progs compliant
CC ?= cc
CFLAGS += -std=gnu2x -Wall -Wextra -Werror -pedantic \
          -I../third-party/btrfs-uapi \
          -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
AR ?= ar

SRCS = image.c super.c
OBJS = $(SRCS:.c=.o)
LIB = libubt.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(LIB)
