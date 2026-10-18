# Userspace BTRFS library — btrfs-progs compliant
CC ?= cc
CFLAGS += -std=gnu2x -Wall -Wextra -Werror -pedantic \
          -I../third-party/btrfs-uapi \
          -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
AR ?= ar

SRCS = image.c super.c extent.c clone.c
OBJS = $(SRCS:.c=.o)
LIB = libubt.a

.PHONY: all clean universal

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

# Per-arch archives for macOS universal builds. Mirrors the top-level
# dedup.arm / dedup.x86_64 pattern: target-specific CFLAGS propagate to
# the shared object names, so the objects are wiped between slices.
libubt.arm: CFLAGS += -target arm64-apple-macos11
libubt.x86_64: CFLAGS += -target x86_64-apple-macos11

libubt.arm libubt.x86_64: $(OBJS)
	$(AR) rcs $@ $(OBJS)

# Rebuild $(LIB) as a fat (arm64 + x86_64) archive.
universal:
	rm -f $(OBJS)
	$(MAKE) libubt.arm
	rm -f $(OBJS)
	$(MAKE) libubt.x86_64
	rm -f $(OBJS)
	lipo -create -output $(LIB) libubt.arm libubt.x86_64

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(LIB) libubt.arm libubt.x86_64
