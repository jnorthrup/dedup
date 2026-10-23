# Copyright © 2023 TTKB, LLC.

# this Makefile does it's best to implement the GNU standard targets (all,
# install, uninstall, clean, check, installcheck, & dist).
#
# `make list` for common commands

LANG = en

VERSION ?= 0.0.6

CFLAGS += \
    -std=gnu2x \
    -Wall -Wextra -Werror -pedantic \
    -Wpointer-arith \
    -Wno-unused-parameter \
    -Wno-gnu-conditional-omitted-operand \
    -Wno-macro-redefined \
    -Wimplicit-fallthrough \
    -Wp,-D_FORTIFY_SOURCE=3 \
    -fexceptions \
    -fpic \
    -fPIE \
    --param=ssp-buffer-size=4  \
    -m64 \
    -ftrapv \
    -pipe \
    -fstack-protector \
    -fno-omit-frame-pointer \
    -mtune=generic \
    -O \
    '-DVERSION="$(VERSION)"' \
    '-DBUILD_DATE="$(shell date '+%Y%m%d')"'

ifdef USE_LIBDISPATCH
CFLAGS += \
    -DUSE_LIBDISPATCH
endif

ifdef USE_ATOMICS
CFLAGS += \
    -DUSE_ATOMICS
endif

ENTITLEMENT_FLAGS =

OBJECTS = \
    dedup.o \
    alist.o \
    backend.o \
    clone.o \
    map.o \
    progress.o \
    queue.o \
    seen_set.o \
    utils.o \
    signature.o \
    sig_table.o \
    runtime_caps.o \
    runtime_dispatch.o \
    output_format.o \

.PHONY: \
    all install uninstall clean check dist distcheck \
    check-build check-test check-fast check-linux \
    check-spelling check-spelling-man check-spelling-readme \
    leaks-build \
    clean-coverage report-coverage \
    universal-dedup universal-dist \
	compiledb tidy \
    list mkdirs

all: dedup

# Optional userspace BTRFS backend (UBT=1 to enable)
ifdef UBT
CFLAGS += -DHAVE_UBT -Iubifs
LDFLAGS_UBT = -Lubifs -lubt
UBT_LIB = ubifs/libubt.a
UBT_SRCS = ubifs/image.c ubifs/super.c ubifs/extent.c ubifs/clone.c
# Host-arch backend archive, built on demand; universal builds replace
# it with a fat archive first (see dedup.universal). Keep UBT_SRCS in
# sync with SRCS in ubifs/Makefile.
ubifs/libubt.a: $(UBT_SRCS)
	$(MAKE) -C ubifs
else
LDFLAGS_UBT =
UBT_LIB =
endif

dedup.o: CFLAGS += -I/opt/homebrew/include

dedup.arm: CFLAGS += -target arm64-apple-macos11 -I/opt/homebrew/include
dedup.x86_64: CFLAGS += -target x86_64-apple-macos11 -I/opt/homebrew/include

dedup dedup.arm dedup.x86_64: $(OBJECTS) $(UBT_LIB)
	$(CC) $(CFLAGS) -o $@ $^ -L/opt/homebrew/lib -lxxhash $(LDFLAGS_UBT)
	mv $@ $@.unsigned
	codesign -s - -v -f $(ENTITLEMENT_FLAGS) $@.unsigned
	mv $@.unsigned $@

dedup.universal:
ifdef UBT
	$(MAKE) -C ubifs universal
endif
	rm -f *.o
	$(MAKE) dedup.arm
	rm -f *.o
	$(MAKE) dedup.x86_64
	lipo -create -output dedup.universal dedup.arm dedup.x86_64

universal-dedup: dedup.universal
	codesign -s - -v -f $(ENTITLEMENT_FLAGS) dedup.universal
	cp -c dedup.universal dedup

# leaks-build is a debug build without ASAN to be used with `leaks(1)`,
# Instruments, and other tools that don't want to evaluate libasan because it
# isn't a system library.
leaks-build: ENTITLEMENT_FLAGS = --entitlements entitlement.plist
leaks-build: CFLAGS += \
        -DNDEBUG \
        --coverage \
        -g \
        -O0
leaks-build: dedup
	dsymutil dedup
check-build: CFLAGS += \
    --coverage \
    -fsanitize=address \
    -fsanitize-address-use-after-return=always
check-build: leaks-build
check-test: check-build
	cd test && make check
check: check-test check-fast tidy check-spelling

# Self-contained regressions: no disk-image setup or mounted test volumes.
check-fast: dedup
	$(MAKE) -C test check-fast

check-linux:
	cd test && $(MAKE) check-linux

clean-coverage:
	find . -type f -name '*.gcda' -delete
	find . -type f -name '*.gcno' -delete
	find . -type f -name '*.gcov' -delete

clean: clean-coverage
	rm -f *.o
	rm -rf *.dSYM/
	rm -f *.tidy
	rm -f dedup dedup.arm dedup.x86_64 dedup.universal
	cd ubifs && $(MAKE) clean
	cd test && make clean
	rm -rf build

report-coverage:
	mkdir -p build/private/coverage
	geninfo . -o build/private/coverage.info --ignore-errors path
	genhtml build/private/coverage.info -o build/private/coverage

PREFIX ?= /usr/local

install: dedup mkdirs
	install dedup $(PREFIX)/bin
	install dedup.1 $(PREFIX)/share/man/man1

build/dist mkdirs:
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/share/man/man1

dist: PREFIX=build/dist
dist: check-spelling universal-dedup build/dist install
	cd build/dist; tar -Jcvf dedup-$(VERSION).tar.xz bin share
	cd build/dist; zip -r dedup-$(VERSION).zip bin share

dist-verify: check dist
	mkdir -p build/dist-check
	cd build/dist-check && tar xvJf ../dist/dedup-$(VERSION).tar.xz
	cd build/dist-check && test -x bin/dedup
	cd build/dist-check && test -f share/man/man1/dedup.1
	cd build/dist-check && file bin/dedup | grep -q 'Mach-O universal'
	cd build/dist-check && file bin/dedup | grep -q '(for architecture x86_64)'
	cd build/dist-check && file bin/dedup | grep -q '(for architecture arm64)'

uninstall:
	rm $(PREFIX)/bin/dedup
	rm $(PREFIX)/share/man/man1/dedup.1

distcheck: PREFIX=build/dist-check
distcheck: dist-verify uninstall

AFLAGS = \
    --lang="$(LANG)" \
    --encoding=utf-8 \
    --home-dir=. \
    --personal dict

check-spelling-man: dedup.1 dict
	! grep . <<< $$(cat dedup.1 | \
        tr '”' ' ' | \
	    aspell list $(AFLAGS) --mode nroff | \
	    sort -u | \
	    awk 'NF { printf "\033[0;31m$< >>>\033[0m %s\n", $$0 }')

check-spelling-readme: README.md dict
	! grep . <<< $$(cat README.md | \
	    aspell list $(AFLAGS) --mode markdown | \
	    sort -u | \
	    awk 'NF { printf "\033[0;31m$< >>>\033[0m %s\n", $$0 }')

check-spelling: check-spelling-readme check-spelling-man

compile_commands.json: SOURCES = $(OBJECTS:.o=.c)
compile_commands.json: $(OBJECTS)
	echo '[' > $@.tmp
	for o in $(SOURCES); do \
        printf \
        '  {\n\
      "directory": "$(PWD)",\n\
      "command": "$(CC) $(CFLAGS) -v -c -o %s.o %s",\n\
      "file": "%s"\n\
  },\n'\
    	$$(basename $$o .c) \
        $$o \
        $$o ; \
    done | sed '$$ s/.$$//' >> $@.tmp
	echo ']' >> $@.tmp
	mv $@.tmp $@
compiledb: compile_commands.json

%.tidy: %.c compiledb
	clang-tidy $< -- $(CFLAGS) | tee $@
	[ ! -s $@ ]
tidy: $(OBJECTS:.o=.tidy)

list:
	@echo "Noteworthy Targets:"
	@echo ""
	@echo "  GNU Standard:"
	@echo ""
	@echo "    all (default) - builds dedup"
	@echo "    install - build and install (to $(PREFIX))"
	@echo "    clean - remove generated files"
	@echo "    check - make a debug build, run tests, static analysis, check spelling"
	@echo "    dist - build a universal binary and create archives suitable for distribution"
	@echo "    distcheck - create a dist build, run unit tests, install to build/dist and verify the archive contents"
	@echo ""
	@echo "  Convenience"
	@echo ""
	@echo "    check-spelling - check spelling of README.md & dedup.1 using aspell"
	@echo "    tidy - run clang-tidy on sources"
	@echo "    check-fast - run self-contained safety, comparison, formatting and CLI tests"
	@echo "    report-coverage - generate a coverage report using lcov"
