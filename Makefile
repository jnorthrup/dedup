# Copyright © 2023 TTKB, LLC.

# this Makefile does it's best to implement the GNU standard targets (all,
# install, uninstall, clean, check, installcheck, & dist).
#
# `make list` for common commands

LANG = en

VERSION ?= 0.0.6

.DEFAULT_GOAL := all

COMMON_CFLAGS = \
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
FEATURE_CPPFLAGS += -DUSE_LIBDISPATCH
endif

ifdef USE_ATOMICS
FEATURE_CPPFLAGS += -DUSE_ATOMICS
endif

ENTITLEMENT_FLAGS ?=

OBJECT_NAMES = \
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

# Every mode owns its objects, dependency files, archive and executable.
# A configuration stamp also invalidates a mode when flags or tools change.
BUILD_MODE ?= release
BUILD_DIR = build/$(BUILD_MODE)
MODE_CFLAGS_leaks = -DNDEBUG --coverage -g -O0
MODE_CFLAGS_check = $(MODE_CFLAGS_leaks) -fsanitize=address -fsanitize-address-use-after-return=always
MODE_CFLAGS_arm64 = -target arm64-apple-macos11
MODE_CFLAGS_x86_64 = -target x86_64-apple-macos11
MODE_ENTITLEMENTS_leaks = --entitlements entitlement.plist
MODE_ENTITLEMENTS_check = $(MODE_ENTITLEMENTS_leaks)
BUILD_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS) $(MODE_CFLAGS_$(BUILD_MODE))
BUILD_CPPFLAGS = -I/opt/homebrew/include $(CPPFLAGS) $(FEATURE_CPPFLAGS)
BUILD_LDFLAGS = -L/opt/homebrew/lib $(LDFLAGS)
BUILD_ENTITLEMENTS = $(ENTITLEMENT_FLAGS) $(MODE_ENTITLEMENTS_$(BUILD_MODE))
OBJECTS = $(addprefix $(BUILD_DIR)/,$(OBJECT_NAMES))
BUILD_BINARY = $(BUILD_DIR)/dedup
BUILD_CONFIG = $(BUILD_DIR)/.build-config

# Quote arbitrary flag strings for the shell when recording the configuration.
shquote = '$(subst ','"'"',$(1))'

.PHONY: \
    all install uninstall clean check dist distcheck \
    build-binary FORCE check-build check-test check-fast check-linux check-build-system \
    check-spelling check-spelling-man check-spelling-readme \
    leaks-build \
    clean-coverage report-coverage \
    universal-dedup universal-dist \
    compiledb tidy \
    list mkdirs

all: dedup

# Optional userspace BTRFS backend (UBT=1 to enable). Build this library with
# the same flags and architecture as its consumer instead of sharing objects.
ifdef UBT
FEATURE_CPPFLAGS += -DHAVE_UBT -Iubifs
UBT_SRCS = ubifs/image.c ubifs/super.c ubifs/extent.c ubifs/clone.c
UBT_OBJECTS = $(addprefix $(BUILD_DIR)/,$(UBT_SRCS:.c=.o))
UBT_LIB = $(BUILD_DIR)/ubifs/libubt.a
$(UBT_OBJECTS): BUILD_CPPFLAGS += -Ithird-party/btrfs-uapi -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
$(UBT_LIB): $(UBT_OBJECTS)
	$(AR) rcs $@ $^
endif

FORCE:

$(BUILD_CONFIG): FORCE
	@mkdir -p $(dir $@)
	@printf '%s\n' $(call shquote,CC=$(CC)) $(call shquote,AR=$(AR)) \
	    $(call shquote,CPPFLAGS=$(BUILD_CPPFLAGS)) $(call shquote,CFLAGS=$(BUILD_CFLAGS)) \
	    $(call shquote,LDFLAGS=$(BUILD_LDFLAGS)) $(call shquote,LDLIBS=$(LDLIBS)) \
	    $(call shquote,ENTITLEMENTS=$(BUILD_ENTITLEMENTS)) > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@

$(BUILD_DIR)/%.o: %.c $(BUILD_CONFIG)
	@mkdir -p $(dir $@)
	rm -f $(@:.o=.gcda)
	$(CC) $(BUILD_CPPFLAGS) $(BUILD_CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD_BINARY): $(OBJECTS) $(UBT_LIB) $(BUILD_CONFIG) $(if $(MODE_ENTITLEMENTS_$(BUILD_MODE)),entitlement.plist)
	$(CC) $(BUILD_CFLAGS) $(BUILD_LDFLAGS) -o $@ $(OBJECTS) $(UBT_LIB) -lxxhash $(LDLIBS)
	codesign -s - -v -f $(BUILD_ENTITLEMENTS) $@

build-binary: $(BUILD_BINARY)

dedup: $(BUILD_BINARY) FORCE
	@cmp -s $< $@ || cp $< $@

dedup.arm: FORCE
	$(MAKE) BUILD_MODE=arm64 build-binary
	cp build/arm64/dedup $@

dedup.x86_64: FORCE
	$(MAKE) BUILD_MODE=x86_64 build-binary
	cp build/x86_64/dedup $@

dedup.universal: dedup.arm dedup.x86_64
	lipo -create -output $@ $^

universal-dedup: dedup.universal
	codesign -s - -v -f $(ENTITLEMENT_FLAGS) dedup.universal
	cp -c dedup.universal dedup

# Instrumented binaries never replace the release executable at ./dedup.
leaks-build:
	$(MAKE) BUILD_MODE=leaks build-binary
	dsymutil build/leaks/dedup

check-build:
	$(MAKE) BUILD_MODE=check build-binary
	dsymutil build/check/dedup

check-test: check-build
	$(MAKE) -C test check $(call shquote,DEDUP_TEST_BINARY=$(abspath build/check/dedup))

check: check-test
	$(MAKE) check-fast tidy check-spelling

# Self-contained regressions: no disk-image setup or mounted test volumes.
check-fast: check-build
	$(MAKE) -C test check-fast $(call shquote,DEDUP_TEST_BINARY=$(abspath build/check/dedup))

check-build-system:
	python3 test/build_test.py

check-linux:
	$(MAKE) -C test check-linux

-include $(OBJECTS:.o=.d) $(UBT_OBJECTS:.o=.d)

clean-coverage:
	find . -type f -name '*.gcda' -delete
	find . -type f -name '*.gcno' -delete
	find . -type f -name '*.gcov' -delete

clean: clean-coverage
	rm -f *.o *.d
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

compile_commands.json: $(OBJECTS) $(BUILD_CONFIG)
	@python3 -c 'import json, shlex, sys; root, cc, flags, out, *sources = sys.argv[1:]; print(json.dumps([{"directory": root, "arguments": shlex.split(cc) + shlex.split(flags) + ["-c", "-o", out + "/" + source[:-2] + ".o", source], "file": source} for source in sources], indent=2))' \
	    $(call shquote,$(CURDIR)) $(call shquote,$(CC)) \
	    $(call shquote,$(BUILD_CPPFLAGS) $(BUILD_CFLAGS)) $(call shquote,$(BUILD_DIR)) \
	    $(OBJECT_NAMES:.o=.c) > $@.tmp
	mv $@.tmp $@
compiledb: compile_commands.json

%.tidy: %.c compiledb .clang-tidy
	@clang-tidy $< -- $(BUILD_CPPFLAGS) $(BUILD_CFLAGS) > $@.tmp 2>&1 || { cat $@.tmp; rm -f $@.tmp; exit 1; }
	@cat $@.tmp
	@mv $@.tmp $@
tidy: $(OBJECT_NAMES:.o=.tidy)

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
	@echo "    check-build-system - verify build isolation, flags and header dependencies"
	@echo "    report-coverage - generate a coverage report using lcov"
