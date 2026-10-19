CFLAGS += \
    -I/opt/homebrew/include \
	-std=c2x \
    -Wall -Wextra -Werror -pedantic \
    -Wpointer-arith \
    -Wno-unused-parameter \
    -Wp,-D_FORTIFY_SOURCE=2 \
    -fexceptions \
    -fpic \
    -fprofile-arcs \
    -Wno-macro-redefined \
    --param=ssp-buffer-size=4  \
    -grecord-gcc-switches \
    -m64 \
    -ftrapv \
    -pipe \
    -ftest-coverage \
    -fstack-protector \
    -fsanitize=address \
    -g \
    -Wno-gnu-zero-variadic-macro-arguments \
    -mtune=generic \
    -fPIE \
    -Og

LDFLAGS += \
    -L/opt/homebrew/lib

.PHONY: \
	check check-linux \
    setup setup-all setup-clonefile setup-symlink setup-link \
    clean clean-test-data clean-clonefile clean-symlink clean-link

%.o: %.c %.h
	rm -f $(basename $<).gcda $(basename $<).gcno
	$(CC) $(CFLAGS) -c -o $@ $<

check: dedup_check setup-all
	./dedup_check
	hdiutil detach /Volumes/dedup-test-hfs-clonefile
	hdiutil detach /Volumes/dedup-test-hfs-link
	hdiutil detach /Volumes/dedup-test-hfs-symlink

# Linux CI target: uses tmpfs/scratch dirs, no mount privileges needed.
# Clone/HFS suites skipped unless running as root with btrfs loop device.
# Symlink+link suites are the primary gates.
check-linux: dedup_check setup-linux
	./dedup_check --suite dedup_symlink
	./dedup_check --suite dedup_link
	@if [ "$(shell id -u)" = "0" ] && losetup -f >/dev/null 2>&1; then \
		echo "root + loop available — running clone suite"; \
		./dedup_check --suite dedup; \
	else \
		echo "skipping clone suite (needs root + loop btrfs)"; \
	fi
	rm -rf test-data-linux

setup-linux:
	rm -rf test-data-linux
	mkdir -p test-data-linux/{bars,empty,big,same-size,same-first-last}
	# "bar" test data
	cd test-data-linux/bars && echo "foo" > bar && cp bar bar2 && ln bar bar3 && cp bar bar4 && cp bar bar5
	# "empty" test data
	cd test-data-linux/empty && touch empty && touch empty2
	# "big" test data
	dd if=/dev/urandom of=test-data-linux/big/big bs=1M count=4 2>/dev/null
	dd if=/dev/urandom of=test-data-linux/big/big2 bs=1M count=4 2>/dev/null
	# "same-size" test data
	dd if=/dev/zero of=test-data-linux/same-size/big bs=1M count=1 2>/dev/null
	dd if=/dev/zero of=test-data-linux/same-size/big2 bs=1M count=1 2>/dev/null
	# "same-first-last" test data
	dd if=/dev/urandom of=test-data-linux/same-first-last/big bs=1M count=4 2>/dev/null
	dd if=/dev/urandom of=test-data-linux/same-first-last/big2 bs=1M count=4 2>/dev/null
	echo "a" > test-data-linux/same-first-last/same-1
	cat test-data-linux/same-first-last/big >> test-data-linux/same-first-last/same-1
	echo "z" >> test-data-linux/same-first-last/same-1
	echo "a" > test-data-linux/same-first-last/same-2
	cat test-data-linux/same-first-last/big2 >> test-data-linux/same-first-last/same-2
	echo "z" >> test-data-linux/same-first-last/same-2

dedup_check: dedup_check.o dedup_suite.o dedup_link_suite.o dedup_symlink_suite.o clone_suite.o signature_suite.o runtime_dispatch_suite.o test_utils.o runtime_caps_test.o runtime_dispatch_test.o alist_test.o clone_test.o map_test.o utils_test.o signature_test.o
	rm -f dedup_check.gcda dedup_check.gcno
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -l check $^

alist_test.o: ../alist.c ../alist.h
	rm -f alist_test.gcda alist_test.gcno
	$(CC) $(CFLAGS) -c -o $@ ../alist.c

clone_test.o: ../clone.c ../clone.h
	rm -f clone_test.gcda clone_test.gcno
	$(CC) $(CFLAGS) -c -o $@ ../clone.c

map_test.o: ../map.c ../map.h
	rm -f map_test.gcda map_test.gcno
	$(CC) $(CFLAGS) -c -o $@ ../map.c

utils_test.o: ../utils.c ../utils.h
	rm -f utils_test.gcda utils_test.gcno
	$(CC) $(CFLAGS) -c -o $@ ../utils.c

signature_test.o: ../signature.c ../signature.h
	rm -f signature_test.gcda signature_test.gcno
	$(CC) $(CFLAGS) -c -o $@ ../signature.c

runtime_caps_test.o: ../runtime_caps.c ../runtime_caps.h
	rm -f runtime_caps_test.gcda runtime_caps_test.gcno
	$(CC) $(CFLAGS) -c -o $@ ../runtime_caps.c

runtime_dispatch_test.o: ../runtime_dispatch.c ../runtime_dispatch.h ../runtime_caps.h ../signature.h
	rm -f runtime_dispatch_test.gcda runtime_dispatch_test.gcno
	$(CC) $(CFLAGS) -c -o $@ ../runtime_dispatch.c

# clean-test-data: NAMESPACE ?= .
clean-test-data:
	if [[ -d /Volumes/dedup-test-hfs-$(NAMESPACE) ]]; then \
	    hdiutil detach /Volumes/dedup-test-hfs-$(NAMESPACE); \
	fi
	if [[ -f test-data/$(NAMESPACE)/clone-dst-acls/.~.bar4 ]]; then \
	    chflags nouchg test-data/$(NAMESPACE)/clone-dst-acls/.~.bar4; \
	fi
	if [[ -f test-data/$(NAMESPACE)/clone-dst-acls/bar4 ]]; then \
	    chflags nouchg test-data/$(NAMESPACE)/clone-dst-acls/bar4; \
	fi
	if [[ -d test-data/$(NAMESPACE)/mtime-immutable ]]; then \
	    chflags nouchg test-data/$(NAMESPACE)/mtime-immutable; \
	fi
	rm -rf test-data/$(NAMESPACE)


#make-link-dmg: NAMESPACE=link
#make-link-dmg: test-data/bars-link.dmg
#
#make-symlink-dmg: NAMESPACE=symlink
#make-symlink-dmg: test-data/bars-symlink.dmg
#
#make-clone-dmg: NAMESPACE=clonefile
#make-clone-dmg: test-data/bars-clonefile.dmg
#
#make-dmg: make-link-dmg make-symlink-dmg make-clone-dmg
#
#bars-dmg: test-data/bars-$(NAMESPACE).dmg
#
#test-data/bars-%.dmg:
#	mkdir -p test-data/bars
#	pushd test-data/bars; \
#	    echo "foo" > bar; \
#	    cp bar bar2; \
#	    ln bar bar3; \
#	    cp -c bar bar4; \
#	    cp bar bar5;
#	hdiutil create \
#	    -srcfolder test-data/bars \
#	    -volname 'dedup-test-hfs-$(NAMESPACE)' \
#	    -fs HFS+ \
#	    -format UDRW \
#	    -size 1m \
#	    test-data/bars-$(NAMESPACE).dmg

# setup: NAMESPACE ?= .
setup: clean-test-data
	mkdir -p test-data/$(NAMESPACE)/{bars,empty,devices,big,same-size,same-first-last,flags-acls,clone-dst-acls,mtime,mtime-not-preserved,mtime-cwd,mtime-immutable}
	# "bar" test data
	pushd test-data/$(NAMESPACE)/bars; \
	    echo "foo" > bar; \
	    cp bar bar2; \
	    ln bar bar3; \
	    cp -c bar bar4; \
	    cp bar bar5;
	# "empty" test data
	pushd test-data/$(NAMESPACE)/empty; \
	    touch empty; \
	    touch empty2; \
	# "devices" test data
	pushd test-data/$(NAMESPACE)/devices; \
	    mkfifo fifo; \
        touch empty;
	# "big" test data
	pushd test-data/$(NAMESPACE)/big; \
	    dd if=/dev/random of=big bs=1m count=4; \
	    dd if=/dev/random of=big2 bs=1m count=4;
	# "same-size" test data
	pushd test-data/$(NAMESPACE)/same-size; \
	    dd if=/dev/zero of=big bs=1m count=1; \
	    dd if=/dev/zero of=big2 bs=1m count=1;
	# "same-first-last" test data
	pushd test-data/$(NAMESPACE)/same-first-last; \
	    dd if=/dev/random of=big bs=1m count=4; \
	    dd if=/dev/random of=big2 bs=1m count=4; \
	    echo "a" > same-1; \
	    cat big >> same-1; \
	    echo "z" >> same-1; \
	    echo "a" > same-2; \
	    cat big2 >> same-2; \
	    echo "z" >> same-2;
	# "flags-acls" test data
	pushd test-data/$(NAMESPACE)/flags-acls; \
	    echo "foo" > bar; \
	    ln bar bar2; \
	    cp bar bar3; \
	    chmod +a "nobody deny append" bar3; \
	    chmod 642 bar3;
	# "clone-dst-acls" test data
	pushd test-data/$(NAMESPACE)/clone-dst-acls; \
	    echo "foo" > bar; \
	    ln bar bar2; \
	    cp bar bar3; \
	    chmod +a "$$USER deny readattr,readextattr" bar3; \
	    cp bar bar4; \
	    chflags uchg bar4;
	# "mtime" test data
	pushd test-data/$(NAMESPACE)/mtime; \
        echo "foo" > bar; \
	    cp bar bar2;
	# "mtime-not-preserved" test data
	pushd test-data/$(NAMESPACE)/mtime-not-preserved; \
        echo "foo" > bar; \
        echo "foo" > bar2;
	# "mtime-cwd" test data
	pushd test-data/$(NAMESPACE)/mtime-cwd; \
        echo "foo" > bar; \
	    cp bar bar2;
	# "mtime-immutable" test data
	pushd test-data/$(NAMESPACE)/mtime-immutable; \
        echo "foo" > bar; \
	    cp bar bar2; \
        chflags uchg .;
	# HFS test
	hdiutil create \
	    -srcfolder test-data/$(NAMESPACE)/bars \
	    -volname 'dedup-test-hfs-$(NAMESPACE)' \
	    -fs HFS+ \
	    -format UDRW \
	    -size 1m \
	    test-data/$(NAMESPACE)/bars.dmg
	# cp -c test-data/bars-$(NAMESPACE).dmg test-data/$(NAMESPACE)/bars.dmg
	device="$$(hdiutil attach \
	    -readwrite \
	    -noverify \
	    -noautoopen \
	    test-data/$(NAMESPACE)/bars.dmg \
	    | egrep '^/dev/' \
	    | sed 1q \
	    | awk '{print $$1}')" && \
	    echo "$$device" >> test-data/$(NAMESPACE)-bars-device

setup-clonefile: NAMESPACE=clonefile
setup-clonefile: setup

setup-link: NAMESPACE=link
setup-link: setup

setup-symlink: NAMESPACE=symlink
setup-symlink: setup

setup-all:
	$(MAKE) setup-clonefile
	$(MAKE) setup-link
	$(MAKE) setup-symlink

clean-clonefile: NAMESPACE=clonefile
clean-clonefile: clean-test-data

clean-link: NAMESPACE=link
clean-link: clean-test-data

clean-symlink: NAMESPACE=symlink
clean-symlink: clean-test-data

clean-all-test-data:
	$(MAKE) clean-clonefile
	$(MAKE) clean-link
	$(MAKE) clean-symlink
	rm -f test-data/*.dmg
	rm -rf test-data/bars
	rm -f test-data/*bars-device
	if [ -d test-data ]; then rmdir test-data; fi

clean: clean-all-test-data
	rm -f *.o
	rm -rf *.dSYM/
	rm -f dedup_check
	rm -f runtime_caps_test.o runtime_dispatch_test.o alist_test.o clone_test.o map_test.o utils_test.o signature_test.o
