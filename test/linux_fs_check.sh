#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Linux filesystem tests for clone mode, which shares blocks in place with
# FIDEDUPERANGE. Runs as root: it loop-mounts scratch btrfs, XFS (with and
# without reflink) and ext4 images, and a tmpfs. Needs btrfs-progs,
# xfsprogs, e2fsprogs (mkfs.ext4, chattr, filefrag), attr, acl and
# util-linux (setpriv).
#
#   usage: linux_fs_check.sh path/to/dedup
#
# Sharing is checked with filefrag(8), independently of dedup's own reading
# of the extent maps: every extent of both files must be marked shared and
# map to the same addresses.

set -u

if [ "$#" -ne 1 ] || [ ! -x "$1" ]; then
    echo "usage: $0 path/to/dedup" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "$0: needs root to loop-mount the test filesystems" >&2
    exit 2
fi

DEDUP=$(realpath "$1")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/dedup-fs-check.XXXXXX") || exit 2
chmod 755 "$WORK"
OUT="$WORK/dedup.out"
USER_ID=4242 # an unprivileged owner for the permission tests
checks=0
failures=0
status=0

cleanup() {
    for m in "$WORK"/mnt/*; do
        [ -d "$m" ] || continue
        chattr -R -i "$m" 2>/dev/null
        mountpoint -q "$m" && umount "$m"
    done
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# check DESCRIPTION COMMAND...: run COMMAND and record the result. On
# failure, show the output of the last dedup run.
check() {
    description=$1
    shift
    checks=$((checks + 1))
    if "$@"; then
        echo "ok   $description"
    else
        failures=$((failures + 1))
        echo "FAIL $description"
        sed 's/^/     | /' "$OUT"
    fi
}

# run_dedup ARGS...: run dedup as root; output in $OUT, exit status in $status
run_dedup() {
    "$DEDUP" "$@" > "$OUT" 2>&1
    status=$?
}

# run_dedup_as_user ARGS...: the same, as the unprivileged USER_ID
run_dedup_as_user() {
    setpriv --reuid="$USER_ID" --regid="$USER_ID" --clear-groups "$DEDUP" "$@" > "$OUT" 2>&1
    status=$?
}

exits() { [ "$status" -eq "$1" ]; }
says() { grep -qF -- "$1" "$OUT"; }
same_content() { cmp -s "$1" "$2"; }

# A file's identity and metadata, without the access time.
meta() {
    stat -c 'inode=%i links=%h mode=%a owner=%u:%g size=%s mtime=%y ctime=%z' "$1"
    getfattr -d -m - --absolute-names "$1" 2>/dev/null | grep -v '^#'
}

# Every extent of both files is marked shared and maps to the same place.
shared() {
    filefrag -v "$1" 2>/dev/null | grep -E '^ *[0-9]+:' > "$WORK/extents-a"
    filefrag -v "$2" 2>/dev/null | grep -E '^ *[0-9]+:' > "$WORK/extents-b"
    [ -s "$WORK/extents-a" ] && [ -s "$WORK/extents-b" ] || return 1
    if grep -vq shared "$WORK/extents-a" || grep -vq shared "$WORK/extents-b"; then
        return 1
    fi
    awk '{ print $2, $3, $4, $5 }' "$WORK/extents-a" > "$WORK/ranges-a"
    awk '{ print $2, $3, $4, $5 }' "$WORK/extents-b" > "$WORK/ranges-b"
    cmp -s "$WORK/ranges-a" "$WORK/ranges-b"
}
separate() { ! shared "$1" "$2"; }
no_blocks() { [ "$(stat -c %b "$1")" -eq 0 ]; }

random_file() { head -c "$2" /dev/urandom > "$1"; }

# An independent copy. cp(1) from coreutils 9 makes reflinks by default and
# cat(1) uses copy_file_range(2), which btrfs and XFS also turn into
# reflinks; through a pipe, the data has to be written out again.
copy() { cat "$1" | cat > "$2"; }

make_fs() { # NAME MKFS-COMMAND...
    name=$1
    shift
    truncate -s 1G "$WORK/$name.img" &&
        "$@" "$WORK/$name.img" > "$WORK/mkfs-$name.log" 2>&1 &&
        mkdir -p "$WORK/mnt/$name" &&
        mount -o loop "$WORK/$name.img" "$WORK/mnt/$name"
}

# Identical files share blocks in place. The duplicate keeps its inode and
# so its mode, owner, timestamps, xattrs and hard links.
test_in_place() {
    fs=$1
    d=$2/in-place
    mkdir -p "$d"
    random_file "$d/a" 1048576
    copy "$d/a" "$d/b"
    chown 1234:5678 "$d/b"
    chmod 640 "$d/b"
    setfattr -n user.dedup-test -v kept "$d/b"
    setfacl -m u:4242:r "$d/b"
    touch -d '2001-02-03 04:05:06.789' "$d/b"
    ln "$d/b" "$d/b-link"
    check "$fs: the copies start out separate" separate "$d/a" "$d/b"
    meta "$d/a" > "$WORK/before-a"
    meta "$d/b" > "$WORK/before-b"

    run_dedup -v "$d"
    check "$fs: deduplicating exits 0" exits 0
    check "$fs: the duplicate is counted" says "duplicates found: 1"
    check "$fs: the files share blocks" shared "$d/a" "$d/b"
    check "$fs: the hard link shares them too" shared "$d/a" "$d/b-link"
    check "$fs: the contents are unchanged" same_content "$d/a" "$d/b"
    meta "$d/a" > "$WORK/after-a"
    meta "$d/b" > "$WORK/after-b"
    check "$fs: the origin's metadata is unchanged" cmp -s "$WORK/before-a" "$WORK/after-a"
    check "$fs: the duplicate keeps inode, links, mode, owner, times, xattrs, ACL" \
        cmp -s "$WORK/before-b" "$WORK/after-b"
    check "$fs: that comparison covers the ACL" grep -q posix_acl_access "$WORK/after-b"

    run_dedup "$d"
    check "$fs: a second run exits 0" exits 0
    check "$fs: a second run finds nothing left to do" says "duplicates found: 0"
}

test_dry_run() {
    fs=$1
    d=$2/dry-run
    mkdir -p "$d"
    random_file "$d/a" 262144
    copy "$d/a" "$d/b"
    run_dedup -n -v "$d"
    check "$fs: a dry run exits 0" exits 0
    check "$fs: a dry run says what it would do" says "would deduplicate"
    check "$fs: a dry run changes nothing" separate "$d/a" "$d/b"
}

# btrfs keeps small files inline with metadata, where they cannot be
# shared; FIDEDUPERANGE reports success for them all the same.
test_small_files() {
    fs=$1
    d=$2/small
    mkdir -p "$d"
    printf 'a small duplicate\n' > "$d/a"
    copy "$d/a" "$d/b"
    run_dedup -v "$d"
    check "$fs: small files: exits 0" exits 0
    if [ "$3" = inline ]; then
        check "$fs: inline data is skipped, with the reason" says "data stored inline, cannot be shared"
        check "$fs: inline data is counted as skipped" says "duplicates skipped: 1"
        check "$fs: inline data is not claimed as saved" says "bytes saved: 0 bytes"
    else
        check "$fs: small files share blocks" shared "$d/a" "$d/b"
    fi
}

test_immutable() {
    fs=$1
    d=$2/immutable
    mkdir -p "$d"
    random_file "$d/a" 65536
    copy "$d/a" "$d/b"
    chattr +i "$d/a" "$d/b"
    run_dedup -v "$d"
    check "$fs: immutable duplicates: exits 0" exits 0
    check "$fs: immutable duplicates are skipped" says "immutable or not writable"
    check "$fs: immutable files are untouched" separate "$d/a" "$d/b"
    chattr -i "$d/a" "$d/b"
}

test_many_copies() {
    fs=$1
    d=$2/many
    mkdir -p "$d"
    random_file "$d/a" 67108864
    for name in b c d; do copy "$d/a" "$d/$name"; done
    check "$fs: the four copies start out separate" separate "$d/a" "$d/d"
    run_dedup "$d"
    check "$fs: 64 MiB in four copies: exits 0" exits 0
    check "$fs: three duplicates are counted" says "duplicates found: 3"
    for name in b c d; do
        check "$fs: copy $name shares blocks with the origin" shared "$d/a" "$d/$name"
    done
}

# Deduplicating against a file with no data blocks punches the duplicate's
# written zeros out; both end up with nothing allocated.
test_sparse() {
    fs=$1
    d=$2/sparse
    mkdir -p "$d/1" "$d/2"
    truncate -s 4M "$d/1/holes"
    head -c 4194304 /dev/zero > "$d/2/zeros"
    run_dedup -v "$d/1" "$d/2"
    check "$fs: sparse origin: exits 0" exits 0
    check "$fs: sparse origin: the duplicate is counted" says "duplicates found: 1"
    check "$fs: sparse origin: the duplicate's blocks are freed" no_blocks "$d/2/zeros"
    check "$fs: sparse origin: the contents are unchanged" same_content "$d/1/holes" "$d/2/zeros"
}

# Files are opened read-only, which the kernel accepts from the owner or
# anyone allowed to write; read-only files are left alone by policy.
test_unprivileged() {
    fs=$1
    d=$2/unprivileged
    mkdir -p "$d/writable" "$d/read-only"
    random_file "$d/writable/a" 65536
    copy "$d/writable/a" "$d/writable/b"
    random_file "$d/read-only/a" 65536
    copy "$d/read-only/a" "$d/read-only/b"
    chown -R "$USER_ID:$USER_ID" "$d"
    chmod 444 "$d/read-only/a" "$d/read-only/b"
    check "$fs: the unprivileged copies start out separate" separate "$d/writable/a" "$d/writable/b"
    run_dedup_as_user -v "$d/writable"
    check "$fs: as the owner: exits 0" exits 0
    check "$fs: as the owner: the files share blocks" shared "$d/writable/a" "$d/writable/b"
    run_dedup_as_user -v "$d/read-only"
    check "$fs: read-only files as their owner: exits 0" exits 0
    check "$fs: read-only files are skipped" says "immutable or not writable"
    check "$fs: read-only files are untouched" separate "$d/read-only/a" "$d/read-only/b"
}

# btrfs refuses to share between checksummed and nodatasum (chattr +C) files.
test_refused() {
    fs=$1
    d=$2/refused
    mkdir -p "$d"
    random_file "$d/a" 65536
    touch "$d/b"
    chattr +C "$d/b"
    cat "$d/a" > "$d/b"
    run_dedup "$d"
    check "$fs: a refused deduplication exits 1" exits 1
    check "$fs: it names the file and the reason" says "could not deduplicate"
    check "$fs: it counts the failure" says "replacements failed: 1"
    check "$fs: the contents are unchanged" same_content "$d/a" "$d/b"
}

test_link_modes() {
    fs=$1
    d=$2/link-modes
    mkdir -p "$d/link" "$d/symlink"
    random_file "$d/link/a" 65536
    copy "$d/link/a" "$d/link/b"
    random_file "$d/symlink/a" 65536
    copy "$d/symlink/a" "$d/symlink/b"
    run_dedup -l "$d/link"
    check "$fs: --link exits 0" exits 0
    check "$fs: --link leaves one inode" [ "$(stat -c %i "$d/link/a")" = "$(stat -c %i "$d/link/b")" ]
    run_dedup -s "$d/symlink"
    check "$fs: --symlink exits 0" exits 0
    check "$fs: --symlink leaves a symbolic link" [ -L "$d/symlink/b" ]
}

for name in btrfs xfs xfs-noreflink ext4; do
    case $name in
        btrfs) make_fs btrfs mkfs.btrfs -q ;;
        xfs) make_fs xfs mkfs.xfs -q -m reflink=1 ;;
        xfs-noreflink) make_fs xfs-noreflink mkfs.xfs -q -m reflink=0 ;;
        ext4) make_fs ext4 mkfs.ext4 -q ;;
    esac || { echo "could not create and mount $name"; cat "$WORK/mkfs-$name.log"; exit 1; }
done

M="$WORK/mnt"
run_dedup -v "$M/btrfs"
check "the clone backend is fideduperange" says "clone backend: fideduperange"

for fs in btrfs xfs; do
    test_in_place "$fs" "$M/$fs"
    test_dry_run "$fs" "$M/$fs"
    test_small_files "$fs" "$M/$fs" "$([ "$fs" = btrfs ] && echo inline || echo shared)"
    test_immutable "$fs" "$M/$fs"
    test_many_copies "$fs" "$M/$fs"
    test_sparse "$fs" "$M/$fs"
    test_unprivileged "$fs" "$M/$fs"
done
test_refused btrfs "$M/btrfs"
test_link_modes btrfs "$M/btrfs"

# XFS without reflink passes the up-front check, which cannot see the
# feature, and refuses each file.
d="$M/xfs-noreflink/files"
mkdir -p "$d"
random_file "$d/a" 65536
copy "$d/a" "$d/b"
run_dedup "$d"
check "xfs without reflink: exits 1" exits 1
check "xfs without reflink: says why" says "Operation not supported"
check "xfs without reflink: the contents are unchanged" same_content "$d/a" "$d/b"

# ext4 and tmpfs cannot share blocks at all, which the up-front check sees.
mkdir -p "$M/tmpfs"
mount -t tmpfs -o size=64m tmpfs "$M/tmpfs" || { echo "could not mount tmpfs"; exit 1; }
for fs in ext4 tmpfs; do
    d="$M/$fs/files"
    mkdir -p "$d"
    random_file "$d/a" 65536
    copy "$d/a" "$d/b"
    inode=$(stat -c %i "$d/b")
    run_dedup "$d"
    check "$fs: exits 0" exits 0
    check "$fs: says cloning is not supported" says "cloning not supported"
    check "$fs: nothing is deduplicated" says "duplicates found: 0"
    check "$fs: the files are untouched" [ "$(stat -c %i "$d/b")" = "$inode" ]
done

echo "$((checks - failures)) of $checks checks passed"
[ "$failures" -eq 0 ]
