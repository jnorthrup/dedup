# ubifs — Userspace BTRFS Library

Minimal implementation of the btrfs on-disk format over plain files,
compliant with btrfs-progs (kdave/btrfs-progs).

## Compliance bar

- **Structs/numbers:** compat.h defines the minimal subset of btrfs
  on-disk structures (superblock, tree nodes) matching the UAPI layout
  from btrfs-progs `kernel-shared/uapi/btrfs.h` and `btrfs_tree.h`.
- **Format acceptance:** images produced by `ubt_format_image()` are
  designed to be parseable by `btrfs inspect-internal dump-super`.
- **Control-plane behavior:** (future) `ubt_clone()` will mirror
  btrfs-progs `BTRFS_IOC_CLONE` semantics.

## Scope

This library implements ONLY:
- Superblock formatting (at 64KiB offset)
- Minimal root tree node
- CRC32C checksums

NOT implemented (and not planned for this phase):
- Extent tree / reflink / CoW
- Mount support
- Full btrfs check/fsck compliance

## Building

```
make          # builds libubt.a
make clean    # removes objects and library
```

## Files

- `compat.h` — macOS/Linux compatibility shims for btrfs structures
- `ubt.h` — Public API
- `image.c` — File-backed image creation
- `super.c` — Superblock and root node formatting
- `Makefile` — Builds libubt.a
