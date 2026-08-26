# Linux Port for Symlink Dedup + Userspace BTRFS Clone Backend

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make `dedup` build and run on Linux (Jules CI VMs) with `--symlink`/`--link` modes doing the heavy lifting, backed by superior early elimination, plus a file-based userspace BTRFS layer (FFI to the btrfs control plane) so reflink-style dedup can be tested without root or loop mounts.

**Architecture:** Split platform-specific code behind a small backend interface (`clone_backend`), keep the existing signature → witness → exact-compare gate untouched (it is already portable POSIX), add a Linux prune path that loses getattrlist clone-id pruning but gains cheap early elimination from inode/dev keys and first/last-byte + size pre-filtering. The userspace BTRFS component lives in its own library (`ubifs-btrfs/`) exposing btrfs ioctl semantics (`BTRFS_IOC_CLONE`-compatible reflink, same-fs checks) over regular image files, consumed by dedup through a thin C FFI so the existing `-C`/clone codepaths can run against it in tests.

**Tech Stack:** C2x, POSIX (fts, unlink/link/symlink/rename), Linux `<linux/fs.h>` `FICLONE`, `<sys/ioctl.h>`, btrfs kernel UAPI headers (`<linux/btrfs.h>`, `<linux/btrfs_tree.h>`) for control-plane structures, Makefile conditionals, Check test harness.

---

## Current context (verified in repo)

- Platform gates exist only in `clone.c` (`__APPLE__` / `__FREEBSD__` / `#error`) and `runtime_caps.c`.
- `queue.h`, `map.h` unconditionally `#include <sys/attr.h>` (macOS-only header) but appear to use only standard types from it — verify each symbol before removal.
- `dedup.c` uses `getattrlist`+`statfs` for `VOL_CAP_INT_CLONE` gating (dedup.c:880-922), `entry->fts_statp->st_flags` (dedup.c:1258,1291), and `chflags`-adjacent logic — all macOS-only.
- `replace_with_link` / `replace_with_symlink` (clone.c:201-291) are pure POSIX already — these are the intended Linux mechanics.
- Pruning (`prune_entry`, dedup.c:519) eliminates on: nlink>1 seen-set (portable), clone-id seen-set (macOS-only). Sequence-deadlock fix must be preserved on all paths.
- Exact-compare gate (`sig_table.c:62-66` + runtime_dispatch backends) uses pread/memcmp — fully portable.
- Test suite mounts HFS DMGs via `hdiutil` — Linux needs a parallel fixture strategy (see Task 8).

## Proposed approach

Three layers, each independently mergeable:

1. **Portable core** — compile on Linux with symlink/hardlink replace modes; clone mode compiles but reports "unsupported on this volume/fs" at runtime instead of `#error`.
2. **Linux early elimination** — strengthen pruning with portable signals so symlink mode rejects non-candidates before any I/O: size bucket, first/last byte, dev+inode seen-set (hardlinks), and (new) a cheap 4KB head-hash seen-set shared across threads. This is what makes `-s` fast on ext4/tmpfs where reflink does not exist.
3. **Userspace BTRFS backend** — new static lib implementing reflink semantics over a plain image file, wire-compatible with the kernel btrfs ioctl control plane (same struct layouts/command numbers from `<linux/btrfs.h>`), exposed via a C FFI (`ubt_clone_fd(dst_fd, src_fd)` mirroring `BTRFS_IOC_CLONE`). dedup's clone backend gains a third implementation selectable at runtime (`DEDUP_BACKEND=clonefile|ficlone|userspace-btrfs`), so Jules VMs exercise the full dedup→reflink path in CI without mounting anything.

---

## Step-by-step plan

### Phase A — Portable build skeleton

### Task 1: Audit and de-`#include <sys/attr.h>` the data structures
**Files:** Modify `queue.h`, `map.h`, `attr.h`
**Steps:** grep every symbol actually used from `sys/attr.h` in those translation units; if none, drop the include; move remaining macOS-only bits behind `#if defined(__APPLE__)`. Build both `make dedup` on macOS (must stay green) and `cc -std=c2x -fsyntax-only *.c` with a simulated Linux gate to confirm nothing else leaks.
**Verify:** `grep -n 'sys/attr' queue.h map.h` returns nothing (or is guarded); macOS build passes.

### Task 2: Guard macOS-only stat fields
**Files:** Modify `queue.c`, `queue.h`, `dedup.c:1250-1300`
**Steps:** wrap `st_flags` capture in `#if defined(__APPLE__)` (pass `0` elsewhere); the flags are only used for uchg detection which has no Linux equivalent yet (note it in a comment).
**Verify:** syntax-only Linux compile of queue.o/dedup.o clean.

### Task 3: Volume-capability gating becomes per-platform
**Files:** Modify `dedup.c:880-930`
**Steps:** split `is_vol_cap_supported` behind `#if defined(__APPLE__)`; on Linux provide `is_clonefile_supported()` that attempts a real probe (see Task 5) and returns false when the backend is unavailable; `are_acls_supported` returns true (rename_swap is universal on Linux).
**Verify:** unit test asserting the Linux stub compiles and the Apple path unchanged.

### Task 4: clone.c gets a Linux branch instead of `#error`
**Files:** Modify `clone.c:100-130`, fix latent FreeBSD bug at clone.c:121 while here (declare `int result;`)
**Steps:** add
```c
#elif defined(__linux__)
#include <linux/fs.h>
int genfile_clone(const char* src, const char* dst) {
    int s = open(src, O_RDONLY);
    if (s < 0) return errno;
    int d = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (d < 0) { int e = errno; close(s); return e; }
    int r = ioctl(d, FICLONE, s);
    int e = errno;
    close(s); close(d);
    return r ? e : 0;
}
#else
#error Operating system not supported.
#endif
```
Also delete the dead `(1<<31)` flag issue on this branch (Apple-only codepath stays untouched).
**Verify:** on a Linux VM (or WSL/container): create two 4MB files on btrfs/xfs, run binary, confirm reflink happened via `du --block-size=1` before/after.

### Task 5: Runtime backend selection
**Files:** Create `backend.h`/`backend.c`; Modify `main()` arg parsing
**Steps:** enum `{ BACKEND_AUTO, BACKEND_CLONEFILE, BACKEND_FICLONE, BACKEND_UBT }`; `AUTO` picks clonefile on Apple, probes FICLONE on Linux (test ioctl on a scratch fd), falls back to refusing clone mode with a clear warnx (symlink/link still work). Env override `DEDUP_BACKEND` for tests.
**Verify:** `DEDUP_BACKEND=ficlone ./dedup -v dir` prints chosen backend under existing verbose print.

---

### Phase B — Superior early elimination (the point of the port)

### Task 6: Portable prune strengthening
**Files:** Modify `prune_entry` (dedup.c:519), `seen_set.[ch]`
**Steps:**
1. Keep nlink/inode seen-set (already portable).
2. Replace clone-id seen-set with `#if defined(__APPLE__)` wrapper; on Linux insert a second SeenSet keyed on `(size, first_byte, last_byte, head_xxh64)` computed during metadata read (signature work already computes most of this — reuse it rather than re-reading).
3. Preserve the sequence-advance contract: every pruned entry must still hit `visit_order_begin`/`visit_order_end` (deadlock fix, commit 1213eae).
**Verify:** TDD — failing test first: two files same size different content must NOT be pruned; two files identical heads on ext4 get eliminated pre-signature (count via strace or an instrumented counter printed at -vv).

### Task 7: Symlink-mode fast path
**Files:** Modify `visit_entry` dispatch
**Steps:** when `replace_mode == DEDUP_SYMLINK`, skip the copyfile-metadata stage entirely (it is Apple-only anyway) and go straight staged-symlink-swap: create `.~.tmp` symlink then `rename(2)` (fixes the acknowledged non-atomic two-step TODO for this mode — clone mode keeps its current flow).
**Verify:** crash-window test: SIGKILL mid-run leaves either original or complete symlink, never missing path (loop 200 kills).

---

### Phase C — Userspace BTRFS (file-based, c-btrfs-compatible)

### Task 8: Library scaffold `ubt/`
**Files:** Create `ubt/ubt.h`, `ubt/image.c`, `ubt/super.c`, `ubt/Makefile`
**Steps:** file-backed image (`ftruncate` + mmap windows); on-disk layout follows kernel btrfs UAPI structs verbatim (`btrfs_super_block`, `btrfs_disk_key`, `btrfs_item`) so a created image is inspectable by `btrfs inspect-internal dump-super` — that is the compliance bar. Implement: format, superblock with correct magic `_BHRfS_M`, chunk tree stub, checksummed node writes (crc32c).
**Verify:** `dump-super` accepts our image; roundtrip mount attempt documented as expected-to-fail until extent tree lands (record which kernel messages appear).

### Task 9: Extent/reflink operations (the control-plane FFI)
**Files:** Create `ubt/clone.c`, `ubt/ioctl_shim.c`
**Steps:** implement the logical equivalent of `BTRFS_IOC_CLONE`: shared-extent bookkeeping (extent refcounts per bytenr), so cloned ranges share blocks and CoW on write. Expose:
```c
int ubt_clone(int dst_fd, int src_fd);          // mirrors BTRFS_IOC_CLONE semantics
int ubt_same_fs(int a_fd, int b_fd);
uint64_t ubt_private_size(int fd);              // mirrors ATTR_CMNEXT_PRIVATESIZE
```
These three calls are exactly what utils.c's getattrlist helpers provide on macOS — the FFI surface dedup needs.
**Verify:** property test: clone N times, mutate each copy, byte-compare all pairs — divergence isolation must be exact; private_size reflects shared savings like APFS.

### Task 10: Wire backend into dedup
**Files:** Modify `backend.c` from Task 5, `Makefile`
**Steps:** `BACKEND_UBT` routes `genfile_clone` through `ubt_clone` when paths live inside a mounted-in-process image (image attach command: `dedup --ubt-image foo.img -- cmd`-style, or simply treat a directory tree whose files carry an xattr pointer into the image — decide: simplest is a dedicated image-backed working dir managed by a small helper `ubt-mount`). Link `libubt.a` optionally (`UBT=1`), degrade gracefully when absent.
**Verify:** full dedup suite subset (empty/bars/same-size/dry-run) running against an image-backed tree on Linux CI, exercising real shared-block accounting.

---

### Phase D — CI for Jules VMs

### Task 11: Linux test target
**Files:** Modify `test/Makefile`
**Steps:** add `check-linux:` replacing hdiutil fixtures with tmpfs/ext4 scratch dirs (no mount privileges needed); skip clone/HFS suites unless running as root with a loop btrfs; add symlink+link suite runs as primary gates; add popen watchdog using repo's own `timeout_exec.c` (fixes audit finding #6).
**Verify:** green run inside a stock Debian/Ubuntu container as non-root.

### Task 12: Docs + dict
**Files:** Modify `README.md`, `dict`
**Steps:** document platform matrix, `DEDUP_BACKEND`, image workflow; add new README words to spelling dict so `check-spelling` stays honest.
**Verify:** `make check-spelling-readme` passes.

---

## Files likely to change
`clone.c`, `clone.h`, `dedup.c`, `utils.c`, `queue.{c,h}`, `map.h`, `runtime_caps.c`, `Makefile`, `test/Makefile`, `test/test_utils.c`; new: `backend.{c,h}`, `ubt/*`.

## Tests / validation
- macOS: `make check` stays at current baseline (45/48 + known toolchain issues) — no regressions.
- Linux VM: new `check-linux` green as non-root; FICLONE path verified on btrfs when root.
- Deadlock regression loop (Task 6/7 verify steps) on both OSes.

## Risks / tradeoffs / open questions
1. **c-btrfs compliance bar is fuzzy.** I've interpreted "compliant with c-btrfs" as *wire-compatible with the kernel btrfs UAPI (ioctl structs/layout) and dump-super-readable*, implemented in C. If you meant compatibility with a specific project named c-btrfs, point me at it and Tasks 8-9 change shape.
2. **Userspace btrfs scope.** Full crash-consistent btrfs is enormous; this plan deliberately targets the reflink/control-plane subset (format + superblock + shared extents + CoW). Mountability is explicitly not promised initially.
3. **st_flags/uchg has no Linux equivalent** — immutable-file protection is lost on Linux (chattr +i detection could substitute later; YAGNI now, noted).
4. **Early-elimination hash reuse** must not weaken the exact-compare gate — the head-hash is only a *prune-negative* signal (never confirms duplicates), keeping the safety invariant from the audit intact.
5. Image-vs-xattr attachment model for UBT (Task 10) is a genuine fork in the road; helper-mount approach is recommended for CI simplicity.
