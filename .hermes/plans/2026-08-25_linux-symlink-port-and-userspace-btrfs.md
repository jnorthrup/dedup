# Linux Port for Symlink Dedup + Userspace BTRFS Clone Backend

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make `dedup` build and run on Linux (Jules CI VMs) with `--symlink`/`--link` modes doing the heavy lifting, backed by superior early elimination, plus a file-based userspace BTRFS layer (FFI to the btrfs control plane) so reflink-style dedup can be tested without root or loop mounts.

**Architecture:** Split platform-specific code behind a small backend interface (`clone_backend`), keep the existing signature → witness → exact-compare gate untouched (it is already portable POSIX), add a Linux prune path that loses getattrlist clone-id pruning but gains cheap early elimination from inode/dev keys and first/last-byte + head-hash pre-filtering. The userspace BTRFS component lives in its own library (`ubifs/`) implementing the btrfs on-disk format and the btrfs control plane (ioctl semantics) in C over regular image files, using **btrfs-progs (github.com/kdave/btrfs-progs) as the compliance reference**: its UAPI headers define the structs/ioctl numbers we implement against, and its tools (`btrfs inspect-internal dump-super`, `btrfs check`) are the acceptance tests that our images are valid.

**Tech Stack:** C2x, POSIX (fts, unlink/link/symlink/rename), Linux `<linux/fs.h>` `FICLONE`, btrfs control plane per btrfs-progs `include/btrfs.h` ioctl definitions, btrfs on-disk format per btrfs-progs `include/btrfs_tree.h` + `mkfs/`/`disk-io/` reference code, Makefile conditionals, Check test harness, btrfs-progs binaries in CI for validation.

---

## Current context (verified in repo)

- Platform gates exist only in `clone.c` (`__APPLE__` / `__FREEBSD__` / `#error`) and `runtime_caps.c`.
- `queue.h`, `map.h` unconditionally `#include <sys/attr.h>` (macOS-only header) but appear to use only standard types from it — verify each symbol before removal.
- `dedup.c` uses `getattrlist`+`statfs` for `VOL_CAP_INT_CLONE` gating (dedup.c:880-922), `entry->fts_statp->st_flags` (dedup.c:1258,1291) — all macOS-only.
- `replace_with_link` / `replace_with_symlink` (clone.c:201-291) are pure POSIX already — these are the intended Linux mechanics.
- Pruning (`prune_entry`, dedup.c:519) eliminates on: nlink>1 seen-set (portable), clone-id seen-set (macOS-only). Sequence-deadlock fix (commit 1213eae) must be preserved on all paths.
- Exact-compare gate (`sig_table.c:62-66` + runtime_dispatch backends) uses pread/memcmp — fully portable.
- Test suite mounts HFS DMGs via `hdiutil` — Linux needs a parallel fixture strategy (see Task 8).

## Proposed approach

Three layers, each independently mergeable:

1. **Portable core** — compile on Linux with symlink/hardlink replace modes; clone mode compiles but reports "unsupported on this volume/fs" at runtime instead of `#error`.
2. **Linux early elimination** — strengthen pruning with portable signals so symlink mode rejects non-candidates before any I/O: size bucket, first/last byte, dev+inode seen-set (hardlinks), and (new) a cheap 4KB head-hash seen-set shared across threads. This is what makes `-s` fast on ext4/tmpfs where reflink does not exist.
3. **Userspace BTRFS backend** — new C library implementing the btrfs on-disk format + control plane over plain image files, **compliant with btrfs-progs**: UAPI structs/ioctl numbers taken verbatim from btrfs-progs `include/`, behavior validated against btrfs-progs tools and (where root is available) golden-compared against kernel btrfs ioctls. Exposed as a C FFI (`ubt_clone_fd(dst_fd, src_fd)` mirroring `BTRFS_IOC_CLONE`), consumed by dedup through a thin backend adapter so the existing clone codepaths run against it in tests.

### The c-btrfs compliance bar (resolved)

"Compliant with c-btrfs" means: btrfs-progs (kdave/btrfs-progs). Concretely:
- **Structs/numbers:** vendor btrfs-progs `include/btrfs.h` (ioctl command definitions = the control plane) and `include/btrfs_tree.h` (on-disk layout) rather than hand-copying them.
- **Format acceptance:** our images must parse under `btrfs inspect-internal dump-super` (hard bar) and `btrfs check` (stretch bar).
- **Control-plane behavior:** the FFI mirrors btrfs-progs `ioctl/` wrapper semantics; where a Jules VM has root + loop, golden tests diff our behavior against real kernel btrfs `FICLONE`/ioctl results (extent sharing, CoW divergence).
- btrfs-progs `libbtrfs`/`libbtrfsutil` is a *reference*, not a link-time dependency — we implement the subset ourselves to keep the library small and portable (no root, no kernel module).

---

## Step-by-step plan

### Phase A — Portable build skeleton

### Task 1: De-`#include <sys/attr.h>` the data structures
**Files:** Modify `queue.h`, `map.h`
**Steps:** audit every symbol actually used from `sys/attr.h` in those TUs; none expected (types come from sys/types.h via sys/stat.h). Replace with `#include <sys/types.h>`. Then grep the tree for files using `attrlist`/`getattrlist` that don't include `sys/attr.h` themselves (transitive-include check) and add the include where needed. Build macOS (`make dedup` must stay green) and run a Linux syntax check in a docker Linux container.
**Verify:** `grep -n 'sys/attr' queue.h map.h` returns nothing; macOS build passes; `docker run --rm -v $PWD:/w -w /w gcc:13 cc -std=c2x -fsyntax-only *.c` clean (modulo intentional `#if __APPLE__` guards).
**Commit.**

### Task 2: Guard macOS-only stat fields
**Files:** Modify `queue.c`, `queue.h`, `dedup.c:1250-1300`
**Steps:** wrap `st_flags` capture in `#if defined(__APPLE__)` (pass `0` elsewhere; Linux has no portable uchg — chattr +i detection is a follow-up, noted in comment).
**Verify:** Linux syntax check clean; macOS build + `make check` dedup_check subset unchanged.
**Commit.**

### Task 3: Volume-capability gating becomes per-platform
**Files:** Modify `dedup.c:880-930`
**Steps:** split `is_vol_cap_supported` behind `#if defined(__APPLE__)`; Linux provides `is_clonefile_supported()` that probes the active backend (Task 5) and `are_acls_supported()` returns true (rename_swap universal on Linux).
**Verify:** unit test asserting the Linux stub compiles; Apple path byte-identical.
**Commit.**

### Task 4: clone.c gets a Linux branch instead of `#error`
**Files:** Modify `clone.c:100-130`; fix latent FreeBSD bug at clone.c:121 while here (declare `int result;`)
**Steps:** add
```c
#elif defined(__linux__)
int genfile_clone(const char* src, const char* dst) {
    int s = open(src, O_RDONLY);
    if (s < 0) return errno;
    int d = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (d < 0) { int e = errno; close(s); return e; }
    int r = ioctl(d, FICLONE, s);   /* <linux/fs.h> */
    int e = errno;
    close(s); close(d);
    return r ? e : 0;
}
```
Leave the Apple branch untouched.
**Verify:** in docker btrfs volume (root) or VM: two 4MB files, run binary, `du` before/after shows shared blocks; also verify the `find_zero_file` + COPYFILE_CHECK-equivalent staging guards still work (Linux has no copyfile CHECK — replace the guard with a `stat` size match against src, keep rename(2) atomic swap).
**Commit.**

### Task 5: Runtime backend selection
**Files:** Create `backend.h`/`backend.c`; Modify `main()` arg parsing
**Steps:** enum `{ BACKEND_AUTO, BACKEND_CLONEFILE, BACKEND_FICLONE, BACKEND_UBT }`; `AUTO` picks clonefile on Apple, probes FICLONE on Linux (test ioctl on a scratch file), falls back to refusing clone mode with a clear warnx (symlink/link still work). Env override `DEDUP_BACKEND` for tests. Verbose print shows chosen backend (reuse the existing runtime verbose section).
**Verify:** `DEDUP_BACKEND=ficlone ./dedup -v dir` prints backend; wrong value → usage error.
**Commit.**

---

### Phase B — Superior early elimination (the point of the port)

### Task 6: Portable prune strengthening
**Files:** Modify `prune_entry` (dedup.c:519), `seen_set.[ch]`
**Steps:**
1. Keep nlink/inode seen-set (portable).
2. Put the clone-id seen-set behind `#if defined(__APPLE__)`; on all platforms add a second SeenSet keyed on `(size, first_byte, last_byte, head_xxh64)` computed from data the signature pass already reads (reuse, no extra reads). Prune-negative signal only — never a confirmation.
3. Preserve the sequence-advance contract (deadlock fix 1213eae): every pruned entry still hits `visit_order_begin`/`visit_order_end`.
**Verify:** TDD — failing test first: same size + same first/last byte + different head hash must NOT be pruned; identical heads on ext4 get eliminated pre-signature (instrumented counter at -vv).
**Commit.**

### Task 7: Symlink-mode fast path
**Files:** Modify `visit_entry` dispatch
**Steps:** when `replace_mode == DEDUP_SYMLINK`, skip the copyfile-metadata stage (Apple-only) and do staged-symlink-swap: create `.~.tmp` symlink then `rename(2)` — fixes the acknowledged non-atomic two-step TODO for this mode (clone mode keeps its current flow; link mode follows next iteration).
**Verify:** crash-window test: SIGKILL mid-run (loop 200) leaves either original or complete symlink, never missing path.
**Commit.**

---

### Phase C — Userspace BTRFS (file-based, btrfs-progs-compliant)

### Task 8: Library scaffold `ubifs/` + btrfs-progs UAPI vendoring
**Files:** Create `ubifs/ubt.h`, `ubifs/image.c`, `ubifs/super.c`, `ubifs/Makefile`, `third-party/btrfs-uapi/` (vendored `btrfs.h`, `btrfs_tree.h` from btrfs-progs include/)
**Steps:** file-backed image (`ftruncate` + mmap windows); format per vendored UAPI structs: superblock with magic `_BHRfS_M`, correct offsets (super at 64KiB, mirrors at 1GiB/2GiB), crc32c checksums (btrfs-progs `checksum/` algorithm).
**Verify (hard bar):** `btrfs inspect-internal dump-super <image>` parses cleanly and reports sane fields; checksums verified by `btrfs check --readonly` reaching the point it accepts the super (record exact output in commit message).
**Commit.**

### Task 9: Extent/reflink operations (the control-plane FFI)
**Files:** Create `ubifs/clone.c`, `ubifs/control.c`
**Steps:** implement the control plane per btrfs-progs `ioctl/` semantics:
```c
int ubt_clone(int dst_fd, int src_fd);          /* BTRFS_IOC_CLONE semantics */
int ubt_same_fs(int a_fd, int b_fd);
uint64_t ubt_private_size(int fd);               /* mirrors APFS ATTR_CMNEXT_PRIVATESIZE */
```
Shared-extent bookkeeping (per-bytenr extent refcounts) + CoW on write, so cloned ranges share blocks until mutation.
**Verify:** property test — clone N times, mutate each copy, byte-compare all pairs: divergence isolation exact; `private_size` tracks shared savings like APFS. Golden test (root VM): same workload on real kernel btrfs via `FICLONE`; assert identical sharing/COW semantics.
**Commit.**

### Task 10: Wire backend into dedup
**Files:** Modify `backend.c` from Task 5, `Makefile`
**Steps:** `BACKEND_UBT` routes clone through `ubt_clone` when paths live inside an image-backed tree (attachment: helper-managed working dir, decided in Task 10 spike — simplest is `ubt-mount`-style helper creating a dir whose files carry an image-pointer xattr; if xattr too fragile, explicit `--ubt-image` root arg). Link `libubt.a` optionally (`UBT=1`), degrade gracefully when absent.
**Verify:** dedup suite subset (empty/bars/same-size/dry-run) against image-backed tree on Linux CI, real shared-block accounting asserted.
**Commit.**

---

### Phase D — CI for Jules VMs

### Task 11: Linux test target
**Files:** Modify `test/Makefile`
**Steps:** add `check-linux:` with tmpfs/ext4 scratch dirs (no mount privileges needed); clone/HFS suites gated behind root+loop btrfs; symlink+link suites are the primary gate; popen watchdog using the repo's own `timeout_exec.c` (fixes audit finding #6).
**Verify:** green in a stock Debian/Ubuntu container as non-root.
**Commit.**

### Task 12: Docs + dict
**Files:** Modify `README.md`, `dict`
**Steps:** platform matrix, `DEDUP_BACKEND`, image workflow, btrfs-progs compliance note; add new words to spelling dict.
**Verify:** `make check-spelling-readme` passes.
**Commit.**

---

## Files likely to change
`clone.c`, `clone.h`, `dedup.c`, `utils.c`, `queue.{c,h}`, `map.h`, `runtime_caps.c`, `Makefile`, `test/Makefile`, `test/test_utils.c`; new: `backend.{c,h}`, `ubifs/*`, `third-party/btrfs-uapi/`.

## Tests / validation
- macOS: `make check` stays at current baseline (45/48 + known toolchain issues) — no regressions.
- Linux VM/container: `check-linux` green as non-root; FICLONE path verified on btrfs when root.
- btrfs-progs acceptance: `dump-super` (hard), `btrfs check` (stretch), golden diff vs kernel ioctls (root).
- Deadlock regression loop (Task 6/7 verifies) on both OSes.

## Risks / tradeoffs / open questions
1. **Userspace btrfs scope.** Full crash-consistent btrfs is enormous; this plan deliberately targets the reflink/control-plane subset (format + superblock + shared extents + CoW). Mountability is not promised; the bar is btrfs-progs *inspect/check* acceptance, not `mount`.
2. **st_flags/uchg has no Linux equivalent** — immutable-file protection is lost on Linux (chattr +i detection is a follow-up; YAGNI now, noted).
3. **Early-elimination head-hash** is prune-negative only — it can reject candidates but never confirm duplicates; the byte-exact gate invariant from the audit stays intact.
4. **Vendored UAPI drift** — btrfs-progs UAPI changes are rare (format stable since 1.0-era), but pin the vendored revision and note its version in `third-party/btrfs-uapi/README`.
5. **Image attachment model for UBT** (Task 10) — xattr-pointer vs explicit `--ubt-image`; decide in the Task 10 spike, recommend whichever the Jules VM harness handles with least setup.
