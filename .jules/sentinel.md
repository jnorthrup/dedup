## 2026-10-19 - Atomic Link Replacement
**Vulnerability:** Non-atomic file replacement in `replace_with_link` (`unlink` followed by `link`). A crash or concurrent access between `unlink` and `link` results in data loss or TOCTOU exploitation.
**Learning:** File replacement operations must use temporary file creation (`tmp_name`) followed by `rename(2)` atomic swap to guarantee atomic replacement semantics across POSIX filesystems.
**Prevention:** Avoid unlinking destination paths prior to link/clone/symlink operations; always stage in a temporary file path and replace atomically with `rename(2)`.
