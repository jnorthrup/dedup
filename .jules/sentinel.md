## 2026-10-21 - [Check return value of write in probe_ficlone]
**Vulnerability:** Unchecked write return value in `probe_ficlone` in `backend.c`.
**Learning:** `write` system call return value was ignored when probing `FICLONE` capability, which could lead to probing files on disk without written data or unhandled I/O failures.
**Prevention:** Always check return values of standard I/O system calls like `write` and perform proper descriptor and file cleanup on error.
