# Palette's Journal - Critical UX Learnings

## 2026-10-30 - TTY stream matching for progress indicators
**Learning:** Progress bars and interactive status lines printed to `stderr` must check `isatty(STDERR_FILENO)` (and query terminal geometry on `STDERR_FILENO`), not `STDOUT_FILENO`. Checking `STDOUT_FILENO` breaks the user experience when stdout is piped/redirected (e.g. `dedup > out.txt`), and pollutes stderr log files with ANSI escape sequences when stderr is redirected.
**Action:** Always check `isatty` and `ioctl(..., TIOCGWINSZ, ...)` against the exact stream (`STDERR_FILENO` or `STDOUT_FILENO`) being used for rendering interactive UI output.
