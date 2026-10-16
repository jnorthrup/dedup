## 2026-10-16 - Unbounded Terminal Width Stack Buffer Overflow in Status Display
**Vulnerability:** `display_status()` in `dedup.c` calculated `path_max` directly from terminal width (`ioctl(STDOUT_FILENO, TIOCGWINSZ, &w)`) without capping `path_max` against the fixed stack buffer size `char truncated_path[256]`. On wide terminals (>= 298 cols), long paths triggered `strcpy(truncated_path, path)`, overflowing the stack buffer.
**Learning:** Terminal columns or window bounds checked at runtime can exceed hardcoded display buffer array sizes.
**Prevention:** Always cap path or text display lengths against `sizeof(buf) - 1` before performing string copies into fixed-size stack arrays, and use `snprintf` or `strlcpy` over `strcpy`.
