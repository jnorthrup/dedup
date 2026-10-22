## 2026-10-22 - Stack Buffer Overflow in Terminal Status Path Truncation
**Vulnerability:** `display_status()` dynamically computed `path_max` based on terminal width (`ioctl(STDOUT_FILENO, TIOCGWINSZ, &w)`). When running in wide terminal windows (>296 columns), `path_max` exceeded 255 bytes, causing `strcpy` or `strncpy` to write past the bounds of `truncated_path[256]` on the stack.
**Learning:** Terminal-width-dependent buffer calculations can easily exceed fixed-size stack buffers if terminal width is not clamped to `sizeof(buf) - 1`.
**Prevention:** Always cap width/path calculations to `sizeof(buf) - 1` and use bounded formatting functions (`snprintf`) instead of `strcpy`/`strncpy`.
