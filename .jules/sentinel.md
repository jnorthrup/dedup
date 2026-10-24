## 2026-08-25 - Terminal Width Unbounded Stack Buffer Overflow in Path Truncation
**Vulnerability:** In `display_status()`, `path_max` was computed directly from terminal column width (`width - 42`) without bounding it to `sizeof(truncated_path) - 2` (254). In wide terminals (> 298 columns), `strcpy` and `strncpy` into `truncated_path[256]` caused a stack buffer overflow when handling long file paths.
**Learning:** Formatting buffers calculated dynamically from external system properties (such as terminal dimensions) must always be clamped to the fixed array capacity.
**Prevention:** Always cap path lengths and maximum string display widths against the destination buffer size before calling `strcpy` or `strncpy`.
