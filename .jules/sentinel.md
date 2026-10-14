## 2026-10-14 - Prevent stack buffer overflow in status path formatting
**Vulnerability:** Unbounded `path_max` value derived from terminal width could cause `strcpy` and `strncpy` to overflow the fixed 256-byte stack buffer `truncated_path` in `display_status()`.
**Learning:** Formatting strings for terminal UI displays using terminal width without capping against fixed stack buffer limits leads to stack-based buffer overflow vulnerabilities when terminal width is large.
**Prevention:** Always cap path and string output length limits against the destination buffer size before performing string formatting or memory copies.
