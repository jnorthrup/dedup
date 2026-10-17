## 2026-04-22 - Terminal Width Derived Bounds Stack Overflow

**Vulnerability:** In `display_status()` (`dedup.c`), `path_max` was dynamically computed based on terminal column width (`width - 42`), but path string formatting copied up to `path_max` bytes into `truncated_path`, a fixed 256-byte stack array, using `strcpy()`/`strncpy()`. On wide terminals (width >= 298), `path_max` exceeded 255 bytes, causing stack buffer overflows when processing long file paths.

**Learning:** Terminal dimensions or environment-derived values cannot be trusted as buffer size limits for fixed-capacity stack allocations.

**Prevention:** Always cap dynamically computed path bounds by `sizeof(buffer) - 1` and use safe bounded string formatting (`snprintf`) instead of unbounded copy functions (`strcpy`).
