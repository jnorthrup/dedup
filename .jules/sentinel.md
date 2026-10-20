## 2026-10-20 - Fix Stack Buffer Overflow in Status Output Formatting
**Vulnerability:** In `display_status()` (`dedup.c`), `truncated_path` was a 256-byte stack buffer, but `path_max` calculated from terminal width (`width - fixed_width - 1`) could exceed 256 on wide terminals. Long file paths copied into `truncated_path` using `strcpy` or `strncpy` caused stack buffer overflow.
**Learning:** Terminal width calculation without explicit upper bounds on static stack buffers allows path lengths to overflow stack variables when terminal width is large.
**Prevention:** Always cap path formatting lengths to `sizeof(buf) - 1` when using fixed-size stack buffers, and use safe string formatting with `snprintf`.
