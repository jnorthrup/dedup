## 2026-10-24 - Avoid O_NONBLOCK/fcntl and 4KB Mallocs in Hot Paths
**Learning:** In file signature computation called for every file in traversal, using `O_NONBLOCK` + two `fcntl` calls added 2 redundant syscalls per file. Also, dynamic `malloc(4096)` and `free()` per file added unnecessary heap allocation overhead on hot path.
**Action:** Always open regular files in standard blocking mode directly with `O_RDONLY` and use fixed 4KB stack buffers for small quick-hash reads.
