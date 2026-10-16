# Bolt's Journal - Critical Learnings

## 2026-10-16 - Buffer Re-use for File Signature Sampling
**Learning:** `compute_signature()` previously called `pread` up to 4 times for sample points and then performed another `pread` for the initial 4KB quick hash window. By reading the initial 4KB buffer first, all sample positions within the first 4KB can be extracted directly from memory, eliminating up to 80% of `pread` syscall overhead for small files ($\le$ 4KB) and at least 20% for large files. When checking buffer boundaries, care must be taken that a full 4-byte sample is present in the buffer before skipping `pread`, or fallback to `read_sample_into` is required for files larger than 4KB.
**Action:** Always inspect whether initial I/O buffers can satisfy subsequent position queries before issuing additional syscalls.
