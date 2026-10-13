## 2026-10-13 - Power-of-2 Hash Table Indexing
**Learning:** `sig_table_insert` performed expensive 64-bit modulo operations (`hash % bucket_count`) on every file insertion. Using a bitwise AND mask (`hash & (bucket_count - 1)`) when `bucket_count` is a power of 2 eliminates integer division latency (~10-15 cycles down to 1 cycle per insertion).
**Action:** Always check if dynamic hash table sizes are powers of 2 and use bitwise masking for fast index lookup in hot table operations.
