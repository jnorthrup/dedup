# Bolt's Journal

## 2026-10-12 - Caching Hash Container Masks and Thresholds
**Learning:** In hot hash table lookup/insertion paths (`SeenSet` and `SigTable`), evaluating expressions like `capacity * 3 / 4` and performing 64-bit integer modulo division (`hash % bucket_count`) on every insertion adds significant CPU overhead. Pre-calculating `mask = capacity - 1` and `max_count = capacity * 3 / 4` during table creation/resizing speeds up `seen_set_insert` by ~1.86x and `sig_table_insert` by ~1.14x.
**Action:** Always store bitwise masks (`capacity - 1`) and pre-calculated threshold limits directly in power-of-two hash table structures rather than recomputing them per query.
