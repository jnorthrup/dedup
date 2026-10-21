## 2026-10-21 - Dead Code Removal in Signature Table
**Learning:** Removing unused functions like `sig_table_has_clone_id` keeps header APIs clean and reduces binary footprint, though active algorithm optimization should be prioritized when searching for execution speed boosts.
**Action:** Always scan for unreferenced helper functions when profiling modules for cleanup opportunities.
