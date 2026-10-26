## 2026-10-26 - Progress Bar Off-By-One Fill Boundary
**Learning:** Checking `i <= complete` when iterating `0` to `width - 1` causes 0% progress (`complete = 0`) to render 1 filled block (`0 <= 0` is true), confusing users into thinking work has already started/progressed.
**Action:** Always use strict comparison `i < complete` for progress bar character fill loops so 0% progress displays 0 filled blocks and 100% progress displays all filled blocks.
