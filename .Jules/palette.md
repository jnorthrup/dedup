## 2026-10-19 - CLI Progress Bar Zero Bounds & Terminal Underflow
**Learning:** Progress bars in C CLI utilities can render misleading filled indicators at 0% if `i <= complete` is used instead of `i < complete`, and division by zero when `totalUnitCount` is 0 results in `nan%` display. Unsigned width calculations (`w.ws_col - overhead`) also underflow in narrow or non-tty environments.
**Action:** Always guard progress division by checking `totalUnits > 0`, use `<` for loop fills, and clamp terminal width calculations safely against overhead.
