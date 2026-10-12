## 2026-10-12 - CLI Help Guidance Clarity for Sub-Commands / Options
**Learning:** CLI help text mentioning non-existent flags or instructions (e.g. `See --help formats`) confuses users. Providing explicit sub-option inspect flags (like `-F formats`) and handling help keywords directly in option parser handlers improves discoverability and user experience.
**Action:** When adding option-level help inspect mechanisms to standard CLI options, handle keywords like `help` or `formats` in option parsing and update usage text accordingly.
