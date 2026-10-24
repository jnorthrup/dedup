## 2026-04-22 - CLI Sub-Help and Standards
**Learning:** Help strings that reference sub-arguments (e.g. `--help formats`) create user expectation; if unhandled, users receive generic usage errors on stderr with non-zero exit codes.
**Action:** Always handle sub-help references mentioned in usage text, and ensure explicit user requests for `--help` exit 0 on `stdout`.
