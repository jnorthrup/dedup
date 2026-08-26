// Copyright © 2023 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#ifndef __DEDUP_BACKEND_H__
#define __DEDUP_BACKEND_H__

typedef enum CloneBackend {
    BACKEND_AUTO     = 0,
    BACKEND_CLONEFILE = 1,  /* macOS clonefile(2) */
    BACKEND_FICLONE  = 2,  /* Linux FICLONE ioctl */
    BACKEND_UBT      = 3,  /* userspace BTRFS (future) */
} CloneBackend;

/// backend_init
///
/// Probe the system and select the clone backend. Checks the
/// DEDUP_BACKEND environment variable first (for testing),
/// then falls back to AUTO which picks the best available.
/// Returns the selected backend.
CloneBackend backend_init(void);

/// backend_name
///
/// Returns a human-readable name for the given backend.
const char* backend_name(CloneBackend b);

/// backend_is_available
///
/// Returns true if the given backend can perform clone operations
/// on this system right now.
int backend_is_available(CloneBackend b);

#endif // __DEDUP_BACKEND_H__
