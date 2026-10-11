// Copyright © 2023 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#ifndef __DEDUP_BACKEND_H__
#define __DEDUP_BACKEND_H__

#if defined(__linux__) && !defined(HAVE_UBT)
/// Clone mode deduplicates in place with the FIDEDUPERANGE ioctl. The
/// kernel compares the files under lock and shares the origin's blocks with
/// the duplicate, which keeps its inode: ownership, permissions, timestamps,
/// extended attributes and hard links are untouched.
#define DEDUP_IN_PLACE 1
#endif

typedef enum CloneBackend {
    BACKEND_AUTO          = 0,
    BACKEND_CLONEFILE     = 1,  /* macOS clonefile(2) */
    BACKEND_FIDEDUPERANGE = 2,  /* Linux FIDEDUPERANGE ioctl, in place */
    BACKEND_UBT           = 3,  /* userspace BTRFS (future) */
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
