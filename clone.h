// Copyright © 2023-2026 TTKB, LLC.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// SPDX-License-Identifier: BSD-2-Clause

#ifndef __DEDUP_CLONE_H__
#define __DEDUP_CLONE_H__

/// replace_with_clone
///
/// The `replace_with_clone` function causes the link named `dst` to be
/// replaced with a clone of `src`. Unlike `clonefile(2)`, it is expected
/// that `dst` already exists. All metadata (mode, flags, & ACLs)
/// are retained on `dst`. The current user must have read access to both
/// `src` and `dst`, permission to copy the destination's metadata, and write
/// access to the directory where `dst` resides. The source may be read-only.
///
/// `src` and `dst` must be on the same volume. (TODO: is it enough
/// that they are with in the same APFS partition, can clones span
/// volume boundaries?).
///
/// On success `dst` will have its data replaced with copy-on-write,
/// cloned blocks from `src` and `replace_with_clone` returns 0.
///
/// On failure clonefile will return one of the following values:
///
///   [ENAMETOOLONG] the temporary path cannot fit in `PATH_MAX`
///
///   In addition, `replace_with_clone` may return any error
///   returned by `clonefile(2)`, `copyfile(2)`, or `rename(2)`.
///
/// See also: `clonefile(2)`, `copyfile(2)`, or `rename(2)`
int replace_with_clone(const char* src, const char* dst, bool preserve_parent_mtime);

/// replace_with_link
///
/// The `replace_with_link` function causes the link named `dst` to be
/// atomically replaced with a hardlink of `src`. `src` and `dst` must be on the same
/// volume.
///
/// On success `dst` will be replaced and `replace_with_link` returns 0.
///
/// On failure the original destination is retained and an errno value
/// is returned.
///
/// See also: `link(2)`, `rename(2)`
int replace_with_link(const char* src, const char* dst);

/// replace_with_symlink
///
/// The `replace_with_symlink` function causes the link named `dst` to be
/// replaced with a symlink to `src`. The link will be a relative path from
/// `dst` to `src`.
///
/// See also: `symlink(2)`
int replace_with_symlink(const char* src, const char* dst);

#include "backend.h"

#if defined(DEDUP_IN_PLACE)
#include <stdint.h>

/// How the storage of a duplicate relates to its origin.
typedef enum ShareState {
    SHARE_SEPARATE, ///< the duplicate has blocks of its own
    SHARE_SHARED,   ///< every block of the duplicate is shared with the origin
    SHARE_INLINE,   ///< the origin's data is stored inline with metadata
                    ///< (btrfs small files), which cannot be shared
    SHARE_UNKNOWN,  ///< the extent maps could not be read or trusted
} ShareState;

/// share_state
///
/// Compares the FIEMAP extent maps of two files of `size` bytes, after
/// flushing their dirty data so that every extent has its final address.
ShareState share_state(const char* origin, const char* duplicate, uint64_t size);

typedef enum DedupeResult {
    DEDUPE_DONE,    ///< the kernel deduplicated every byte
    DEDUPE_DIFFERS, ///< the files no longer match; nothing was changed
    DEDUPE_FAILED,  ///< errno says why; nothing was changed
} DedupeResult;

/// dedupe_in_place
///
/// Shares the blocks of `origin` with the identical file `duplicate` using
/// FIDEDUPERANGE. The kernel compares both files under lock before sharing
/// anything, so a file that changed since it was compared is left alone.
/// `duplicate` keeps its inode, and with it its ownership, permissions,
/// timestamps, extended attributes and hard links. It is opened read-only:
/// the kernel lets its owner, or anyone allowed to write it, deduplicate.
///
/// A successful call does not prove that blocks are shared (btrfs reports
/// success for inline data, which stays unshared); check with `share_state`.
DedupeResult dedupe_in_place(const char* origin, const char* duplicate, uint64_t size);

/// dedupe_supported
///
/// Asks whether the filesystem holding the regular file at `path`
/// implements FIDEDUPERANGE, with a zero-length request that changes
/// nothing. Returns 1 if it does, 0 if it does not, and -1 with errno set
/// when this file cannot tell (for example, it cannot be opened).
///
/// The request stops in the VFS, before the filesystem's own checks: XFS
/// formatted without reflink answers 1 here and refuses the real request
/// with EOPNOTSUPP, and other filesystems may do the same.
int dedupe_supported(const char* path);
#endif // DEDUP_IN_PLACE

#endif // __DEDUP_CLONE_H__
