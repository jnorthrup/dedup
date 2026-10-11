// SPDX-License-Identifier: BSD-2-Clause

#ifndef __DEDUP_EXTENT_MAP_H__
#define __DEDUP_EXTENT_MAP_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// One mapping from a file's logical offsets to device addresses, as
/// reported by FIEMAP on Linux.
typedef struct Extent {
    uint64_t logical;
    uint64_t physical;
    uint64_t length;
    uint32_t flags;
} Extent;

/// The filesystem reports the extent as shared with another file.
#define EXTENT_SHARED (1u << 0)

/// The address is not a real, shareable location: unknown or delayed
/// allocation, or data stored inline with metadata, which is how btrfs
/// keeps small files.
#define EXTENT_NOT_SHAREABLE (1u << 1)

/// The data is encoded (compressed or encrypted), so offsets inside the
/// extent do not map linearly onto device addresses.
#define EXTENT_ENCODED (1u << 2)

/// True when the storage of [0, size) is entirely shared between the two
/// files: every byte range is a hole in both, or maps to the same device
/// address in both with both extents reported as shared. Files with no
/// data in the range share trivially. Extents must be sorted by logical
/// offset and must not overlap.
bool extent_maps_shared(const Extent* a, size_t a_count,
                        const Extent* b, size_t b_count,
                        uint64_t size);

/// The number of extents that overlap [0, size) and have any of `flags`.
/// With `flags` 0, every overlapping extent counts.
size_t extent_map_count(const Extent* extents, size_t count,
                        uint64_t size, uint32_t flags);

#endif // __DEDUP_EXTENT_MAP_H__
