// SPDX-License-Identifier: BSD-2-Clause

#include "extent_map.h"

// Index of the first extent at or after i that ends after pos.
static size_t skip_extents_before(const Extent* extents, size_t count, size_t i, uint64_t pos) {
    while (i < count && extents[i].logical + extents[i].length <= pos) {
        i++;
    }
    return i;
}

bool extent_maps_shared(const Extent* a, size_t a_count,
                        const Extent* b, size_t b_count,
                        uint64_t size) {
    size_t i = 0;
    size_t j = 0;
    uint64_t pos = 0;

    // Walk both maps over [0, size) in lockstep. The two files may split
    // the same data into extents at different boundaries, so compare the
    // address of each byte range rather than the extent lists.
    while (pos < size) {
        i = skip_extents_before(a, a_count, i, pos);
        j = skip_extents_before(b, b_count, j, pos);

        bool a_mapped = i < a_count && a[i].logical <= pos;
        bool b_mapped = j < b_count && b[j].logical <= pos;
        if (a_mapped != b_mapped) {
            return false; // data in one file, a hole in the other
        }

        if (!a_mapped) {
            // a hole in both: resume at the next extent of either file
            uint64_t next = size;
            if (i < a_count && a[i].logical < next) {
                next = a[i].logical;
            }
            if (j < b_count && b[j].logical < next) {
                next = b[j].logical;
            }
            pos = next;
            continue;
        }

        const Extent* ea = &a[i];
        const Extent* eb = &b[j];
        uint32_t flags = ea->flags | eb->flags;
        if ((flags & EXTENT_NOT_SHAREABLE) || !(ea->flags & eb->flags & EXTENT_SHARED)) {
            return false;
        }

        if (flags & EXTENT_ENCODED) {
            // offsets inside an encoded extent are not linear: only the
            // whole, identical extent counts as shared
            if (ea->logical != eb->logical || ea->physical != eb->physical ||
                ea->length != eb->length || ea->flags != eb->flags) {
                return false;
            }
        } else if (ea->physical + (pos - ea->logical) != eb->physical + (pos - eb->logical)) {
            return false;
        }

        uint64_t a_end = ea->logical + ea->length;
        uint64_t b_end = eb->logical + eb->length;
        pos = a_end < b_end ? a_end : b_end;
    }

    return true;
}

size_t extent_map_count(const Extent* extents, size_t count,
                        uint64_t size, uint32_t flags) {
    size_t n = 0;
    for (size_t i = 0; i < count; i++) {
        if (extents[i].logical < size && (flags == 0 || (extents[i].flags & flags))) {
            n++;
        }
    }
    return n;
}
