/*
 * clone.c — Control-plane FFI for reflink-style deduplication.
 *
 * Provides:
 *   ubt_clone(dst_fd, src_fd)     — BTRFS_IOC_CLONE semantics
 *   ubt_same_fs(a_fd, b_fd)       — check if two fds share an image
 *   ubt_private_size(fd)          — ATTR_CMNEXT_PRIVATESIZE semantics
 */

#include "compat.h"
#include "ubt.h"
#include "extent.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

/* ── ubt_same_fs ──────────────────────────────────────────────────────── */

int
ubt_same_fs(int a_fd, int b_fd)
{
    struct ubt_image *img_a = ubt_find_image(a_fd);
    struct ubt_image *img_b = ubt_find_image(b_fd);

    if (!img_a || !img_b) {
        errno = EINVAL;
        return -1;
    }

    return (img_a == img_b) ? 1 : 0;
}

/* ── ubt_clone ────────────────────────────────────────────────────────── */

/*
 * Clone all extents from src to dst within the same image.
 * Both fds must be registered via ubt_register_image / ubt_register_file.
 *
 * Semantics mirror BTRFS_IOC_CLONE:
 *   - All extents in src are shared with dst (refcount incremented)
 *   - dst's file extent map points to the same bytenr as src
 *   - dst's file size is set to match src
 */
int
ubt_clone(int dst_fd, int src_fd)
{
    /* Look up file contexts */
    struct ubt_file *src_file = ubt_find_file(src_fd);
    struct ubt_file *dst_file = ubt_find_file(dst_fd);

    if (!src_file || !dst_file) {
        errno = EINVAL;
        return -1;
    }

    /* Both must be in the same image */
    struct ubt_image *img = ubt_find_image(src_file->image_fd);
    if (!img || img->fd != dst_file->image_fd) {
        errno = EXDEV;
        return -1;
    }

    /* Clear any existing dst extents (fresh clone) */
    struct ubt_file_extent *fe = dst_file->extents;
    while (fe) {
        struct ubt_file_extent *next = fe->next;
        free(fe);
        fe = next;
    }
    dst_file->extents = NULL;

    /* Walk src extents and share them with dst */
    for (fe = src_file->extents; fe; fe = fe->next) {
        /* Add to shared extent table (bump refcount) */
        if (ubt_extent_inc(img, fe->bytenr, fe->length) < 0) {
            errno = ENOMEM;
            return -1;
        }

        /* Add the same extent mapping to dst */
        ubt_file_add_extent(dst_file, fe->file_offset,
                             fe->bytenr, fe->length);
    }

    return 0;
}

/* ── ubt_private_size ─────────────────────────────────────────────────── */

/*
 * Returns the number of bytes in the file that are NOT shared — i.e.,
 * unique to this file. For a freshly cloned file this is 0 (all bytes
 * are shared). After a CoW write, the mutated extent's refcount drops
 * to 1 and becomes private.
 *
 * private_size = Σ length  for all extents where refcount == 1
 */
int64_t
ubt_private_size(int fd)
{
    struct ubt_file *file = ubt_find_file(fd);
    if (!file) {
        errno = EINVAL;
        return -1;
    }

    struct ubt_image *img = ubt_find_image(file->image_fd);
    if (!img) {
        errno = EINVAL;
        return -1;
    }

    int64_t total = 0;
    for (struct ubt_file_extent *fe = file->extents; fe; fe = fe->next) {
        int ref = ubt_extent_refcount(img, fe->bytenr);
        if (ref == 1)
            total += (int64_t)fe->length;
    }
    return total;
}
