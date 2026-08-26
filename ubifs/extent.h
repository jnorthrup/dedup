/*
 * extent.h — Shared-extent bookkeeping table for libubt.
 *
 * Maintains a hash table mapping (image_fd, bytenr) → refcount,
 * plus per-file extent maps that track which shared extents each
 * file references.
 */

#ifndef UBIFS_EXTENT_H
#define UBIFS_EXTENT_H

#include <stdint.h>

/* ── Shared extent entry ───────────────────────────────────────────────── */

struct ubt_extent {
    int                 image_fd;
    uint64_t            bytenr;      /* offset within the image           */
    uint64_t            length;      /* extent length in bytes            */
    int                 refcount;    /* number of files sharing this      */
    struct ubt_extent  *next;        /* hash chain                       */
};

/* ── Per-file extent map entry ────────────────────────────────────────── */

struct ubt_file_extent {
    uint64_t                 file_offset;  /* offset within the file      */
    uint64_t                 bytenr;       /* shared extent bytenr        */
    uint64_t                 length;       /* extent length               */
    struct ubt_file_extent  *next;
};

/* ── Hash table for shared extents ────────────────────────────────────── */

#define UBT_EXTENT_BUCKETS 64

struct ubt_extent_table {
    struct ubt_extent *buckets[UBT_EXTENT_BUCKETS];
};

/* ── Image context (one per opened image) ─────────────────────────────── */

struct ubt_image {
    int                      fd;
    struct ubt_extent_table  extents;
    struct ubt_image        *next;
};

/* ── File context (one per opened file within an image) ───────────────── */

struct ubt_file {
    int                      fd;
    int                      image_fd;
    struct ubt_file_extent  *extents;   /* linked list of extent mappings */
    struct ubt_file         *next;
};

/* ── API ──────────────────────────────────────────────────────────────── */

/* Register / unregister an image fd */
void  ubt_register_image(int fd);
void  ubt_unregister_image(int fd);

/* Find the image context for an fd (returns NULL if not registered) */
struct ubt_image *ubt_find_image(int fd);

/* Register / unregister a file fd within an image */
void  ubt_register_file(int fd, int image_fd);
void  ubt_unregister_file(int fd);
struct ubt_file *ubt_find_file(int fd);

/* Add a file extent mapping (called during clone) */
void  ubt_file_add_extent(struct ubt_file *file, uint64_t file_offset,
                           uint64_t bytenr, uint64_t length);

/* Increment / decrement shared extent refcount.
 * Returns the new refcount, or -1 on error. */
int   ubt_extent_inc(struct ubt_image *img, uint64_t bytenr, uint64_t length);
int   ubt_extent_dec(struct ubt_image *img, uint64_t bytenr);

/* Look up the refcount for an extent. Returns 0 if not found. */
int   ubt_extent_refcount(struct ubt_image *img, uint64_t bytenr);

#endif /* UBIFS_EXTENT_H */
