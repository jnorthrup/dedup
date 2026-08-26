/*
 * extent.c — Shared-extent hash table and per-file extent map.
 *
 * The extent table maps (image_fd, bytenr) → refcount so that multiple
 * files can share the same extent with proper reference counting.
 * The per-file extent map tracks which shared extents each file points to.
 */

#include "extent.h"

#include <stdlib.h>
#include <string.h>

/* ── Global registries ────────────────────────────────────────────────── */

static struct ubt_image *g_images;
static struct ubt_file   *g_files;

/* ── Simple hash function ─────────────────────────────────────────────── */

static unsigned
extent_hash(int image_fd, uint64_t bytenr)
{
    uint64_t h = (uint64_t)image_fd ^ bytenr;
    h = (h >> 16) ^ h;
    h *= 0x45d9f3b;
    h = (h >> 16) ^ h;
    return (unsigned)(h % UBT_EXTENT_BUCKETS);
}

/* ── Image registry ───────────────────────────────────────────────────── */

void
ubt_register_image(int fd)
{
    /* Skip if already registered */
    if (ubt_find_image(fd))
        return;

    struct ubt_image *img = calloc(1, sizeof(*img));
    if (!img)
        return;

    img->fd = fd;
    memset(&img->extents, 0, sizeof(img->extents));
    img->next  = g_images;
    g_images   = img;
}

void
ubt_unregister_image(int fd)
{
    struct ubt_image **pp = &g_images;
    while (*pp) {
        if ((*pp)->fd == fd) {
            struct ubt_image *del = *pp;
            *pp = del->next;

            /* Free all extent entries */
            for (unsigned i = 0; i < UBT_EXTENT_BUCKETS; i++) {
                struct ubt_extent *e = del->extents.buckets[i];
                while (e) {
                    struct ubt_extent *next = e->next;
                    free(e);
                    e = next;
                }
            }
            free(del);
            return;
        }
        pp = &(*pp)->next;
    }
}

struct ubt_image *
ubt_find_image(int fd)
{
    for (struct ubt_image *img = g_images; img; img = img->next)
        if (img->fd == fd)
            return img;
    return NULL;
}

/* ── File registry ────────────────────────────────────────────────────── */

void
ubt_register_file(int fd, int image_fd)
{
    /* Skip if already registered */
    if (ubt_find_file(fd))
        return;

    struct ubt_file *f = calloc(1, sizeof(*f));
    if (!f)
        return;

    f->fd       = fd;
    f->image_fd = image_fd;
    f->extents  = NULL;
    f->next     = g_files;
    g_files     = f;
}

void
ubt_unregister_file(int fd)
{
    struct ubt_file **pp = &g_files;
    while (*pp) {
        if ((*pp)->fd == fd) {
            struct ubt_file *del = *pp;
            *pp = del->next;

            /* Free all file extent entries */
            struct ubt_file_extent *fe = del->extents;
            while (fe) {
                struct ubt_file_extent *next = fe->next;
                free(fe);
                fe = next;
            }
            free(del);
            return;
        }
        pp = &(*pp)->next;
    }
}

struct ubt_file *
ubt_find_file(int fd)
{
    for (struct ubt_file *f = g_files; f; f = f->next)
        if (f->fd == fd)
            return f;
    return NULL;
}

/* ── Per-file extent mapping ──────────────────────────────────────────── */

void
ubt_file_add_extent(struct ubt_file *file, uint64_t file_offset,
                     uint64_t bytenr, uint64_t length)
{
    struct ubt_file_extent *fe = calloc(1, sizeof(*fe));
    if (!fe)
        return;

    fe->file_offset = file_offset;
    fe->bytenr      = bytenr;
    fe->length      = length;
    fe->next        = file->extents;
    file->extents   = fe;
}

/* ── Shared extent refcount operations ────────────────────────────────── */

/* Find an existing extent entry, or return NULL */
static struct ubt_extent *
extent_lookup(struct ubt_extent_table *tbl, int image_fd, uint64_t bytenr)
{
    unsigned h = extent_hash(image_fd, bytenr);
    for (struct ubt_extent *e = tbl->buckets[h]; e; e = e->next) {
        if (e->image_fd == image_fd && e->bytenr == bytenr)
            return e;
    }
    return NULL;
}

int
ubt_extent_inc(struct ubt_image *img, uint64_t bytenr, uint64_t length)
{
    struct ubt_extent *e = extent_lookup(&img->extents, img->fd, bytenr);
    if (e) {
        e->refcount++;
        return e->refcount;
    }

    /* New entry */
    e = calloc(1, sizeof(*e));
    if (!e)
        return -1;

    e->image_fd = img->fd;
    e->bytenr   = bytenr;
    e->length   = length;
    e->refcount = 1;

    unsigned h = extent_hash(img->fd, bytenr);
    e->next            = img->extents.buckets[h];
    img->extents.buckets[h] = e;
    return 1;
}

int
ubt_extent_dec(struct ubt_image *img, uint64_t bytenr)
{
    struct ubt_extent *e = extent_lookup(&img->extents, img->fd, bytenr);
    if (!e)
        return -1;

    e->refcount--;
    if (e->refcount <= 0) {
        /* Remove from hash table */
        unsigned h = extent_hash(img->fd, bytenr);
        struct ubt_extent **pp = &img->extents.buckets[h];
        while (*pp) {
            if (*pp == e) {
                *pp = e->next;
                free(e);
                return 0;
            }
            pp = &(*pp)->next;
        }
        return 0;
    }
    return e->refcount;
}

int
ubt_extent_refcount(struct ubt_image *img, uint64_t bytenr)
{
    struct ubt_extent *e = extent_lookup(&img->extents, img->fd, bytenr);
    return e ? e->refcount : 0;
}
