/*
 * ubt.h — Public API for the userspace BTRFS image library (libubt).
 *
 * This library creates plain-file images that contain a valid btrfs
 * superblock and minimal tree structure, suitable for parsing by
 * btrfs-progs tools (e.g.  btrfs inspect-internal dump-super).
 */

#ifndef UBIFS_UBT_H
#define UBIFS_UBT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ubt_create_image — create (or truncate) a file at `path` with the given
 *                    size in bytes.  Returns 0 on success, -1 on error
 *                    (errno is set).
 */
int ubt_create_image(const char *path, uint64_t size);

/*
 * ubt_format_image — write a minimal btrfs superblock and root-tree leaf
 *                    into the open file descriptor `fd`.
 *
 * The fd must be opened for read/write and refer to a file that is at
 * least 256 KiB in size (created by ubt_create_image).
 *
 * Returns 0 on success, -1 on error (errno is set).
 */
int ubt_format_image(int fd);

#ifdef __cplusplus
}
#endif

#endif /* UBIFS_UBT_H */
