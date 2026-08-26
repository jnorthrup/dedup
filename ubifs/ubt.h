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
#include <sys/types.h>

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

/*
 * Image / file registration — must be called before clone/same_fs/
 * private_size so the library knows which image each fd belongs to.
 */
void ubt_register_image(int fd);
void ubt_unregister_image(int fd);
void ubt_register_file(int fd, int image_fd);
void ubt_unregister_file(int fd);

/*
 * ubt_same_fs — check if two fds belong to the same image.
 *
 * Both fds must have been registered with ubt_register_file.
 * Returns 1 if same image, 0 if different, -1 on error.
 */
int ubt_same_fs(int a_fd, int b_fd);

/*
 * ubt_clone — mirror BTRFS_IOC_CLONE semantics.
 *
 * Both fds must be in the same image.  The dst file's extent map is
 * replaced with a shared copy of src's extent map; refcounts are
 * incremented for each shared extent.
 *
 * Returns 0 on success, -1 on error (errno is set).
 */
int ubt_clone(int dst_fd, int src_fd);

/*
 * ubt_private_size — mirror ATTR_CMNEXT_PRIVATESIZE.
 *
 * Returns the number of bytes in the file that are NOT shared (unique
 * to this file).  For a freshly cloned file this is 0; after a CoW
 * write to one extent, that extent becomes private.
 *
 * Returns the private byte count, or -1 on error.
 */
int64_t ubt_private_size(int fd);

#ifdef __cplusplus
}
#endif

#endif /* UBIFS_UBT_H */
