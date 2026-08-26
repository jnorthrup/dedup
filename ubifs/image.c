/*
 * image.c — File-backed btrfs image helpers.
 *
 * Provides the low-level plumbing for creating an image file and
 * reading/writing fixed-size blocks within it.
 */

#include "compat.h"
#include "ubt.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int
ubt_create_image(const char *path, uint64_t size)
{
    int fd;

    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;

    if (ftruncate(fd, (off_t)size) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }

    close(fd);
    return 0;
}
