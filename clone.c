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

#if defined(__APPLE__)
#include <sys/clonefile.h>
#include <copyfile.h>
#endif
#include <sys/random.h>
#include <sys/stat.h>
#if defined(__FREEBSD__) || defined(__linux__)
#include <sys/ioctl.h>
#endif
#if defined(__linux__)
#include <fcntl.h>
#include <linux/fs.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "clone.h"

#if defined(HAVE_UBT)
#include "ubt.h"
#endif
#if defined(__linux__) || defined(HAVE_UBT)
#include <fcntl.h>
#endif
#if defined(DEDUP_IN_PLACE)
#include <linux/fiemap.h>
#include <stdint.h>

#include "extent_map.h"
#endif

static int find_zero_file(const char* restrict path) {
    struct stat s = { 0 };
    if (stat(path, &s)) {
        fprintf(stderr, "Could not stat %s\n", path);
        perror("stat(2)");
        return 2;
    }

    if (s.st_size == 0) {
        return 3;
    }

    return 0;
}

#if !defined(__APPLE__)
#include <libgen.h>
#include <limits.h>
static char* dirname_r(const char* path, char* buf) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    char* d = dirname(tmp);
    if (!d) return NULL;
    snprintf(buf, PATH_MAX, "%s", d);
    return buf;
}
#endif

// Expects `out` to be char[PATH_MAX].
//
char* tmp_name(const char* restrict path, char* restrict out, size_t size) {
    if (size == 0) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    out[0] = '\0';

    char dir[PATH_MAX] = { 0 };
    char base[PATH_MAX] = { 0 };
#if defined(__APPLE__)
    if (!dirname_r(path, dir)) {
        return NULL;
    }

    if (!basename_r(path, base)) {
        return NULL;
    }
#else
    // POSIX dirname(3) and basename(3) may modify their argument and may
    // return static storage, so split a private copy and copy the results.
    char copy[PATH_MAX];
    if (snprintf(copy, sizeof(copy), "%s", path) >= (int)sizeof(copy)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    snprintf(dir, sizeof(dir), "%s", dirname(copy));
    snprintf(copy, sizeof(copy), "%s", path);
    snprintf(base, sizeof(base), "%s", basename(copy));
#endif

    long name_max = pathconf(dir, _PC_NAME_MAX);
    if (name_max < 0) name_max = NAME_MAX;

    // Keep recognizable staging names where they fit. A valid destination
    // can already use NAME_MAX bytes, so use a short random suffix rather
    // than extending (or truncating) that basename. The caller still creates
    // this path exclusively; neither a collision nor a failed create gives
    // us ownership of an existing file.
    char suffix[33];
    const char* stage_base = base;
    if (strlen(base) + 3 > (size_t)name_max ||
        strlen(dir) + strlen(base) + 5 > size) {
        unsigned char random[16];
        static const char hex[] = "0123456789abcdef";
        if (getentropy(random, sizeof(random)) != 0) return NULL;
        for (size_t i = 0; i < sizeof(random); i++) {
            suffix[i * 2] = hex[random[i] >> 4];
            suffix[i * 2 + 1] = hex[random[i] & 0x0f];
        }
        suffix[sizeof(suffix) - 1] = '\0';
        stage_base = suffix;
    }

    if (strlen(stage_base) + 3 > (size_t)name_max) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    if (strlcat(out, dir, size) >= size ||
        strlcat(out, "/.~.", size) >= size ||
        strlcat(out, stage_base, size) >= size) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    struct stat st;
    if (lstat(out, &st) == 0) {
        fprintf(stderr,
                "Staging file %s already exists. Remove it to replace %s\n",
                out,
                path);
        errno = EEXIST;
        return NULL;
    }
    if (errno != ENOENT) {
        return NULL;
    }

    return out;
}

static int genfile_clone(const char* src, const char* dst) {
#if defined(HAVE_UBT)
    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) return errno;
    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (dst_fd < 0) { int e = errno; close(src_fd); return e; }
    int r = ubt_clone(dst_fd, src_fd);
    int e = errno;
    close(src_fd);
    close(dst_fd);
    if (r) unlink(dst);
    errno = e;
    return r ? e : 0;
#elif defined(__APPLE__)
    return clonefile(src, dst, 0);
#elif defined(__FREEBSD__)
    // n.b.! This is completely untested and probably erases
    //       everything it touches. There are currently no
    //       equivalents to volume capability checks on the
    //       frontend, so it's not even clear that the files
    //       that are being passed in here are on a partition
    //       that can be cloned.
    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) {
        perror("open(2) failed");
        return errno;
    }
    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (dst_fd < 0) {
        int e = errno;
        close(src_fd);
        errno = e;
        perror("open(2) failed");
        return errno;
    }
    int result = ioctl(dst_fd, CF_FICLONE, src_fd);
    int errno_saved = errno;
    close(src_fd);
    close(dst_fd);
    if (result) unlink(dst);
    errno = errno_saved;
    return result;
#elif defined(__linux__)
    int s = open(src, O_RDONLY);
    if (s < 0) return errno;
    int d = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (d < 0) { int e = errno; close(s); return e; }
    int r = ioctl(d, FICLONE, s);   /* <linux/fs.h> */
    int e = errno;
    close(s);
    close(d);
    if (r) unlink(dst);
    errno = e;
    return r ? e : 0;
#else
#error Operating system not supported.
#endif
}

// get the parent directory mtime and return it and a file descriptor
// for the directory. if return is 0, caller is responsible for closing
// the returned fd
static int dir_mtime(const char* path, int* fd_out, struct timespec* mtime_out) {
    char buffer[PATH_MAX] = { 0 };
    char* parent = dirname_r(path, buffer);
    if (!parent) {
        perror("dirname_r");
        return -1;
    }

    int fd = open(parent, O_RDONLY);
    if (fd == -1) {
        perror("open parent dir");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat parent dir");
        close(fd);
        return -1;
    }

    *fd_out = fd;
#if defined(__APPLE__)
    *mtime_out = st.st_mtimespec;
#else
    *mtime_out = st.st_mtim;
#endif
    return 0;
}

// restore the provided mtime to the provided fd. fd is closed
// before the function returns
static void restore_dir_mtime(int fd, struct timespec mtime) {
    struct timespec times[2] = {
        // omit atime
        { .tv_sec = 0, .tv_nsec = UTIME_OMIT },
        mtime,
    };
    if (futimens(fd, times) == -1) {
        switch (errno) {
        case EPERM:
            fprintf(stderr, "Warning: cannot preserve parent mtime, permission denied\n");
            break;
        case EROFS:
            fprintf(stderr, "Warning: cannot preserve parent mtime, filesystem is read-only\n");
            break;
        default:
            perror("Warning: futimens");
            break;
        }
    }
    close(fd);
}

#ifdef DEBUG
#define COPYFILE_DEBUG (1<<31)
#else
#define COPYFILE_DEBUG (0)
#endif

int replace_with_clone(const char* src, const char* dst, bool preserve_parent_mtime) {
    int parent_fd = -1;
    struct timespec saved_mtime = { 0 };

    if (preserve_parent_mtime &&
        dir_mtime(dst, &parent_fd, &saved_mtime) == -1) {
        return errno;
    }

    int result = 0;

    char path[PATH_MAX] = { 0 };
    if (!tmp_name(dst, path, PATH_MAX)) {
        result = errno;
        goto cleanup;
    }

    errno = 0;
    result = genfile_clone(src, path);

    if (result) {
        perror("could not clonefile");
        // clonefile is atomic; the ioctl backends clean up files they
        // created themselves. This path may belong to another process.
        goto cleanup;
    }

    if (find_zero_file(path)) {
        fprintf(stderr,
                "invalid file created by clonefile(2)\n");
        unlink(path);
        result = ENOENT;
        goto cleanup;
    }

#if defined(__APPLE__)
    // TODO: use COPYFILE_CHECK during dry-run and
    //       higher verbosity levels
    int check = copyfile(dst,
                         path,
                         NULL,
                         COPYFILE_CHECK | COPYFILE_METADATA);
    if (check & COPYFILE_DATA) {
        perror("copyfile(3) should not copy data");
        unlink(path);
        result = check;
        goto cleanup;
    }

    result = copyfile(dst,
                      path,
                      NULL,
                      COPYFILE_METADATA | COPYFILE_DEBUG);
    if (result) {
        perror("could not copy metadata");
        unlink(path);
        goto cleanup;
    }

    if (find_zero_file(path)) {
        fprintf(stderr,
                "invalid file created by copyfile(3)\n");
        unlink(path);
        result = ENOENT;
        goto cleanup;
    }
#else
    /* Linux/FreeBSD: verify clone produced a same-size file */
    {
        struct stat src_sb, dst_sb;
        if (stat(src, &src_sb) || stat(path, &dst_sb)) {
            result = errno;
            perror("stat(2) failed during clone verification");
            unlink(path);
            goto cleanup;
        }
        if (src_sb.st_size != dst_sb.st_size) {
            fprintf(stderr,
                    "clone size mismatch: %zu vs %zu\n",
                    (size_t)src_sb.st_size,
                    (size_t)dst_sb.st_size);
            unlink(path);
            result = EIO;
            goto cleanup;
        }
    }
#endif

    // TODO: use COPYFILE_CHECK to verify that nothing
    //       would be copied back to the original file

    result = rename(path, dst);
    if (result) {
        perror("could not replace existing file");
        unlink(path);
        goto cleanup;
    }

cleanup:
    if (preserve_parent_mtime) {
        restore_dir_mtime(parent_fd, saved_mtime);
    }
    return result;
}


int replace_with_link(const char* src, const char* dst) {
    char tmp[PATH_MAX];
    if (!tmp_name(dst, tmp, sizeof(tmp))) {
        return errno;
    }

    if (link(src, tmp)) {
        return errno;
    }

    int result = rename(tmp, dst) ? errno : 0;
    // rename is a no-op when dst already names the source inode. Remove
    // the extra staging link in that case, and after a failed rename.
    unlink(tmp);
    return result;
}

// returns a relative path to dst from src
char* path_relative_to(const char* src, const char* dst) {
    char* real_src = realpath(src, NULL);
    if (real_src == NULL) {
        fprintf(stderr, "%s could not be resolved to a canonical path.\n", src);
        return NULL;
    }

    char* real_dst = realpath(dst, NULL);
    if (real_dst == NULL) {
        free(real_src);
        fprintf(stderr, "%s could not be resolved to a canonical path.\n", dst);
        return NULL;
    }

    char* orig_real_src = real_src,
        * orig_real_dst = real_dst;

    // consume root '/' if it exists
    if (*real_src == '/') real_src++;
    if (*real_dst == '/') real_dst++;

    // consume common directories
    do {
        char* src_dir_end = strchr(real_src, '/');
        char* dst_dir_end = strchr(real_dst, '/');

        if (src_dir_end == NULL && dst_dir_end != NULL) {
            // we've reached the end of the dst path, but not the end of src.
            // (e.g. /foo/bar/baz/car vs. /foo/bar/baz)
            break;
        }

        if (src_dir_end != NULL && dst_dir_end == NULL) {
            // we've reached thed end of src path, but not the end of dst.
            // (e.g. /foo/bar/baz vs. /foo/bar/baz/car). if this last entry
            // is a file, the depth of the dst is one higher. in this case
            // we're only dealing with files
            break;
        }

        if (src_dir_end == NULL && dst_dir_end == NULL) {
            break;
        }

        if ((src_dir_end - real_src) != (dst_dir_end - real_dst) ||
            strncmp(real_src, real_dst, (src_dir_end - real_src))) {
            break;
        }

        real_src = src_dir_end + 1;
        real_dst = dst_dir_end + 1;
    } while (true);

    size_t depth = 0;
    for (const char* end = real_src; *end != '\0'; end++) {
        if (*end == '/') depth++;
    }

    free(orig_real_src);
    // Two individually valid absolute paths can need a relative path
    // longer than PATH_MAX (each parent component expands to "../").
    size_t suffix_len = strlen(real_dst);
    char* path = malloc(depth * 3 + suffix_len + 1);
    if (!path) {
        free(orig_real_dst);
        return NULL;
    }
    size_t pos = 0;
    for (size_t i = 0; i < depth; i++) {
        path[pos++] = '.';
        path[pos++] = '.';
        path[pos++] = '/';
    }
    memcpy(path + pos, real_dst, suffix_len + 1);
    free(orig_real_dst);

    return path;
}

int replace_with_symlink(const char* src, const char* dst) {
    // must be called prior to unlink because realpath
    // is used. unlinking first removes the real path
    char* path = path_relative_to(dst, src);
    if (!path) return EINVAL;

    // Stage: create a temporary symlink, then atomic rename(2) swap.
    // At any point during this sequence, dst is either the original
    // file or a valid symlink — never missing.
    char tmp[PATH_MAX];
    if (!tmp_name(dst, tmp, PATH_MAX)) {
        free(path);
        return errno;
    }

    int r = symlink(path, tmp);
    if (r) {
        int e = errno;
        free(path);
        return e;
    }

    r = rename(tmp, dst);
    if (r) {
        int e = errno;
        unlink(tmp);
        free(path);
        return e;
    }

    free(path);
    return 0;
}

#if defined(DEDUP_IN_PLACE)

// Largest range handed to one FIDEDUPERANGE call. The kernel may shorten a
// request anyway (older btrfs capped it at 16 MiB), and smaller calls bound
// how long both files stay locked while the kernel compares them.
#define DEDUPE_CHUNK ((uint64_t)16 << 20)

typedef struct ExtentMap {
    Extent* extents;
    size_t count;
    bool inline_data;      // data stored with metadata, never shareable
    bool unknown_location; // no settled address even after flushing
} ExtentMap;

static uint32_t extent_flags(uint32_t fiemap_flags, ExtentMap* map) {
    uint32_t flags = 0;
    if (fiemap_flags & (FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_DATA_TAIL |
                        FIEMAP_EXTENT_NOT_ALIGNED)) {
        map->inline_data = true;
        flags |= EXTENT_NOT_SHAREABLE;
    }
    if (fiemap_flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC)) {
        map->unknown_location = true;
        flags |= EXTENT_NOT_SHAREABLE;
    }
    if (fiemap_flags & FIEMAP_EXTENT_ENCODED) {
        flags |= EXTENT_ENCODED;
    }
    if (fiemap_flags & FIEMAP_EXTENT_SHARED) {
        flags |= EXTENT_SHARED;
    }
    return flags;
}

// Reads the whole extent map of the file open at fd. The first request
// flushes dirty data so that every extent has its final address. Returns 0,
// or -1 with errno set.
static int read_extent_map(int fd, ExtentMap* map) {
    enum { BATCH = 256 };
    memset(map, 0, sizeof(*map));

    struct fiemap* fm = malloc(sizeof(*fm) + BATCH * sizeof(struct fiemap_extent));
    if (!fm) {
        return -1;
    }

    size_t capacity = 0;
    uint64_t start = 0;
    uint32_t sync = FIEMAP_FLAG_SYNC;
    for (;;) {
        memset(fm, 0, sizeof(*fm));
        fm->fm_start = start;
        fm->fm_length = FIEMAP_MAX_OFFSET - start;
        fm->fm_flags = sync;
        fm->fm_extent_count = BATCH;
        if (ioctl(fd, FS_IOC_FIEMAP, fm) < 0) {
            int e = errno;
            free(fm);
            free(map->extents);
            memset(map, 0, sizeof(*map));
            errno = e;
            return -1;
        }
        sync = 0;

        uint32_t mapped = fm->fm_mapped_extents;
        if (mapped == 0) {
            break;
        }

        if (map->count + mapped > capacity) {
            size_t wanted = capacity ? capacity * 2 : BATCH;
            while (wanted < map->count + mapped) {
                wanted *= 2;
            }
            Extent* grown = realloc(map->extents, wanted * sizeof(Extent));
            if (!grown) {
                free(fm);
                free(map->extents);
                memset(map, 0, sizeof(*map));
                errno = ENOMEM;
                return -1;
            }
            map->extents = grown;
            capacity = wanted;
        }

        bool last = false;
        uint64_t previous = start;
        for (uint32_t k = 0; k < mapped; k++) {
            const struct fiemap_extent* fe = &fm->fm_extents[k];
            uint32_t flags = extent_flags(fe->fe_flags, map);
            map->extents[map->count++] = (Extent){
                .logical = fe->fe_logical,
                .physical = fe->fe_physical,
                .length = fe->fe_length,
                .flags = flags,
            };
            start = fe->fe_logical + fe->fe_length;
            if (fe->fe_flags & FIEMAP_EXTENT_LAST) {
                last = true;
            }
        }

        // a short batch is the end of the map, as is a batch that does
        // not move forward
        if (last || mapped < BATCH || start <= previous) {
            break;
        }
    }

    free(fm);
    return 0;
}

ShareState share_state(const char* origin, const char* duplicate, uint64_t size) {
    ShareState state = SHARE_UNKNOWN;
    ExtentMap a = { 0 };
    ExtentMap b = { 0 };
    struct stat as = { 0 };
    struct stat bs = { 0 };

    int fa = open(origin, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int fb = fa < 0 ? -1 : open(duplicate, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fb < 0 || fstat(fa, &as) || fstat(fb, &bs) ||
        read_extent_map(fa, &a) || read_extent_map(fb, &b)) {
        goto done;
    }

    if (a.inline_data) {
        state = SHARE_INLINE;
    } else if (a.unknown_location || b.unknown_location) {
        state = SHARE_UNKNOWN;
    } else if (extent_map_count(a.extents, a.count, size, 0) == 0 &&
               extent_map_count(b.extents, b.count, size, 0) == 0 &&
               (as.st_blocks != 0 || bs.st_blocks != 0)) {
        // no data in either map, yet blocks are allocated: the map is not
        // telling the whole story, so do not call that shared
        state = SHARE_UNKNOWN;
    } else if (extent_maps_shared(a.extents, a.count, b.extents, b.count, size)) {
        state = SHARE_SHARED;
    } else {
        state = SHARE_SEPARATE;
    }

done:
    free(a.extents);
    free(b.extents);
    if (fb >= 0) {
        close(fb);
    }
    if (fa >= 0) {
        close(fa);
    }
    return state;
}

DedupeResult dedupe_in_place(const char* origin, const char* duplicate, uint64_t size) {
    DedupeResult result = DEDUPE_FAILED;
    struct file_dedupe_range* range = NULL;
    struct stat ss = { 0 };
    struct stat ds = { 0 };

    int src = open(origin, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int dst = src < 0 ? -1 : open(duplicate, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (dst < 0 || fstat(src, &ss) || fstat(dst, &ds)) {
        goto done;
    }

    if (!S_ISREG(ss.st_mode) || !S_ISREG(ds.st_mode) ||
        (uint64_t)ss.st_size != size || (uint64_t)ds.st_size != size) {
        result = DEDUPE_DIFFERS;
        goto done;
    }

    size_t range_size = sizeof(*range) + sizeof(struct file_dedupe_range_info);
    range = malloc(range_size);
    if (!range) {
        goto done;
    }

    uint64_t offset = 0;
    while (offset < size) {
        uint64_t length = size - offset;
        if (length > DEDUPE_CHUNK) {
            length = DEDUPE_CHUNK;
        }

        memset(range, 0, range_size);
        range->src_offset = offset;
        range->src_length = length;
        range->dest_count = 1;
        range->info[0].dest_fd = dst;
        range->info[0].dest_offset = offset;
        if (ioctl(src, FIDEDUPERANGE, range) < 0) {
            goto done;
        }

        int32_t status = range->info[0].status;
        if (status == FILE_DEDUPE_RANGE_DIFFERS) {
            result = DEDUPE_DIFFERS;
            goto done;
        }
        if (status < 0) {
            errno = -status;
            goto done;
        }
        if (range->info[0].bytes_deduped == 0) {
            errno = EIO; // no progress; never loop forever
            goto done;
        }
        offset += range->info[0].bytes_deduped;
    }
    result = DEDUPE_DONE;

done:;
    int saved_errno = errno;
    free(range);
    if (dst >= 0) {
        close(dst);
    }
    if (src >= 0) {
        close(src);
    }
    errno = saved_errno;
    return result;
}

int dedupe_supported(const char* path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    size_t range_size = sizeof(struct file_dedupe_range) + sizeof(struct file_dedupe_range_info);
    struct file_dedupe_range* range = calloc(1, range_size);
    if (!range) {
        close(fd);
        return -1;
    }

    // zero bytes of the file onto itself: nothing to compare or share
    range->dest_count = 1;
    range->info[0].dest_fd = fd;

    int supported;
    if (ioctl(fd, FIDEDUPERANGE, range) == 0) {
        if (range->info[0].status == FILE_DEDUPE_RANGE_SAME) {
            supported = 1;
        } else {
            // e.g. EPERM: this user may not deduplicate this file
            errno = range->info[0].status < 0 ? -range->info[0].status : EIO;
            supported = -1;
        }
    } else {
        supported = (errno == EOPNOTSUPP || errno == ENOTTY || errno == EINVAL) ? 0 : -1;
    }

    int saved_errno = errno;
    free(range);
    close(fd);
    errno = saved_errno;
    return supported;
}

#endif // DEDUP_IN_PLACE
