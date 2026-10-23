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

static int find_zero_file(const char* restrict path) {
    if (access(path, W_OK)) {
        return 1;
    }

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

// Expects `out` to be char[PATH_MAX].
//
char* tmp_name(const char* restrict path, char* restrict out, size_t size) {
    if (size == 0) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    out[0] = '\0';

    char dir[PATH_MAX] = { 0 };
    if (!dirname_r(path, dir)) {
        return NULL;
    }

    char base[PATH_MAX] = { 0 };
    if (!basename_r(path, base)) {
        return NULL;
    }

    if (strlcat(out, dir, size) >= size ||
        strlcat(out, "/.~.", size) >= size ||
        strlcat(out, base, size) >= size) {
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
    *mtime_out = st.st_mtimespec;
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
