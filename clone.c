// Copyright © 2023 TTKB, LLC.
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

#include <err.h>
#include <errno.h>
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

int find_zero_file(const char* restrict path) {
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

    if (access(out, F_OK) == 0) {
        fprintf(stderr,
                "Staging file %s already exists. Remove it to replace %s with a clone\n",
                out,
                path);
        errno = EEXIST;
        return NULL;
    }

    return out;
}

int genfile_clone(const char* src, const char* dst) {
#if defined(HAVE_UBT)
    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) return errno;
    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (dst_fd < 0) { int e = errno; close(src_fd); return e; }
    int r = ubt_clone(dst_fd, src_fd);
    int e = errno;
    close(src_fd);
    close(dst_fd);
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
    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL);
    if (dst_fd < 0) {
        close(src_fd);
        perror("open(2) failed");
        return errno;
    }
    int result = ioctl(dst_fd, CF_FICLONE, src_fd);
    int errno_saved = errno;
    close(src_fd);
    close(dst_fd);
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
    return r ? e : 0;
#else
#error Operating system not supported.
#endif
}

int replace_with_clone(const char* src, const char* dst) {
    char path[PATH_MAX] = { 0 };
    if (!tmp_name(dst, path, PATH_MAX)) {
        return errno;
    }

    errno = 0;
    int result = genfile_clone(src, path);

    if (result) {
        perror("could not clonefile");
        unlink(path); // if it exists
        return result;
    }

    if (find_zero_file(path)) {
        fprintf(stderr,
                "invalid file created by clonefile(2)\n");
        unlink(path);
        return ENOENT;
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
        return check;
    }

    result = copyfile(dst,
                      path,
                      NULL,
                      COPYFILE_METADATA | (1<<31));
    if (result) {
        perror("could not copy metadata");
        unlink(path);
        return result;
    }

    if (find_zero_file(path)) {
        fprintf(stderr,
                "invalid file created by copyfile(3)\n");
        unlink(path);
        return ENOENT;
    }
#else
    /* Linux/FreeBSD: verify clone produced a same-size file */
    {
        struct stat src_sb, dst_sb;
        if (stat(src, &src_sb) || stat(path, &dst_sb)) {
            perror("stat(2) failed during clone verification");
            unlink(path);
            return errno;
        }
        if (src_sb.st_size != dst_sb.st_size) {
            fprintf(stderr,
                    "clone size mismatch: %zu vs %zu\n",
                    (size_t)src_sb.st_size,
                    (size_t)dst_sb.st_size);
            unlink(path);
            return EIO;
        }
    }
#endif

    // TODO: use COPYFILE_CHECK to verify that nothing
    //       would be copied back to the original file

    result = rename(path, dst);
    if (result) {
        perror("could not replace existing file");
        unlink(path);
        return result;
    }

    return 0;
}


int replace_with_link(const char* src, const char* dst) {
    // Security: Atomically replace dst with a hard link to src using a temporary
    // staging file and rename(2). Unlinking dst first creates a TOCTOU race
    // condition where dst is briefly missing or could be hijacked.
    char tmp[PATH_MAX];
    if (!tmp_name(dst, tmp, PATH_MAX)) {
        return errno ? errno : EINVAL;
    }

    int result = link(src, tmp);
    if (result) {
        int e = errno;
        perror("could not link file");
        return e;
    }

    result = rename(tmp, dst);
    if (result) {
        int e = errno;
        perror("could not replace existing file with link");
        unlink(tmp);
        return e;
    }

    return 0;
}

// returns a relative path to dst from src
char* path_relative_to(const char* src, const char* dst) {
    char* real_src = realpath(src, NULL),
        * real_dst = realpath(dst, NULL),
        * orig_real_src = real_src,
        * orig_real_dst = real_dst;

    // consume root /
    real_src++;
    real_dst++;

    int depth = 0;

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

    for (char* end = real_src; end != NULL && *end != '\0'; end = strchr(end, '/')) {
        end++;
        depth++;
    }
    depth--;

    free(orig_real_src);
    char* path = calloc(PATH_MAX, 1);
    int pos = 0;
    for (int i = 0; i < depth; i++) {
        path[pos++] = '.';
        path[pos++] = '.';
        path[pos++] = '/';
    }
    memcpy(path + pos, real_dst, strlen(real_dst));
    free(orig_real_dst);

    return path;
}

int replace_with_symlink(const char* src, const char* dst) {
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
