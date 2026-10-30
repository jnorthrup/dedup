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
#include <sys/attr.h>
#endif
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include <check.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../clone.h"

#define PRESERVE_PARENT_MTIME true

START_TEST(clone_path_to_long) {
    char dest[PATH_MAX + 10] = { 0 };
    memset(dest, 'x', PATH_MAX + 9);

    int r = replace_with_clone("/tmp/does-not-exist", dest, PRESERVE_PARENT_MTIME);
    ck_assert_int_eq(r, ENAMETOOLONG);

    dest[PATH_MAX + 4] = '/';
    r = replace_with_clone("/tmp/does-not-exist", dest, PRESERVE_PARENT_MTIME);
    ck_assert_int_eq(r, ENAMETOOLONG);
    dest[PATH_MAX + 4] = 'x';

    dest[PATH_MAX / 2] = '/';
    r = replace_with_clone("/tmp/does-not-exist", dest, PRESERVE_PARENT_MTIME);
    ck_assert_int_eq(r, ENAMETOOLONG);
} END_TEST

START_TEST(clone_bad_src) {
    int r = replace_with_clone("/tmp/does-not-exist", "test-data/also-does-not-exist", PRESERVE_PARENT_MTIME);
    ck_assert_int_eq(r, -1);
} END_TEST

START_TEST(clone_bad_dst) {
    int r = replace_with_clone("test-data/clonefile/clone-dst-acls/bar",
                               "test-data/clonefile/clone-dst-acls/bar3",
                               PRESERVE_PARENT_MTIME);
    ck_assert_int_eq(r, -1);
} END_TEST

START_TEST(clone_cannot_replace) {
    struct stat before, after;
    ck_assert_int_eq(stat("test-data/clonefile/clone-dst-acls/bar4", &before), 0);
    int r = replace_with_clone("test-data/clonefile/clone-dst-acls/bar",
                               "test-data/clonefile/clone-dst-acls/bar4",
                               PRESERVE_PARENT_MTIME);
    ck_assert_int_ne(r, 0);
    ck_assert_int_eq(stat("test-data/clonefile/clone-dst-acls/bar4", &after), 0);
    ck_assert_uint_eq(before.st_ino, after.st_ino);
    ck_assert_uint_eq(before.st_flags, after.st_flags);
} END_TEST

char* tmp_name(const char* restrict path, char* restrict out, size_t size);

START_TEST(clone_tmp_name) {
    char path[PATH_MAX] = { 0 };

    char* result = tmp_name("foo.bar", path, PATH_MAX);
    ck_assert_ptr_eq(path, result);
    ck_assert_str_eq("./.~.foo.bar", result);
    // memset(path, '\0', PATH_MAX);

    result = tmp_name("foo/bar.baz", path, PATH_MAX);
    ck_assert_ptr_eq(path, result);
    ck_assert_str_eq("foo/.~.bar.baz", result);
    // memset(path, '\0', PATH_MAX);

    result = tmp_name("/foo/bar/baz.car", path, PATH_MAX);
    ck_assert_ptr_eq(path, result);
    ck_assert_str_eq("/foo/bar/.~.baz.car", result);
    // memset(path, '\0', PATH_MAX);
} END_TEST

char* path_relative_to(const char* src, const char* dst);

START_TEST(clone_path_relative_to_test) {
    char* path = path_relative_to("test-data/clonefile/clone-dst-acls/bar",
                                  "test-data/clonefile/clone-dst-acls/bar4");
    ck_assert_str_eq("bar4", path);
    free(path);

    path = path_relative_to("test-data/clonefile/bars/bar",
                            "test-data/clonefile/clone-dst-acls/bar");
    ck_assert_str_eq("../clone-dst-acls/bar", path);
    free(path);

    path = path_relative_to("../clone.c",
                            "test-data/clonefile/bars/bar");
    ck_assert_str_eq("test/test-data/clonefile/bars/bar", path);
    free(path);

    path = path_relative_to("test-data/clonefile/bars/bar",
                            "../clone.c");
    ck_assert_str_eq("../../../../clone.c", path);
    free(path);

} END_TEST

static char safety_dir[PATH_MAX];
static char safety_src[PATH_MAX];
static char safety_dst[PATH_MAX];
static char safety_tmp[PATH_MAX];

static void safety_setup(void) {
    strcpy(safety_dir, "/tmp/dedup-safety-XXXXXX");
    ck_assert_ptr_nonnull(mkdtemp(safety_dir));
    snprintf(safety_src, sizeof(safety_src), "%s/source", safety_dir);
    snprintf(safety_dst, sizeof(safety_dst), "%s/destination", safety_dir);
    snprintf(safety_tmp, sizeof(safety_tmp), "%s/.~.destination", safety_dir);
}

static void safety_teardown(void) {
    unlink(safety_tmp);
    unlink(safety_src);
    unlink(safety_dst);
    rmdir(safety_dst);
    rmdir(safety_dir);
}

static void safety_write(const char* path, const char* content) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(write(fd, content, strlen(content)), strlen(content));
    ck_assert_int_eq(close(fd), 0);
}

static void safety_assert_content(const char* path, const char* expected) {
    char buffer[64] = { 0 };
    int fd = open(path, O_RDONLY);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(read(fd, buffer, sizeof(buffer)), strlen(expected));
    ck_assert_str_eq(buffer, expected);
    ck_assert_int_eq(close(fd), 0);
}

START_TEST(link_failure_retains_destination) {
    safety_write(safety_dst, "original destination");
    ck_assert_int_eq(replace_with_link(safety_src, safety_dst), ENOENT);
    safety_assert_content(safety_dst, "original destination");
    ck_assert_int_eq(access(safety_tmp, F_OK), -1);
} END_TEST

START_TEST(link_replacement_is_hardlink) {
    safety_write(safety_src, "shared contents");
    safety_write(safety_dst, "old contents");
    ck_assert_int_eq(replace_with_link(safety_src, safety_dst), 0);
    struct stat src, dst;
    ck_assert_int_eq(stat(safety_src, &src), 0);
    ck_assert_int_eq(stat(safety_dst, &dst), 0);
    ck_assert_uint_eq(src.st_ino, dst.st_ino);
    ck_assert_uint_eq(src.st_nlink, 2);
    safety_assert_content(safety_dst, "shared contents");
    ck_assert_int_eq(access(safety_tmp, F_OK), -1);

    // Replacing an existing link to the same inode must not leak a link.
    ck_assert_int_eq(replace_with_link(safety_src, safety_dst), 0);
    ck_assert_int_eq(stat(safety_src, &src), 0);
    ck_assert_uint_eq(src.st_nlink, 2);
    ck_assert_int_eq(access(safety_tmp, F_OK), -1);
} END_TEST

START_TEST(link_rename_failure_removes_staging_file) {
    safety_write(safety_src, "source contents");
    ck_assert_int_eq(mkdir(safety_dst, 0700), 0);
    ck_assert_int_ne(replace_with_link(safety_src, safety_dst), 0);
    struct stat dst;
    ck_assert_int_eq(stat(safety_dst, &dst), 0);
    ck_assert(S_ISDIR(dst.st_mode));
    safety_assert_content(safety_src, "source contents");
    ck_assert_int_eq(access(safety_tmp, F_OK), -1);
} END_TEST

START_TEST(replacement_preserves_staging_collision) {
    safety_write(safety_src, "source contents");
    safety_write(safety_dst, "original destination");
    ck_assert_int_eq(symlink("missing-target", safety_tmp), 0);

    ck_assert_int_eq(replace_with_clone(safety_src, safety_dst, false), EEXIST);
    ck_assert_int_eq(replace_with_link(safety_src, safety_dst), EEXIST);
    ck_assert_int_eq(replace_with_symlink(safety_src, safety_dst), EEXIST);

    char target[64] = { 0 };
    ck_assert_int_eq(readlink(safety_tmp, target, sizeof(target)), strlen("missing-target"));
    ck_assert_str_eq(target, "missing-target");
    safety_assert_content(safety_dst, "original destination");
} END_TEST

START_TEST(clone_accepts_readonly_source) {
    safety_write(safety_src, "source contents");
    ck_assert_int_eq(chmod(safety_src, 0444), 0);

    const mode_t modes[] = { 0640, 0444 };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        safety_write(safety_dst, "original destination");
        ck_assert_int_eq(chmod(safety_dst, modes[i]), 0);
        ck_assert_int_eq(replace_with_clone(safety_src, safety_dst, false), 0);

        struct stat src, dst;
        ck_assert_int_eq(stat(safety_src, &src), 0);
        ck_assert_int_eq(stat(safety_dst, &dst), 0);
        ck_assert_uint_eq(src.st_mode & 0777, 0444);
        ck_assert_uint_eq(dst.st_mode & 0777, modes[i]);
        ck_assert_uint_ne(src.st_ino, dst.st_ino);
        safety_assert_content(safety_dst, "source contents");
        ck_assert_int_eq(unlink(safety_dst), 0);
        ck_assert_int_eq(access(safety_tmp, F_OK), -1);
    }
} END_TEST

START_TEST(replacement_accepts_maximum_length_names) {
    long name_max = pathconf(safety_dir, _PC_NAME_MAX);
    ck_assert_int_gt(name_max, 3);
    ck_assert_int_le(name_max, NAME_MAX);
    safety_write(safety_src, "source contents");

    // A truncated .~.<basename> would collide with this unrelated file.
    char collision[NAME_MAX + 1];
    memcpy(collision, ".~.", 3);
    memset(collision + 3, 'x', (size_t)name_max - 3);
    collision[name_max] = '\0';
    snprintf(safety_tmp, sizeof(safety_tmp), "%s/%s", safety_dir, collision);
    safety_write(safety_tmp, "unrelated staging file");

    for (size_t length = (size_t)name_max - 2; length <= (size_t)name_max; length++) {
        char base[NAME_MAX + 1];
        memset(base, 'x', length);
        base[length] = '\0';
        snprintf(safety_dst, sizeof(safety_dst), "%s/%s", safety_dir, base);
        safety_write(safety_dst, "original destination");

        int result;
        if (_i == 0) {
            result = replace_with_clone(safety_src, safety_dst, false);
        } else if (_i == 1) {
            result = replace_with_link(safety_src, safety_dst);
        } else {
            result = replace_with_symlink(safety_src, safety_dst);
        }
        ck_assert_int_eq(result, 0);
        safety_assert_content(safety_dst, "source contents");
        safety_assert_content(safety_tmp, "unrelated staging file");

        struct stat src, dst;
        ck_assert_int_eq(stat(safety_src, &src), 0);
        ck_assert_int_eq(lstat(safety_dst, &dst), 0);
        if (_i == 0) ck_assert_uint_ne(src.st_ino, dst.st_ino);
        if (_i == 1) ck_assert_uint_eq(src.st_ino, dst.st_ino);
        if (_i == 2) ck_assert(S_ISLNK(dst.st_mode));

        DIR* dir = opendir(safety_dir);
        ck_assert_ptr_nonnull(dir);
        size_t entries = 0;
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) entries++;
        }
        ck_assert_int_eq(closedir(dir), 0);
        ck_assert_uint_eq(entries, 3);
        ck_assert_int_eq(unlink(safety_dst), 0);
    }
} END_TEST

START_TEST(relative_path_can_exceed_path_max) {
    // A short component in an absolute path expands to "../" in a
    // relative path. Both inputs fit PATH_MAX while the result does not.
    const size_t depth = PATH_MAX / 3 + 1;
    char nested[PATH_MAX];
    strcpy(nested, safety_dir);
    for (size_t i = 0; i < depth; i++) {
        strcat(nested, "/d");
        ck_assert_int_eq(mkdir(nested, 0700), 0);
    }
    strcat(nested, "/leaf");
    safety_write(nested, "leaf");
    safety_write(safety_src, "source contents");

    char* relative = path_relative_to(nested, safety_src);
    ck_assert_ptr_nonnull(relative);
    ck_assert_uint_eq(strlen(relative), depth * 3 + strlen("source"));
    for (size_t i = 0; i < depth; i++) {
        ck_assert_int_eq(strncmp(relative + i * 3, "../", 3), 0);
    }
    ck_assert_str_eq(relative + depth * 3, "source");
    free(relative);

    ck_assert_int_eq(unlink(nested), 0);
    *strrchr(nested, '/') = '\0';
    for (size_t i = 0; i < depth; i++) {
        ck_assert_int_eq(rmdir(nested), 0);
        *strrchr(nested, '/') = '\0';
    }
} END_TEST

START_TEST(replace_with_link_success) {
    char src[] = "/tmp/dedup_link_test_src_XXXXXX";
    char dst[] = "/tmp/dedup_link_test_dst_XXXXXX";
    int fd1 = mkstemp(src);
    int fd2 = mkstemp(dst);
    ck_assert_int_ge(fd1, 0);
    ck_assert_int_ge(fd2, 0);
    ck_assert_int_eq(write(fd1, "testdata", 8), 8);
    ck_assert_int_eq(write(fd2, "testdata", 8), 8);
    close(fd1);
    close(fd2);

    int r = replace_with_link(src, dst);
    ck_assert_int_eq(r, 0);

    struct stat sb1, sb2;
    ck_assert_int_eq(0, stat(src, &sb1));
    ck_assert_int_eq(0, stat(dst, &sb2));
    ck_assert_int_eq(sb1.st_ino, sb2.st_ino);

    unlink(src);
    unlink(dst);
} END_TEST

START_TEST(replace_with_link_preserves_dst_on_failure) {
    char dst[] = "/tmp/dedup_link_test_dst_preserve_XXXXXX";
    int fd = mkstemp(dst);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(write(fd, "important data", 14), 14);
    close(fd);

    int r = replace_with_link("/tmp/nonexistent_src_file_xyz_12345", dst);
    ck_assert_int_ne(r, 0);

    // Verify dst still exists and was NOT destroyed by link failure
    struct stat sb;
    ck_assert_int_eq(0, stat(dst, &sb));
    ck_assert_int_eq(14, sb.st_size);

    unlink(dst);
} END_TEST

Suite* clone_suite() {
    TCase* tc = tcase_create("clone");
    tcase_add_test(tc, clone_path_to_long);
    tcase_add_test(tc, clone_bad_src);
    tcase_add_test(tc, clone_bad_dst);
    tcase_add_test(tc, clone_cannot_replace);
    tcase_add_test(tc, clone_tmp_name);
    tcase_add_test(tc, clone_path_relative_to_test);
    tcase_add_test(tc, replace_with_link_success);
    tcase_add_test(tc, replace_with_link_preserves_dst_on_failure);

    Suite* s = suite_create("clone");
    suite_add_tcase(s, tc);

    TCase* safety = tcase_create("replacement_safety");
    tcase_set_timeout(safety, 30);
    tcase_add_checked_fixture(safety, safety_setup, safety_teardown);
    tcase_add_test(safety, link_failure_retains_destination);
    tcase_add_test(safety, link_replacement_is_hardlink);
    tcase_add_test(safety, link_rename_failure_removes_staging_file);
    tcase_add_test(safety, replacement_preserves_staging_collision);
    tcase_add_test(safety, clone_accepts_readonly_source);
    tcase_add_loop_test(safety, replacement_accepts_maximum_length_names, 0, 3);
    tcase_add_test(safety, relative_path_can_exceed_path_max);
    suite_add_tcase(s, safety);

    return s;
}
