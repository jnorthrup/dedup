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
#include <sys/attr.h>
#include <sys/acl.h>
#endif
#include <sys/stat.h>

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../utils.h"
#include "test_utils.h"

START_TEST(dedup_empty) {
    char* output = run(DEDUP_COMMAND " test-data/clonefile/empty");
    ck_assert_str_eq("duplicates found: 0\nentries pruned: 0\nbytes saved: 0 bytes\nalready saved: 0 bytes\n", output);
    free(output);

    struct stat e1 = { 0 }, e2 = { 0 };
    stat("test-data/clonefile/empty/empty", &e1);
    stat("test-data/clonefile/empty/empty2", &e2);

    ck_assert_int_ne(e1.st_ino, e2.st_ino);
    ck_assert_int_eq(e1.st_dev, e2.st_dev);
    ck_assert_int_eq(0, e1.st_size);
    ck_assert_int_eq(0, e2.st_size);
} END_TEST

void check_bars() {
    uint64_t bcid = get_clone_id("test-data/clonefile/bars/bar");

    char* output = run(DEDUP_COMMAND " test-data/clonefile/bars");
    free(output);

    struct stat b1, b2, b3, b4, b5;
    stat("test-data/clonefile/bars/bar", &b1);
    stat("test-data/clonefile/bars/bar2", &b2);
    stat("test-data/clonefile/bars/bar3", &b3);
    stat("test-data/clonefile/bars/bar4", &b4);
    stat("test-data/clonefile/bars/bar5", &b5);

    ck_assert_int_ne(b1.st_ino, b2.st_ino);
    ck_assert_int_eq(b1.st_ino, b3.st_ino);
    ck_assert_int_ne(b1.st_ino, b2.st_ino);
    ck_assert_int_ne(b1.st_ino, b2.st_ino);
    ck_assert_int_ne(b1.st_ino, b2.st_ino);

    uint64_t bcid1 = get_clone_id("test-data/clonefile/bars/bar"),
             bcid2 = get_clone_id("test-data/clonefile/bars/bar2"),
             bcid3 = get_clone_id("test-data/clonefile/bars/bar3"),
             bcid4 = get_clone_id("test-data/clonefile/bars/bar4"),
             bcid5 = get_clone_id("test-data/clonefile/bars/bar5");
    ck_assert_uint_eq(bcid, bcid1); // the clone origin should be "bar"
    ck_assert_uint_eq(bcid, bcid2);
    ck_assert_uint_eq(bcid, bcid3);
    ck_assert_uint_eq(bcid, bcid4);
    ck_assert_uint_eq(bcid, bcid5);
}

START_TEST(dedup_hardlinks) {
    check_bars();
    check_bars(); // assert again
} END_TEST

START_TEST(dedup_devices) {
    int r = system(DEDUP_COMMAND " test-data/clonefile/devices");
    ck_assert_int_eq(0, r);

    struct stat f, e;
    stat("test-data/clonefile/devices/fifo", &f);
    stat("test-data/clonefile/devices/empty", &e);

    ck_assert_uint_ne(get_clone_id("test-data/clonefile/devices/fifo"),
                      get_clone_id("test-data/clonefile/devices/empty"));
} END_TEST

START_TEST(dedup_big) {
    int r = system(DEDUP_COMMAND " test-data/clonefile/big");
    ck_assert_int_eq(0, r);

    struct stat f, e;
    stat("test-data/clonefile/big/big", &f);
    stat("test-data/clonefile/big/big2", &e);

    ck_assert_uint_ne(get_clone_id("test-data/clonefile/big/big"),
                      get_clone_id("test-data/clonefile/big/big2"));
} END_TEST

START_TEST(dedup_same_size) {
    int r = system(DEDUP_COMMAND " -t0 test-data/clonefile/same-size");
    ck_assert_int_eq(0, r);

    ck_assert_uint_eq(get_clone_id("test-data/clonefile/same-size/big"),
                      get_clone_id("test-data/clonefile/same-size/big2"));
} END_TEST

START_TEST(dedup_same_first_last) {
    int r = system(DEDUP_COMMAND " test-data/clonefile/same-first-last");
    ck_assert_int_eq(0, r);

    ck_assert_uint_ne(get_clone_id("test-data/clonefile/same-first-last/same-1"),
                      get_clone_id("test-data/clonefile/same-first-last/same-2"));
} END_TEST

START_TEST(dedup_flags_acls) {
    int r = system(DEDUP_COMMAND " test-data/clonefile/flags-acls");
    ck_assert_int_eq(0, r);

    struct stat b1, b3;
    stat("test-data/clonefile/flags-acls/bar", &b1);
    stat("test-data/clonefile/flags-acls/bar3", &b3);

    ck_assert_int_eq(0642 | S_IFREG, b3.st_mode);
    ck_assert_uint_eq(get_clone_id("test-data/clonefile/flags-acls/bar"),
                      get_clone_id("test-data/clonefile/flags-acls/bar3"));

    acl_t acl = acl_get_file("test-data/clonefile/flags-acls/bar3", ACL_TYPE_EXTENDED);
    ck_assert_ptr_nonnull(acl);
    acl_entry_t entry;
    acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    ck_assert_ptr_nonnull(entry);
    char* acl_text = acl_to_text(acl, NULL);
    ck_assert_int_eq(0, strncmp("!#acl 1", acl_text, 7));
    ck_assert_int_eq(0, strncmp("nobody", acl_text + 50 , 6));
    ck_assert_int_eq(0, strncmp("deny", acl_text + 60 , 4));
    ck_assert_int_eq(0, strncmp("append", acl_text + 65 , 6));
    free(acl_text);
    acl_free(acl);
} END_TEST

START_TEST(dedup_hfs) {
    char* output = run(DEDUP_COMMAND " -Phx /Volumes/dedup-test-hfs-clonefile 2>&1");
    ck_assert_str_eq("dedup: Skipping /Volumes/dedup-test-hfs-clonefile: cloning not supported\nduplicates found: 0\nentries pruned: 0\nbytes saved: 0 bytes\nalready saved: 0 bytes\n", output);
    free(output);
} END_TEST

START_TEST(dedup_does_not_exist) {
    int r = system(DEDUP_COMMAND " '' ''");
    ck_assert_int_eq(1, WEXITSTATUS(r));
} END_TEST

START_TEST(dedup_negative_threads) {
    int r = system(DEDUP_COMMAND " -t -1 test-data/clonefile/bars");
    ck_assert_int_eq(1, WEXITSTATUS(r));
} END_TEST

START_TEST(dedup_help) {
    int r = system(DEDUP_COMMAND " --help");
    ck_assert_int_eq(0, WEXITSTATUS(r));
} END_TEST

START_TEST(dedup_ignore_refused) {
    // -I is not implemented. Running anyway would replace files the caller
    // asked to exclude, so dedup must refuse before touching anything.
    int r = system(DEDUP_COMMAND " -I bar test-data/clonefile/empty");
    ck_assert_int_eq(1, WEXITSTATUS(r));
} END_TEST

START_TEST(dedup_dry_run) {
    int r = system(DEDUP_COMMAND " -nP /Volumes/dedup-test-hfs-clonefile test-data/clonefile/bars");
    ck_assert_int_eq(0, WEXITSTATUS(r));
} END_TEST

START_TEST(dedup_dry_run_reports_without_terminal) {
    // run() reads stdout through a pipe, so no status line is drawn. The
    // dry-run plan must be printed anyway.
    ck_assert_int_eq(0, system("mkdir -p test-data/clonefile/report"
                               " && printf report > test-data/clonefile/report/a"
                               " && cp test-data/clonefile/report/a test-data/clonefile/report/b"));
    char* output = run(DEDUP_COMMAND " -nv test-data/clonefile/report");
    ck_assert_ptr_nonnull(strstr(output, "would deduplicate test-data/clonefile/report/"));
    free(output);
} END_TEST

START_TEST(dedup_permission_denied) {
    char* output = run(DEDUP_COMMAND " -nP test-data/clonefile/clone-dst-acls 2>&1");
    ck_assert_ptr_nonnull(output);
    ck_assert_ptr_null(strstr(output, "could not getattrlist"));
    free(output);
} END_TEST

#if defined(__APPLE__)
#define st_mtim st_mtimespec
#endif

#define ck_assert_timespec_eq(t1, t2) \
    ck_assert_msg(((t1).tv_sec == (t2).tv_sec && (t1).tv_nsec == (t2).tv_nsec), \
                  "Timespecs differ: %ld.%09ld != %ld.%09ld", \
                  (long)(t1).tv_sec, (t1).tv_nsec, \
                  (long)(t2).tv_sec, (t2).tv_nsec)

#define ck_assert_timespec_ne(t1, t2) \
    ck_assert_msg(((t1).tv_sec != (t2).tv_sec || (t1).tv_nsec != (t2).tv_nsec), \
                  "Timespecs are identical: %ld.%09ld", \
                  (long)(t1).tv_sec, (t1).tv_nsec)

// ensure mtime is preserved and atime is not
START_TEST(dedup_preserve_mtime) {
    struct stat before = { 0 }, after = { 0 };
    stat("test-data/clonefile/mtime", &before);

    int r = system(DEDUP_COMMAND " -Pm test-data/clonefile/mtime");
    ck_assert_int_eq(0, WEXITSTATUS(r));

    stat("test-data/clonefile/mtime", &after);
    ck_assert_timespec_eq(before.st_mtim, after.st_mtim);

    // atime is explicitly omitted from restoration (UTIME_OMIT). it may
    // or may not advance due to directory reads but we do not assert it
    // must change since APFS may defer atime updates
} END_TEST

// ensure mtime is not preserved
START_TEST(dedup_do_not_preserve_mtime) {
    struct stat before = { 0 }, after = { 0 };
    stat("test-data/clonefile/mtime-not-preserved", &before);

    int r = system(DEDUP_COMMAND " -P test-data/clonefile/mtime-not-preserved");
    ck_assert_int_eq(0, WEXITSTATUS(r));

    stat("test-data/clonefile/mtime-not-preserved", &after);
    ck_assert_timespec_ne(before.st_mtim, after.st_mtim);
} END_TEST


// dedup is running in the current directory and has to set mtime on '.'
START_TEST(dedup_preserve_mtime_relative_cwd) {
    // build an absolute path to the binary before chdir changes cwd
    char dedup_path[PATH_MAX] = { 0 };
    ck_assert_ptr_nonnull(realpath(DEDUP_TEST_BINARY, dedup_path));

    char cwd[PATH_MAX] = { 0 };
    getcwd(cwd, sizeof(cwd));
    chdir("test-data/clonefile/mtime-cwd");

    struct stat before = { 0 }, after = { 0 };
    stat(".", &before);

    char cmd[PATH_MAX + 8];
    snprintf(cmd, sizeof(cmd), "\"%s\" -Pm .", dedup_path);
    int r = system(cmd);

    stat(".", &after);
    chdir(cwd);

    ck_assert_int_eq(0, WEXITSTATUS(r));
    ck_assert_timespec_eq(before.st_mtim, after.st_mtim);
} END_TEST

/*
// when `UF_IMMUTABLE` is set mtime cannot be set, but the clone should succed with warning
START_TEST(dedup_parent_mtime_immutable) {
    chflags("test-data/clonefile/mtime-immutable", UF_IMMUTABLE);

    char* output = run(DEDUP_COMMAND " -P test-data/clonefile/mtime-immutable 2>&1");

    // clear the flag before any assertions so cleanup always runs
    chflags("test-data/clonefile/mtime-immutable", 0);

    ck_assert_ptr_nonnull(strstr(output, "Warning: cannot preserve parent mtime"));
    free(output);

    ck_assert_uint_eq(get_clone_id("test-data/clonefile/mtime-immutable/bar"),
                      get_clone_id("test-data/clonefile/mtime-immutable/bar2"));
} END_TEST
*/

START_TEST(dedup_failed_replacement_exit_status) {
    // A duplicate in a directory that is not writable cannot be replaced. The
    // run must name it, count it, and exit nonzero.
    ck_assert_int_eq(0, system("mkdir -p test-data/clonefile/readonly-dir"
                               " && printf locked > test-data/clonefile/readonly-dir/a"
                               " && cp test-data/clonefile/readonly-dir/a test-data/clonefile/readonly-dir/b"
                               " && chmod 555 test-data/clonefile/readonly-dir"));
    char output[2048] = { 0 };
    FILE* pout = popen(DEDUP_COMMAND " -P test-data/clonefile/readonly-dir 2>&1", "r");
    ck_assert_ptr_nonnull(pout);
    size_t read = fread(output, 1, sizeof(output) - 1, pout);
    int r = pclose(pout);
    // restore first, so the fixture can be removed even if an assertion fails
    ck_assert_int_eq(0, system("chmod 755 test-data/clonefile/readonly-dir"));

    ck_assert_uint_gt(read, 0);
    ck_assert_int_eq(1, WEXITSTATUS(r));
    ck_assert_ptr_nonnull(strstr(output, "could not replace test-data/clonefile/readonly-dir/"));
    ck_assert_ptr_nonnull(strstr(output, "replacements failed: 1\n"));
} END_TEST

START_TEST(dedup_skipped_not_counted_as_saved) {
    // Read-only duplicates are left in place. They are still stored twice, so
    // they must be reported as skipped, not as space already saved.
    ck_assert_int_eq(0, system("mkdir -p test-data/clonefile/readonly-files"
                               " && printf readonly > test-data/clonefile/readonly-files/a"
                               " && cp test-data/clonefile/readonly-files/a test-data/clonefile/readonly-files/b"
                               " && chmod 444 test-data/clonefile/readonly-files/a"
                               " test-data/clonefile/readonly-files/b"));
    char* output = run(DEDUP_COMMAND " -P test-data/clonefile/readonly-files");
    ck_assert_str_eq("duplicates found: 0\nentries pruned: 0\nbytes saved: 0 bytes\n"
                     "already saved: 0 bytes\nduplicates skipped: 1 (8 bytes)\n", output);
    free(output);
} END_TEST

START_TEST(dedup_keeps_existing_clones) {
    // "bar" and "bar4" are clones of each other and "bar2" is a separate copy.
    // Whatever order the directory lists them in, the clones are the origin:
    // only "bar2" is replaced, and the clone is space already saved.
    ck_assert_int_eq(0, system("mkdir -p test-data/clonefile/clone-family"
                               " && printf family > test-data/clonefile/clone-family/bar"
                               " && cp -c test-data/clonefile/clone-family/bar"
                               " test-data/clonefile/clone-family/bar4"
                               " && cp test-data/clonefile/clone-family/bar"
                               " test-data/clonefile/clone-family/bar2"));
    uint64_t family = get_clone_id("test-data/clonefile/clone-family/bar");
    ck_assert_uint_eq(family, get_clone_id("test-data/clonefile/clone-family/bar4"));
    ck_assert_uint_ne(family, get_clone_id("test-data/clonefile/clone-family/bar2"));

    char* output = run(DEDUP_COMMAND " -P test-data/clonefile/clone-family");
    // The pruner drops "bar4" before comparison: its clone id was already
    // seen, so it counts as pruned and as space already saved.
    ck_assert_str_eq("duplicates found: 1\nentries pruned: 1\nbytes saved: 6 bytes\n"
                     "already saved: 6 bytes\n", output);
    free(output);

    ck_assert_uint_eq(family, get_clone_id("test-data/clonefile/clone-family/bar"));
    ck_assert_uint_eq(family, get_clone_id("test-data/clonefile/clone-family/bar4"));
    ck_assert_uint_eq(family, get_clone_id("test-data/clonefile/clone-family/bar2"));
} END_TEST

Suite* dedup_suite() {
    TCase* tc = tcase_create("dedup");
    tcase_add_test(tc, dedup_empty);
    tcase_add_test(tc, dedup_hardlinks);
    tcase_add_test(tc, dedup_devices);
    tcase_add_test(tc, dedup_big);
    tcase_add_test(tc, dedup_same_size);
    tcase_add_test(tc, dedup_same_first_last);
    tcase_add_test(tc, dedup_flags_acls);
    tcase_add_test(tc, dedup_hfs);
    tcase_add_test(tc, dedup_does_not_exist);
    tcase_add_test(tc, dedup_negative_threads);
    tcase_add_test(tc, dedup_help);
    tcase_add_test(tc, dedup_ignore_refused);
    tcase_add_test(tc, dedup_dry_run);
    tcase_add_test(tc, dedup_dry_run_reports_without_terminal);
    tcase_add_test(tc, dedup_permission_denied);
    tcase_add_test(tc, dedup_preserve_mtime);
    tcase_add_test(tc, dedup_do_not_preserve_mtime);
    tcase_add_test(tc, dedup_preserve_mtime_relative_cwd);
    // tcase_add_test(tc, dedup_parent_mtime_immutable);
    tcase_add_test(tc, dedup_failed_replacement_exit_status);
    tcase_add_test(tc, dedup_skipped_not_counted_as_saved);
    tcase_add_test(tc, dedup_keeps_existing_clones);

    Suite* s = suite_create("dedup");
    suite_add_tcase(s, tc);

    return s;
}
