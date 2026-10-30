// Copyright © 2026 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include <check.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../signature.h"
#include "../sig_table.h"
#include "test_utils.h"

bool files_match_exact_xor_or(const char* a_path, const char* b_path);
bool files_match_exact_cpu_tiles(const char* a_path, const char* b_path);

static void write_bytes(const char* path, const void* data, size_t size) {
    FILE* f = fopen(path, "wb");
    ck_assert_ptr_nonnull(f);
    ck_assert_uint_eq(size, fwrite(data, 1, size, f));
    ck_assert_int_eq(0, fclose(f));
}

static char* make_temp_dir(const char* suffix) {
    size_t len = strlen("/tmp/dedup-signature--XXXXXX") + strlen(suffix) + 1;
    char* dir = calloc(len, 1);
    ck_assert_ptr_nonnull(dir);
    snprintf(dir, len, "/tmp/dedup-signature-%s-XXXXXX", suffix);
    ck_assert_ptr_nonnull(mkdtemp(dir));
    return dir;
}

START_TEST(signature_supports_subword_files) {
    char* dir = make_temp_dir("small");
    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/a", dir);
    write_bytes(path, "A", 1);

    struct stat st = {0};
    ck_assert_int_eq(0, stat(path, &st));

    FileSignature* sig = compute_signature(path, st.st_dev, (uint64_t)st.st_size);
    ck_assert_ptr_nonnull(sig);
    free_signature(sig);

    ck_assert_int_eq(0, unlink(path));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

START_TEST(signature_hash_supports_unaligned_input) {
    unsigned char aligned[128];
    unsigned char unaligned[136];
    for (size_t i = 0; i < sizeof(aligned); i++) {
        aligned[i] = (unsigned char)i;
    }
    ck_assert_uint_eq(signature_fast_hash_bytes("", 0), UINT64_C(0xef46db3751d8e999));
    ck_assert_uint_eq(signature_fast_hash_bytes("hello", 5), UINT64_C(0x26c7827d889f6da3));
    for (size_t offset = 1; offset < 8; offset++) {
        memcpy(unaligned + offset, aligned, sizeof(aligned));
        for (size_t size = 0; size <= sizeof(aligned); size++) {
            ck_assert_uint_eq(signature_fast_hash_bytes(aligned, size),
                              signature_fast_hash_bytes(unaligned + offset, size));
        }
    }
} END_TEST

START_TEST(signature_rejects_stale_metadata_and_special_files) {
    char* dir = make_temp_dir("metadata");
    char path[PATH_MAX] = {0}, fifo[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/a", dir);
    snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
    write_bytes(path, "abc", 3);
    ck_assert_int_eq(0, mkfifo(fifo, 0600));

    struct stat st = {0};
    ck_assert_int_eq(0, stat(path, &st));
    ck_assert_ptr_null(compute_signature(NULL, st.st_dev, 0));
    ck_assert_int_eq(EINVAL, errno);
    ck_assert_ptr_null(compute_signature(path, st.st_dev, 0));
    ck_assert_int_eq(ESTALE, errno);
    ck_assert_ptr_null(compute_signature(path, st.st_dev, 1));
    ck_assert_int_eq(ESTALE, errno);
    ck_assert_ptr_null(compute_signature(path, st.st_dev + 1, 3));
    ck_assert_int_eq(ESTALE, errno);
    ck_assert_ptr_null(compute_signature(fifo, st.st_dev, 0));
    ck_assert_int_eq(EINVAL, errno);

    ck_assert_int_eq(0, unlink(path));
    ck_assert_int_eq(0, unlink(fifo));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

START_TEST(exact_backends_compare_past_chunk_boundaries) {
    char* dir = make_temp_dir("chunks");
    char a[PATH_MAX] = {0}, b[PATH_MAX] = {0};
    snprintf(a, sizeof(a), "%s/a", dir);
    snprintf(b, sizeof(b), "%s/b", dir);
    const size_t size = 1024U * 1024U + 19U;
    unsigned char* contents = malloc(size);
    ck_assert_ptr_nonnull(contents);
    memset(contents, 0x5a, size);
    write_bytes(a, contents, size);
    bool (*backends[])(const char*, const char*) = {
        files_match_exact_memcmp, files_match_exact_xor_or, files_match_exact_cpu_tiles
    };
    for (size_t i = 0; i < sizeof(backends) / sizeof(backends[0]); i++) {
        write_bytes(b, contents, size);
        ck_assert(backends[i](a, b));
        contents[size - 1] ^= 1;
        write_bytes(b, contents, size);
        ck_assert(!backends[i](a, b));
        contents[size - 1] ^= 1;
        write_bytes(b, contents, size - 1);
        ck_assert(!backends[i](a, b));
    }
    free(contents);
    ck_assert_int_eq(0, unlink(a));
    ck_assert_int_eq(0, unlink(b));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

START_TEST(exact_backends_reject_special_files) {
    char* dir = make_temp_dir("special");
    char path[PATH_MAX] = {0}, fifo[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "%s/empty", dir);
    snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
    write_bytes(path, "", 0);
    ck_assert_int_eq(0, mkfifo(fifo, 0600));

    // Keep a FIFO writer present so a regression fails instead of blocking.
    int fifo_fd = open(fifo, O_RDWR | O_NONBLOCK);
    ck_assert_int_ge(fifo_fd, 0);
    bool (*backends[])(const char*, const char*) = {
        files_match_exact_memcmp, files_match_exact_xor_or, files_match_exact_cpu_tiles
    };
    for (size_t i = 0; i < sizeof(backends) / sizeof(backends[0]); i++) {
        ck_assert(!backends[i](path, fifo));
        ck_assert(!backends[i](fifo, path));
        ck_assert(!backends[i](path, "/dev/null"));
        ck_assert(backends[i](path, path));
    }
    ck_assert_int_eq(0, close(fifo_fd));
    ck_assert_int_eq(0, unlink(path));
    ck_assert_int_eq(0, unlink(fifo));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

START_TEST(signature_table_rejects_zero_buckets) {
    ck_assert_ptr_null(new_sig_table(0));
    SigTable invalid = {0};
    FileSignature sig = {0};
    ck_assert_ptr_null(sig_table_insert(&invalid, &sig, "unused", 0, NULL));
} END_TEST

START_TEST(signature_table_verifies_colliding_candidates) {
    char* dir = make_temp_dir("table");
    char a[PATH_MAX] = {0}, b[PATH_MAX] = {0}, c[PATH_MAX] = {0};
    snprintf(a, sizeof(a), "%s/a", dir);
    snprintf(b, sizeof(b), "%s/b", dir);
    snprintf(c, sizeof(c), "%s/c", dir);
    write_bytes(a, "first", 5);
    write_bytes(b, "other", 5);
    write_bytes(c, "first", 5);

    SigTable* table = new_sig_table(1);
    ck_assert_ptr_nonnull(table);
    for (size_t i = 0; i < 3; i++) {
        // Deliberately identical candidate signatures for different contents.
        FileSignature* sig = calloc(1, sizeof(*sig));
        ck_assert_ptr_nonnull(sig);
        sig->size = 5;
        const char* path = i == 0 ? a : (i == 1 ? b : c);
        SigTableEntry* match = sig_table_insert(table, sig, path, 0, NULL);
        if (i < 2) {
            ck_assert_ptr_null(match);
            ck_assert_uint_eq(sig_table_size(table), i + 1);
        } else {
            ck_assert_ptr_nonnull(match);
            ck_assert_str_eq(match->path, a);
            ck_assert_uint_eq(sig_table_size(table), 2);
            free_signature(sig);
        }
    }
    ck_assert_uint_eq(sig_table_collisions(table), 1);
    free_sig_table(table, NULL);
    ck_assert_int_eq(0, unlink(a));
    ck_assert_int_eq(0, unlink(b));
    ck_assert_int_eq(0, unlink(c));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

START_TEST(dedup_detects_small_duplicate_files) {
    char* dir = make_temp_dir("small-dedup");
    char a[PATH_MAX] = {0}, b[PATH_MAX] = {0}, cmd[PATH_MAX * 2] = {0};
    snprintf(a, sizeof(a), "%s/a", dir);
    snprintf(b, sizeof(b), "%s/b", dir);
    write_bytes(a, "A", 1);
    write_bytes(b, "A", 1);

    // a dry run in link mode: detection is the same in every mode, and
    // clone mode would depend on whether /tmp can share blocks
    snprintf(cmd, sizeof(cmd), DEDUP_COMMAND " -nlP %s", dir);
    char* output = run(cmd);
    ck_assert_ptr_nonnull(strstr(output, "duplicates found: 1\n"));
    ck_assert_ptr_nonnull(strstr(output, "bytes saved: 1 bytes\n"));
    free(output);

    ck_assert_int_eq(0, unlink(a));
    ck_assert_int_eq(0, unlink(b));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

START_TEST(dedup_rejects_sample_only_signature_collisions) {
    char* dir = make_temp_dir("collision");
    char base[PATH_MAX] = {0}, variant[PATH_MAX] = {0}, cmd[PATH_MAX * 2] = {0};
    snprintf(base, sizeof(base), "%s/base.bin", dir);
    snprintf(variant, sizeof(variant), "%s/variant.bin", dir);

    const size_t size = 16384;
    unsigned char* file_a = malloc(size);
    unsigned char* file_b = malloc(size);
    ck_assert_ptr_nonnull(file_a);
    ck_assert_ptr_nonnull(file_b);

    memset(file_a, 'A', size);
    memcpy(file_b, file_a, size);
    file_b[7000] = 'B';
    file_b[12000] = 'C';

    write_bytes(base, file_a, size);
    write_bytes(variant, file_b, size);
    free(file_a);
    free(file_b);

    // a dry run in link mode: detection is the same in every mode, and
    // clone mode would depend on whether /tmp can share blocks
    snprintf(cmd, sizeof(cmd), DEDUP_COMMAND " -nlP %s", dir);
    char* output = run(cmd);
    ck_assert_ptr_nonnull(strstr(output, "duplicates found: 0\n"));
    ck_assert_ptr_nonnull(strstr(output, "bytes saved: 0 bytes\n"));
    free(output);

    ck_assert_int_eq(0, unlink(base));
    ck_assert_int_eq(0, unlink(variant));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

START_TEST(files_match_exact_xor_or_handles_equal_and_different_files) {
    char* dir = make_temp_dir("xor-or");
    char a[PATH_MAX] = {0}, b[PATH_MAX] = {0};
    snprintf(a, sizeof(a), "%s/a", dir);
    snprintf(b, sizeof(b), "%s/b", dir);

    write_bytes(a, "same-data", 9);
    write_bytes(b, "same-data", 9);
    ck_assert(files_match_exact_xor_or(a, b));

    write_bytes(b, "diff-data", 9);
    ck_assert(!files_match_exact_xor_or(a, b));

    ck_assert_int_eq(0, unlink(a));
    ck_assert_int_eq(0, unlink(b));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

START_TEST(files_match_exact_cpu_tiles_handles_equal_and_different_files) {
    char* dir = make_temp_dir("cpu-tiles");
    char a[PATH_MAX] = {0}, b[PATH_MAX] = {0};
    snprintf(a, sizeof(a), "%s/a", dir);
    snprintf(b, sizeof(b), "%s/b", dir);

    write_bytes(a, "same-data", 9);
    write_bytes(b, "same-data", 9);
    ck_assert(files_match_exact_cpu_tiles(a, b));

    write_bytes(b, "diff-data", 9);
    ck_assert(!files_match_exact_cpu_tiles(a, b));

    ck_assert_int_eq(0, unlink(a));
    ck_assert_int_eq(0, unlink(b));
    ck_assert_int_eq(0, rmdir(dir));
    free(dir);
} END_TEST

Suite* signature_suite() {
    TCase* tc = tcase_create("signature");
    tcase_add_test(tc, signature_supports_subword_files);
    tcase_add_test(tc, signature_hash_supports_unaligned_input);
    tcase_add_test(tc, signature_rejects_stale_metadata_and_special_files);
    tcase_add_test(tc, exact_backends_reject_special_files);
    tcase_add_test(tc, exact_backends_compare_past_chunk_boundaries);
    tcase_add_test(tc, signature_table_rejects_zero_buckets);
    tcase_add_test(tc, signature_table_verifies_colliding_candidates);
    tcase_add_test(tc, dedup_detects_small_duplicate_files);
    tcase_add_test(tc, dedup_rejects_sample_only_signature_collisions);
    tcase_add_test(tc, files_match_exact_xor_or_handles_equal_and_different_files);
    tcase_add_test(tc, files_match_exact_cpu_tiles_handles_equal_and_different_files);

    Suite* s = suite_create("signature");
    suite_add_tcase(s, tc);
    return s;
}
