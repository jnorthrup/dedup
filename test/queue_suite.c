// Copyright © 2026 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../queue.h"

static FileEntry* entry(const char* name, size_t size, nlink_t nlink, uint64_t sequence) {
    FileEntry* fe = calloc(1, sizeof(FileEntry));
    ck_assert_ptr_nonnull(fe);
    fe->path = strdup(name);
    fe->size = size;
    fe->nlink = nlink;
    fe->sequence = sequence;
    return fe;
}

// Pops everything and returns the paths joined with spaces.
static void drain(FileEntryHeap* heap, char* out, size_t out_size) {
    size_t used = 0;
    out[0] = '\0';
    for (FileEntry* fe = file_entry_heap_pop(heap); fe; fe = file_entry_heap_pop(heap)) {
        int n = snprintf(out + used, out_size - used, "%s%s", used ? " " : "", fe->path);
        ck_assert_int_ge(n, 0);
        used += (size_t) n;
        ck_assert_uint_lt(used, out_size);
        file_entry_free(fe);
    }
}

static void load(FileEntryHeap* heap) {
    // Found in this order: sizes 100, 5000, 1000, 5000, 100, 1000; a hard-linked
    // group (nlink 2) of size 40 is found last.
    ck_assert(file_entry_heap_push(heap, entry("a1", 100, 1, 0)));
    ck_assert(file_entry_heap_push(heap, entry("b1", 5000, 1, 1)));
    ck_assert(file_entry_heap_push(heap, entry("c1", 1000, 1, 2)));
    ck_assert(file_entry_heap_push(heap, entry("b2", 5000, 1, 3)));
    ck_assert(file_entry_heap_push(heap, entry("a2", 100, 1, 4)));
    ck_assert(file_entry_heap_push(heap, entry("c2", 1000, 1, 5)));
    ck_assert(file_entry_heap_push(heap, entry("h1", 40, 2, 6)));
}

START_TEST(test_heap_default_pops_in_discovery_order) {
    FileEntryHeap* heap = new_file_entry_heap(0);
    load(heap);
    char out[128];
    drain(heap, out, sizeof(out));
    ck_assert_str_eq(out, "a1 b1 c1 b2 a2 c2 h1");
    free_file_entry_heap(heap);
}
END_TEST

START_TEST(test_heap_largest_first_ranks_everything_found) {
    FileEntryHeap* heap = new_file_entry_heap(1);
    load(heap);
    char out[128];
    drain(heap, out, sizeof(out));
    // By size across all files, ties by discovery.
    ck_assert_str_eq(out, "b1 b2 c1 c2 a1 a2 h1");
    free_file_entry_heap(heap);
}
END_TEST

START_TEST(test_heap_smallest_first_ranks_everything_found) {
    FileEntryHeap* heap = new_file_entry_heap(-1);
    load(heap);
    char out[128];
    drain(heap, out, sizeof(out));
    ck_assert_str_eq(out, "h1 a1 a2 c1 c2 b1 b2");
    free_file_entry_heap(heap);
}
END_TEST

START_TEST(test_heap_ranks_among_what_is_pending) {
    // A later, larger find outranks what is still waiting, but not what a
    // worker already took.
    FileEntryHeap* heap = new_file_entry_heap(1);
    ck_assert(file_entry_heap_push(heap, entry("small", 10, 1, 0)));
    ck_assert(file_entry_heap_push(heap, entry("medium", 500, 1, 1)));
    FileEntry* fe = file_entry_heap_pop(heap);
    ck_assert_str_eq(fe->path, "medium");
    file_entry_free(fe);
    ck_assert(file_entry_heap_push(heap, entry("huge", 90000, 1, 2)));
    char out[128];
    drain(heap, out, sizeof(out));
    ck_assert_str_eq(out, "huge small");
    free_file_entry_heap(heap);
}
END_TEST

START_TEST(test_heap_grows_and_frees_leftovers) {
    FileEntryHeap* heap = new_file_entry_heap(1);
    for (uint64_t i = 0; i < 5000; i++) {
        char name[16];
        snprintf(name, sizeof(name), "f%llu", (unsigned long long) i);
        ck_assert(file_entry_heap_push(heap, entry(name, (size_t) ((i * 7919) % 1000), 1, i)));
    }
    ck_assert_uint_eq(file_entry_heap_count(heap), 5000);
    size_t last = SIZE_MAX;
    for (int i = 0; i < 2500; i++) {
        FileEntry* fe = file_entry_heap_pop(heap);
        ck_assert_ptr_nonnull(fe);
        ck_assert_uint_le(fe->size, last);
        last = fe->size;
        file_entry_free(fe);
    }
    ck_assert_uint_eq(file_entry_heap_count(heap), 2500);
    free_file_entry_heap(heap);  // frees the remaining entries
    ck_assert_ptr_null(file_entry_heap_pop(NULL));
}
END_TEST

Suite* queue_suite(void) {
    Suite* s = suite_create("queue");
    TCase* tc = tcase_create("Core");
    tcase_add_test(tc, test_heap_default_pops_in_discovery_order);
    tcase_add_test(tc, test_heap_largest_first_ranks_everything_found);
    tcase_add_test(tc, test_heap_smallest_first_ranks_everything_found);
    tcase_add_test(tc, test_heap_ranks_among_what_is_pending);
    tcase_add_test(tc, test_heap_grows_and_frees_leftovers);
    suite_add_tcase(s, tc);
    return s;
}
