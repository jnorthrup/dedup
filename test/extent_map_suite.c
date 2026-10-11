// SPDX-License-Identifier: BSD-2-Clause

#include <check.h>
#include <stdbool.h>
#include <stdint.h>

#include "../extent_map.h"

#define KiB(n) ((uint64_t)(n) << 10)
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const uint32_t S = EXTENT_SHARED;

START_TEST(extent_maps_shared_same_extent) {
    Extent a[] = { { 0, KiB(1024), KiB(64), S } };
    Extent b[] = { { 0, KiB(1024), KiB(64), S } };
    ck_assert(extent_maps_shared(a, COUNT(a), b, COUNT(b), KiB(64)));
} END_TEST

START_TEST(extent_maps_shared_needs_the_shared_flag) {
    // same address, but the filesystem does not say the blocks are shared
    // (some report 0 for every address)
    Extent a[] = { { 0, 0, KiB(64), 0 } };
    Extent b[] = { { 0, 0, KiB(64), 0 } };
    ck_assert(!extent_maps_shared(a, COUNT(a), b, COUNT(b), KiB(64)));

    Extent c[] = { { 0, 0, KiB(64), S } };
    ck_assert(!extent_maps_shared(a, COUNT(a), c, COUNT(c), KiB(64)));
} END_TEST

START_TEST(extent_maps_shared_different_addresses) {
    Extent a[] = { { 0, KiB(1024), KiB(64), S } };
    Extent b[] = { { 0, KiB(2048), KiB(64), S } };
    ck_assert(!extent_maps_shared(a, COUNT(a), b, COUNT(b), KiB(64)));
} END_TEST

START_TEST(extent_maps_shared_split_differently) {
    // the same blocks, reported as one extent for a and two for b
    Extent a[] = { { 0, KiB(1024), KiB(8), S } };
    Extent b[] = { { 0, KiB(1024), KiB(4), S }, { KiB(4), KiB(1028), KiB(4), S } };
    ck_assert(extent_maps_shared(a, COUNT(a), b, COUNT(b), KiB(8)));

    // the second half of b lives elsewhere
    Extent c[] = { { 0, KiB(1024), KiB(4), S }, { KiB(4), KiB(4096), KiB(4), S } };
    ck_assert(!extent_maps_shared(a, COUNT(a), c, COUNT(c), KiB(8)));
} END_TEST

START_TEST(extent_maps_shared_holes) {
    // holes that line up are fine
    Extent a[] = { { 0, KiB(1024), KiB(4), S }, { KiB(8), KiB(2048), KiB(4), S } };
    Extent b[] = { { 0, KiB(1024), KiB(4), S }, { KiB(8), KiB(2048), KiB(4), S } };
    ck_assert(extent_maps_shared(a, COUNT(a), b, COUNT(b), KiB(12)));

    // data in one file where the other has a hole is not shared
    Extent c[] = { { 0, KiB(1024), KiB(12), S } };
    ck_assert(!extent_maps_shared(a, COUNT(a), c, COUNT(c), KiB(12)));
    ck_assert(!extent_maps_shared(c, COUNT(c), a, COUNT(a), KiB(12)));

    // a hole at the start of one file only
    Extent d[] = { { KiB(4), KiB(1028), KiB(8), S } };
    ck_assert(!extent_maps_shared(c, COUNT(c), d, COUNT(d), KiB(12)));
} END_TEST

START_TEST(extent_maps_shared_no_data) {
    // two files that are holes throughout have nothing stored twice
    ck_assert(extent_maps_shared(NULL, 0, NULL, 0, KiB(64)));

    Extent a[] = { { 0, KiB(1024), KiB(64), S } };
    ck_assert(!extent_maps_shared(a, COUNT(a), NULL, 0, KiB(64)));
    ck_assert(!extent_maps_shared(NULL, 0, a, COUNT(a), KiB(64)));
} END_TEST

START_TEST(extent_maps_shared_not_shareable) {
    // btrfs inline data: address 0, never shared, even when "shared"
    Extent a[] = { { 0, 0, KiB(4), S | EXTENT_NOT_SHAREABLE } };
    Extent b[] = { { 0, 0, KiB(4), S | EXTENT_NOT_SHAREABLE } };
    ck_assert(!extent_maps_shared(a, COUNT(a), b, COUNT(b), 100));
} END_TEST

START_TEST(extent_maps_shared_encoded) {
    // a compressed extent counts only when both files reference all of it
    Extent a[] = { { 0, KiB(1024), KiB(128), S | EXTENT_ENCODED } };
    Extent b[] = { { 0, KiB(1024), KiB(128), S | EXTENT_ENCODED } };
    ck_assert(extent_maps_shared(a, COUNT(a), b, COUNT(b), KiB(128)));

    // the same compressed extent, but b references only part of it: the
    // address does not advance with the offset, so it proves nothing
    Extent c[] = { { 0, KiB(1024), KiB(64), S | EXTENT_ENCODED },
                   { KiB(64), KiB(1024), KiB(64), S | EXTENT_ENCODED } };
    ck_assert(!extent_maps_shared(a, COUNT(a), c, COUNT(c), KiB(128)));

    // compressed in one file and plain in the other
    Extent d[] = { { 0, KiB(1024), KiB(128), S } };
    ck_assert(!extent_maps_shared(a, COUNT(a), d, COUNT(d), KiB(128)));
} END_TEST

START_TEST(extent_maps_shared_only_inside_size) {
    // XFS preallocates past the end of a file; that extent is not data
    Extent a[] = { { 0, KiB(1024), KiB(64), S }, { KiB(64), KiB(4096), KiB(64), 0 } };
    Extent b[] = { { 0, KiB(1024), KiB(64), S } };
    ck_assert(extent_maps_shared(a, COUNT(a), b, COUNT(b), KiB(64)));

    // the last block is rounded up past the size of the file
    ck_assert(extent_maps_shared(b, COUNT(b), b, COUNT(b), 3000));
} END_TEST

START_TEST(extent_map_count_overlap_and_flags) {
    Extent a[] = { { 0, KiB(1024), KiB(4), S },
                   { KiB(8), 0, KiB(4), EXTENT_NOT_SHAREABLE },
                   { KiB(64), KiB(2048), KiB(4), S } };
    ck_assert_uint_eq(2, extent_map_count(a, COUNT(a), KiB(12), 0));
    ck_assert_uint_eq(3, extent_map_count(a, COUNT(a), KiB(68), 0));
    ck_assert_uint_eq(1, extent_map_count(a, COUNT(a), KiB(12), EXTENT_NOT_SHAREABLE));
    ck_assert_uint_eq(1, extent_map_count(a, COUNT(a), KiB(12), S));
    ck_assert_uint_eq(0, extent_map_count(a, COUNT(a), KiB(8), EXTENT_NOT_SHAREABLE));
    ck_assert_uint_eq(0, extent_map_count(NULL, 0, KiB(8), 0));
} END_TEST

Suite* extent_map_suite() {
    TCase* tc = tcase_create("extent_map");
    tcase_add_test(tc, extent_maps_shared_same_extent);
    tcase_add_test(tc, extent_maps_shared_needs_the_shared_flag);
    tcase_add_test(tc, extent_maps_shared_different_addresses);
    tcase_add_test(tc, extent_maps_shared_split_differently);
    tcase_add_test(tc, extent_maps_shared_holes);
    tcase_add_test(tc, extent_maps_shared_no_data);
    tcase_add_test(tc, extent_maps_shared_not_shareable);
    tcase_add_test(tc, extent_maps_shared_encoded);
    tcase_add_test(tc, extent_maps_shared_only_inside_size);
    tcase_add_test(tc, extent_map_count_overlap_and_flags);

    Suite* s = suite_create("extent_map");
    suite_add_tcase(s, tc);
    return s;
}
