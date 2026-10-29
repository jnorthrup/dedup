// Copyright © 2026 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include "../seen_set.h"

START_TEST(test_seen_set_basic) {
    SeenSet* set = new_seen_set(16);
    ck_assert_ptr_nonnull(set);

    // Initial insert should return false (not previously seen)
    ck_assert_msg(!seen_set_insert(set, 100), "First insert of 100 should return false");
    ck_assert_msg(!seen_set_insert(set, 200), "First insert of 200 should return false");

    // Re-insert should return true (already seen)
    ck_assert_msg(seen_set_insert(set, 100), "Re-insert of 100 should return true");
    ck_assert_msg(seen_set_insert(set, 200), "Re-insert of 200 should return true");

    // Key 0 handling
    ck_assert_msg(!seen_set_insert(set, 0), "First insert of 0 should return false");
    ck_assert_msg(seen_set_insert(set, 0), "Re-insert of 0 should return true");

    // Key UINT64_MAX handling and non-collision with key 0
    uint64_t max_key = UINT64_MAX;
    ck_assert_msg(!seen_set_insert(set, max_key), "First insert of UINT64_MAX should return false");
    ck_assert_msg(seen_set_insert(set, max_key), "Re-insert of UINT64_MAX should return true");
    ck_assert_msg(seen_set_insert(set, 0), "Key 0 should still return true");

    free_seen_set(set);
}
END_TEST

START_TEST(test_seen_set_grow) {
    SeenSet* set = new_seen_set(16);
    ck_assert_ptr_nonnull(set);

    // Insert 1000 items to force table expansion multiple times
    for (uint64_t i = 1; i <= 1000; i++) {
        ck_assert_msg(!seen_set_insert(set, i * 37), "First insert should return false");
    }

    // Verify all items are still present
    for (uint64_t i = 1; i <= 1000; i++) {
        ck_assert_msg(seen_set_insert(set, i * 37), "Re-insert should return true");
    }

    free_seen_set(set);
}
END_TEST

Suite* seen_set_suite(void) {
    Suite* s = suite_create("seen_set");
    TCase* tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_seen_set_basic);
    tcase_add_test(tc_core, test_seen_set_grow);
    suite_add_tcase(s, tc_core);

    return s;
}
