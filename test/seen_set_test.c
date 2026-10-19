// Copyright © 2025 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include "seen_set.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    // Test 1: Basic non-zero insertions and duplicate detection
    SeenSet* set = new_seen_set(16);
    assert(set != NULL);

    assert(!seen_set_insert(set, 100));
    assert(seen_set_insert(set, 100));

    assert(!seen_set_insert(set, 200));
    assert(seen_set_insert(set, 200));

    // Test 2: Key 0 handling
    assert(!seen_set_insert(set, 0));
    assert(seen_set_insert(set, 0));

    // Test 3: Large scale insertion causing multiple grows & rehashes
    for (uint64_t i = 1000; i < 50000; i++) {
        assert(!seen_set_insert(set, i));
    }

    for (uint64_t i = 1000; i < 50000; i++) {
        assert(seen_set_insert(set, i));
    }

    free_seen_set(set);

    printf("All SeenSet unit tests passed successfully!\n");
    return 0;
}
