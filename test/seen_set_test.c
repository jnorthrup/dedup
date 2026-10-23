// Copyright © 2026 TTKB, LLC.
// SPDX-License-Identifier: BSD-2-Clause

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static bool fail_malloc;
static bool fail_calloc;

static void* test_malloc(size_t size) {
    return fail_malloc ? NULL : malloc(size);
}

static void* test_calloc(size_t count, size_t size) {
    return fail_calloc ? NULL : calloc(count, size);
}

// Compile this standalone test without separately linking seen_set.c. Local
// allocator substitution exercises allocation failures without production hooks.
#define malloc test_malloc
#define calloc test_calloc
#include "../seen_set.c"
#undef calloc
#undef malloc

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void exact_pairs(void) {
    SeenSet* set = new_seen_set(1);
    REQUIRE(set != NULL);
    const uint64_t pairs[][2] = {
        { 0, 0 },
        { 0, UINT64_C(1) << 32 },
        { 1, 0 },
        { UINT64_C(1) << 32, 0 },
        { 1, UINT64_C(1) << 32 },
        { UINT64_MAX, UINT64_MAX },
        { UINT64_MAX, UINT64_MAX - (UINT64_C(1) << 32) },
    };
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        REQUIRE(!seen_set_insert(set, pairs[i][0], pairs[i][1]));
    }
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        REQUIRE(seen_set_insert(set, pairs[i][0], pairs[i][1]));
    }
    free_seen_set(set);
}

static void collisions_and_growth(void) {
    SeenSet* set = new_seen_set(1);
    REQUIRE(set != NULL);
    // Every identifier has the same low 32 bits. This corpus exercises hash
    // collisions and repeated growth while requiring exact 64-bit matching.
    for (uint64_t i = 0; i < 20000; i++) {
        uint64_t device = ((i % 31) << 32) | 3;
        uint64_t id = (i << 32) | 9;
        REQUIRE(!seen_set_insert(set, device, id));
        REQUIRE(seen_set_insert(set, device, id));
    }
    for (uint64_t i = 20000; i-- > 0;) {
        REQUIRE(seen_set_insert(set, ((i % 31) << 32) | 3, (i << 32) | 9));
    }
    free_seen_set(set);
}

static void allocation_failures(void) {
    REQUIRE(!seen_set_insert(NULL, 1, 1));
    REQUIRE(new_seen_set(SIZE_MAX) == NULL);
    REQUIRE(new_seen_set(SIZE_MAX / 2) == NULL);
    free_seen_set(NULL);

    fail_malloc = true;
    REQUIRE(new_seen_set(16) == NULL);
    fail_malloc = false;
    fail_calloc = true;
    REQUIRE(new_seen_set(16) == NULL);
    fail_calloc = false;

    SeenSet* set = new_seen_set(16);
    REQUIRE(set != NULL);
    bool recorded[128];
    size_t recorded_count = 0;
    fail_calloc = true;
    for (size_t i = 0; i < 128; i++) {
        REQUIRE(!seen_set_insert(set, 5, i));
        recorded[i] = seen_set_insert(set, 5, i);
        recorded_count += recorded[i];
    }
    REQUIRE(recorded_count > 0 && recorded_count < 128);

    // Existing entries remain recognized, omitted entries remain safe misses,
    // and insertion recovers when allocation becomes available again.
    fail_calloc = false;
    for (size_t i = 0; i < 128; i++) {
        REQUIRE(seen_set_insert(set, 5, i) == recorded[i]);
        REQUIRE(seen_set_insert(set, 5, i));
    }
    free_seen_set(set);
}

static void exact_paths(void) {
    SeenPaths* paths = new_seen_paths(16);
    REQUIRE(paths != NULL);
    char path[128];
    for (unsigned i = 0; i < 5000; i++) {
        snprintf(path, sizeof(path), "/scan/folder-%u/file", i);
        REQUIRE(seen_paths_insert(paths, path) == 0);
    }
    for (unsigned i = 5000; i-- > 0;) {
        snprintf(path, sizeof(path), "/scan/folder-%u/file", i);
        REQUIRE(seen_paths_insert(paths, path) == 1);
    }
    // Different directory entries must remain distinct, including hard links.
    REQUIRE(seen_paths_insert(paths, "/scan/a") == 0);
    REQUIRE(seen_paths_insert(paths, "/scan/b") == 0);
    REQUIRE(seen_paths_insert(paths, "/scan/a") == 1);
    free_seen_paths(paths);
}

static void path_allocation_failures(void) {
    REQUIRE(new_seen_paths(SIZE_MAX) == NULL);
    REQUIRE(seen_paths_insert(NULL, "/scan/a") == -1);
    free_seen_paths(NULL);
    fail_calloc = true;
    REQUIRE(new_seen_paths(16) == NULL);
    fail_calloc = false;

    SeenPaths* paths = new_seen_paths(16);
    REQUIRE(paths != NULL);
    REQUIRE(seen_paths_insert(paths, "/scan/a") == 0);
    fail_malloc = true;
    REQUIRE(seen_paths_insert(paths, "/scan/a") == 1);
    REQUIRE(seen_paths_insert(paths, "/scan/b") == -1);
    fail_malloc = false;
    REQUIRE(seen_paths_insert(paths, "/scan/b") == 0);

    // A failed resize retains all entries and can recover on a later insert.
    fail_calloc = true;
    char path[128];
    for (unsigned i = 0; i < 128; i++) {
        snprintf(path, sizeof(path), "/scan/growth-%u", i);
        REQUIRE(seen_paths_insert(paths, path) == 0);
    }
    fail_calloc = false;
    REQUIRE(seen_paths_insert(paths, "/scan/after-growth") == 0);
    for (unsigned i = 0; i < 128; i++) {
        snprintf(path, sizeof(path), "/scan/growth-%u", i);
        REQUIRE(seen_paths_insert(paths, path) == 1);
    }
    free_seen_paths(paths);
}

int main(void) {
    exact_pairs();
    collisions_and_growth();
    allocation_failures();
    exact_paths();
    path_allocation_failures();
    puts("seen set: exact pairs/paths, collisions, growth, and allocation failures passed");
    return EXIT_SUCCESS;
}
