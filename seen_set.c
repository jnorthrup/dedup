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
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
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

#include "seen_set.h"

#include <stdlib.h>
#include <string.h>

#define EMPTY_KEY 0ULL

// Bolt Optimization:
// Flatten the hash table array from `Slot` structs (16 bytes due to alignment padding)
// to a contiguous uint64_t array (8 bytes per entry). Empty slots are represented
// by EMPTY_KEY (0ULL). The `has_zero` flag tracks whether key 0 itself has been inserted.
// This reduces the memory footprint per slot by 50% (doubling L1/L2 cache line efficiency)
// and avoids branching on `state` bytes during linear probing.
struct SeenSet {
    uint64_t* keys;
    size_t    capacity; // always a power of 2
    size_t    count;
    bool      has_zero;
};

static size_t next_power_of_2(size_t v) {
    if (v < 16) return 16;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    return v;
}

SeenSet* new_seen_set(size_t capacity) {
    capacity = next_power_of_2(capacity);

    SeenSet* set = malloc(sizeof(SeenSet));
    if (!set) return NULL;

    set->keys = calloc(capacity, sizeof(uint64_t));
    if (!set->keys) {
        free(set);
        return NULL;
    }

    set->capacity = capacity;
    set->count = 0;
    set->has_zero = false;
    return set;
}

void free_seen_set(SeenSet* set) {
    if (!set) return;
    free(set->keys);
    free(set);
}

// Fibonacci hashing for good distribution with power-of-2 tables
static inline size_t hash_key(uint64_t key, size_t mask) {
    return (size_t)((key * 11400714819323198485ULL) >> 32) & mask;
}

static bool seen_set_grow(SeenSet* set) {
    size_t new_cap = set->capacity * 2;
    uint64_t* new_keys = calloc(new_cap, sizeof(uint64_t));
    if (!new_keys) return false;

    size_t mask = new_cap - 1;
    for (size_t i = 0; i < set->capacity; i++) {
        uint64_t key = set->keys[i];
        if (key == EMPTY_KEY) continue;
        size_t idx = hash_key(key, mask);
        while (new_keys[idx] != EMPTY_KEY) {
            idx = (idx + 1) & mask;
        }
        new_keys[idx] = key;
    }

    free(set->keys);
    set->keys = new_keys;
    set->capacity = new_cap;
    return true;
}

bool seen_set_insert(SeenSet* set, uint64_t key) {
    // Handle 0 key out-of-band so EMPTY_KEY (0) can act as sentinel for empty slot
    if (key == EMPTY_KEY) {
        if (set->has_zero) {
            return true; // already present
        }
        set->has_zero = true;
        set->count++;
        return false; // newly inserted
    }

    // Grow at 75% load
    if (set->count * 4 >= set->capacity * 3) {
        if (!seen_set_grow(set)) {
            return false;
        }
    }

    size_t mask = set->capacity - 1;
    size_t idx = hash_key(key, mask);

    while (set->keys[idx] != EMPTY_KEY) {
        if (set->keys[idx] == key) {
            return true; // already present
        }
        idx = (idx + 1) & mask;
    }

    set->keys[idx] = key;
    set->count++;
    return false; // newly inserted
}
