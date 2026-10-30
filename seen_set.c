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

// A slot is 16 bytes, not 24: no per-slot state byte (and its 7 bytes of
// padding), so the table is a third smaller and four slots share a cache line.
// An all-zero slot is empty. The one pair that would look empty, (0, 0), is
// tracked by `has_zero` instead, so every 64-bit pair stays exact.
typedef struct {
    uint64_t device;
    uint64_t id;
} Slot;

struct SeenSet {
    Slot*  slots;
    size_t capacity; // always a power of 2
    size_t count;    // pairs in `slots`, not counting (0, 0)
    bool   has_zero; // (0, 0) has been inserted
};

static inline bool slot_empty(const Slot* slot) {
    return slot->device == 0 && slot->id == 0;
}

static size_t next_power_of_2(size_t v) {
    size_t power = 1;
    while (power < v) {
        if (power > SIZE_MAX / 2) return 0;
        power *= 2;
    }
    return power;
}

SeenSet* new_seen_set(size_t capacity) {
    if (capacity < 16) capacity = 16;
    capacity = next_power_of_2(capacity);
    if (capacity == 0 || capacity > SIZE_MAX / sizeof(Slot)) return NULL;

    SeenSet* set = malloc(sizeof(SeenSet));
    if (!set) return NULL;

    set->slots = calloc(capacity, sizeof(Slot));
    if (!set->slots) {
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
    free(set->slots);
    free(set);
}

static inline size_t hash_key(uint64_t device, uint64_t id, size_t mask) {
    uint64_t hash = id ^ (device * UINT64_C(0x9e3779b97f4a7c15));
    hash = (hash ^ (hash >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    hash = (hash ^ (hash >> 27)) * UINT64_C(0x94d049bb133111eb);
    return (size_t)(hash ^ (hash >> 31)) & mask;
}

static bool seen_set_grow(SeenSet* set) {
    if (set->capacity == 0 || set->capacity > SIZE_MAX / 2 / sizeof(Slot)) return false;
    size_t new_cap = set->capacity * 2;
    Slot* new_slots = calloc(new_cap, sizeof(Slot));
    if (!new_slots) return false;

    size_t mask = new_cap - 1;
    for (size_t i = 0; i < set->capacity; i++) {
        if (slot_empty(&set->slots[i])) continue;
        Slot slot = set->slots[i];
        size_t idx = hash_key(slot.device, slot.id, mask);
        while (!slot_empty(&new_slots[idx])) {
            idx = (idx + 1) & mask;
        }
        new_slots[idx] = slot;
    }

    free(set->slots);
    set->slots = new_slots;
    set->capacity = new_cap;
    return true;
}

bool seen_set_insert(SeenSet* set, uint64_t device, uint64_t id) {
    if (!set) return false;

    if (device == 0 && id == 0) {
        if (set->has_zero) return true;
        set->has_zero = true;
        return false;
    }

    size_t mask = set->capacity - 1;
    size_t idx = hash_key(device, id, mask);

    for (size_t probes = 0; probes < set->capacity; probes++) {
        if (slot_empty(&set->slots[idx])) break;
        if (set->slots[idx].device == device && set->slots[idx].id == id) {
            return true; // already present
        }
        idx = (idx + 1) & mask;
    }

    // Grow at 75% load. If allocation fails, retain the current set and
    // leave this pair unrecorded rather than risking a full-table loop.
    if (set->count >= set->capacity - set->capacity / 4) {
        if (!seen_set_grow(set)) return false;
        mask = set->capacity - 1;
        idx = hash_key(device, id, mask);
        while (!slot_empty(&set->slots[idx])) {
            idx = (idx + 1) & mask;
        }
    }

    set->slots[idx].device = device;
    set->slots[idx].id = id;
    set->count++;
    return false; // newly inserted
}

typedef struct PathEntry {
    char* path;
    uint64_t hash;
    struct PathEntry* next;
} PathEntry;

struct SeenPaths {
    PathEntry** buckets;
    size_t capacity;
    size_t count;
};

SeenPaths* new_seen_paths(size_t capacity) {
    if (capacity < 16) capacity = 16;
    if (capacity > SIZE_MAX / sizeof(PathEntry*)) return NULL;
    SeenPaths* paths = calloc(1, sizeof(*paths));
    if (!paths) return NULL;
    paths->buckets = calloc(capacity, sizeof(*paths->buckets));
    if (!paths->buckets) {
        free(paths);
        return NULL;
    }
    paths->capacity = capacity;
    return paths;
}

void free_seen_paths(SeenPaths* paths) {
    if (!paths) return;
    for (size_t i = 0; i < paths->capacity; i++) {
        PathEntry* entry = paths->buckets[i];
        while (entry) {
            PathEntry* next = entry->next;
            free(entry->path);
            free(entry);
            entry = next;
        }
    }
    free(paths->buckets);
    free(paths);
}

static void grow_seen_paths(SeenPaths* paths) {
    if (paths->capacity == 0 || paths->capacity > SIZE_MAX / 2 / sizeof(PathEntry*)) return;
    size_t capacity = paths->capacity * 2;
    PathEntry** buckets = calloc(capacity, sizeof(*buckets));
    // Chaining remains correct if resizing fails.
    if (!buckets) return;
    for (size_t i = 0; i < paths->capacity; i++) {
        PathEntry* entry = paths->buckets[i];
        while (entry) {
            PathEntry* next = entry->next;
            size_t bucket = entry->hash % capacity;
            entry->next = buckets[bucket];
            buckets[bucket] = entry;
            entry = next;
        }
    }
    free(paths->buckets);
    paths->buckets = buckets;
    paths->capacity = capacity;
}

int seen_paths_insert(SeenPaths* paths, const char* path) {
    if (!paths || !path) return -1;
    uint64_t hash = UINT64_C(14695981039346656037);
    for (const unsigned char* p = (const unsigned char*)path; *p; p++) {
        hash = (hash ^ *p) * UINT64_C(1099511628211);
    }
    size_t bucket = hash % paths->capacity;
    for (PathEntry* entry = paths->buckets[bucket]; entry; entry = entry->next) {
        if (entry->hash == hash && strcmp(entry->path, path) == 0) return 1;
    }
    PathEntry* entry = malloc(sizeof(*entry));
    if (!entry) return -1;
    size_t length = strlen(path) + 1;
    entry->path = malloc(length);
    if (!entry->path) {
        free(entry);
        return -1;
    }
    memcpy(entry->path, path, length);
    entry->hash = hash;
    entry->next = paths->buckets[bucket];
    paths->buckets[bucket] = entry;
    paths->count++;
    if (paths->count >= paths->capacity) grow_seen_paths(paths);
    return 0;
}
