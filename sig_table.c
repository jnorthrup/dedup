// Copyright © 2025 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include "sig_table.h"
#include <stdlib.h>
#include <string.h>

#include "runtime_dispatch.h"

#include <stdint.h>

static size_t next_power_of_2(size_t v) {
    if (v < 16) return 16;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
#if SIZE_MAX > 0xFFFFFFFFU
    v |= v >> 32;
#endif
    v++;
    return v;
}

SigTable* new_sig_table(size_t bucket_count) {
    SigTable* table = calloc(1, sizeof(SigTable));
    if (!table) {
        return NULL;
    }

    // Ensure bucket_count is a power of 2 for fast bitwise mask indexing
    bucket_count = next_power_of_2(bucket_count);

    table->buckets = calloc(bucket_count, sizeof(SigTableEntry*));
    if (!table->buckets) {
        free(table);
        return NULL;
    }

    table->bucket_count = bucket_count;
    table->entry_count = 0;

    return table;
}

void free_sig_table(SigTable* table) {
    if (!table) {
        return;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {
        SigTableEntry* entry = table->buckets[i];
        while (entry) {
            SigTableEntry* next = entry->next;
            free_signature(entry->signature);
            free(entry->path);
            free(entry);
            entry = next;
        }
    }

    free(table->buckets);
    free(table);
}

SigTableEntry* sig_table_insert(SigTable* table, FileSignature* sig, const char* path, uint64_t clone_id) {
    if (!table || !sig || !path) {
        return NULL;
    }

    uint64_t hash = hash_signature(sig);
    // Performance optimization: bucket_count is guaranteed to be a power of 2 by new_sig_table().
    // Using bitwise AND (hash & mask) instead of integer modulo (hash % bucket_count)
    // eliminates expensive 64-bit hardware division (~25-40 CPU cycles down to 1 CPU cycle).
    size_t bucket_idx = hash & (table->bucket_count - 1);

    // Check for existing match in collision chain.
    // SMHasher-style discipline: a fast hash/signature only nominates candidates;
    // witness stages may reject quickly, but exact comparison is still required
    // before treating files as equal.
    SigTableEntry* entry = table->buckets[bucket_idx];
    while (entry) {
        if (signatures_match(entry->signature, sig) &&
            dedup_runtime_witness_compare(entry->path, path, sig->size) &&
            dedup_runtime_exact_compare(entry->path, path, sig->size)) {
            return entry;
        }
        entry = entry->next;
    }

    SigTableEntry* new_entry = calloc(1, sizeof(SigTableEntry));
    if (!new_entry) {
        return NULL;
    }

    new_entry->signature = sig;  // Takes ownership
    new_entry->path = strdup(path);
    new_entry->clone_id = clone_id;
    new_entry->next = table->buckets[bucket_idx];

    table->buckets[bucket_idx] = new_entry;
    table->entry_count++;

    return NULL;
}

bool sig_table_has_clone_id(const SigTable* table, uint64_t clone_id) {
    if (!table || clone_id == 0) {
        return false;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {
        SigTableEntry* entry = table->buckets[i];
        while (entry) {
            if (entry->clone_id == clone_id) {
                return true;
            }
            entry = entry->next;
        }
    }

    return false;
}

size_t sig_table_size(const SigTable* table) {
    return table ? table->entry_count : 0;
}

size_t sig_table_collisions(const SigTable* table) {
    if (!table) {
        return 0;
    }

    size_t collisions = 0;
    for (size_t i = 0; i < table->bucket_count; i++) {
        size_t chain_len = 0;
        SigTableEntry* entry = table->buckets[i];
        while (entry) {
            chain_len++;
            entry = entry->next;
        }
        if (chain_len > 1) {
            collisions += chain_len - 1;
        }
    }

    return collisions;
}
