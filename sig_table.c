// Copyright © 2025 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include "sig_table.h"
#include <stdlib.h>
#include <string.h>

#include "runtime_dispatch.h"

// Helper to round capacity up to nearest power of 2 for fast bitwise masking
static size_t next_power_of_2(size_t v) {
    if (v < 16) v = 16;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    if (sizeof(size_t) > 4) {
        v |= v >> 32;
    }
    v++;
    return v;
}

// Dynamically double bucket capacity when entry count reaches bucket count.
// Keeps average collision chain length O(1) even when scanning millions of files.
static void sig_table_grow(SigTable* table) {
    size_t new_bucket_count = table->bucket_count * 2;
    SigTableEntry** new_buckets = calloc(new_bucket_count, sizeof(SigTableEntry*));
    if (!new_buckets) {
        return; // Memory allocation failure: continue using existing buckets safely
    }

    size_t mask = new_bucket_count - 1;
    for (size_t i = 0; i < table->bucket_count; i++) {
        SigTableEntry* entry = table->buckets[i];
        while (entry) {
            SigTableEntry* next = entry->next;
            uint64_t hash = hash_signature(entry->signature);
            size_t new_idx = hash & mask;
            entry->next = new_buckets[new_idx];
            new_buckets[new_idx] = entry;
            entry = next;
        }
    }

    free(table->buckets);
    table->buckets = new_buckets;
    table->bucket_count = new_bucket_count;
}

SigTable* new_sig_table(size_t bucket_count) {
    bucket_count = next_power_of_2(bucket_count);

    SigTable* table = calloc(1, sizeof(SigTable));
    if (!table) {
        return NULL;
    }

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

    // Auto-expand table when load factor reaches 1.0 to prevent O(N) chain degradation
    if (table->entry_count >= table->bucket_count) {
        sig_table_grow(table);
    }

    uint64_t hash = hash_signature(sig);
    // Fast bitwise AND mask instead of integer modulo '%'
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
