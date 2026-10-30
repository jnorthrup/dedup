// Copyright © 2025 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include "sig_table.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "runtime_dispatch.h"

// Round a capacity up to a power of two, at least 16, so that a bucket can be
// chosen with a bitwise AND instead of a 64-bit division.
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

// Double the bucket count when the entry count reaches it, so the average
// collision chain stays short even when millions of files are scanned. On
// allocation failure the table keeps working with its current buckets.
static void sig_table_grow(SigTable* table) {
    size_t new_bucket_count = table->bucket_count * 2;
    if (new_bucket_count < table->bucket_count) {
        return;
    }
    SigTableEntry** new_buckets = calloc(new_bucket_count, sizeof(SigTableEntry*));
    if (!new_buckets) {
        return;
    }

    size_t new_mask = new_bucket_count - 1;
    for (size_t i = 0; i < table->bucket_count; i++) {
        SigTableEntry* entry = table->buckets[i];
        while (entry) {
            SigTableEntry* next = entry->next;
            size_t new_idx = hash_signature(entry->signature) & new_mask;
            entry->next = new_buckets[new_idx];
            new_buckets[new_idx] = entry;
            entry = next;
        }
    }

    free(table->buckets);
    table->buckets = new_buckets;
    table->bucket_count = new_bucket_count;
    table->mask = new_mask;
}

SigTable* new_sig_table(size_t bucket_count) {
    if (bucket_count == 0) {
        return NULL;
    }
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
    table->mask = bucket_count - 1;
    table->entry_count = 0;

    return table;
}

void free_sig_table(SigTable* table, void (*free_data)(void* data)) {
    if (!table) {
        return;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {
        SigTableEntry* entry = table->buckets[i];
        while (entry) {
            SigTableEntry* next = entry->next;
            if (free_data) {
                free_data(entry->data);
            }
            free_signature(entry->signature);
            free(entry->path);
            free(entry);
            entry = next;
        }
    }

    free(table->buckets);
    free(table);
}

SigTableEntry* sig_table_insert(SigTable* table, FileSignature* sig, const char* path, uint64_t clone_id, void* data) {
    if (!table || !table->buckets || table->bucket_count == 0 || !sig || !path) {
        return NULL;
    }

    // Grow before computing the index, which depends on the bucket count.
    if (table->entry_count >= table->bucket_count) {
        sig_table_grow(table);
    }

    uint64_t hash = hash_signature(sig);
    // bucket_count is a power of two (see new_sig_table), so a mask replaces
    // the integer modulo on the hot lookup path.
    size_t bucket_idx = hash & table->mask;

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

    new_entry->path = strdup(path);
    if (!new_entry->path) {
        free(new_entry);
        return NULL;
    }
    new_entry->signature = sig;  // Takes ownership only after allocation succeeds
    new_entry->clone_id = clone_id;
    new_entry->data = data;      // Takes ownership
    new_entry->next = table->buckets[bucket_idx];

    table->buckets[bucket_idx] = new_entry;
    table->entry_count++;

    return NULL;
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
