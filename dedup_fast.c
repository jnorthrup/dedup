// Copyright © 2025 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <xxhash.h>
#include <arm_neon.h>

// Fast signature structure using sampling
typedef struct FastSignature {
    uint32_t samples[4];  // Sampled 32-bit values from file
    uint64_t hash;        // xxHash64 of first 4KB
} FastSignature;

// Hash table entry for fast dedup
typedef struct HashEntry {
    FastSignature sig;
    char* path;
    struct HashEntry* next;
} HashEntry;

// Simple hash table
#define HASH_TABLE_SIZE 65536
static HashEntry* hash_table[HASH_TABLE_SIZE];

// Generate fast signature for a file
static int generate_fast_signature(const char* path, FastSignature* sig) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    size_t size = st.st_size;
    if (size == 0) {
        close(fd);
        memset(sig, 0, sizeof(*sig));
        return 0;
    }

    // Map file for reading
    void* data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        close(fd);
        return -1;
    }

    // Sample 4 positions in the file
    uint32_t* file_data = (uint32_t*)data;
    size_t num_words = size / sizeof(uint32_t);

    if (num_words >= 4) {
        // Sample at 25%, 50%, 75%, and end positions
        sig->samples[0] = file_data[num_words / 4];
        sig->samples[1] = file_data[num_words / 2];
        sig->samples[2] = file_data[3 * num_words / 4];
        sig->samples[3] = file_data[num_words - 1];
    } else {
        // For small files, use available data
        memset(sig->samples, 0, sizeof(sig->samples));
        for (size_t i = 0; i < num_words && i < 4; i++) {
            sig->samples[i] = file_data[i];
        }
    }

    // Compute xxHash64 of first 4KB
    size_t hash_size = size < 4096 ? size : 4096;
    sig->hash = XXH64(data, hash_size, 0);

    munmap(data, size);
    close(fd);
    return 0;
}

// Compare signatures using NEON
static int signatures_equal_neon(const FastSignature* a, const FastSignature* b) {
    // Load samples into NEON registers
    uint32x4_t va = vld1q_u32(a->samples);
    uint32x4_t vb = vld1q_u32(b->samples);

    // Compare all 4 samples at once
    uint32x4_t cmp = vceqq_u32(va, vb);

    // Check if all comparisons are true
    uint32_t result = vminvq_u32(cmp);
    return result == 0xFFFFFFFF && a->hash == b->hash;
}

// Hash function for hash table
static uint32_t hash_signature(const FastSignature* sig) {
    return (uint32_t)(sig->hash ^ (sig->hash >> 32));
}

// Add file to hash table
static void add_to_hash_table(const char* path, const FastSignature* sig) {
    uint32_t hash = hash_signature(sig) % HASH_TABLE_SIZE;

    HashEntry* entry = malloc(sizeof(HashEntry));
    entry->sig = *sig;
    entry->path = strdup(path);
    entry->next = hash_table[hash];
    hash_table[hash] = entry;
}

// Find duplicate using fast signatures
static const char* find_duplicate_fast(const char* path, const FastSignature* sig) {
    uint32_t hash = hash_signature(sig) % HASH_TABLE_SIZE;

    for (HashEntry* entry = hash_table[hash]; entry; entry = entry->next) {
        if (signatures_equal_neon(&entry->sig, sig)) {
            return entry->path;
        }
    }
    return NULL;
}

// Main fast dedup function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file1> [file2] ...\n", argv[0]);
        return 1;
    }

    printf("Fast dedup using sampling + xxHash64 + NEON\n");

    for (int i = 1; i < argc; i++) {
        const char* path = argv[i];
        FastSignature sig;

        if (generate_fast_signature(path, &sig) < 0) {
            fprintf(stderr, "Failed to process %s\n", path);
            continue;
        }

        const char* duplicate = find_duplicate_fast(path, &sig);
        if (duplicate) {
            printf("DUPLICATE: %s == %s\n", path, duplicate);
        } else {
            printf("UNIQUE: %s\n", path);
            add_to_hash_table(path, &sig);
        }
    }

    // Cleanup
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashEntry* entry = hash_table[i];
        while (entry) {
            HashEntry* next = entry->next;
            free(entry->path);
            free(entry);
            entry = next;
        }
    }

    return 0;
}
