// Copyright © 2025 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#ifndef __DEDUP_SIGNATURE_H__
#define __DEDUP_SIGNATURE_H__

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

// Lightweight file signature using strategic sampling
// Avoids expensive SHA256 computation in favor of fast sampling + xxHash
typedef struct FileSignature {
    dev_t device;        // Device ID (from stat)
    uint64_t size;       // File size (from stat)
    int32_t samples[4];  // Sampled int32 values at strategic positions
    uint64_t quick_hash; // xxHash64 of first 4KB (or entire file if smaller)
} FileSignature;

// Compute signature for a file
// Returns NULL on error
FileSignature* compute_signature(const char* path, dev_t device, uint64_t size);

// Free signature
void free_signature(FileSignature* sig);

// Compare two signatures
// Returns true if signatures match (files are likely identical)
bool signatures_match(const FileSignature* a, const FileSignature* b);

// Hash a signature for use in hash table
uint64_t hash_signature(const FileSignature* sig);

#endif // __DEDUP_SIGNATURE_H__
