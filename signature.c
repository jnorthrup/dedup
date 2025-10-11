// Copyright © 2025 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include "signature.h"

#include <sys/uio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

// Simple xxHash64 implementation for first 4KB
// Based on xxHash by Yann Collet
static const uint64_t PRIME64_1 = 0x9E3779B185EBCA87ULL;
static const uint64_t PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
static const uint64_t PRIME64_3 = 0x165667B19E3779F9ULL;
static const uint64_t PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
static const uint64_t PRIME64_5 = 0x27D4EB2F165667C5ULL;

static inline uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t xxhash64(const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    const uint8_t* const end = p + len;
    uint64_t h64;

    if (len >= 32) {
        const uint8_t* const limit = end - 32;
        uint64_t v1 = PRIME64_1 + PRIME64_2;
        uint64_t v2 = PRIME64_2;
        uint64_t v3 = 0;
        uint64_t v4 = -(int64_t)PRIME64_1;

        do {
            v1 += *(uint64_t*)p * PRIME64_2; v1 = rotl64(v1, 31); v1 *= PRIME64_1; p += 8;
            v2 += *(uint64_t*)p * PRIME64_2; v2 = rotl64(v2, 31); v2 *= PRIME64_1; p += 8;
            v3 += *(uint64_t*)p * PRIME64_2; v3 = rotl64(v3, 31); v3 *= PRIME64_1; p += 8;
            v4 += *(uint64_t*)p * PRIME64_2; v4 = rotl64(v4, 31); v4 *= PRIME64_1; p += 8;
        } while (p <= limit);

        h64 = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);

        v1 *= PRIME64_2; v1 = rotl64(v1, 31); v1 *= PRIME64_1; h64 ^= v1; h64 = h64 * PRIME64_1 + PRIME64_4;
        v2 *= PRIME64_2; v2 = rotl64(v2, 31); v2 *= PRIME64_1; h64 ^= v2; h64 = h64 * PRIME64_1 + PRIME64_4;
        v3 *= PRIME64_2; v3 = rotl64(v3, 31); v3 *= PRIME64_1; h64 ^= v3; h64 = h64 * PRIME64_1 + PRIME64_4;
        v4 *= PRIME64_2; v4 = rotl64(v4, 31); v4 *= PRIME64_1; h64 ^= v4; h64 = h64 * PRIME64_1 + PRIME64_4;
    } else {
        h64 = PRIME64_5;
    }

    h64 += (uint64_t)len;

    while (p + 8 <= end) {
        uint64_t k1 = *(uint64_t*)p;
        k1 *= PRIME64_2; k1 = rotl64(k1, 31); k1 *= PRIME64_1;
        h64 ^= k1; h64 = rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
        p += 8;
    }

    if (p + 4 <= end) {
        h64 ^= (uint64_t)(*(uint32_t*)p) * PRIME64_1;
        h64 = rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
        p += 4;
    }

    while (p < end) {
        h64 ^= (*p++) * PRIME64_5;
        h64 = rotl64(h64, 11) * PRIME64_1;
    }

    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}

FileSignature* compute_signature(const char* path, dev_t device, uint64_t size) {
    FileSignature* sig = calloc(1, sizeof(FileSignature));
    if (!sig) {
        return NULL;
    }

    sig->device = device;
    sig->size = size;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        free(sig);
        return NULL;
    }

    // Sample at 4 strategic positions
    off_t positions[4] = {
        0,                                    // Start
        (off_t)(size / 3),                    // 1/3 point
        (off_t)((size * 2) / 3),              // 2/3 point
        (off_t)(size > 4 ? size - 4 : 0)      // End (or start if file < 4 bytes)
    };

#ifdef __ARM_NEON
    // Use NEON to load all 4 samples in parallel if aligned
    if (size >= 16) {
        char buf[16] __attribute__((aligned(16)));
        for (int i = 0; i < 4; i++) {
            if (pread(fd, &buf[i * 4], 4, positions[i]) != 4) {
                close(fd);
                free(sig);
                return NULL;
            }
        }
        // Load into NEON register
        int32x4_t samples_vec = vld1q_s32((int32_t*)buf);
        vst1q_s32(sig->samples, samples_vec);
    } else
#endif
    {
        // Fallback: sequential reads for small files
        for (int i = 0; i < 4; i++) {
            if (pread(fd, &sig->samples[i], sizeof(int32_t), positions[i]) != sizeof(int32_t)) {
                close(fd);
                free(sig);
                return NULL;
            }
        }
    }

    // Compute xxHash64 of first 4KB (or entire file if smaller)
    size_t hash_size = size < 4096 ? size : 4096;
    char* buf = malloc(hash_size);
    if (!buf) {
        close(fd);
        free(sig);
        return NULL;
    }

    ssize_t n = pread(fd, buf, hash_size, 0);
    if (n < 0) {
        free(buf);
        close(fd);
        free(sig);
        return NULL;
    }

    sig->quick_hash = xxhash64(buf, n);

    free(buf);
    close(fd);

    return sig;
}

void free_signature(FileSignature* sig) {
    free(sig);
}

bool signatures_match(const FileSignature* a, const FileSignature* b) {
    if (!a || !b) {
        return false;
    }

    // Early exits for fast negative cases
    if (a->device != b->device) return false;
    if (a->size != b->size) return false;
    if (a->quick_hash != b->quick_hash) return false;

#ifdef __ARM_NEON
    // Use NEON for vectorized comparison of samples
    int32x4_t a_vec = vld1q_s32(a->samples);
    int32x4_t b_vec = vld1q_s32(b->samples);
    uint32x4_t cmp = vceqq_s32(a_vec, b_vec);

    // All lanes must match
    uint32x2_t tmp = vand_u32(vget_low_u32(cmp), vget_high_u32(cmp));
    return vget_lane_u32(vpmin_u32(tmp, tmp), 0) == 0xFFFFFFFF;
#else
    // Scalar comparison fallback
    return memcmp(a->samples, b->samples, sizeof(a->samples)) == 0;
#endif
}

uint64_t hash_signature(const FileSignature* sig) {
    // Combine all fields into a single hash
    uint64_t h = sig->size;
    h ^= (uint64_t)sig->device + 0x9e3779b97f4a7c15ULL;
    h ^= sig->quick_hash + 0x9e3779b97f4a7c15ULL;

#ifdef __ARM_NEON
    // Use NEON to hash samples
    int32x4_t samples_vec = vld1q_s32(sig->samples);
    // Reinterpret as two 64-bit values
    uint64x2_t hash_vec = vreinterpretq_u64_s32(samples_vec);
    h ^= vgetq_lane_u64(hash_vec, 0);
    h ^= vgetq_lane_u64(hash_vec, 1);
#else
    for (int i = 0; i < 4; i++) {
        h ^= (uint64_t)sig->samples[i] * PRIME64_1;
        h = rotl64(h, 27);
    }
#endif

    return h;
}
