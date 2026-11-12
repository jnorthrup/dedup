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
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
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

#ifndef __DEDUP_QUEUE_H__
#define __DEDUP_QUEUE_H__

#include <sys/types.h>
#include <sys/queue.h>
#include <stdbool.h>
#include <stdint.h>

STAILQ_HEAD(FileEntryHead, FileEntry);

typedef struct FileEntryHead FileEntryHead;

typedef struct FileEntry {
    char* path;
    dev_t device;
    ino_t inode;
    nlink_t nlink;
    uint32_t flags;
    size_t size;
    uint64_t sequence;      /* discovery order; tie-break for the heap */
    uint64_t ticket;        /* visit turn, assigned when popped for a worker */
    bool acls_supported;
    short level;
    STAILQ_ENTRY(FileEntry) entries;    /* Tail queue. */
} FileEntry;


FileEntryHead* new_file_entry_queue();
void free_file_entry_queue(FileEntryHead* queue);
void file_entry_queue_append(FileEntryHead* queue,
                             char* path,
                             dev_t device,
                             ino_t inode,
                             nlink_t nlink,
                             uint32_t flags,
                             size_t size,
                             uint64_t sequence,
                             short level);
void file_entry_queue_push(FileEntryHead* queue, FileEntry* fe);
FileEntry* file_entry_next(FileEntryHead* queue);
void file_entry_free(FileEntry* fe);

/// The work queue: entries found and waiting for a worker. `pop` returns the
/// best entry among those pending right now; later finds can still outrank
/// the rest. `size_order` 0 pops in discovery order, > 0 the largest first,
/// < 0 the smallest first. Equal sizes fall back to discovery order, so two
/// identical files are always popped in the order they were found, as in the
/// default order. That keeps the same file as the source in every mode.
/// Hard-link-first order stays a property of the scan, not of this ranking.
typedef struct FileEntryHeap FileEntryHeap;

FileEntryHeap* new_file_entry_heap(int size_order);
/// Frees the heap and any entries still in it.
void free_file_entry_heap(FileEntryHeap* heap);
/// Returns false, leaving `fe` with the caller, if memory ran out.
bool file_entry_heap_push(FileEntryHeap* heap, FileEntry* fe);
FileEntry* file_entry_heap_pop(FileEntryHeap* heap);
size_t file_entry_heap_count(const FileEntryHeap* heap);

#endif // __DEDUP_QUEUE_H__
