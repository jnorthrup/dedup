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

#include <stdlib.h>
#include <string.h>

#include "queue.h"

FileEntryHead* new_file_entry_queue() {
    FileEntryHead* head = malloc(sizeof(FileEntryHead));
    STAILQ_INIT(head);

    return head;
}

void free_file_entry_queue(FileEntryHead* queue) {
    free(queue);
}

void file_entry_queue_append(FileEntryHead* queue,
                             char* path,
                             dev_t device,
                             ino_t inode,
                             nlink_t nlink,
                             uint32_t flags,
                             size_t size,
                             uint64_t sequence,
                             short level) {
    FileEntry* e = malloc(sizeof(FileEntry));
    *e = (FileEntry) {
        .path = strdup(path),
        .device = device,
        .inode = inode,
        .nlink = nlink,
        .flags = flags,
        .size = size,
        .sequence = sequence,
        .level = level,
    };
    STAILQ_INSERT_TAIL(queue, e, entries);
}

void file_entry_queue_push(FileEntryHead* queue, FileEntry* fe) {
    if (queue && fe) {
        STAILQ_INSERT_TAIL(queue, fe, entries);
    }
}

FileEntry* file_entry_next(FileEntryHead* queue) {
     if (STAILQ_EMPTY(queue)) {
         return NULL;
     }

     FileEntry* e = STAILQ_FIRST(queue);
     // Use STAILQ_REMOVE_HEAD for O(1) popping of the head element.
     // STAILQ_REMOVE compares and scans the queue, whereas STAILQ_REMOVE_HEAD
     // directly updates the head/tail pointers.
     STAILQ_REMOVE_HEAD(queue, entries);

     return e;
}

void file_entry_free(FileEntry* fe) {
    free(fe->path);
    free(fe);
}

struct FileEntryHeap {
    FileEntry** items;
    size_t count;
    size_t capacity;
    int size_order;
};

FileEntryHeap* new_file_entry_heap(int size_order) {
    FileEntryHeap* heap = calloc(1, sizeof(FileEntryHeap));
    if (heap) heap->size_order = size_order;
    return heap;
}

void free_file_entry_heap(FileEntryHeap* heap) {
    if (!heap) return;
    for (size_t i = 0; i < heap->count; i++) file_entry_free(heap->items[i]);
    free(heap->items);
    free(heap);
}

// True when `a` should be popped before `b`.
static bool heap_before(const FileEntryHeap* heap, const FileEntry* a, const FileEntry* b) {
    if (heap->size_order != 0) {
        if (a->size != b->size) return (a->size > b->size) == (heap->size_order > 0);
    }
    return a->sequence < b->sequence;
}

bool file_entry_heap_push(FileEntryHeap* heap, FileEntry* fe) {
    if (!heap || !fe) return false;
    if (heap->count == heap->capacity) {
        size_t capacity = heap->capacity ? heap->capacity * 2 : 1024;
        FileEntry** items = realloc(heap->items, capacity * sizeof(FileEntry*));
        if (!items) return false;
        heap->items = items;
        heap->capacity = capacity;
    }
    size_t i = heap->count++;
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (!heap_before(heap, fe, heap->items[parent])) break;
        heap->items[i] = heap->items[parent];
        i = parent;
    }
    heap->items[i] = fe;
    return true;
}

FileEntry* file_entry_heap_pop(FileEntryHeap* heap) {
    if (!heap || heap->count == 0) return NULL;
    FileEntry* top = heap->items[0];
    FileEntry* last = heap->items[--heap->count];
    size_t i = 0;
    for (;;) {
        size_t child = 2 * i + 1;
        if (child >= heap->count) break;
        if (child + 1 < heap->count &&
            heap_before(heap, heap->items[child + 1], heap->items[child])) {
            child++;
        }
        if (!heap_before(heap, heap->items[child], last)) break;
        heap->items[i] = heap->items[child];
        i = child;
    }
    if (heap->count > 0) heap->items[i] = last;
    return top;
}

size_t file_entry_heap_count(const FileEntryHeap* heap) {
    return heap ? heap->count : 0;
}
