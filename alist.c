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

#include "alist.h"
#include <string.h>

AList* new_alist() {
    return new_alist_with_capacity(ALIST_DEFAULT_CAPACITY);
}

AList* new_alist_with_capacity(size_t initial) {
    AList* a = malloc(sizeof(AList));
    a->size = 0;
    a->capacity = initial;
    a->elements = malloc(sizeof(void*) * initial);
    return a;
}

void free_alist(AList* list) {
    free(list->elements);
    free(list);
}

AList* alist_dup(const AList* list) {
    // TODO
    return NULL;
}

void alist_trim(AList* list) {
    // TODO
}


void alist_ensure(AList* list, size_t required) {
    if (list->capacity >= required) {
        return;
    }
    // Optimization: Calculate target capacity first to execute a single realloc,
    // avoiding redundant intermediate reallocations in a loop and handling 0 capacity.
    size_t new_capacity = list->capacity == 0 ? ALIST_DEFAULT_CAPACITY : list->capacity;
    while (new_capacity < required) {
        new_capacity *= 2;
    }
    void** new_elements = realloc(list->elements, sizeof(void*) * new_capacity);
    if (new_elements) {
        list->elements = new_elements;
        list->capacity = new_capacity;
    }
}

size_t alist_size(const AList* list) {
    return list->size;
}

bool alist_empty(const AList* list) {
    return list->size == 0;
}

void* alist_get(const AList* list, size_t index) {
    if (index >= list->size) {
        return NULL;
    }
    return list->elements[index];
}

void alist_add(AList* list, void* item) {
    alist_ensure(list, list->size + 1);
    list->elements[list->size++] = item;
}

void alist_set(AList* list, size_t index, void* item) {
    if (index >= list->size) {
        // ?
        return;
    }
    list->elements[index] = item;
}


void* alist_remove(AList* list, size_t index) {
    if (index >= list->size) {
        return NULL;
    }
    void* e = list->elements[index];
    // Optimization: Use memmove for fast vectorized contiguous block memory shifting
    // instead of an element-by-element loop.
    size_t num_to_move = list->size - index - 1;
    if (num_to_move > 0) {
        memmove(&list->elements[index], &list->elements[index + 1], num_to_move * sizeof(void*));
    }
    list->size--;
    return e;
}
