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

#include <sys/cdefs.h>
#ifndef lint
__attribute__((used)) static char const copyright[] =
    "@(#) Copyright © 2023\n"
        "TTKB, LLC. All rights reserved.\n";
#ifndef VERSION
#define VERSION 0.0.0
#endif // VERSION
#ifndef BUILD_DATE
#define BUILD_DATE 00000000
#endif // BUILD_DATE
#define STR(x) #x
#define XSTR(x) STR(x)
__attribute__((used)) static char const version[] =
    "TTKB dedup " XSTR(VERSION) " (" XSTR(BUILD_DATE) ")";
#if 0
static char sccsid[] = "@(#)dedup.c)";
#endif // 0
#endif // lint

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>

#include <assert.h>
#include <stdlib.h>
#include <err.h>
#include <fts.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "clone.h"
#include "backend.h"
#include "progress.h"
#include "queue.h"
#include "output_format.h"
#include "runtime_dispatch.h"
#include "runtime_caps.h"
#include "seen_set.h"
#include "signature.h"
#include "sig_table.h"
#include "utils.h"

#define PROGRESS_LOCK(p, m, block) do { \
        if ((p)) { \
            pthread_mutex_lock((m)); \
            block; \
            pthread_mutex_unlock((m)); \
        } \
    } while (0)

// Print a message without tearing the status line. Unlike PROGRESS_LOCK, the
// block always runs: messages must not depend on whether a progress display
// exists (-P, or stdout that is not a terminal). display_status() draws the
// status line only when stdout is a terminal, so only then is it cleared.
#define REPORT_LOCKED(ctx, block) do { \
        pthread_mutex_lock(&(ctx)->progress_mutex); \
        if (isatty(STDOUT_FILENO)) { \
            clear_progress(); \
        } \
        block; \
        pthread_mutex_unlock(&(ctx)->progress_mutex); \
    } while (0)

// Forward declaration
typedef struct DedupContext DedupContext;

// Clone record streaming functions
static FILE* clone_summary_stream = NULL;
static pthread_mutex_t clone_summary_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t clone_summary_count = 0;

static void clone_summary_open(const char* filepath) {
    pthread_mutex_lock(&clone_summary_mutex);
    if (!clone_summary_stream) {
        clone_summary_stream = fopen(filepath, "w");
        if (clone_summary_stream) {
            fprintf(clone_summary_stream, "DEDUP CLONING SUMMARY\n");
            fprintf(clone_summary_stream, "=====================\n");
            fprintf(clone_summary_stream, "\n");
        }
    }
    pthread_mutex_unlock(&clone_summary_mutex);
}

static void clone_summary_write(const char* origin, const char* clone, size_t size) {
    pthread_mutex_lock(&clone_summary_mutex);
    if (clone_summary_stream) {
        fprintf(clone_summary_stream, "  Origin: %s\n", origin);
        fprintf(clone_summary_stream, "    Clone: %s (size: %zu bytes)\n", clone, size);
        clone_summary_count++;
    }
    pthread_mutex_unlock(&clone_summary_mutex);
}

static void clone_summary_close() {
    pthread_mutex_lock(&clone_summary_mutex);
    if (clone_summary_stream) {
        // Write count at the end
        fprintf(clone_summary_stream, "\nTotal cloning operations: %zu\n", clone_summary_count);
        fflush(clone_summary_stream);
        
        fclose(clone_summary_stream);
        clone_summary_stream = NULL;
        clone_summary_count = 0;
    }
    pthread_mutex_unlock(&clone_summary_mutex);
}

typedef enum ReplaceMode {
    DEDUP_CLONE    = 0,
    DEDUP_LINK     = 1,
    DEDUP_SYMLINK  = 2,
} ReplaceMode;

static const char* replacement_name(ReplaceMode mode) {
    switch (mode) {
    case DEDUP_LINK:    return "a hard link";
    case DEDUP_SYMLINK: return "a symbolic link";
    case DEDUP_CLONE:   break;
    }
    return "a clone";
}

// A file with the same content as at least one other, as the traversal found it.
typedef struct Duplicate {
    char* path;
    uint64_t clone_id;
    dev_t device;
    ino_t inode;
    nlink_t nlink;
    uint32_t flags;
    size_t size;
} Duplicate;

// The files that share one content. Every file in the signature table has a
// set; once a duplicate turns up, members holds the first file seen followed
// by each duplicate in traversal order. Nothing is replaced until every file
// has been seen, so the origin is chosen from the whole set (see
// deduplicate()).
typedef struct DuplicateSet {
    Duplicate first;     // The first file seen; the table entry holds its path
    Duplicate* members;  // NULL until a duplicate is found
    size_t count;
    size_t capacity;
} DuplicateSet;

typedef struct DedupContext {
    Progress* progress;
    FileEntryHead* queue;
    FileEntryHead* raw_queue;
    SigTable* signatures;
    DuplicateSet** sets;  // Sets with a duplicate, in the order one was found
    size_t set_count;
    size_t set_capacity;
    size_t found;
    size_t saved;
    size_t already_saved;
    size_t pruned;
    size_t skipped;       // Duplicates left in place (hard-linked, unwritable, ...)
    size_t skipped_bytes;
    size_t failed;       // Duplicates that could not be replaced
    size_t total_bytes;  // Accumulated bytes of all scanned files
    size_t queued_count; // Entries in raw_queue + work_queue combined
    uint64_t next_file_sequence;
    uint64_t next_visit_sequence;
    uint8_t scan_done;
    uint8_t prune_done;
    uint8_t thread_count;
    bool dry_run;
    uint8_t verbosity;
    bool force;
    ReplaceMode replace_mode;
    OutputFormat output_format;
    bool clone_converted;        // Whether to convert clones (true by default)
    const char* summary_file;    // File to write detailed summary to (NULL by default)
    pthread_mutex_t metrics_mutex;
    pthread_mutex_t progress_mutex;
    pthread_mutex_t queue_mutex;
    pthread_mutex_t raw_queue_mutex;
    pthread_mutex_t signatures_mutex;
    pthread_mutex_t scan_done_mutex;
    pthread_mutex_t prune_done_mutex;
    pthread_mutex_t visit_order_mutex;
    pthread_cond_t visit_order_cond;
} DedupContext;

static int get_terminal_width(void) {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0) {
        return w.ws_col;
    }
    return 80; // fallback
}

// Fixed-width compact format for a file count (e.g., "2.1K", " 99K", "999K")
static void format_count(size_t count, char buf[5]) {
    buf[4] = '\0';
    
    if (count < 1000) {
        snprintf(buf, 5, "%4zu", count);
    } else if (count < 9950) {
        snprintf(buf, 5, "%.1fK", (double)count / 1000.0);
    } else if (count < 999500) {
        snprintf(buf, 5, "%3lluK", (unsigned long long)((count + 500) / 1000));
    } else if (count < 9950000) {
        snprintf(buf, 5, "%.1fM", (double)count / 1000000.0);
    } else if (count < 999500000) {
        snprintf(buf, 5, "%3lluM", (unsigned long long)((count + 500000) / 1000000));
    } else {
        snprintf(buf, 5, "%.1fG", (double)count / 1000000000.0);
    }
    
    size_t len = strlen(buf);
    if (len < 4) {
        size_t pad = 4 - len;
        memmove(buf + pad, buf, len + 1);
        for (size_t i = 0; i < pad; i++) buf[i] = ' ';
    } else if (len > 4) {
        buf[4] = '\0';
    }
}

static void display_status(DedupContext* ctx, const char* path) {
    if (!isatty(STDOUT_FILENO)) {
        return;
    }
    
    static bool header_printed = false;
    if (!header_printed) {
        fprintf(stderr, "%-4s %-4s %-4s %-5s %-20s %s\n",
                "TOTL", "QUED", "SHRD", "DELTA", "PROGRESS", "PATH");
        header_printed = true;
    }

    int width = get_terminal_width();
    if (width < 80) width = 80;
    
    pthread_mutex_lock(&ctx->metrics_mutex);
    size_t total_bytes = ctx->total_bytes;
    size_t queued = ctx->queued_count;
    size_t shared = ctx->already_saved;
    size_t delta = ctx->saved;
    pthread_mutex_unlock(&ctx->metrics_mutex);
    
    size_t completed = 0;
    size_t total = 0;
    if (ctx->progress) {
        PROGRESS_LOCK(ctx->progress, &ctx->progress_mutex, {
            completed = ctx->progress->completedUnitCount;
            total = ctx->progress->totalUnitCount;
        });
    }
    
    char total_bytes_str[5];
    char queued_str[5];
    char shared_str[5];
    char delta_str[5];
    char done_str[5];
    char total_str[5];
    
    format_compact(total_bytes, total_bytes_str);
    format_compact(queued, queued_str);
    format_compact(shared, shared_str);
    format_compact(delta, delta_str);
    format_count(completed, done_str);
    format_count(total, total_str);
    
    char bar[12];
    bar[0] = '[';
    bar[10] = ']';
    bar[11] = '\0';
    
    if (total == 0) {
        for (int i = 1; i < 10; i++) bar[i] = '-';
    } else {
        double fraction = (double)completed / (double)total;
        int fill = (int)(fraction * 8.0);
        if (fill < 0) fill = 0;
        if (fill > 8) fill = 8;
        
        for (int i = 1; i <= fill; i++) bar[i] = '=';
        for (int i = fill + 1; i < 10; i++) bar[i] = '-';
    }
    
    char progress_str[21];
    snprintf(progress_str, sizeof(progress_str), "%s%s%s", done_str, bar, total_str);
    
    int fixed_width = 41;
    int path_max = width - fixed_width - 1;
    if (path_max < 10) path_max = 10;
    
    char truncated_path[256];
    memset(truncated_path, 0, sizeof(truncated_path));
    if (path) {
        size_t len = strlen(path);
        if (len <= (size_t)path_max) {
            strcpy(truncated_path, path);
        } else {
            size_t keep = path_max - 1;
            truncated_path[0] = '~';
            strncpy(truncated_path + 1, path + len - keep, keep);
            truncated_path[keep + 1] = '\0';
        }
    }
    
    char delta_display[6];
    if (delta > 0) {
        snprintf(delta_display, sizeof(delta_display), "+%-4s", delta_str);
    } else {
        snprintf(delta_display, sizeof(delta_display), " %-4s", delta_str);
    }
    delta_display[5] = '\0';
    
    int line_len = 4 + 1 + 4 + 1 + 4 + 1 + 5 + 1 + 20 + 1 + (int)strlen(truncated_path);
    int padding = width - line_len;
    if (padding < 0) padding = 0;
    
    char padding_str[256];
    if (padding > 0 && padding < (int)sizeof(padding_str) - 1) {
        memset(padding_str, ' ', padding);
        padding_str[padding] = '\0';
    } else {
        padding_str[0] = '\0';
    }
    
    fprintf(stderr, "\r%-4s %-4s %-4s %s %s %s%s\033[0m\033[K",
            total_bytes_str, queued_str, shared_str, delta_display,
            progress_str, truncated_path, padding_str);
    fflush(stderr);
}

static void visit_order_begin(DedupContext* ctx, uint64_t sequence) {
    if (!ctx || ctx->thread_count == 0) {
        return;
    }

    pthread_mutex_lock(&ctx->visit_order_mutex);
    while (sequence != ctx->next_visit_sequence) {
        pthread_cond_wait(&ctx->visit_order_cond, &ctx->visit_order_mutex);
    }
    pthread_mutex_unlock(&ctx->visit_order_mutex);
}

static void visit_order_end(DedupContext* ctx) {
    if (!ctx || ctx->thread_count == 0) {
        return;
    }

    pthread_mutex_lock(&ctx->visit_order_mutex);
    ctx->next_visit_sequence++;
    pthread_cond_broadcast(&ctx->visit_order_cond);
    pthread_mutex_unlock(&ctx->visit_order_mutex);
}

// A duplicate that is left in place. Its bytes are still stored twice, so it
// is counted as skipped, never as space already saved.
static void skip_duplicate(DedupContext* ctx, const Duplicate* d, const char* reason) {
    if (ctx->verbosity) {
        REPORT_LOCKED(ctx, {
            printf("skipping %s, %s\n", d->path, reason);
        });
    }
    pthread_mutex_lock(&ctx->metrics_mutex);
    ctx->skipped++;
    ctx->skipped_bytes += d->size;
    pthread_mutex_unlock(&ctx->metrics_mutex);
}

// Add a file whose content matches the table entry's to the entry's set.
// Called with signatures_mutex held. Returns false if memory ran out; the file
// is then left alone.
static bool add_duplicate(DedupContext* ctx, SigTableEntry* entry,
                          const Duplicate* found, const char* path) {
    DuplicateSet* set = entry->data;
    if (!set) {
        return false;
    }

    // the first duplicate also brings in the file it duplicates
    size_t needed = set->count ? set->count + 1 : 2;
    if (needed > set->capacity) {
        size_t capacity = set->capacity ? set->capacity * 2 : 2;
        Duplicate* members = realloc(set->members, capacity * sizeof(Duplicate));
        if (!members) {
            return false;
        }
        set->members = members;
        set->capacity = capacity;
    }

    if (set->count == 0) {
        if (ctx->set_count == ctx->set_capacity) {
            size_t capacity = ctx->set_capacity ? ctx->set_capacity * 2 : 64;
            DuplicateSet** sets = realloc(ctx->sets, capacity * sizeof(DuplicateSet*));
            if (!sets) {
                return false;
            }
            ctx->sets = sets;
            ctx->set_capacity = capacity;
        }

        char* first_path = strdup(entry->path);
        if (!first_path) {
            return false;
        }
        set->members[0] = set->first;
        set->members[0].path = first_path;
        set->count = 1;
        ctx->sets[ctx->set_count++] = set;
    }

    char* copy = strdup(path);
    if (!copy) {
        return false;
    }
    set->members[set->count] = *found;
    set->members[set->count].path = copy;
    set->count++;
    return true;
}

static void free_duplicate_set(void* data) {
    DuplicateSet* set = data;
    if (!set) {
        return;
    }
    for (size_t i = 0; i < set->count; i++) {
        free(set->members[i].path);
    }
    free(set->members);
    free(set);
}

void visit_entry(FileEntry* fe, Progress* p, DedupContext* ctx) {
    if (!fe || !ctx) {
        return;
    }

    FileSignature* sig = compute_signature(fe->path, fe->device, fe->size);
    visit_order_begin(ctx, fe->sequence);
    if (!sig) {
        // Silently skip files we can't read (locked, slow FUSE mounts, etc)
        visit_order_end(ctx);
        return;
    }

    // Insert into signature table and check for duplicates
    if (!ctx->signatures) {
        REPORT_LOCKED(ctx, {
            fprintf(stderr, "signature table not initialized for %s\n", fe->path);
        });
        free_signature(sig);
        visit_order_end(ctx);
        return;
    }

    // The file starts a set of its own, unless its content matches an earlier
    // file's: then it joins that file's set.
    DuplicateSet* set = calloc(1, sizeof(DuplicateSet));
    if (!set) {
        REPORT_LOCKED(ctx, {
            fprintf(stderr, "failed to store signature for %s: memory allocation failed\n", fe->path);
        });
        free_signature(sig);
        visit_order_end(ctx);
        return;
    }
    set->first = (Duplicate) {
        .path = NULL,
        .clone_id = get_clone_id(fe->path),
        .device = fe->device,
        .inode = fe->inode,
        .nlink = fe->nlink,
        .flags = fe->flags,
        .size = fe->size,
    };

    pthread_mutex_lock(&ctx->signatures_mutex);
    size_t table_size_before = sig_table_size(ctx->signatures);
    SigTableEntry* existing = sig_table_insert(ctx->signatures, sig, fe->path, set->first.clone_id, set);
    size_t table_size_after = sig_table_size(ctx->signatures);
    bool recorded = false;
    if (existing) {
        recorded = add_duplicate(ctx, existing, &set->first, fe->path);
    }
    pthread_mutex_unlock(&ctx->signatures_mutex);

    // Safety check: table size should only increase by 0 or 1
    if (table_size_after > table_size_before + 1) {
        REPORT_LOCKED(ctx, {
            fprintf(stderr, "warning: signature table size increased by %zu (expected 0 or 1)\n",
                    table_size_after - table_size_before);
        });
    }

    bool table_took_ownership = (table_size_after > table_size_before);

    if (existing) {
        // Found a duplicate. It is replaced after the traversal, once the
        // whole set is known.
        display_status(ctx, fe->path);
        if (!recorded) {
            REPORT_LOCKED(ctx, {
                fprintf(stderr, "failed to record duplicate %s: memory allocation failed\n", fe->path);
            });
        }
        free(set);
        free_signature(sig);
    } else if (table_took_ownership) {
        // First instance of this signature
        display_status(ctx, fe->path);
    } else {
        // Table failed to take ownership (allocation failure)
        REPORT_LOCKED(ctx, {
            fprintf(stderr, "failed to store signature for %s: memory allocation failed\n", fe->path);
        });
        free(set);
        free_signature(sig);
    }

    visit_order_end(ctx);
}

// Returns true if the entry was pruned (caller should free it), false if it survived.
//
// Only another path to an inode already seen is pruned. Clones are not: a
// clone can be modified without changing its clone id, and whether a clone
// needs replacing depends on the origin chosen for its whole set.
static bool prune_entry(FileEntry* fe, SeenSet* seen_inodes, DedupContext* c) {
    bool pruned = false;

    if (fe->nlink > 1) {
        uint64_t key = (uint64_t)fe->device << 32 | (uint64_t)(fe->inode & 0xFFFFFFFF);
        if (seen_set_insert(seen_inodes, key)) {
            pruned = true;
        }
    }

    if (!pruned) {
        return false;
    }

    // A pruned entry never reaches visit_entry, so its sequence number would
    // never be advanced by visit_order_end. A worker waiting on
    // visit_order_begin would block forever and deadlock the whole run, so
    // advance it here instead.
    visit_order_begin(c, fe->sequence);
    visit_order_end(c);

    pthread_mutex_lock(&c->metrics_mutex);
    c->already_saved += fe->size;
    c->pruned++;
    pthread_mutex_unlock(&c->metrics_mutex);
    PROGRESS_LOCK(c->progress, &c->progress_mutex, {
        c->progress->completedUnitCount++;
    });
    display_status(c, fe->path);
    return true;
}

void* prune_work(void* ctx) {
    DedupContext* c = ctx;
    SeenSet* seen_inodes = new_seen_set(4096);

    for (;;) {
        pthread_mutex_lock(&c->raw_queue_mutex);
        FileEntry* fe = file_entry_next(c->raw_queue);
        pthread_mutex_unlock(&c->raw_queue_mutex);

        if (!fe) {
            pthread_mutex_lock(&c->scan_done_mutex);
            uint8_t done = c->scan_done;
            pthread_mutex_unlock(&c->scan_done_mutex);
            if (done) {
                // Drain remaining entries
                pthread_mutex_lock(&c->raw_queue_mutex);
                fe = file_entry_next(c->raw_queue);
                pthread_mutex_unlock(&c->raw_queue_mutex);
                if (!fe) break;
            } else {
                usleep(100);
                continue;
            }
        }

        // Decrement queued_count for raw_queue pop
        pthread_mutex_lock(&c->metrics_mutex);
        c->queued_count--;
        pthread_mutex_unlock(&c->metrics_mutex);

        if (prune_entry(fe, seen_inodes, c)) {
            file_entry_free(fe);
            continue;
        }

        // Survivor: pass to work queue
        // queued_count stays the same (file moves between queues)
        pthread_mutex_lock(&c->queue_mutex);
        file_entry_queue_append(c->queue,
                                fe->path,
                                fe->device,
                                fe->inode,
                                fe->nlink,
                                fe->flags,
                                fe->size,
                                fe->sequence,
                                fe->level);
        pthread_mutex_unlock(&c->queue_mutex);
        
        // Show pruner progress (survivor passes through)
        display_status(c, fe->path);
        file_entry_free(fe);
    }

    free_seen_set(seen_inodes);
    return NULL;
}

void* dedup_work(void* ctx) {
    DedupContext* c = ctx;
    uint8_t done = c->prune_done;

    while (!done) {
        pthread_mutex_lock(&c->queue_mutex);
        FileEntry* fe = file_entry_next(c->queue);
        pthread_mutex_unlock(&c->queue_mutex);

        if (!fe) {
            pthread_mutex_lock(&c->prune_done_mutex);
            done = c->prune_done;
            pthread_mutex_unlock(&c->prune_done_mutex);
            if (done) {
                break;
            }
            usleep(100);
            continue;
        }

        // Decrement queued_count for work_queue pop
        pthread_mutex_lock(&c->metrics_mutex);
        c->queued_count--;
        pthread_mutex_unlock(&c->metrics_mutex);

        // Visit the entry (worker processes the file)
        visit_entry(fe, c->progress, c);

        PROGRESS_LOCK(c->progress, &c->progress_mutex, {
            c->progress->completedUnitCount++;
        });
        
        // Show worker progress (entry processed)
        display_status(c, fe->path);
        file_entry_free(fe);

        if (c->thread_count == 0) {
            break;
        }
    }

    return NULL;
}

typedef struct CloneRank {
    uint64_t clone_id;
    size_t index;
} CloneRank;

static int compare_clone_rank(const void* a, const void* b) {
    const CloneRank* x = a;
    const CloneRank* y = b;
    if (x->clone_id != y->clone_id) {
        return x->clone_id < y->clone_id ? -1 : 1;
    }
    return (x->index > y->index) - (x->index < y->index);
}

// Returns how many members of the largest group of clones there are, and sets
// *first to the index of that group's first member. Ties go to the group seen
// first. A clone id of 0 is unknown and matches nothing. If memory runs out,
// every file counts as a group of one.
static size_t largest_clone_group(const Duplicate* members, size_t count, size_t* first) {
    *first = 0;
    CloneRank* ranks = malloc(count * sizeof(CloneRank));
    if (!ranks) {
        return 1;
    }
    for (size_t i = 0; i < count; i++) {
        ranks[i] = (CloneRank) { .clone_id = members[i].clone_id, .index = i };
    }
    qsort(ranks, count, sizeof(CloneRank), compare_clone_rank);

    size_t largest = 1;
    for (size_t i = 0; i < count;) {
        size_t end = i + 1;
        while (end < count && ranks[end].clone_id == ranks[i].clone_id) {
            end++;
        }
        size_t size = ranks[i].clone_id ? end - i : 1;
        if (size > largest || (size == largest && size > 1 && ranks[i].index < *first)) {
            largest = size;
            *first = ranks[i].index;
        }
        i = end;
    }

    free(ranks);
    return largest;
}

// Replace every file in a set with a clone (or link) of one origin. As dedup(1)
// describes, the origin is the file with the most hard links, since it cannot
// be replaced without breaking them; otherwise the file with the most clones,
// so a set deduplicated before needs no changes; otherwise the first file seen
// that is not compressed.
static void deduplicate(DuplicateSet* set, DedupContext* ctx) {
    Duplicate* members = set->members;
    size_t count = set->count;
    if (count < 2) {
        return;
    }

    const Duplicate* origin = NULL;
    const char* reason = NULL;

    for (size_t i = 0; i < count; i++) {
        if (members[i].nlink > 1 && (!origin || origin->nlink < members[i].nlink)) {
            origin = &members[i];
            reason = "most hardlinks";
        }
    }

    if (!origin) {
        size_t first = 0;
        size_t clones = largest_clone_group(members, count, &first);

        if (clones == count) {
            pthread_mutex_lock(&ctx->metrics_mutex);
            ctx->already_saved += members[0].size * (count - 1);
            pthread_mutex_unlock(&ctx->metrics_mutex);
            if (ctx->verbosity) {
                REPORT_LOCKED(ctx, {
                    printf("%s is already cloned to\n", members[0].path);
                    for (size_t i = 1; i < count; i++) {
                        printf("\t%s\n", members[i].path);
                    }
                });
            }
            return;
        }

        if (clones > 1) {
            origin = &members[first];
            reason = "most clones";
        } else {
            // n.b.! transparently compressed files (UF_COMPRESSED) keep their
            //       data in a resource fork, so no clone can share their
            //       blocks: they are worthless as clone origins.
            for (size_t i = 0; i < count; i++) {
                if (!(members[i].flags & UF_COMPRESSED)) {
                    origin = &members[i];
                    reason = "first seen";
                    break;
                }
            }

            if (!origin) {
                for (size_t i = 1; i < count; i++) {
                    skip_duplicate(ctx, &members[i], "every copy is compressed");
                }
                return;
            }
        }
    }

    if (ctx->verbosity) {
        REPORT_LOCKED(ctx, {
            printf("using %s as the clone origin (%s)\n", origin->path, reason);
        });
    }

    for (size_t i = 0; i < count; i++) {
        const Duplicate* d = &members[i];
        if (d == origin) {
            continue;
        }
        display_status(ctx, d->path);

        // Check if already deduplicated
        if ((ctx->replace_mode == DEDUP_CLONE && d->clone_id != 0 && d->clone_id == origin->clone_id) ||
            (ctx->replace_mode == DEDUP_LINK && d->device == origin->device && d->inode == origin->inode)) {
            pthread_mutex_lock(&ctx->metrics_mutex);
            ctx->already_saved += d->size;
            pthread_mutex_unlock(&ctx->metrics_mutex);
            continue;
        }

        // Skip if hardlinked and not forcing
        if (!ctx->force && d->nlink > 1) {
            skip_duplicate(ctx, d, "hardlinked");
            continue;
        }

        // Skip if immutable or read-only
        if (d->flags & UF_IMMUTABLE || d->flags & SF_IMMUTABLE ||
            (access(d->path, W_OK) != 0)) {
            skip_duplicate(ctx, d, "immutable or not writable");
            continue;
        }

        if (ctx->dry_run) {
            if (ctx->verbosity) {
                REPORT_LOCKED(ctx, {
                    printf("would deduplicate %s to %s\n", d->path, origin->path);
                });
            }
            pthread_mutex_lock(&ctx->metrics_mutex);
            ctx->saved += d->size;
            ctx->found++;
            pthread_mutex_unlock(&ctx->metrics_mutex);
            continue;
        }

        // Check if clone conversion is disabled
        if (ctx->replace_mode == DEDUP_CLONE && !ctx->clone_converted) {
            skip_duplicate(ctx, d, "clone conversion disabled");
            continue;
        }

        int result = 0;
        switch (ctx->replace_mode) {
        case DEDUP_CLONE:
            result = replace_with_clone(origin->path, d->path);
            break;
        case DEDUP_LINK:
            result = replace_with_link(origin->path, d->path);
            break;
        case DEDUP_SYMLINK:
            result = replace_with_symlink(origin->path, d->path);
            break;
        }

        if (result) {
            // The replace_* functions print the system error; name the
            // file that was left alone and fail the run's exit status.
            REPORT_LOCKED(ctx, {
                warnx("could not replace %s with %s of %s",
                      d->path, replacement_name(ctx->replace_mode), origin->path);
            });
            pthread_mutex_lock(&ctx->metrics_mutex);
            ctx->failed++;
            pthread_mutex_unlock(&ctx->metrics_mutex);
            continue;
        }

        if (ctx->verbosity) {
            REPORT_LOCKED(ctx, {
                printf("deduplicated %s\n", d->path);
            });
        }

        // Verify the clone worked: a different clone id is still a clone if
        // the file has no private data.
        if (ctx->replace_mode == DEDUP_CLONE &&
            get_clone_id(d->path) != origin->clone_id &&
            private_size(d->path) != 0) {
            // The file was replaced by a copy that shares no blocks
            // with the origin: its data is intact but nothing was saved.
            REPORT_LOCKED(ctx, {
                warnx("%s was replaced, but the clone does not share blocks with %s",
                      d->path, origin->path);
            });
            pthread_mutex_lock(&ctx->metrics_mutex);
            ctx->failed++;
            pthread_mutex_unlock(&ctx->metrics_mutex);
            continue;
        }

        pthread_mutex_lock(&ctx->metrics_mutex);
        ctx->saved += d->size;
        ctx->found++;
        pthread_mutex_unlock(&ctx->metrics_mutex);

        // Write clone operation to summary file (streamed)
        if (ctx->summary_file) {
            clone_summary_write(origin->path, d->path, d->size);
        }
    }
}

__attribute__((noreturn))
static void usage(char* pgm, DedupContext* ctx) {
    fprintf(stderr,
            "%s\nusage: %s [-I pattern] [-t n] [-PVcnvx] [-d n] [file ...]\n\n"
                "Options:\n"
                // "  --ignore, -I pattern     Exclude a pattern from being used as a clone\n"
                // "                           source or being replaced by a clone. This option\n"
                // "                           can be specified multiple times.\n"
                "  --dry-run, -n            Don't replace file content, just print what \n"
                "                           would have happend.\n"
                "  --depth, -d depth        Don't descend further than the specified depth.\n"
                "  --format, -F format      Output format for byte sizes. See --help formats.\n"
                "  --one-file-system, -x    Don't evaluate directories on a different device\n"
                "                           than the starting paths.\n"
                "  --link, -l               Use hardlinks instead of clones.\n"
                "  --symlink, -s            Use symlinks instead of clones.\n"
                // "  --color, -c              Enabled colored output.\n"
                "  --no-progress, -P        Do not display a progress bar.\n"
                "  --no-clone-conversion    Do not convert clones (skip clone mode)\n"
                "  --summary, -S file       Write detailed cloning summary to file\n"
                "                           (itemized by directory hierarchy)\n"
                "  --threads, -t n          The number of threads to use for file building\n"
                "                           lookup tables and replacing clones. Default: %d\n"
                "  --verbose, -v            Increase verbosity. May be used multiple times.\n"
                "  --version, -V            Print the version and exit\n"
                // "  --force, -f              Don't preserve existing hardlinks.\n"
                "  -h                       Human readable output.\n"
                "  --help                   Show this help.\n",
            version,
            pgm,
            ctx->thread_count);

    exit(1);
}

__attribute__((const))
int32_t cpu_count() {
    int32_t c = 0;
    size_t len = sizeof(int32_t);
    sysctlbyname("hw.ncpu", &c, &len, NULL, 0);
    return c;
}

#if defined(__APPLE__)
__attribute__((const))
bool is_vol_cap_supported(char* path, int vol_cap) {
    struct VolAttrsBuf {
        u_int32_t length;
        vol_capabilities_attr_t capabilities;
        vol_attributes_attr_t attributes;
    } __attribute__((aligned(4), packed));
    struct VolAttrsBuf vol_attrs;

    struct attrlist attr_list = {
        .bitmapcount = ATTR_BIT_MAP_COUNT,
        .volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES,
    };
    // get the file system's mount point path for the input path
    struct statfs stat_buf;
    int result = statfs(path, &stat_buf);

    if (result) {
        perror("Could not get volume stat");
        exit(1);
    }

    // get the supported capabilities and attributes
    result = getattrlist(stat_buf.f_mntonname,
                         &attr_list,
                         &vol_attrs,
                         sizeof(vol_attrs),
                         FSOPT_ATTR_CMN_EXTENDED);
    if (result) {
        perror("Could not retrieve volume attributes");
        exit(1);
    }

     #define VOL_CAPABILITIES_FORMAT     0
     #define VOL_CAPABILITIES_INTERFACES 1
     #define VOL_CAPABILITIES_RESERVED1  2
     #define VOL_CAPABILITIES_RESERVED2  3

    return vol_attrs.capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] & vol_cap;
}
#endif /* __APPLE__ */

#if defined(__APPLE__)
__attribute__((const))
#endif
bool is_clonefile_supported(char* path) {
#if defined(__APPLE__)
    return is_vol_cap_supported(path, VOL_CAP_INT_CLONE);
#else
    (void)path;
    return backend_is_available(BACKEND_FICLONE);
#endif
}

__attribute__((unused))
__attribute__((const))
bool are_acls_supported(char* path) {
#if defined(__APPLE__)
    return is_vol_cap_supported(path, VOL_CAP_INT_RENAME_SWAP);
#else
    /* rename_swap is universal on Linux */
    (void)path;
    return true;
#endif
}

int main(int argc, char* argv[]) {

    FileEntryHead* queue = new_file_entry_queue();
    FileEntryHead* raw_queue = new_file_entry_queue();
    Progress p = { 0 };
    uint16_t max_depth = UINT16_MAX;
    int user_fts_options = 0;

    DedupContext dc = {
        .progress = &p,
        .queue = queue,
        .raw_queue = raw_queue,
        .signatures = new_sig_table(65536),
        .sets = NULL,
        .set_count = 0,
        .set_capacity = 0,
        .found = 0,
        .saved = 0,
        .already_saved = 0,
        .pruned = 0,
        .skipped = 0,
        .skipped_bytes = 0,
        .failed = 0,
        .total_bytes = 0,
        .queued_count = 0,
        .next_file_sequence = 0,
        .next_visit_sequence = 0,
        .scan_done = 0,
        .prune_done = 0,
        .dry_run = false,
        .verbosity = 0,
        .force = 0,
        .replace_mode = DEDUP_CLONE,
        .output_format = OUTPUT_SI_HUMAN,
        .clone_converted = true,
        .summary_file = NULL,
        .thread_count = cpu_count(),
        .metrics_mutex = PTHREAD_MUTEX_INITIALIZER,
        .progress_mutex = PTHREAD_MUTEX_INITIALIZER,
        .queue_mutex = PTHREAD_MUTEX_INITIALIZER,
        .raw_queue_mutex = PTHREAD_MUTEX_INITIALIZER,
        .signatures_mutex = PTHREAD_MUTEX_INITIALIZER,
        .scan_done_mutex = PTHREAD_MUTEX_INITIALIZER,
        .prune_done_mutex = PTHREAD_MUTEX_INITIALIZER,
        .visit_order_mutex = PTHREAD_MUTEX_INITIALIZER,
        .visit_order_cond = PTHREAD_COND_INITIALIZER,
    };

    // Validate signature table was created successfully
    if (!dc.signatures) {
        fprintf(stderr, "failed to create signature table\n");
        return 1;
    }

    static const struct option options[] = {
        { "ignore",          required_argument, NULL, 'I' },
        { "no-progress",     no_argument,       NULL, 'P' },
        { "version",         no_argument,       NULL, 'V' },
        { "color",           optional_argument, NULL, 'c' },
        { "depth",           required_argument, NULL, 'd' },
        { "format",          required_argument, NULL, 'F' },
        { "link",            no_argument,       NULL, 'l' },
        { "dry-run",         no_argument,       NULL, 'n' },
        { "symlink",         no_argument,       NULL, 's' },
        { "threads",         required_argument, NULL, 't' },
        { "verbose",         no_argument,       NULL, 'v' },
        { "one-file-system", no_argument,       NULL, 'x' },
        // { "force",           no_argument,       NULL, 'f' },
        { "no-clone-conversion", no_argument,   NULL, 'C' },
        { "summary",         required_argument, NULL, 'S' },
        { "help",            no_argument,       NULL, '?' },
        { NULL, 0, NULL, 0 },
    };

    bool human_readable = true;

    int ch = -1, t;
    short d;
    while ((ch = getopt_long(argc, argv, "I:PVc::d:F:hlnst:vxCS:", options, NULL)) != -1) {
        switch (ch) {
            case 'I':
                // Exclusions are not implemented. Carrying on without them
                // would replace the very files the caller asked to keep.
                errx(1, "-I/--ignore is not implemented; refusing to run");
            case 'P':
                dc.progress = NULL;
                break;
            case 'V':
                fprintf(stderr, "%s\n", version);
                return 1;
            case 'c':
                fprintf(stderr, "-c is unimplemented\n");
                break;
            case 'd':
                d = atoi(optarg);
                if (d < 0) {
                    fprintf(stderr, "Depth must be a positive value: %s\n",
                            optarg);
                    usage(argv[0], &dc);
                }
                max_depth = d;
                break;
            case 'F':
                dc.output_format = parse_output_format(optarg);
                break;
            case 'h':
                human_readable = true;
                break;
            case 'l':
                dc.replace_mode = DEDUP_LINK;
                break;
            case 'n':
                dc.dry_run = true;
                break;
            case 's':
                dc.replace_mode = DEDUP_SYMLINK;
                break;
            case 't':
                t = atoi(optarg);
                if (t < 0) {
                    fprintf(stderr,
                            "Thread count must be a positive value: %s\n",
                            optarg);
                    usage(argv[0], &dc);
                }
                dc.thread_count = t;
                break;
            case 'v':
                dc.verbosity++;
                break;
            case 'x':
                user_fts_options |= FTS_XDEV;
                break;
            case 'C':
                dc.clone_converted = false;
                break;
            case 'S':
                dc.summary_file = optarg;
                break;
            case '?':
            default:
                usage(argv[0], &dc);
        }
    }
    argc -= optind;
    argv += optind;

    if (!isatty(STDOUT_FILENO)) {
        dc.progress = NULL;
    }
    
    // Initialize clone backend
    CloneBackend backend = backend_init();

    // Settle the runtime capabilities and dispatch table here, before any
    // worker thread starts, so the startup benchmarks run exactly once.
    (void)dedup_runtime_dispatch_get();

    // Print verbose runtime information if requested
    if (dc.verbosity > 0) {
        printf("clone backend: %s\n", backend_name(backend));
        dedup_runtime_caps_print_verbose();
        dedup_runtime_dispatch_print_verbose();
    }
    
    // Open summary file if requested
    if (dc.summary_file) {
        clone_summary_open(dc.summary_file);
    }

    static const char* const DEFAULT_PATHS[] = {
        ".",
        NULL,
    };

    char** paths = (argc > 0)
        ? argv
        : (char**) DEFAULT_PATHS;

    for (int i = 0; i < argc; i++) {
        if (access(argv[i], F_OK) < 0) {
            fprintf(stderr, "cannot open %s\n", argv[i]);
            perror("access(2)");
            return 1;
        }
    }

    FTS* traversal = fts_open(paths,
                              FTS_NOCHDIR | FTS_PHYSICAL | user_fts_options,
                              NULL);

    // n.b! as of Libc-1244.1.7 fts_open will only fail if it cannot
    //      allocate memory. this makes this check extremely unlikely
    //      to ever fail, but if it does fail, `traversal` will be
    //      invalid.
    // LCOV_EXCL_START
    if (!traversal) {
        perror("Could not open starting directories");
        return 1;
    }
    // LCOV_EXCL_STOP

    pthread_t pruner_thread = NULL;
    if (dc.thread_count > 0) {
        int r = pthread_create(&pruner_thread, NULL, prune_work, &dc);
        if (r) {
            warn("Could not create pruner thread: error %i", r);
            pruner_thread = NULL;
        }
    }

    // -t0 runs on this thread and needs no array (calloc(0) is
    // implementation-defined)
    pthread_t* threads = NULL;
    if (dc.thread_count > 0) {
        threads = calloc(dc.thread_count, sizeof(pthread_t));
        if (!threads) {
            err(1, "could not allocate %d threads", dc.thread_count);
        }
    }
    for (int i = 0; i < dc.thread_count; i++) {
        int r = pthread_create(&threads[i], NULL, dedup_work, &dc);
        if (r) {
            warn("Could not create threads: error %i\nRunning single threaded.",
                 r);
            dc.thread_count = i;
            break;
        }
    }

    // Single-threaded seen set (only used when thread_count == 0)
    SeenSet* st_seen_inodes = NULL;
    if (dc.thread_count == 0) {
        st_seen_inodes = new_seen_set(4096);
    }

    dev_t current_dev = -1;
    bool clonefile_supported = false;
    FTSENT* entry = NULL;
    while ((entry = fts_read(traversal)) != NULL) {
        if (entry->fts_errno) {
            char* e = strerror(entry->fts_errno);
            REPORT_LOCKED(&dc, {
                warnx("%s: error (%d): %s",
                      entry->fts_path,
                      entry->fts_errno,
                      e);
            });
            display_status(&dc, entry->fts_path);
            continue;
        }

        if (entry->fts_level > (max_depth + 1)) {
            fts_set(traversal, entry, FTS_SKIP);
            continue;
        }

        if (dc.replace_mode == DEDUP_CLONE &&
            current_dev != entry->fts_statp->st_dev) {
            current_dev = entry->fts_statp->st_dev;
            clonefile_supported = is_clonefile_supported(entry->fts_path);

            if (!clonefile_supported) {
                warnx("Skipping %s: cloning not supported", entry->fts_path);

                // if FTS_XDEV is set, we can't accidentally cross into a
                // volume that does support clonefile, so skip everything else
                if (user_fts_options & FTS_XDEV) {
                    fts_set(traversal, entry, FTS_SKIP);
                    continue;
                }
            }
        }

        if (dc.replace_mode == DEDUP_CLONE &&
            !clonefile_supported) {
            continue;
        }

        // the file cannot be a directory
        if (entry->fts_info == FTS_D ||
            entry->fts_info == FTS_DC ||
            entry->fts_info == FTS_DNR ||
            entry->fts_info == FTS_DOT ||
            entry->fts_info == FTS_DP) {
            continue;
        }

        // make sure named pipes (fifo), character special,
        // block special, symlinks, whiteout, etc.
        if (entry->fts_info != FTS_F) {
            continue;
        }

        // the file cannot be empty
        if (entry->fts_statp->st_size == 0) {
            continue;
        }

        // the file looks like a previously failed clone
        if (strnlen(entry->fts_path, PATH_MAX) > 3 &&
            entry->fts_path[0] == '.' &&
            entry->fts_path[1] == '~' &&
            entry->fts_path[2] == '.') {
            continue;
        }

        // skip .padding files (browser cache files that are often locked)
        const char* basename = strrchr(entry->fts_path, '/');
        if (basename && strcmp(basename + 1, ".padding") == 0) {
            continue;
        }

        // skip cloud storage mounts (GoogleDrive, Dropbox, iCloud, OneDrive)
        if (strstr(entry->fts_path, "/Library/CloudStorage/")) {
            continue;
        }

        // skip iOS simulator cache files (often locked)
        if (strstr(entry->fts_path, "/PhotoData/Caches/")) {
            continue;
        }

        // at this point we have a regular file
        // that only has one link
        pthread_mutex_lock(&dc.metrics_mutex);
        dc.total_bytes += entry->fts_statp->st_size;
        pthread_mutex_unlock(&dc.metrics_mutex);
        PROGRESS_LOCK(dc.progress, &dc.progress_mutex, {
            dc.progress->totalUnitCount++;
        });
        display_status(&dc, entry->fts_path);

        // Track queued count (increment for raw_queue entry)
        pthread_mutex_lock(&dc.metrics_mutex);
        dc.queued_count++;
        pthread_mutex_unlock(&dc.metrics_mutex);

        uint64_t sequence = dc.next_file_sequence++;

        if (dc.thread_count == 0) {
            // Single-threaded: prune and process inline
            file_entry_queue_append(raw_queue,
                                    entry->fts_path,
                                    entry->fts_statp->st_dev,
                                    entry->fts_statp->st_ino,
                                    entry->fts_statp->st_nlink,
#if defined(__APPLE__)
                                    entry->fts_statp->st_flags,
#else
                                    0, /* no portable uchg equivalent on Linux */
#endif
                                    entry->fts_statp->st_size,
                                    sequence,
                                    entry->fts_level);
            FileEntry* fe = file_entry_next(raw_queue);
            // Decrement queued_count since we're processing it immediately
            pthread_mutex_lock(&dc.metrics_mutex);
            dc.queued_count--;
            pthread_mutex_unlock(&dc.metrics_mutex);
            
            if (prune_entry(fe, st_seen_inodes, &dc)) {
                file_entry_free(fe);
            } else {
                // Survivor goes to work_queue (already counted in queued_count)
                file_entry_queue_append(queue,
                                        fe->path,
                                        fe->device,
                                        fe->inode,
                                        fe->nlink,
                                        fe->flags,
                                        fe->size,
                                        fe->sequence,
                                        fe->level);
                file_entry_free(fe);
                dedup_work(&dc);
            }
        } else {
            pthread_mutex_lock(&dc.raw_queue_mutex);
            file_entry_queue_append(raw_queue,
                                    entry->fts_path,
                                    entry->fts_statp->st_dev,
                                    entry->fts_statp->st_ino,
                                    entry->fts_statp->st_nlink,
#if defined(__APPLE__)
                                    entry->fts_statp->st_flags,
#else
                                    0, /* no portable uchg equivalent on Linux */
#endif
                                    entry->fts_statp->st_size,
                                    sequence,
                                    entry->fts_level);
            pthread_mutex_unlock(&dc.raw_queue_mutex);
        }
    }

    fts_close(traversal);

    // Signal FTS scan complete to pruner
    pthread_mutex_lock(&dc.scan_done_mutex);
    dc.scan_done = 1;
    pthread_mutex_unlock(&dc.scan_done_mutex);

    // Wait for pruner to drain raw_queue
    if (pruner_thread) {
        if (pthread_join(pruner_thread, NULL)) {
            fprintf(stderr, "Failed to wait for pruner thread\n");
        }
    }

    // Signal pruner complete to workers
    pthread_mutex_lock(&dc.prune_done_mutex);
    dc.prune_done = 1;
    pthread_mutex_unlock(&dc.prune_done_mutex);

    for (int i = 0; threads && i < dc.thread_count; i++) {
        // clang-analyzer thinks threads[i] can be NULL, but `pthread_t`
        // is an opaque type (to us). if `pthread_create` is successful
        // the API contract says we can pass that value to pthread_join.
        // the assertion is less intrusive than suppressing the warning
        // by checking for the _clang_analyzer macro
        assert(threads[i] != NULL);
        if (pthread_join(threads[i], NULL)) {
            fprintf(stderr, "Failed to wait for thread %i\n", i);
        }
    }
    free(threads); threads = NULL;

    // Every file has been compared, so each set is complete: choose its
    // origin and replace the rest.
    for (size_t i = 0; i < dc.set_count; i++) {
        deduplicate(dc.sets[i], &dc);
    }
    free(dc.sets); dc.sets = NULL;

    free_seen_set(st_seen_inodes);
    free_file_entry_queue(raw_queue); raw_queue = NULL;
    free_file_entry_queue(queue); queue = NULL;
    free_sig_table(dc.signatures, free_duplicate_set); dc.signatures = NULL;

    if (dc.progress) {
        clear_progress();
    }
    printf("duplicates found: %zu\n", dc.found);
    printf("entries pruned: %zu\n", dc.pruned);

    printf("bytes saved: ");
    if (human_readable) {
        printf("%s", format_bytes(dc.saved, dc.output_format));
    } else {
        printf("%zu", dc.saved);
    }
    putchar('\n');

    printf("already saved: ");
    if (human_readable) {
        printf("%s", format_bytes(dc.already_saved, dc.output_format));
    } else {
        printf("%zu", dc.already_saved);
    }
    putchar('\n');

    if (dc.skipped) {
        printf("duplicates skipped: %zu (", dc.skipped);
        if (human_readable) {
            printf("%s", format_bytes(dc.skipped_bytes, dc.output_format));
        } else {
            printf("%zu", dc.skipped_bytes);
        }
        printf(")\n");
    }

    if (dc.failed) {
        printf("replacements failed: %zu\n", dc.failed);
    }

    // Clear status line
    if (isatty(STDOUT_FILENO)) {
        fprintf(stderr, "\r\033[K\n");
    }
    
    // Close summary file if it was opened
    if (dc.summary_file) {
        clone_summary_close();
    }

    // Each failure was reported when it happened; the status tells scripts
    // that some duplicates were left in place.
    return dc.failed ? 1 : 0;
}
