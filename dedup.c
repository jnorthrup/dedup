// Copyright © 2023-2026 TTKB, LLC.
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

#include <sys/stat.h>
#include <sys/ioctl.h>
#if defined(__APPLE__)
#include <sys/mount.h>
#include <sys/attr.h>
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <getopt.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "clone.h"
#include "backend.h"
#if defined(__APPLE__)
#include "map.h"
#endif
#include "progress.h"
#include "queue.h"
#include "output_format.h"
#include "runtime_dispatch.h"
#include "runtime_caps.h"
#include "seen_set.h"
#include "signature.h"
#include "sig_table.h"
#include "utils.h"

#if !defined(__BLOCKS__)
// Without the Blocks extension (clang on Linux), a __block variable is an
// ordinary local: the non-libdispatch lock macros run their code inline.
#define __block
#endif

#if !defined(__APPLE__)
// BSD file flags from st_flags. FileEntry.flags is always 0 elsewhere; on
// Linux an immutable file fails the access(W_OK) check instead.
#ifndef UF_IMMUTABLE
#define UF_IMMUTABLE 0
#endif
#ifndef SF_IMMUTABLE
#define SF_IMMUTABLE 0
#endif
#ifndef UF_COMPRESSED
#define UF_COMPRESSED 0
#endif
#endif

#ifdef USE_LIBDISPATCH

#include <dispatch/dispatch.h>

#define PROGRESS_LOCK(p, m, block) \
    do { \
        if ((p)) { \
            dispatch_sync((m), ^{ block }); \
        } \
    } while (0)

#define SYNC(m, block) \
	dispatch_sync(m, ^{ block })

#else

#define PROGRESS_LOCK(p, m, block) \
    do { \
        if ((p)) { \
            pthread_mutex_lock(&(m)); \
            block; \
            pthread_mutex_unlock(&(m)); \
        } \
    } while (0)

#define SYNC(m, block) \
    do { \
        pthread_mutex_lock(&(m)); \
        block; \
        pthread_mutex_unlock(&(m)); \
    } while (0)

#endif

// Output must remain visible even when progress is disabled or redirected.
#define OUTPUT_LOCK(ctx, block) \
    SYNC((ctx)->progress_mutex, { \
        if ((ctx)->progress) clear_progress(); \
        block; \
    })

// Forward declaration
typedef struct DedupContext DedupContext;

// Clone record streaming functions
static FILE* clone_summary_stream = NULL;
static pthread_mutex_t clone_summary_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t clone_summary_count = 0;

static int clone_summary_open(const char* filepath) {
    pthread_mutex_lock(&clone_summary_mutex);
    if (!clone_summary_stream) {
        int fd = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            clone_summary_stream = fdopen(fd, "w");
            if (!clone_summary_stream) {
                int error = errno;
                close(fd);
                errno = error;
            }
        }
        if (clone_summary_stream) {
            fprintf(clone_summary_stream, "DEDUP CLONING SUMMARY\n");
            fprintf(clone_summary_stream, "=====================\n");
            fprintf(clone_summary_stream, "\n");
        }
    }
    pthread_mutex_unlock(&clone_summary_mutex);
    return clone_summary_stream ? 0 : -1;
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

static int clone_summary_close() {
    int result = 0;
    pthread_mutex_lock(&clone_summary_mutex);
    if (clone_summary_stream) {
        // Write count at the end
        fprintf(clone_summary_stream, "\nTotal cloning operations: %zu\n", clone_summary_count);
        if (ferror(clone_summary_stream)) result = -1;
        if (fclose(clone_summary_stream) != 0) result = -1;
        clone_summary_stream = NULL;
        clone_summary_count = 0;
    }
    pthread_mutex_unlock(&clone_summary_mutex);
    return result;
}

typedef enum ReplaceMode {
    DEDUP_CLONE    = 0,
    DEDUP_LINK     = 1,
    DEDUP_SYMLINK  = 2,
} ReplaceMode;

typedef struct DedupContext {
    Progress* progress;
    FileEntryHead* queue;
    FileEntryHead* raw_queue;
    SigTable* signatures;
    size_t found;
    size_t saved;
    size_t already_saved;
    size_t pruned;
    size_t errors;
    size_t skipped;        // Duplicates left in place (hard-linked, unwritable, ...)
    size_t skipped_bytes;
    size_t failed;         // Duplicates that could not be replaced
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
    bool preserve_parent_mtime;
    ReplaceMode replace_mode;
    OutputFormat output_format;
    bool clone_converted;        // Whether to convert clones (true by default)
    char* summary_file;          // File to write detailed summary to (NULL by default)
    pthread_mutex_t metrics_mutex;
#ifdef USE_LIBDISPATCH
    dispatch_queue_t progress_mutex;
    dispatch_queue_t queue_mutex;
#else
    pthread_mutex_t progress_mutex;
    pthread_mutex_t queue_mutex;
#endif
    pthread_mutex_t raw_queue_mutex;
    pthread_mutex_t signatures_mutex;
    pthread_mutex_t scan_done_mutex;
    pthread_mutex_t prune_done_mutex;
    pthread_mutex_t visit_order_mutex;
    pthread_cond_t visit_order_cond;
} DedupContext;

static void report_error(DedupContext* ctx, const char* path,
                         const char* operation, int error) {
    OUTPUT_LOCK(ctx, {
        fprintf(stderr, "%s: %s: %s\n", path, operation, strerror(error));
    });
    pthread_mutex_lock(&ctx->metrics_mutex);
    ctx->errors++;
    pthread_mutex_unlock(&ctx->metrics_mutex);
}

static const char* replacement_name(ReplaceMode mode) {
    switch (mode) {
    case DEDUP_LINK:    return "a hard link";
    case DEDUP_SYMLINK: return "a symbolic link";
    case DEDUP_CLONE:   break;
    }
    return "a clone";
}

// A duplicate that is left in place. Its bytes are still stored twice, so it
// is counted as skipped, never as space already saved.
static void skip_duplicate(DedupContext* ctx, const FileEntry* fe, const char* reason) {
    if (ctx->verbosity) {
        OUTPUT_LOCK(ctx, {
            printf("skipping %s, %s\n", fe->path, reason);
        });
    }
    pthread_mutex_lock(&ctx->metrics_mutex);
    ctx->skipped++;
    ctx->skipped_bytes += fe->size;
    pthread_mutex_unlock(&ctx->metrics_mutex);
}

// A replacement that failed. The replace_* functions print the system error;
// this names the file left alone and fails the run's exit status.
static void fail_duplicate(DedupContext* ctx, const FileEntry* fe, const char* origin) {
    OUTPUT_LOCK(ctx, {
        warnx("could not replace %s with %s of %s",
              fe->path, replacement_name(ctx->replace_mode), origin);
    });
    pthread_mutex_lock(&ctx->metrics_mutex);
    ctx->failed++;
    ctx->errors++;
    pthread_mutex_unlock(&ctx->metrics_mutex);
}

// Whether clone mode keeps the duplicate's inode (see DEDUP_IN_PLACE).
static bool dedupes_in_place(const DedupContext* ctx) {
#if defined(DEDUP_IN_PLACE)
    return ctx->replace_mode == DEDUP_CLONE;
#else
    (void)ctx;
    return false;
#endif
}

#if defined(DEDUP_IN_PLACE)
// Shares the origin's blocks with the duplicate in place and accounts for the
// outcome. Only blocks seen to be shared afterwards count as saved.
static void dedupe_duplicate_in_place(DedupContext* ctx, const FileEntry* fe, const char* origin) {
    DedupeResult result = dedupe_in_place(origin, fe->path, fe->size);
    if (result == DEDUPE_DIFFERS) {
        skip_duplicate(ctx, fe, "changed since it was compared");
        return;
    }

    if (result == DEDUPE_FAILED) {
        int error = errno;
        OUTPUT_LOCK(ctx, {
            errno = error;
            warn("could not deduplicate %s with %s", fe->path, origin);
        });
        pthread_mutex_lock(&ctx->metrics_mutex);
        ctx->failed++;
        ctx->errors++;
        pthread_mutex_unlock(&ctx->metrics_mutex);
        return;
    }

    if (share_state(origin, fe->path, fe->size) != SHARE_SHARED) {
        OUTPUT_LOCK(ctx, {
            warnx("%s was deduplicated, but does not share blocks with %s",
                  fe->path, origin);
        });
        pthread_mutex_lock(&ctx->metrics_mutex);
        ctx->failed++;
        ctx->errors++;
        pthread_mutex_unlock(&ctx->metrics_mutex);
        return;
    }

    if (ctx->verbosity) {
        OUTPUT_LOCK(ctx, {
            printf("deduplicated %s\n", fe->path);
        });
    }

    pthread_mutex_lock(&ctx->metrics_mutex);
    ctx->saved += fe->size;
    ctx->found++;
    pthread_mutex_unlock(&ctx->metrics_mutex);

    if (ctx->summary_file) {
        clone_summary_write(origin, fe->path, fe->size);
    }
}
#endif // DEDUP_IN_PLACE

static int get_terminal_width(void) {
    struct winsize w;
    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0) {
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
    if (!ctx->progress || !isatty(STDERR_FILENO)) {
        return;
    }
    static pthread_mutex_t status_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&status_mutex);
    
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
    
    __block size_t completed = 0;
    __block size_t total = 0;
    if (ctx->progress) {
        PROGRESS_LOCK(ctx->progress, ctx->progress_mutex, {
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
    if (path_max >= (int)sizeof(truncated_path)) {
        path_max = sizeof(truncated_path) - 1;
    }
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
    pthread_mutex_unlock(&status_mutex);
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

void visit_entry(FileEntry* fe, Progress* p, DedupContext* ctx) {
    if (!fe || !ctx) {
        return;
    }

    FileSignature* sig = compute_signature(fe->path, fe->device, fe->size);
    visit_order_begin(ctx, fe->sequence);
    if (!sig) {
        report_error(ctx, fe->path, "cannot read file signature", errno ? errno : EIO);
        visit_order_end(ctx);
        return;
    }

    // Insert into signature table and check for duplicates
    if (!ctx->signatures) {
        OUTPUT_LOCK(ctx, {
            fprintf(stderr, "signature table not initialized for %s\n", fe->path);
        });
        free_signature(sig);
        visit_order_end(ctx);
        return;
    }

    pthread_mutex_lock(&ctx->signatures_mutex);
    size_t table_size_before = sig_table_size(ctx->signatures);
    SigTableEntry* existing = sig_table_insert(ctx->signatures, sig, fe->path, get_clone_id(fe->path), NULL);
    size_t table_size_after = sig_table_size(ctx->signatures);
    pthread_mutex_unlock(&ctx->signatures_mutex);

    // Safety check: table size should only increase by 0 or 1
    if (table_size_after > table_size_before + 1) {
        OUTPUT_LOCK(ctx, {
            fprintf(stderr, "warning: signature table size increased by %zu (expected 0 or 1)\n",
                    table_size_after - table_size_before);
        });
    }

    bool table_took_ownership = (table_size_after > table_size_before);

    if (existing) {
        // Found a duplicate
        display_status(ctx, fe->path);

        // Check if already deduplicated
#if !defined(DEDUP_IN_PLACE)
        uint64_t current_clone_id = get_clone_id(fe->path);
#endif
        bool same_inode = fe->inode == get_inode(existing->path);
        bool shared_storage = false;
        if (ctx->replace_mode == DEDUP_CLONE) {
#if defined(DEDUP_IN_PLACE)
            ShareState state = share_state(existing->path, fe->path, fe->size);
            if (!same_inode && (state == SHARE_INLINE || state == SHARE_UNKNOWN)) {
                skip_duplicate(ctx, fe, state == SHARE_INLINE
                                        ? "data stored inline, cannot be shared"
                                        : "could not read its extent map");
                free_signature(sig);
                visit_order_end(ctx);
                return;
            }
            shared_storage = (state == SHARE_SHARED);
#else
            // A clone id of 0 means it could not be read (or the platform
            // has none), which proves nothing.
            shared_storage = current_clone_id != 0 &&
                             current_clone_id == existing->clone_id;
#endif
        }
        if (shared_storage || same_inode) {
            pthread_mutex_lock(&ctx->metrics_mutex);
            // Repeating a single-link input path does not save storage.
            if (!same_inode || fe->nlink > 1) ctx->already_saved += fe->size;
            pthread_mutex_unlock(&ctx->metrics_mutex);
            free_signature(sig);
            visit_order_end(ctx);
            return;
        }

        // Skip if hardlinked and not forcing: replacing one name would split
        // it from the others. Deduplicating in place keeps every name.
        if (!ctx->force && fe->nlink > 1 && !dedupes_in_place(ctx)) {
            skip_duplicate(ctx, fe, "hardlinked");
            free_signature(sig);
            visit_order_end(ctx);
            return;
        }

        // Skip if immutable or read-only
        if (fe->flags & UF_IMMUTABLE || fe->flags & SF_IMMUTABLE ||
            (access(fe->path, W_OK) != 0)) {
            skip_duplicate(ctx, fe, "immutable or not writable");
            free_signature(sig);
            visit_order_end(ctx);
            return;
        }

        if (ctx->replace_mode == DEDUP_CLONE && !ctx->clone_converted) {
            skip_duplicate(ctx, fe, "clone conversion disabled");
            free_signature(sig);
            visit_order_end(ctx);
            return;
        }

        // Perform deduplication
        if (ctx->dry_run) {
            if (ctx->verbosity) {
                OUTPUT_LOCK(ctx, {
                    printf("would deduplicate %s to %s\n", fe->path, existing->path);
                });
            }
            pthread_mutex_lock(&ctx->metrics_mutex);
            ctx->saved += fe->size;
            ctx->found++;
            pthread_mutex_unlock(&ctx->metrics_mutex);
        } else if (dedupes_in_place(ctx)) {
#if defined(DEDUP_IN_PLACE)
            dedupe_duplicate_in_place(ctx, fe, existing->path);
#endif
        } else {
            int result = 0;
            switch (ctx->replace_mode) {
            case DEDUP_CLONE:
                result = replace_with_clone(existing->path, fe->path,
                                           ctx->preserve_parent_mtime);
                break;
            case DEDUP_LINK:
                result = replace_with_link(existing->path, fe->path);
                break;
            case DEDUP_SYMLINK:
                result = replace_with_symlink(existing->path, fe->path);
                break;
            }

            if (result) {
                // The replace_* functions print the system error; name the
                // file that was left alone.
                fail_duplicate(ctx, fe, existing->path);
                free_signature(sig);
                visit_order_end(ctx);
                return;
            } else {
                if (ctx->verbosity) {
                    OUTPUT_LOCK(ctx, {
                        printf("deduplicated %s\n", fe->path);
                    });
                }

                // Verify clone worked if using clone mode
                if (ctx->replace_mode == DEDUP_CLONE) {
#if defined(__APPLE__)
                    uint64_t new_clone_id = get_clone_id(fe->path);
                    if (new_clone_id != existing->clone_id) {
                        if (private_size(fe->path) != 0) {
                            result = -1; // Mark as failed
                        }
                        // Else: clone_id mismatch but no private data = success
                    }
#endif
                }

                if (result == 0) {
                    pthread_mutex_lock(&ctx->metrics_mutex);
                    ctx->saved += fe->size;
                    ctx->found++;
                    pthread_mutex_unlock(&ctx->metrics_mutex);
                    
                    // Write clone operation to summary file (streamed)
                    if (ctx->summary_file) {
                        clone_summary_write(existing->path, fe->path, fe->size);
                    }
                } else {
                    report_error(ctx, fe->path, "cannot verify cloned data", EIO);
                    pthread_mutex_lock(&ctx->metrics_mutex);
                    ctx->failed++;
                    pthread_mutex_unlock(&ctx->metrics_mutex);
                }
            }
        }

        free_signature(sig);
    } else {
        // First instance of this signature
        if (table_took_ownership) {
            display_status(ctx, fe->path);
        } else {
            // Table failed to take ownership (allocation failure)
            report_error(ctx, fe->path, "cannot store signature", ENOMEM);
            free_signature(sig);
        }
    }

    visit_order_end(ctx);
}

// Returns true if the entry was pruned (caller should free it), false if it survived.
static bool prune_entry(FileEntry* fe, SeenSet* seen_inodes, SeenSet* seen_clones, DedupContext* c) {
    bool pruned = false;

    if (fe->nlink > 1) {
        if (seen_set_insert(seen_inodes, (uint64_t)fe->device, (uint64_t)fe->inode)) {
            pruned = true;
        }
    }

    if (!pruned && c->replace_mode == DEDUP_CLONE) {
#if defined(__APPLE__)
        uint64_t clone_id = get_clone_id(fe->path);
        if (clone_id != 0) {
            if (seen_set_insert(seen_clones, (uint64_t)fe->device, clone_id)) {
                pruned = true;
            }
        }
#endif
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
    c->queued_count--;
    pthread_mutex_unlock(&c->metrics_mutex);
    PROGRESS_LOCK(c->progress, c->progress_mutex, {
        c->progress->completedUnitCount++;
    });
    display_status(c, fe->path);
    return true;
}

void* prune_work(void* ctx) {
    DedupContext* c = ctx;
    SeenSet* seen_inodes = new_seen_set(4096);
    SeenSet* seen_clones = new_seen_set(4096);

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

        if (prune_entry(fe, seen_inodes, seen_clones, c)) {
            file_entry_free(fe);
            continue;
        }

        // Survivor: pass to work queue
        // queued_count stays the same (file moves between queues)
        // Show pruner progress (survivor passes through) before the hand-off:
        // once queued, a worker may take and free the entry.
        display_status(c, fe->path);
        SYNC(c->queue_mutex, {
            file_entry_queue_push(c->queue, fe);
        });
    }

    free_seen_set(seen_inodes);
    free_seen_set(seen_clones);
    return NULL;
}

void* dedup_work(void* ctx) {
    DedupContext* c = ctx;
    for (;;) {
        __block FileEntry* fe;
        SYNC(c->queue_mutex, {
            fe = file_entry_next(c->queue);
        });

        if (!fe) {
            pthread_mutex_lock(&c->prune_done_mutex);
            uint8_t done = c->prune_done;
            pthread_mutex_unlock(&c->prune_done_mutex);
            if (done) {
                // Publishing prune_done follows the final queue insertion.
                // Recheck in case that insertion raced with our empty read.
                SYNC(c->queue_mutex, {
                    fe = file_entry_next(c->queue);
                });
                if (!fe) break;
            }
            if (!fe) {
                usleep(100);
                continue;
            }
        }

        // Decrement queued_count for work_queue pop
        pthread_mutex_lock(&c->metrics_mutex);
        c->queued_count--;
        pthread_mutex_unlock(&c->metrics_mutex);

        // Visit the entry (worker processes the file)
        visit_entry(fe, c->progress, c);

        PROGRESS_LOCK(c->progress, c->progress_mutex, {
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

#if defined(__APPLE__)
// The two-phase replacement over file metadata sets; it needs the Apple-only
// file metadata and clone-size helpers.
size_t deduplicate(AList* metadata_set, DedupContext* ctx) {
    FileMetadata* origin = NULL;
    char* reason = NULL;

    // if there is a file with more than one hard link, use that as the
    // source candidate (optimally a hardlink with the most links)
    for (size_t i = 0; i < alist_size(metadata_set); i++) {
        FileMetadata* fm = alist_get(metadata_set, i);
        if (fm->nlink > 1 && (!origin || origin->nlink < fm->nlink)) {
            origin = fm;
            reason = "most hardlinks";
        }
    }

    // otherwise, use the file with the most clones.
    if (!origin) {
        rb_tree_t* clone_counts = new_clone_id_counts();
        for (size_t i = 0; i < alist_size(metadata_set); i++) {
            FileMetadata* fm = alist_get(metadata_set, i);
            clone_id_tree_increment(clone_counts, fm);
        }

        if (rb_tree_count(clone_counts) == 1) {
            origin = alist_get(metadata_set, 0);
            ctx->already_saved += origin->size * (alist_size(metadata_set) - 1);
            if (ctx->verbosity) {
                printf("%s is already cloned to\n",
                       origin->path);
                for (size_t i = 1; i < alist_size(metadata_set); i++) {
                    FileMetadata* fm = alist_get(metadata_set, i);
                    printf("\t%s\n", fm->path);
                }
            }
            free_clone_id_counts(clone_counts);
            clone_counts = NULL;
            return 0;
        }

        // none of the files are cloned (they all of a clone count of 1)
        if (rb_tree_count(clone_counts) == alist_size(metadata_set)) {
            // find the first file that is not compressed
            //
            // n.b.! transparently compressed files will have the UF_COMPRESSED
            //       flag set, compressed data in the resource fork, and an
            //       xattr named `com.apple.decmpfs`. since the data for the
            //       file is actually stored in metadata, these files cannot
            //       share data blocks, so they are worthless for using as
            //       clone origins.
            for (size_t i = 0; i < alist_size(metadata_set); i++) {
                FileMetadata* fm = alist_get(metadata_set, i);
                if (fm->flags & UF_COMPRESSED) {
                    if (ctx->verbosity > 1) {
                        printf("found a compressed file: %s\n", fm->path);
                    }
                    continue;
                }
                origin = fm;
                reason = "first seen";
                break;
            }

            if (!origin) {
                if (ctx->verbosity) {
                    printf("All files in this set use HFS compression. Remove HFS compression from at least one to "
                           "replace with clones:\n");
                    for (size_t i = 0; i < alist_size(metadata_set); i++) {
                        FileMetadata* fm = alist_get(metadata_set, i);
                        printf("\t%s\n", fm->path);
                    }
                }
                free_clone_id_counts(clone_counts);
                return 0;
            }
        } else {
            origin = clone_id_tree_max(clone_counts);
            reason = "most clones";
        }
        free_clone_id_counts(clone_counts);
        clone_counts = NULL;
    }

    printf("using %s as the clone origin (%s)\n",
           origin->path,
           reason);

    uint64_t origin_clone_id = get_clone_id(origin->path);

    for (size_t i = 0; i < alist_size(metadata_set); i++) {
        FileMetadata* fm = alist_get(metadata_set, i);

        if (fm == origin) {
            continue;
        }

        if (!ctx->force && fm->nlink > 1) {
            printf("\tskipping %s, hardlinked\n",
                   fm->path);
            ctx->already_saved += fm->size;
            continue;
        }

        if ((ctx->replace_mode == DEDUP_CLONE && fm->clone_id == origin->clone_id) ||
            (ctx->replace_mode == DEDUP_LINK && fm->inode == origin->inode)) {
            printf("\tskipping %s, already cloned\n",
                   fm->path);
            ctx->already_saved += fm->size;
            continue;
        }

        if (fm->flags & UF_IMMUTABLE ||
            fm->flags & SF_IMMUTABLE) {
            printf("\tskipping %s, immutable\n",
                   fm->path);
            continue;
        }

        if (ctx->dry_run) {
            printf("\tcloning to %s\n",
                   fm->path);
            ctx->saved += fm->size;
            continue;
        }

        int result = 0;
        switch (ctx->replace_mode) {
        case DEDUP_CLONE:
            result = replace_with_clone(origin->path,
                                        fm->path,
                                        ctx->preserve_parent_mtime);
            break;
        case DEDUP_LINK:
            result = replace_with_link(origin->path,
                                       fm->path);
            break;
        case DEDUP_SYMLINK:
            result = replace_with_symlink(origin->path,
                                          fm->path);
            break;
        }

        if (result) {
            perror("clone failed");
            fprintf(stderr,
                    "\tcould not clone %s\n",
                    fm->path);
            continue;
        }

        printf("\tcloned to %s\n",
               fm->path);

        if (ctx->replace_mode == DEDUP_CLONE && origin_clone_id != get_clone_id(fm->path)) {
            if (private_size(fm->path) == 0) {
                fprintf(stderr,
                        "\t\tclonefile(2) did not clone %s as expected, but it is a clone\n",
                        fm->path);
                ctx->already_saved += fm->size;
                continue;
            } else {
                fprintf(stderr,
                        "\t\tclonefile(2) did not clone %s as expected, did not report an error\n",
                        fm->path);
                continue;
            }
        }

        ctx->saved += fm->size;
    }

    return 0;
}

#endif // __APPLE__

__attribute__((noreturn))
static void usage(char* pgm, DedupContext* ctx, int status) {
    fprintf(stderr,
            "%s\nusage: %s [-t n] [-PVhlmnsvxC] [-d n] [-F format] [-S file] [file ...]\n\n"
                "Options:\n"
                // "  --ignore, -I pattern     Exclude a pattern from being used as a clone\n"
                // "                           source or being replaced by a clone. This option\n"
                // "                           can be specified multiple times.\n"
                "  --dry-run, -n            Don't replace file content; just print what \n"
                "                           would have happened.\n"
                "  --depth, -d depth        Don't descend further than the specified depth.\n"
                "  --format, -F format      Output format for byte sizes. Use '-F help' to\n"
                "                           list the formats.\n"
                "  --one-file-system, -x    Don't evaluate directories on a different device\n"
                "                           than the starting paths.\n"
                "  --link, -l               Use hardlinks instead of clones.\n"
                "  --symlink, -s            Use symlinks instead of clones.\n"
                // "  --color, -c              Enabled colored output.\n"
                "  --no-progress, -P        Do not display a progress bar.\n"
                "  --no-clone-conversion    Do not convert clones (skip clone mode)\n"
                "  --summary, -S file       Write cloning summary to a new file.\n"
                "  --threads, -t n          The number of threads to use for file building\n"
                "                           lookup tables and replacing clones. Default: %d\n"
                "  --parent-mtime, -m       Preserve the mtime of any parent directory\n"
                "                           modified with a clone.\n"
                "  --verbose, -v            Increase verbosity. May be used multiple times.\n"
                "  --version, -V            Print the version and exit\n"
                // "  --force, -f              Don't preserve existing hardlinks.\n"
                "  -h                       Human readable output.\n"
                "  --help                   Show this help.\n",
            version,
            pgm,
            ctx->thread_count);

    list_available_formats(stderr);
    exit(status);
}

static unsigned long parse_count(const char* value, unsigned long maximum,
                                const char* label) {
    char* end = NULL;
    errno = 0;
    unsigned long result = strtoul(value, &end, 10);
    if (!value[0] || strspn(value, "0123456789") != strlen(value) ||
        errno == ERANGE || !end || *end || result > maximum) {
        errx(EXIT_FAILURE, "%s must be an integer from 0 to %lu: %s",
             label, maximum, value);
    }
    return result;
}

__attribute__((const))
int32_t cpu_count() {
#if defined(__APPLE__) || defined(__FreeBSD__)
    int32_t c = 0;
    size_t len = sizeof(int32_t);
    sysctlbyname("hw.ncpu", &c, &len, NULL, 0);
#else
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    int32_t c = online > 0 ? (int32_t)(online > INT32_MAX ? INT32_MAX : online) : 1;
#endif
    return c < 1 ? 1 : (c > UINT8_MAX ? UINT8_MAX : c);
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
    return backend_is_available(BACKEND_FIDEDUPERANGE);
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

static int traversal_order(const FTSENT** a, const FTSENT** b) {
    // Preserve existing hard-link groups by considering them as sources
    // before replaceable siblings. Break ties consistently across runs.
    nlink_t a_links = ((*a)->fts_info == FTS_F) ? (*a)->fts_statp->st_nlink : 0;
    nlink_t b_links = ((*b)->fts_info == FTS_F) ? (*b)->fts_statp->st_nlink : 0;
    if (a_links != b_links) return a_links > b_links ? -1 : 1;
    return strcmp((*a)->fts_name, (*b)->fts_name);
}

static char* canonical_input_path(const char* path) {
    char* resolved = realpath(path, NULL);
#if defined(__APPLE__)
    // An ACL can deny attribute reads while allowing file contents to be read.
    // F_GETPATH still resolves the actual name, including its case, without
    // requiring those attributes. Do not follow a raced-in symlink or block
    // if the entry changed into a FIFO after traversal.
    if (!resolved && (errno == EACCES || errno == EPERM)) {
        int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
        if (fd < 0) return NULL;
        char buffer[PATH_MAX];
        int result = fcntl(fd, F_GETPATH, buffer);
        int error = errno;
        close(fd);
        if (result < 0) {
            errno = error;
            return NULL;
        }
        resolved = strdup(buffer);
    }
#endif
    return resolved;
}

int main(int argc, char* argv[]) {

    FileEntryHead* queue = new_file_entry_queue();
    FileEntryHead* raw_queue = new_file_entry_queue();
    Progress p = { 0 };
    uint16_t max_depth = UINT16_MAX;
    int user_fts_options = 0;

    __block DedupContext dc = {
        .progress = &p,
        .queue = queue,
        .raw_queue = raw_queue,
        .signatures = new_sig_table(65536),
        .found = 0,
        .saved = 0,
        .already_saved = 0,
        .pruned = 0,
        .total_bytes = 0,
        .queued_count = 0,
        .next_file_sequence = 0,
        .next_visit_sequence = 0,
        .scan_done = 0,
        .prune_done = 0,
        .dry_run = false,
        .verbosity = 0,
        .force = false,
        .preserve_parent_mtime = false,
        .replace_mode = DEDUP_CLONE,
        .output_format = OUTPUT_SI_HUMAN,
        .clone_converted = true,
        .summary_file = NULL,
        .thread_count = cpu_count(),
        .metrics_mutex = PTHREAD_MUTEX_INITIALIZER,
#ifdef USE_LIBDISPATCH
        .progress_mutex = dispatch_queue_create("progress", DISPATCH_QUEUE_SERIAL),
        .queue_mutex = dispatch_queue_create("queue", DISPATCH_QUEUE_SERIAL),
#else
        .progress_mutex = PTHREAD_MUTEX_INITIALIZER,
        .queue_mutex = PTHREAD_MUTEX_INITIALIZER,
#endif
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
        { "parent-mtime",    no_argument,       NULL, 'm' },
        { "symlink",         no_argument,       NULL, 's' },
        { "threads",         required_argument, NULL, 't' },
        { "verbose",         no_argument,       NULL, 'v' },
        { "one-file-system", no_argument,       NULL, 'x' },
        // { "force",           no_argument,       NULL, 'f' },
        { "no-clone-conversion", no_argument,   NULL, 'C' },
        { "summary",         required_argument, NULL, 'S' },
        { "help",            no_argument,       NULL, 256 },
        { NULL, 0, NULL, 0 },
    };

    bool human_readable = true;

    int ch = -1;
    while ((ch = getopt_long(argc, argv, "I:PVc::d:F:fhlmnst:vxCS:?", options, NULL)) != -1) {
        switch (ch) {
            case 'I':
                errx(EXIT_FAILURE, "--ignore (-I) is not implemented; no files were processed");
            case 'P':
                dc.progress = NULL;
                break;
            case 'V':
                fprintf(stderr, "%s\n", version);
                return 0;
            case 'c':
                errx(EXIT_FAILURE, "--color (-c) is not implemented; no files were processed");
            case 'd':
                max_depth = parse_count(optarg, UINT16_MAX, "Depth");
                break;
            case 'F':
                if (strcmp(optarg, "help") == 0 || strcmp(optarg, "formats") == 0 ||
                    strcmp(optarg, "list") == 0 || strcmp(optarg, "?") == 0) {
                    list_available_formats(stdout);
                    exit(EXIT_SUCCESS);
                }
                dc.output_format = parse_output_format(optarg);
                break;
            case 'h':
                human_readable = true;
                break;
            case 'l':
                dc.replace_mode = DEDUP_LINK;
                break;
            case 'm':
                dc.preserve_parent_mtime = true;
                break;
            case 'n':
                dc.dry_run = true;
                break;
            case 's':
                dc.replace_mode = DEDUP_SYMLINK;
                break;
            case 't':
                dc.thread_count = parse_count(optarg, UINT8_MAX, "Thread count");
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
            case 256:
                usage(argv[0], &dc, EXIT_SUCCESS);
            case '?':
                if (optind > 0 && strcmp(argv[optind - 1], "-?") == 0) {
                    usage(argv[0], &dc, EXIT_SUCCESS);
                }
                usage(argv[0], &dc, EXIT_FAILURE);
            default:
                usage(argv[0], &dc, EXIT_FAILURE);
        }
    }
    argc -= optind;
    argv += optind;

    if (!isatty(STDERR_FILENO)) {
        dc.progress = NULL;
    }
    
    // Initialize clone backend
    CloneBackend backend = backend_init();

    // Print verbose runtime information if requested
    if (dc.verbosity > 0) {
        printf("clone backend: %s\n", backend_name(backend));
        dedup_runtime_caps_print_verbose();
        dedup_runtime_dispatch_print_verbose();
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
                              traversal_order);

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

    SeenPaths* visited_paths = new_seen_paths(4096);
    if (!visited_paths) {
        fts_close(traversal);
        errx(EXIT_FAILURE, "cannot allocate visited path table");
    }

    struct stat summary_stat = {0};
    if (dc.summary_file) {
        if (clone_summary_open(dc.summary_file) != 0 ||
            fstat(fileno(clone_summary_stream), &summary_stat) != 0) {
            warn("cannot create summary %s", dc.summary_file);
            clone_summary_close();
            fts_close(traversal);
            free_seen_paths(visited_paths);
            return 1;
        }
    }

    const int requested_threads = dc.thread_count;
    pthread_t* threads = requested_threads ? calloc(requested_threads, sizeof(pthread_t)) : NULL;
    int started_threads = 0;
    while (threads && started_threads < requested_threads) {
        int r = pthread_create(&threads[started_threads], NULL, dedup_work, &dc);
        if (r) {
            warnx("Could not create worker: %s; using %d workers", strerror(r), started_threads);
            break;
        }
        started_threads++;
    }
    dc.thread_count = started_threads;

    // pthread_t is opaque (a pointer on Apple platforms, an integer on glibc),
    // so record whether the pruner started instead of testing the handle.
    pthread_t pruner_thread;
    bool pruner_started = false;
    if (dc.thread_count > 0) {
        int r = pthread_create(&pruner_thread, NULL, prune_work, &dc);
        if (r) {
            warnx("Could not create pruner: %s; running serially", strerror(r));
            pthread_mutex_lock(&dc.prune_done_mutex);
            dc.prune_done = 1;
            pthread_mutex_unlock(&dc.prune_done_mutex);
            for (int i = 0; i < started_threads; i++) pthread_join(threads[i], NULL);
            started_threads = 0;
            dc.thread_count = 0;
            dc.prune_done = 0;
        } else {
            pruner_started = true;
        }
    }

    // Single-threaded seen sets (only used when thread_count == 0)
    SeenSet* st_seen_inodes = NULL;
    SeenSet* st_seen_clones = NULL;
    if (dc.thread_count == 0) {
        st_seen_inodes = new_seen_set(4096);
        st_seen_clones = new_seen_set(4096);
    }

    dev_t current_dev = -1;
    bool clonefile_supported = false;
    FTSENT* entry = NULL;
    while ((entry = fts_read(traversal)) != NULL) {
        if (entry->fts_errno) {
            report_error(&dc, entry->fts_path, "cannot traverse", entry->fts_errno);
            display_status(&dc, entry->fts_path);
            continue;
        }

        if (entry->fts_level > (max_depth + 1)) {
            fts_set(traversal, entry, FTS_SKIP);
            continue;
        }

#if defined(DEDUP_IN_PLACE)
        // FIDEDUPERANGE can only be asked about a regular file, so decide at
        // the first candidate on each filesystem. A file that cannot answer
        // (unreadable, say) goes through, and the next one is asked.
        if (dc.replace_mode == DEDUP_CLONE &&
            current_dev != entry->fts_statp->st_dev &&
            (entry->fts_info == FTS_F || entry->fts_info == FTS_NSOK)) {
            int supported = dedupe_supported(entry->fts_path);
            if (supported >= 0) {
                current_dev = entry->fts_statp->st_dev;
                clonefile_supported = (supported == 1);
                if (!clonefile_supported) {
                    OUTPUT_LOCK(&dc, {
                        warnx("Skipping %s and the rest of its filesystem: cloning not supported",
                              entry->fts_path);
                    });
                    if (user_fts_options & FTS_XDEV) {
                        fts_set(traversal, entry, FTS_SKIP);
                        continue;
                    }
                }
            } else {
                current_dev = (dev_t)-1;
                clonefile_supported = true;
            }
        }
#else
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
#endif

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

        // Never deduplicate an output stream that this process is still writing.
        if (dc.summary_file && entry->fts_statp->st_dev == summary_stat.st_dev &&
            entry->fts_statp->st_ino == summary_stat.st_ino) {
            continue;
        }

        // the file cannot be empty
        if (entry->fts_statp->st_size == 0) {
            continue;
        }

        // the file looks like a previously failed clone
        if (strncmp(entry->fts_name, ".~.", 3) == 0) {
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

        // An overlapping root can revisit the same directory entry, even after
        // replacement changed its inode. Canonical paths avoid counting that
        // visit as shared storage while keeping distinct hard-link names.
        char* canonical_path = canonical_input_path(entry->fts_path);
        if (!canonical_path) {
            report_error(&dc, entry->fts_path, "cannot resolve input path", errno);
            continue;
        }
        int seen = seen_paths_insert(visited_paths, canonical_path);
        free(canonical_path);
        if (seen != 0) {
            if (seen < 0) report_error(&dc, entry->fts_path, "cannot record input path", ENOMEM);
            continue;
        }

        pthread_mutex_lock(&dc.metrics_mutex);
        dc.total_bytes += entry->fts_statp->st_size;
        pthread_mutex_unlock(&dc.metrics_mutex);
        PROGRESS_LOCK(dc.progress, dc.progress_mutex, {
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
            if (prune_entry(fe, st_seen_inodes, st_seen_clones, &dc)) {
                file_entry_free(fe);
            } else {
                // Survivor goes to work_queue (already counted in queued_count)
                file_entry_queue_push(queue, fe);
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
    free_seen_paths(visited_paths);

    // Signal FTS scan complete to pruner
    pthread_mutex_lock(&dc.scan_done_mutex);
    dc.scan_done = 1;
    pthread_mutex_unlock(&dc.scan_done_mutex);

    // Wait for pruner to drain raw_queue
    if (pruner_started) {
        if (pthread_join(pruner_thread, NULL)) {
            fprintf(stderr, "Failed to wait for pruner thread\n");
        }
    }

    // Signal pruner complete to workers
    pthread_mutex_lock(&dc.prune_done_mutex);
    dc.prune_done = 1;
    pthread_mutex_unlock(&dc.prune_done_mutex);

    for (int i = 0; i < started_threads; i++) {
        // clang-analyzer thinks threads[i] can be NULL, but `pthread_t`
        // is an opaque type (to us). if `pthread_create` is successful
        // the API contract says we can pass that value to pthread_join.
        // `threads` is non-NULL whenever a thread was started
        assert(threads != NULL);
        if (pthread_join(threads[i], NULL)) {
            fprintf(stderr, "Failed to wait for thread %i\n", i);
        }
    }
    free(threads); threads = NULL;

    free_seen_set(st_seen_inodes);
    free_seen_set(st_seen_clones);
    free_file_entry_queue(raw_queue); raw_queue = NULL;
    free_file_entry_queue(queue); queue = NULL;
    free_sig_table(dc.signatures, NULL); dc.signatures = NULL;

    if (dc.progress) {
        clear_progress();
    }
    printf("duplicates found: %zu\n", dc.found);
    printf("entries pruned: %zu\n", dc.pruned);

    // Fast dedup processes files immediately during traversal
    // No additional deduplication step needed

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
    if (dc.progress) {
        fprintf(stderr, "\r\033[K\n");
    }
    
    // Close summary file if it was opened
    if (dc.summary_file && clone_summary_close() != 0) {
        report_error(&dc, dc.summary_file, "cannot write summary", EIO);
    }

    return dc.errors ? EXIT_FAILURE : EXIT_SUCCESS;
}
