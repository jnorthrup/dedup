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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "progress.h"

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

static bool progress_enabled = true;

void disable_progress(void) {
    progress_enabled = false;
}

void enable_progress(void) {
    progress_enabled = true;
}

void display_progress(const Progress* progress) {
    if (!progress_enabled || !progress) {
        return;
    }

    struct winsize w;
    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &w) != 0 || w.ws_col == 0) {
        w.ws_col = 80;
    }

    size_t note_len = progress->note ? strlen(progress->note) : 6;
    size_t reserved = 23 + note_len;
    size_t width = w.ws_col > reserved ? w.ws_col - reserved : 10;
    width = MIN(width, 80);

    clear_progress();
    fputc('[', stderr);
    double percent_complete = progress->totalUnitCount > 0
        ? (double) progress->completedUnitCount / (double) progress->totalUnitCount
        : 0.0;
    if (percent_complete > 1.0) {
        percent_complete = 1.0;
    }

    size_t complete = (size_t)(width * percent_complete);
    for (size_t i = 0; i < width; i++) {
        if (i < complete) {
            fputc('#', stderr);
        } else {
            fputc(' ', stderr);
        }
    }
    fprintf(stderr, "] %.0f%% (%llu of %llu) %s",
            percent_complete * 100.0,
            (unsigned long long) progress->completedUnitCount,
            (unsigned long long) progress->totalUnitCount,
            progress->note ? progress->note : "");
    fflush(stderr);
}

void clear_progress(void) {
    if (!progress_enabled) {
        return;
    }
    fprintf(stderr, "\r\033[K");
    fflush(stderr);
}
