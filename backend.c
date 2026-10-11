// Copyright © 2023 TTKB, LLC.
//
// SPDX-License-Identifier: BSD-2-Clause

#include "backend.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/clonefile.h>
#endif

static CloneBackend selected_backend = BACKEND_AUTO;

CloneBackend backend_init(void) {
    const char* env = getenv("DEDUP_BACKEND");
    if (env) {
        if (strcmp(env, "clonefile") == 0) {
            selected_backend = BACKEND_CLONEFILE;
        } else if (strcmp(env, "fideduperange") == 0) {
            selected_backend = BACKEND_FIDEDUPERANGE;
        } else if (strcmp(env, "ubt") == 0) {
            selected_backend = BACKEND_UBT;
        } else if (strcmp(env, "auto") == 0) {
            selected_backend = BACKEND_AUTO;
        } else {
            fprintf(stderr, "unknown DEDUP_BACKEND: %s\n", env);
            selected_backend = BACKEND_AUTO;
        }
    }

    if (selected_backend == BACKEND_AUTO) {
#if defined(__APPLE__)
        selected_backend = BACKEND_CLONEFILE;
#elif defined(DEDUP_IN_PLACE)
        selected_backend = BACKEND_FIDEDUPERANGE;
#else
        selected_backend = BACKEND_AUTO;
#endif
    }

    return selected_backend;
}

const char* backend_name(CloneBackend b) {
    switch (b) {
    case BACKEND_CLONEFILE:     return "clonefile";
    case BACKEND_FIDEDUPERANGE: return "fideduperange";
    case BACKEND_UBT:           return "userspace-btrfs";
    case BACKEND_AUTO:          return "auto";
    }
    return "unknown";
}

int backend_is_available(CloneBackend b) {
    switch (b) {
    case BACKEND_CLONEFILE:
#if defined(__APPLE__)
        return 1;
#else
        return 0;
#endif
    case BACKEND_FIDEDUPERANGE:
#if defined(DEDUP_IN_PLACE)
        return 1;
#else
        return 0;
#endif
    case BACKEND_UBT:
#if defined(HAVE_UBT)
        return 1;
#else
        return 0; /* libubt not linked */
#endif
    case BACKEND_AUTO:
        return selected_backend != BACKEND_AUTO &&
               selected_backend != BACKEND_UBT;
    }
    return 0;
}
