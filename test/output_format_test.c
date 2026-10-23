// Copyright © 2026 TTKB, LLC.
// SPDX-License-Identifier: BSD-2-Clause

#include "../output_format.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const struct {
        uint64_t bytes;
        OutputFormat format;
        const char* expected;
    } cases[] = {
        {0, OUTPUT_SI_HUMAN, "0 bytes"},
        {999, OUTPUT_SI_HUMAN, "999 bytes"},
        {1000, OUTPUT_SI_HUMAN, "1.0kB"},
        {1000000000000000ULL, OUTPUT_SI_HUMAN, "1.0PB"},
        {1000000000000000ULL, OUTPUT_SI_HUMAN_LONG, "1.0 petabytes"},
        {1125899906842624ULL, OUTPUT_BINARY_HUMAN, "1.0PiB"},
        {1125899906842624ULL, OUTPUT_BINARY_HUMAN_LONG, "1.0 pebibytes"},
        {1000000000000ULL, OUTPUT_DISK_TRADITIONAL, "1.0T"},
        {1000000000000ULL, OUTPUT_DISK_TRADITIONAL_LONG, "1.0 terabytes"},
        {UINT64_MAX, OUTPUT_SI_HUMAN, "18446.7PB"},
        {UINT64_MAX, OUTPUT_BINARY_HUMAN, "16384.0PiB"},
        {UINT64_MAX, OUTPUT_DISK_TRADITIONAL, "18446744.1T"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char* actual = format_bytes(cases[i].bytes, cases[i].format);
        if (strcmp(actual, cases[i].expected) != 0) {
            fprintf(stderr, "case %zu: expected '%s', got '%s'\n",
                    i, cases[i].expected, actual);
            return EXIT_FAILURE;
        }
    }
    puts("output formatting: all boundary cases passed");
    return EXIT_SUCCESS;
}
