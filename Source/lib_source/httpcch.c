/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * httpcch.c - Cache-Control directive parsing (RFC 9111 subset).
 */

#include <exec/types.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <libraries/amihttp.h>

#include "private/ht_internal.h"

void
Http_cc_reset_accum(struct Http_cc_accum *a)
{
    if (a == NULL) {
        return;
    }
    a->forbid_disk = FALSE;
    a->must_revalidate = FALSE;
    a->saw_positive_max_age = FALSE;
    a->min_max_age = -1;
}

static int
ht_strniequal(const char *a, const char *b, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        char ca;
        char cb;
        if (a[i] == '\0' || b[i] == '\0') {
            return 0;
        }
        ca = a[i];
        cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

void
Http_cc_parse(STRPTR v, struct Http_cc_accum *z)
{
    STRPTR h;
    STRPTR eq;
    long n;
    long line_min;

    Http_cc_reset_accum(z);
    if (v == NULL) {
        return;
    }
    line_min = -1;
    for (h = v; *h != '\0'; h++) {
        if (ht_strniequal((const char *)h, "must-revalidate", 15)) {
            if (h[15] == '\0' || h[15] == ',' || isspace((unsigned char)h[15])) {
                z->must_revalidate = TRUE;
            }
        }
        if (ht_strniequal((const char *)h, "no-store", 8)) {
            if (h[8] == '\0' || h[8] == ',' || isspace((unsigned char)h[8])) {
                z->forbid_disk = TRUE;
            }
        }
        if (ht_strniequal((const char *)h, "no-cache", 8)) {
            if (h[8] == '\0' || h[8] == ',' || isspace((unsigned char)h[8])) {
                z->forbid_disk = TRUE;
            }
        }
        if (ht_strniequal((const char *)h, "max-age", 7)) {
            eq = h + 7;
            while (*eq == ' ' || *eq == '\t') {
                eq++;
            }
            if (*eq != '=') {
                continue;
            }
            eq++;
            while (*eq == ' ' || *eq == '\t') {
                eq++;
            }
            n = -999999;
            if (sscanf((const char *)eq, "%ld", &n) != 1) {
                continue;
            }
            if (n <= 0) {
                z->forbid_disk = TRUE;
            } else {
                if (line_min < 0 || n < line_min) {
                    line_min = n;
                }
            }
        }
    }
    if (line_min >= 0) {
        z->saw_positive_max_age = TRUE;
        z->min_max_age = line_min;
    }
}

void
Http_cc_merge(struct Http_cc_accum *dst, struct Http_cc_accum *src)
{
    if (dst == NULL || src == NULL) {
        return;
    }
    dst->forbid_disk |= src->forbid_disk;
    dst->must_revalidate |= src->must_revalidate;
    if (src->saw_positive_max_age) {
        if (!dst->saw_positive_max_age || src->min_max_age < dst->min_max_age) {
            dst->min_max_age = src->min_max_age;
            dst->saw_positive_max_age = TRUE;
        }
    }
}
