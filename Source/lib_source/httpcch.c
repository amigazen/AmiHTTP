/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * httpcch.c - Cache-Control directive parsing (RFC 9111 subset).
 */

#define __USE_SYSBASE

#include <exec/types.h>

#include <proto/dos.h>
#include <proto/utility.h>

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

void
Http_cc_parse(STRPTR v, struct Http_cc_accum *z)
{
    STRPTR h;
    STRPTR eq;
    LONG n;
    LONG line_min;
    LONG consumed;

    Http_cc_reset_accum(z);
    if (v == NULL) {
        return;
    }
    line_min = -1;
    for (h = v; *h != '\0'; h++) {
        if (Strnicmp(h, (STRPTR)"must-revalidate", 15) == 0) {
            if (h[15] == '\0' || h[15] == ',' ||
                h[15] == ' ' || h[15] == '\t' || h[15] == '\r' || h[15] == '\n') {
                z->must_revalidate = TRUE;
            }
        }
        if (Strnicmp(h, (STRPTR)"no-store", 8) == 0) {
            if (h[8] == '\0' || h[8] == ',' ||
                h[8] == ' ' || h[8] == '\t' || h[8] == '\r' || h[8] == '\n') {
                z->forbid_disk = TRUE;
            }
        }
        if (Strnicmp(h, (STRPTR)"no-cache", 8) == 0) {
            if (h[8] == '\0' || h[8] == ',' ||
                h[8] == ' ' || h[8] == '\t' || h[8] == '\r' || h[8] == '\n') {
                z->forbid_disk = TRUE;
            }
        }
        if (Strnicmp(h, (STRPTR)"max-age", 7) == 0) {
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
            consumed = StrToLong(eq, &n);
            if (consumed < 1) {
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
