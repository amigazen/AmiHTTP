/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>

#include <proto/exec.h>

#include "private/ht_internal.h"

APTR
ht_alloc(ULONG size, ULONG flags)
{
    return AllocMem(size, flags);
}

VOID
ht_free(APTR p)
{
    if (p != NULL) {
        FreeMem(p, -1);
    }
}

ULONG
ht_strlen(STRPTR s)
{
    ULONG len;

    if (s == NULL) {
        return 0;
    }
    len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

STRPTR
ht_strdup(STRPTR s)
{
    ULONG len;
    STRPTR d;

    if (s == NULL) {
        return NULL;
    }
    len = ht_strlen(s);
    d = (STRPTR)ht_alloc(len + 1, MEMF_CLEAR);
    if (d == NULL) {
        return NULL;
    }
    CopyMem(s, d, len + 1);
    return d;
}

STRPTR
ht_strndup(STRPTR s, LONG n)
{
    STRPTR d;
    LONG i;

    if (s == NULL || n < 0) {
        return NULL;
    }
    d = (STRPTR)ht_alloc((ULONG)n + 1, MEMF_CLEAR);
    if (d == NULL) {
        return NULL;
    }
    for (i = 0; i < n && s[i] != '\0'; i++) {
        d[i] = s[i];
    }
    d[i] = '\0';
    return d;
}
