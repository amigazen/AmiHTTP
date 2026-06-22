/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_auth.c - HTTP Basic authentication
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <ctype.h>
#include <string.h>

#include "private/ht_internal.h"

static const char ht_b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int
ht_strnicmp_local(STRPTR a, STRPTR b, LONG n)
{
    LONG i;
    char ca;
    char cb;

    if (a == NULL || b == NULL || n <= 0) {
        return (a == b) ? 0 : 1;
    }
    for (i = 0; i < n; i++) {
        if (a[i] == '\0' || b[i] == '\0') {
            break;
        }
        ca = (char)a[i];
        cb = (char)b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
        }
    }
    return 0;
}

/*
 * Encode "user:password" as Base64 for Authorization: Basic header value.
 */
STRPTR
ht_auth_basic_encode(STRPTR userpass)
{
    STRPTR cookie;
    STRPTR src;
    STRPTR dest;
    ULONG length1;
    ULONG length2;
    UBYTE c;
    short t;

    if (userpass == NULL || userpass[0] == '\0') {
        return NULL;
    }
    length1 = ht_strlen(userpass);
    length2 = length1 * 4UL / 3UL + 5UL;
    cookie = (STRPTR)ht_alloc(length2, MEMF_CLEAR);
    if (cookie == NULL) {
        return NULL;
    }
    src = userpass;
    dest = cookie;
    t = 0;
    while (*src != '\0') {
        switch (t) {
        case 0:
            c = (UBYTE)((src[0] & 0xfc) >> 2);
            break;
        case 1:
            c = (UBYTE)(((src[0] & 0x03) << 4) | ((src[1] & 0xf0) >> 4));
            src++;
            break;
        case 2:
            c = (UBYTE)(((src[0] & 0x0f) << 2) | ((src[1] & 0xc0) >> 6));
            src++;
            break;
        default:
            c = (UBYTE)(src[0] & 0x3f);
            src++;
            break;
        }
        *dest++ = ht_b64[c];
        t++;
        if (t > 3) {
            t = 0;
        }
    }
    while (t != 0) {
        while (t < 4) {
            *dest++ = '=';
            t++;
        }
    }
    *dest = '\0';
    return cookie;
}

/*
 * Parse "Basic realm=\"...\"" from WWW-Authenticate / Proxy-Authenticate.
 */
STRPTR
ht_auth_parse_basic_realm(STRPTR value)
{
    STRPTR p;
    STRPTR q;
    STRPTR realm;
    ULONG len;

    if (value == NULL) {
        return NULL;
    }
    p = value;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (ht_strnicmp_local(p, (STRPTR)"Basic", 5) != 0) {
        return NULL;
    }
    p += 5;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (ht_strnicmp_local(p, (STRPTR)"realm", 5) != 0) {
            while (*p != '\0' && *p != ',') {
                p++;
            }
            continue;
        }
        p += 5;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p != '=') {
            return NULL;
        }
        p++;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p != '"') {
            return NULL;
        }
        p++;
        q = p;
        while (*q != '\0' && *q != '"') {
            q++;
        }
        len = (ULONG)(q - p);
        realm = ht_strndup(p, (LONG)len);
        return realm;
    }
    return ht_strdup((STRPTR)"");
}
