/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_cookie.c - Cookie jar store/match
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/semaphores.h>
#include <ctype.h>
#include <string.h>

#include <proto/exec.h>

#include "private/ht_internal.h"

struct HtCookie
{
    struct Node hc_Node;
    STRPTR      hc_Name;
    STRPTR      hc_Value;
    STRPTR      hc_Domain;
    STRPTR      hc_Path;
    BOOL        hc_Secure;
};

static int
ht_str_ieq(STRPTR a, STRPTR b)
{
    char ca;
    char cb;

    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        ca = *a++;
        cb = *b++;
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
    return (*a == '\0' && *b == '\0');
}

static VOID
ht_cookie_free_one(struct HtCookie *ck)
{
    if (ck == NULL) {
        return;
    }
    if (ck->hc_Name) {
        ht_free(ck->hc_Name);
    }
    if (ck->hc_Value) {
        ht_free(ck->hc_Value);
    }
    if (ck->hc_Domain) {
        ht_free(ck->hc_Domain);
    }
    if (ck->hc_Path) {
        ht_free(ck->hc_Path);
    }
    ht_free(ck);
}

static STRPTR
ht_cookie_skip_ws(STRPTR p)
{
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return p;
}

static STRPTR
ht_cookie_attr_value(STRPTR p, STRPTR *out_end)
{
    STRPTR start;
    STRPTR end;

    p = ht_cookie_skip_ws(p);
    if (*p == '"') {
        start = p + 1;
        end = start;
        while (*end != '\0' && *end != '"') {
            end++;
        }
        if (*end == '"') {
            *out_end = end + 1;
        } else {
            *out_end = end;
        }
        return ht_strndup(start, (LONG)(end - start));
    }
    start = p;
    while (*p != '\0' && *p != ';' && *p != '\r' && *p != '\n') {
        p++;
    }
    *out_end = p;
    return ht_strndup(start, (LONG)(p - start));
}

static BOOL
ht_cookie_domain_match(STRPTR ckdomain, STRPTR host)
{
    ULONG l1;
    ULONG l2;

    if (ckdomain == NULL || host == NULL) {
        return TRUE;
    }
    if (ht_str_ieq(ckdomain, host)) {
        return TRUE;
    }
    if (ckdomain[0] == '.' && ht_str_ieq(ckdomain + 1, host)) {
        return TRUE;
    }
    l1 = ht_strlen(ckdomain);
    l2 = ht_strlen(host);
    if (l2 > l1 && ht_str_ieq(host + l2 - l1, ckdomain)) {
        if (l2 == l1 || host[l2 - l1 - 1] == '.') {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL
ht_cookie_path_match(STRPTR ckpath, STRPTR reqpath)
{
    ULONG len;
    ULONG orglen;

    if (ckpath == NULL || reqpath == NULL) {
        return TRUE;
    }
    len = ht_strlen(ckpath);
    orglen = ht_strlen(reqpath);
    if (orglen < len) {
        return FALSE;
    }
    if (memcmp(ckpath, reqpath, len) != 0) {
        return FALSE;
    }
    if (orglen == len) {
        return TRUE;
    }
    if (reqpath[len] == '/') {
        return TRUE;
    }
    return FALSE;
}

static VOID
ht_cookie_remove_match(struct HttpCookieJar *jar, STRPTR domain, STRPTR path,
    STRPTR name)
{
    struct HtCookie *ck;
    struct HtCookie *next;

    for (ck = (struct HtCookie *)jar->hj_Cookies.lh_Head;
         ck != NULL && ck->hc_Node.ln_Succ != NULL;
         ck = next) {
        next = (struct HtCookie *)ck->hc_Node.ln_Succ;
        if (ht_str_ieq(ck->hc_Name, name) &&
            ht_str_ieq(ck->hc_Domain, domain) &&
            ht_str_ieq(ck->hc_Path, path)) {
            Remove(&ck->hc_Node);
            ht_cookie_free_one(ck);
        }
    }
}

VOID
ht_cookie_jar_clear(struct HttpCookieJar *jar)
{
    struct HtCookie *ck;
    struct HtCookie *next;

    if (jar == NULL) {
        return;
    }
    ObtainSemaphore(&jar->hj_Sema);
    for (ck = (struct HtCookie *)jar->hj_Cookies.lh_Head;
         ck != NULL && ck->hc_Node.ln_Succ != NULL;
         ck = next) {
        next = (struct HtCookie *)ck->hc_Node.ln_Succ;
        Remove(&ck->hc_Node);
        ht_cookie_free_one(ck);
    }
    ReleaseSemaphore(&jar->hj_Sema);
}

VOID
ht_cookie_jar_trim(struct HttpCookieJar *jar, ULONG max_count)
{
    struct HtCookie *ck;
    struct HtCookie *next;
    ULONG count;

    if (jar == NULL || max_count == 0) {
        return;
    }
    ObtainSemaphore(&jar->hj_Sema);
    count = 0;
    for (ck = (struct HtCookie *)jar->hj_Cookies.lh_Head;
         ck != NULL && ck->hc_Node.ln_Succ != NULL;
         ck = (struct HtCookie *)ck->hc_Node.ln_Succ) {
        count++;
    }
    for (ck = (struct HtCookie *)jar->hj_Cookies.lh_Head;
         ck != NULL && ck->hc_Node.ln_Succ != NULL && count > max_count;
         ck = next) {
        next = (struct HtCookie *)ck->hc_Node.ln_Succ;
        Remove(&ck->hc_Node);
        ht_cookie_free_one(ck);
        count--;
    }
    ReleaseSemaphore(&jar->hj_Sema);
}

LONG
ht_cookie_store_line(struct HttpCookieJar *jar, STRPTR url, STRPTR spec,
    BOOL from_response)
{
    struct ParsedUrl pu;
    struct HtCookie *ck;
    STRPTR p;
    STRPTR end;
    STRPTR eq;
    STRPTR attr;
    STRPTR attr_end;
    STRPTR name;
    STRPTR value;
    STRPTR req_host;
    STRPTR req_path;
    LONG rc;

    if (jar == NULL || spec == NULL || spec[0] == '\0') {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    req_host = NULL;
    req_path = NULL;
    if (url != NULL) {
        rc = ht_url_parse(url, &pu);
        if (rc != 0) {
            return rc;
        }
        req_host = pu.pu_Host;
        req_path = pu.pu_Path;
        if (req_path == NULL || req_path[0] == '\0') {
            req_path = (STRPTR)"/";
        }
    }
    ck = (struct HtCookie *)ht_alloc(sizeof(struct HtCookie), MEMF_CLEAR);
    if (ck == NULL) {
        if (url != NULL) {
            ht_url_free_fields(&pu);
        }
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    p = spec;
    p = ht_cookie_skip_ws(p);
    end = p;
    while (*end != '\0' && *end != '=' && *end != ';' && *end != '\r' &&
        *end != '\n') {
        end++;
    }
    name = ht_strndup(p, (LONG)(end - p));
    eq = end;
    if (*eq == '=') {
        p = eq + 1;
        value = ht_cookie_attr_value(p, &p);
    } else {
        value = ht_strdup((STRPTR)"");
        p = eq;
    }
    if (name == NULL || value == NULL) {
        ht_cookie_free_one(ck);
        if (url != NULL) {
            ht_url_free_fields(&pu);
        }
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    ck->hc_Name = name;
    ck->hc_Value = value;
    ck->hc_Domain = req_host ? ht_strdup(req_host) : NULL;
    ck->hc_Path = req_path ? ht_strdup(req_path) : ht_strdup((STRPTR)"/");
    while (*p == ';') {
        p++;
        p = ht_cookie_skip_ws(p);
        attr = p;
        attr_end = p;
        while (*attr_end != '\0' && *attr_end != '=' && *attr_end != ';') {
            attr_end++;
        }
        if (*attr_end == '=') {
            p = attr_end + 1;
            if (ht_str_ieq(attr, (STRPTR)"Domain")) {
                if (ck->hc_Domain) {
                    ht_free(ck->hc_Domain);
                }
                ck->hc_Domain = ht_cookie_attr_value(p, &p);
            } else if (ht_str_ieq(attr, (STRPTR)"Path")) {
                if (ck->hc_Path) {
                    ht_free(ck->hc_Path);
                }
                ck->hc_Path = ht_cookie_attr_value(p, &p);
            } else if (ht_str_ieq(attr, (STRPTR)"Secure")) {
                ck->hc_Secure = TRUE;
                while (*p != '\0' && *p != ';') {
                    p++;
                }
            } else {
                while (*p != '\0' && *p != ';') {
                    p++;
                }
            }
        } else {
            if (ht_str_ieq(attr, (STRPTR)"Secure")) {
                ck->hc_Secure = TRUE;
            }
            p = attr_end;
        }
    }
    if (ck->hc_Domain == NULL) {
        ck->hc_Domain = req_host ? ht_strdup(req_host) : ht_strdup((STRPTR)"");
    }
    if (ck->hc_Path == NULL || ck->hc_Path[0] == '\0') {
        if (ck->hc_Path) {
            ht_free(ck->hc_Path);
        }
        ck->hc_Path = ht_strdup((STRPTR)"/");
    }
    if (url != NULL) {
        ht_url_free_fields(&pu);
    }
    ObtainSemaphore(&jar->hj_Sema);
    ht_cookie_remove_match(jar, ck->hc_Domain, ck->hc_Path, ck->hc_Name);
    AddTail(&jar->hj_Cookies, &ck->hc_Node);
    ReleaseSemaphore(&jar->hj_Sema);
    return 0;
}

STRPTR
ht_cookie_header_for_url(struct HttpCookieJar *jar, STRPTR url, BOOL secure)
{
    struct ParsedUrl pu;
    struct HtCookie *ck;
    STRPTR out;
    STRPTR p;
    ULONG len;
    BOOL first;
    LONG rc;

    if (jar == NULL || url == NULL) {
        return NULL;
    }
    rc = ht_url_parse(url, &pu);
    if (rc != 0) {
        return NULL;
    }
    if (pu.pu_Path == NULL || pu.pu_Path[0] == '\0') {
        pu.pu_Path = (STRPTR)"/";
    }
    len = 1;
    ObtainSemaphore(&jar->hj_Sema);
    for (ck = (struct HtCookie *)jar->hj_Cookies.lh_Head;
         ck != NULL && ck->hc_Node.ln_Succ != NULL;
         ck = (struct HtCookie *)ck->hc_Node.ln_Succ) {
        if (ck->hc_Secure && !secure) {
            continue;
        }
        if (!ht_cookie_domain_match(ck->hc_Domain, pu.pu_Host)) {
            continue;
        }
        if (!ht_cookie_path_match(ck->hc_Path, pu.pu_Path)) {
            continue;
        }
        len += ht_strlen(ck->hc_Name) + ht_strlen(ck->hc_Value) + 3;
    }
    if (len <= 1) {
        ReleaseSemaphore(&jar->hj_Sema);
        ht_url_free_fields(&pu);
        return ht_strdup((STRPTR)"");
    }
    out = (STRPTR)ht_alloc(len, MEMF_CLEAR);
    if (out == NULL) {
        ReleaseSemaphore(&jar->hj_Sema);
        ht_url_free_fields(&pu);
        return NULL;
    }
    p = out;
    first = TRUE;
    for (ck = (struct HtCookie *)jar->hj_Cookies.lh_Head;
         ck != NULL && ck->hc_Node.ln_Succ != NULL;
         ck = (struct HtCookie *)ck->hc_Node.ln_Succ) {
        if (ck->hc_Secure && !secure) {
            continue;
        }
        if (!ht_cookie_domain_match(ck->hc_Domain, pu.pu_Host)) {
            continue;
        }
        if (!ht_cookie_path_match(ck->hc_Path, pu.pu_Path)) {
            continue;
        }
        if (!first) {
            *p++ = ';';
            *p++ = ' ';
        }
        strcpy((char *)p, (char *)ck->hc_Name);
        p += ht_strlen(ck->hc_Name);
        *p++ = '=';
        strcpy((char *)p, (char *)ck->hc_Value);
        p += ht_strlen(ck->hc_Value);
        first = FALSE;
    }
    *p = '\0';
    ReleaseSemaphore(&jar->hj_Sema);
    ht_url_free_fields(&pu);
    return out;
}

VOID
ht_cookie_ingest_headers(struct HttpCookieJar *jar, struct HttpTransaction *txn)
{
    struct HttpHeader *hh;
    STRPTR url;

    if (jar == NULL || txn == NULL) {
        return;
    }
    url = txn->ht_Url;
    for (hh = (struct HttpHeader *)txn->ht_RespHeaders.lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = (struct HttpHeader *)hh->hh_Node.ln_Succ) {
        if (hh->hh_Name != NULL && hh->hh_Value != NULL &&
            ht_str_ieq(hh->hh_Name, (STRPTR)"Set-Cookie")) {
            ht_cookie_store_line(jar, url, hh->hh_Value, TRUE);
        }
    }
}
