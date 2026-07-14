/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * cookie.c - Cookie jar LVOs (ht_cookie.c backend)
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/semaphores.h>

#include <proto/exec.h>

#include <utility/tagitem.h>

#include <libraries/amihttp.h>

#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_internal.h"

static struct HttpCookieJar *
ht_cookie_jar_new(void)
{
    struct HttpCookieJar *jar;

    jar = (struct HttpCookieJar *)ht_alloc(sizeof(struct HttpCookieJar), MEMF_CLEAR);
    if (jar == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
    }
    jar->hj_Magic = HT_MAGIC_JAR;
    NewList(&jar->hj_Cookies);
    InitSemaphore(&jar->hj_Sema);
    ht_set_error(0);
    return jar;
}

struct HttpCookieJar *
__ASM__ __SAVE_DS__ NewHttpCookieJarA(
    __REG__(a0, struct TagItem *tags))
{
    struct HttpCookieJar *jar;
    struct TagItem *t;

    /* NULL tags = default jar (replaces the former zero-arg NewHttpCookieJar). */
    jar = ht_cookie_jar_new();
    if (jar == NULL) {
        return NULL;
    }
    if (tags != NULL) {
        for (t = tags; t->ti_Tag != TAG_DONE; t++) {
            switch (t->ti_Tag) {
            case HTCJ_REQUEST_HOOK:
                jar->hj_RequestHook = (struct Hook *)t->ti_Data;
                break;
            case HTCJ_RESPONSE_HOOK:
                jar->hj_ResponseHook = (struct Hook *)t->ti_Data;
                break;
            default:
                break;
            }
        }
    }
    return jar;
}

VOID
__ASM__ __SAVE_DS__ DisposeHttpCookieJar(
    __REG__(a0, struct HttpCookieJar *jar))
{
    if (jar == NULL || !ht_check_handle(jar->hj_Magic, HT_MAGIC_JAR)) {
        return;
    }
    ht_cookie_jar_clear(jar);
    jar->hj_Magic = 0;
    ht_free(jar);
}

LONG
__ASM__ __SAVE_DS__ LoadHttpCookieJar(
    __REG__(a0, struct HttpCookieJar *jar),
    __REG__(a1, STRPTR filename))
{
    if (!ht_check_handle(jar ? jar->hj_Magic : 0, HT_MAGIC_JAR)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    return ht_lvo_status(ERROR_HTTP_NOT_IMPLEMENTED);
}

LONG
__ASM__ __SAVE_DS__ SaveHttpCookieJar(
    __REG__(a0, struct HttpCookieJar *jar),
    __REG__(a1, STRPTR filename))
{
    if (!ht_check_handle(jar ? jar->hj_Magic : 0, HT_MAGIC_JAR)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    return ht_lvo_status(ERROR_HTTP_NOT_IMPLEMENTED);
}

VOID
__ASM__ __SAVE_DS__ FlushHttpCookieJar(
    __REG__(a0, struct HttpCookieJar *jar),
    __REG__(d0, ULONG max_count))
{
    if (jar == NULL || jar->hj_Magic != HT_MAGIC_JAR) {
        return;
    }
    if (max_count == 0) {
        ht_cookie_jar_clear(jar);
        return;
    }
    ht_cookie_jar_trim(jar, max_count);
}

LONG
__ASM__ __SAVE_DS__ SetHttpCookie(
    __REG__(a0, struct HttpCookieJar *jar),
    __REG__(a1, STRPTR cookie_line))
{
    if (!ht_check_handle(jar ? jar->hj_Magic : 0, HT_MAGIC_JAR)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (cookie_line == NULL || cookie_line[0] == '\0') {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (jar->hj_RequestHook != NULL || jar->hj_ResponseHook != NULL) {
        return ht_lvo_status(ERROR_HTTP_NOT_IMPLEMENTED);
    }
    return ht_lvo_status(ht_cookie_store_line(jar, NULL, cookie_line, FALSE));
}

STRPTR
__ASM__ __SAVE_DS__ GetHttpCookieString(
    __REG__(a0, struct HttpCookieJar *jar),
    __REG__(a1, STRPTR url))
{
    struct ParsedUrl pu;
    BOOL secure;
    LONG rc;

    if (!ht_check_handle(jar ? jar->hj_Magic : 0, HT_MAGIC_JAR)) {
        return NULL;
    }
    if (jar->hj_RequestHook != NULL || jar->hj_ResponseHook != NULL) {
        return ht_strdup((STRPTR)"");
    }
    if (url == NULL) {
        return ht_strdup((STRPTR)"");
    }
    secure = FALSE;
    rc = ht_url_parse(url, &pu);
    if (rc == 0) {
        secure = pu.pu_IsSecure;
        ht_url_free_fields(&pu);
    }
    return ht_cookie_header_for_url(jar, url, secure);
}
