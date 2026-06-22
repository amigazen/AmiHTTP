/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * cookie.c - Basic cookie jar (in-memory store)
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/semaphores.h>
#include <string.h>

#include <proto/exec.h>

#include <libraries/amihttp.h>

#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_internal.h"

struct HttpCookieEntry
{
    struct Node hce_Node;
    STRPTR      hce_Line;
};

struct HttpCookieJar *
__ASM__ __SAVE_DS__ NewHttpCookieJar(void)
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

VOID
__ASM__ __SAVE_DS__ DisposeHttpCookieJar(
    __REG__(a0, struct HttpCookieJar *jar))
{
    struct HttpCookieEntry *e;
    struct HttpCookieEntry *next;

    if (jar == NULL || !ht_check_handle(jar->hj_Magic, HT_MAGIC_JAR)) {
        return;
    }
    ObtainSemaphore(&jar->hj_Sema);
    for (e = (struct HttpCookieEntry *)jar->hj_Cookies.lh_Head;
         e != NULL && e->hce_Node.ln_Succ != NULL;
         e = next) {
        next = (struct HttpCookieEntry *)e->hce_Node.ln_Succ;
        Remove(&e->hce_Node);
        if (e->hce_Line) {
            ht_free(e->hce_Line);
        }
        ht_free(e);
    }
    ReleaseSemaphore(&jar->hj_Sema);
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
    struct HttpCookieEntry *e;
    struct HttpCookieEntry *next;
    ULONG count;

    if (!ht_check_handle(jar ? jar->hj_Magic : 0, HT_MAGIC_JAR)) {
        return;
    }
    ObtainSemaphore(&jar->hj_Sema);
    count = 0;
    for (e = (struct HttpCookieEntry *)jar->hj_Cookies.lh_Head;
         e != NULL && e->hce_Node.ln_Succ != NULL;
         e = next) {
        next = (struct HttpCookieEntry *)e->hce_Node.ln_Succ;
        count++;
        if (max_count > 0 && count > max_count) {
            Remove(&e->hce_Node);
            if (e->hce_Line) {
                ht_free(e->hce_Line);
            }
            ht_free(e);
        }
    }
    ReleaseSemaphore(&jar->hj_Sema);
}

LONG
__ASM__ __SAVE_DS__ SetHttpCookie(
    __REG__(a0, struct HttpCookieJar *jar),
    __REG__(a1, STRPTR cookie_line))
{
    struct HttpCookieEntry *e;

    if (!ht_check_handle(jar ? jar->hj_Magic : 0, HT_MAGIC_JAR)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (cookie_line == NULL || cookie_line[0] == '\0') {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    e = (struct HttpCookieEntry *)ht_alloc(sizeof(struct HttpCookieEntry), MEMF_CLEAR);
    if (e == NULL) {
        return ht_lvo_status(ERROR_HTTP_OUT_OF_MEMORY);
    }
    e->hce_Line = ht_strdup(cookie_line);
    if (e->hce_Line == NULL) {
        ht_free(e);
        return ht_lvo_status(ERROR_HTTP_OUT_OF_MEMORY);
    }
    ObtainSemaphore(&jar->hj_Sema);
    AddTail(&jar->hj_Cookies, &e->hce_Node);
    ReleaseSemaphore(&jar->hj_Sema);
    return 1;
}

STRPTR
__ASM__ __SAVE_DS__ GetHttpCookieString(
    __REG__(a0, struct HttpCookieJar *jar),
    __REG__(a1, STRPTR url))
{
    struct HttpCookieEntry *e;
    ULONG len;
    STRPTR out;
    STRPTR p;

    if (!ht_check_handle(jar ? jar->hj_Magic : 0, HT_MAGIC_JAR)) {
        return NULL;
    }
    len = 0;
    ObtainSemaphore(&jar->hj_Sema);
    for (e = (struct HttpCookieEntry *)jar->hj_Cookies.lh_Head;
         e != NULL && e->hce_Node.ln_Succ != NULL;
         e = (struct HttpCookieEntry *)e->hce_Node.ln_Succ) {
        if (e->hce_Line != NULL) {
            len += (ULONG)strlen((char *)e->hce_Line) + 2;
        }
    }
    if (len == 0) {
        ReleaseSemaphore(&jar->hj_Sema);
        return ht_strdup((STRPTR)"");
    }
    out = (STRPTR)ht_alloc(len, MEMF_CLEAR);
    if (out == NULL) {
        ReleaseSemaphore(&jar->hj_Sema);
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
    }
    p = out;
    for (e = (struct HttpCookieEntry *)jar->hj_Cookies.lh_Head;
         e != NULL && e->hce_Node.ln_Succ != NULL;
         e = (struct HttpCookieEntry *)e->hce_Node.ln_Succ) {
        if (e->hce_Line != NULL) {
            if (p != out) {
                *p++ = ';';
                *p++ = ' ';
            }
            strcpy((char *)p, (char *)e->hce_Line);
            p += strlen((char *)p);
        }
    }
    ReleaseSemaphore(&jar->hj_Sema);
    return out;
}
