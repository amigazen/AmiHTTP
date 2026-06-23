/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * session.c - Tier 1 HttpSession LVO implementations
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <stdlib.h>
#include <utility/tagitem.h>

#include <proto/exec.h>
#include <libraries/amihttp.h>

#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_debug.h"
#include "private/ht_internal.h"
#include "private/ht_zlib.h"

extern struct AmiHttpBase *HttpBase;

static VOID
ht_session_defaults(struct HttpSession *session)
{
    session->hs_Magic = HT_MAGIC_SESSION;
    session->hs_UserAgent = ht_strdup((STRPTR)"amihttp/1.0");
    session->hs_MaxRedirects = 10;
    session->hs_FollowRedirects = TRUE;
    session->hs_KeepAlive = TRUE;
    session->hs_MaxConnections = 8;
    session->hs_ConnectTimeout = 0;
    session->hs_ReadTimeout = 0;
    session->hs_TotalTimeout = 0;
    session->hs_SslVerify = HTSSL_VERIFY_PEER;
    session->hs_RefererPolicy = HTRP_ORIGIN;
    session->hs_TaskSerial = (ULONG)FindTask(NULL);
  /* When z.library is present, negotiate gzip/deflate by default. */
    if (HttpBase != NULL && ht_zlib_ensure(HttpBase)) {
        session->hs_AcceptEncoding = ht_strdup((STRPTR)"gzip, deflate");
    }
}

struct HttpSession *
__ASM__ __SAVE_DS__ NewHttpSession(void)
{
    struct HttpSession *session;

    htDbgPut("NewHttpSession");
    session = (struct HttpSession *)ht_alloc(sizeof(struct HttpSession), MEMF_CLEAR);
    if (session == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
    }
    ht_session_defaults(session);
    ht_set_error(0);
    htDbgPutHex("NewHttpSession ok=", (ULONG)session);
    return session;
}

VOID
__ASM__ __SAVE_DS__ DisposeHttpSession(
    __REG__(a0, struct HttpSession *session))
{
    if (session == NULL) {
        return;
    }
    if (!ht_check_handle(session->hs_Magic, HT_MAGIC_SESSION)) {
        return;
    }
    session->hs_Magic = 0;
    if (session->hs_UserAgent) {
        ht_free(session->hs_UserAgent);
    }
    if (session->hs_Proxy) {
        ht_free(session->hs_Proxy);
    }
    if (session->hs_ProxyAuth) {
        ht_free(session->hs_ProxyAuth);
    }
    if (session->hs_Credentials) {
        ht_free(session->hs_Credentials);
    }
    if (session->hs_AcceptEncoding) {
        ht_free(session->hs_AcceptEncoding);
    }
    ht_free(session);
}

LONG
__ASM__ __SAVE_DS__ SetHttpSessionAttrsA(
    __REG__(a0, struct HttpSession *session),
    __REG__(a1, struct TagItem *tags))
{
    struct TagItem *t;

    if (!ht_check_handle(session ? session->hs_Magic : 0, HT_MAGIC_SESSION)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (tags == NULL) {
        return 1;
    }
    for (t = tags; t->ti_Tag != TAG_DONE; t++) {
        switch (t->ti_Tag) {
        case HTSA_USERAGENT:
            if (session->hs_UserAgent) {
                ht_free(session->hs_UserAgent);
            }
            session->hs_UserAgent = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTSA_PROXY:
            if (session->hs_Proxy) {
                ht_free(session->hs_Proxy);
            }
            session->hs_Proxy = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTSA_PROXY_AUTH:
            if (session->hs_ProxyAuth) {
                ht_free(session->hs_ProxyAuth);
            }
            session->hs_ProxyAuth = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTSA_CREDENTIALS:
            if (session->hs_Credentials) {
                ht_free(session->hs_Credentials);
            }
            session->hs_Credentials = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTSA_MAX_REDIRECTS:
            session->hs_MaxRedirects = (ULONG)t->ti_Data;
            break;
        case HTSA_FOLLOW_REDIRECTS:
            session->hs_FollowRedirects = (BOOL)t->ti_Data;
            break;
        case HTSA_ACCEPT_ENCODING:
            if (session->hs_AcceptEncoding) {
                ht_free(session->hs_AcceptEncoding);
            }
            session->hs_AcceptEncoding = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTSA_KEEPALIVE:
            session->hs_KeepAlive = (BOOL)t->ti_Data;
            break;
        case HTSA_MAX_CONNECTIONS:
            session->hs_MaxConnections = (ULONG)t->ti_Data;
            break;
        case HTSA_CONNECT_TIMEOUT:
            session->hs_ConnectTimeout = (ULONG)t->ti_Data;
            break;
        case HTSA_READ_TIMEOUT:
            session->hs_ReadTimeout = (ULONG)t->ti_Data;
            break;
        case HTSA_TOTAL_TIMEOUT:
            session->hs_TotalTimeout = (ULONG)t->ti_Data;
            break;
        case HTSA_SSL_VERIFY:
            session->hs_SslVerify = (ULONG)t->ti_Data;
            break;
        case HTSA_REFERER_POLICY:
            session->hs_RefererPolicy = (ULONG)t->ti_Data;
            break;
        case HTSA_COOKIE_JAR:
            session->hs_CookieJar = (struct HttpCookieJar *)t->ti_Data;
            break;
        case HTSA_TASK_SERIAL:
            session->hs_TaskSerial = (ULONG)t->ti_Data;
            break;
        default:
            break;
        }
    }
    return 1;
}

LONG
__ASM__ __SAVE_DS__ HttpSessionAttachCookieJar(
    __REG__(a0, struct HttpSession *session),
    __REG__(a1, struct HttpCookieJar *jar))
{
    if (!ht_check_handle(session ? session->hs_Magic : 0, HT_MAGIC_SESSION)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    session->hs_CookieJar = jar;
    return 1;
}

VOID
__ASM__ __SAVE_DS__ HttpSessionDetachCookieJar(
    __REG__(a0, struct HttpSession *session))
{
    if (session == NULL || !ht_check_handle(session->hs_Magic, HT_MAGIC_SESSION)) {
        return;
    }
    session->hs_CookieJar = NULL;
}

LONG
__ASM__ __SAVE_DS__ SetHttpSessionHook(
    __REG__(a0, struct HttpSession *session),
    __REG__(d0, ULONG type),
    __REG__(a1, struct Hook *hook))
{
    struct HttpSession *sess;
    ULONG hooktype;
    struct Hook *hk;

    sess = session;
    hooktype = type;
    hk = hook;
    if (!ht_check_handle(sess ? sess->hs_Magic : 0, HT_MAGIC_SESSION)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (hooktype < 1 || hooktype > 8) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    sess->hs_Hooks[hooktype - 1] = hk;
    return 1;
}
