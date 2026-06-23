/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * connection.c - Tier 3 streaming HttpConnection LVO implementations
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/lists.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <libraries/amihttp.h>
#include <amihttp/amihttpbase.h>

#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_internal.h"

extern struct AmiHttpBase *HttpBase;

static struct HtStreamConn *
ht_stream_from_handle(struct HttpConnection *conn)
{
    struct HtStreamConn *hst;

    hst = (struct HtStreamConn *)conn;
    if (hst == NULL || !ht_check_handle(hst->hsc_Magic, HT_MAGIC_STREAM)) {
        return NULL;
    }
    return hst;
}

static VOID
ht_stream_clear_resp(struct HtStreamConn *hst)
{
    struct HttpHeader *hh;
    struct HttpHeader *next;

    if (hst == NULL) {
        return;
    }
    if (hst->hsc_StatusLine) {
        ht_free(hst->hsc_StatusLine);
        hst->hsc_StatusLine = NULL;
    }
    for (hh = (struct HttpHeader *)hst->hsc_RespHeaders.lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = next) {
        next = (struct HttpHeader *)hh->hh_Node.ln_Succ;
        Remove(&hh->hh_Node);
        if (hh->hh_Name) {
            ht_free(hh->hh_Name);
        }
        if (hh->hh_Value) {
            ht_free(hh->hh_Value);
        }
        ht_free(hh);
    }
    hst->hsc_StatusCode = 0;
    hst->hsc_ContentLength = -1;
    hst->hsc_BytesReceived = 0;
    hst->hsc_Flags = 0;
}

static LONG
ht_conn_stub(void)
{
    ht_set_error(ERROR_HTTP_NOT_IMPLEMENTED);
    return ht_lvo_status(ERROR_HTTP_NOT_IMPLEMENTED);
}

struct HttpConnection *
__ASM__ __SAVE_DS__ OpenHttpConnection(
    __REG__(a0, struct HttpSession *session),
    __REG__(a1, STRPTR host),
    __REG__(d0, ULONG port),
    __REG__(d1, BOOL ssl))
{
    struct HtStreamConn *hst;
    ULONG use_port;

    if (!ht_check_handle(session ? session->hs_Magic : 0, HT_MAGIC_SESSION)) {
        ht_set_error(ERROR_HTTP_INVALID_HANDLE);
        return NULL;
    }
    if (host == NULL || host[0] == '\0') {
        ht_set_error(ERROR_HTTP_INVALID_URL);
        return NULL;
    }
    if (HttpBase == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_HANDLE);
        return NULL;
    }
    use_port = port;
    if (use_port == 0) {
        use_port = ssl ? 443UL : 80UL;
    }
    hst = (struct HtStreamConn *)ht_alloc(sizeof(struct HtStreamConn), MEMF_CLEAR);
    if (hst == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
    }
    hst->hsc_Magic = HT_MAGIC_STREAM;
    hst->hsc_Session = session;
    hst->hsc_ContentLength = -1;
    NewList(&hst->hsc_RespHeaders);
    hst->hsc_Conn = ht_pool_acquire(HttpBase, session, host, use_port, ssl);
    if (hst->hsc_Conn == NULL) {
        ht_free(hst);
        ht_set_error(HttpBase->ahb_LastError);
        return NULL;
    }
    ht_set_error(0);
    return (struct HttpConnection *)hst;
}

VOID
__ASM__ __SAVE_DS__ CloseHttpConnection(
    __REG__(a0, struct HttpConnection *conn))
{
    struct HtStreamConn *hst;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL) {
        return;
    }
    if (hst->hsc_Conn != NULL) {
        ht_pool_release(HttpBase, hst->hsc_Conn, FALSE);
        hst->hsc_Conn = NULL;
    }
    hst->hsc_Magic = 0;
    ht_stream_clear_resp(hst);
    ht_free(hst);
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionWrite(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG len))
{
    struct HtStreamConn *hst;
    LONG rc;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL || hst->hsc_Conn == NULL) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    rc = ht_transport_send(HttpBase, hst->hsc_Conn, buffer, len);
    if (rc < 0) {
        return ht_lvo_status(ht_wire_to_status(rc));
    }
    return 1;
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionRead(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG len))
{
    struct HtStreamConn *hst;
    ULONG timeout;
    LONG n;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL || hst->hsc_Conn == NULL) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    timeout = hst->hsc_Session ? hst->hsc_Session->hs_ReadTimeout : 0;
    if (timeout == 0 && HttpBase != NULL) {
        timeout = HttpBase->ahb_DefaultTimeout;
    }
    n = ht_transport_recv(HttpBase, hst->hsc_Conn, buffer, len, timeout);
    if (n < 0) {
        return ht_lvo_status(ht_wire_to_status(n));
    }
    return n;
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionSendRequest(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, STRPTR method),
    __REG__(a2, STRPTR path),
    __REG__(a3, struct TagItem *tags))
{
    return ht_conn_stub();
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionReadResponseLine(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, STRPTR buffer),
    __REG__(d0, ULONG buflen))
{
    struct HtStreamConn *hst;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL || buffer == NULL || buflen == 0) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (hst->hsc_StatusLine == NULL) {
        return 0;
    }
    strncpy((char *)buffer, (char *)hst->hsc_StatusLine, buflen - 1);
    buffer[buflen - 1] = '\0';
    return (LONG)strlen((char *)buffer);
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionReadResponseHeaders(
    __REG__(a0, struct HttpConnection *conn))
{
    struct HtStreamConn *hst;
    LONG rc;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL || hst->hsc_Conn == NULL) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    ht_stream_clear_resp(hst);
    rc = ht_http_read_stream_headers(HttpBase, hst->hsc_Session, hst->hsc_Conn,
        &hst->hsc_RespHeaders, &hst->hsc_StatusLine, &hst->hsc_StatusCode,
        &hst->hsc_ContentLength, &hst->hsc_Flags);
    if (rc != 0) {
        return ht_lvo_status(rc);
    }
    hst->hsc_Flags |= HTF_HEADERS_DONE;
    return 1;
}

STRPTR
__ASM__ __SAVE_DS__ HttpConnectionRespHeader(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, STRPTR header_name))
{
    struct HtStreamConn *hst;
    struct HttpHeader *hh;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL || header_name == NULL) {
        return NULL;
    }
    for (hh = (struct HttpHeader *)hst->hsc_RespHeaders.lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = (struct HttpHeader *)hh->hh_Node.ln_Succ) {
        if (hh->hh_Name != NULL &&
            stricmp((char *)hh->hh_Name, (char *)header_name) == 0) {
            return hh->hh_Value;
        }
    }
    return NULL;
}

struct List *
__ASM__ __SAVE_DS__ HttpConnectionRespHeaders(
    __REG__(a0, struct HttpConnection *conn))
{
    struct HtStreamConn *hst;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL) {
        return NULL;
    }
    return &hst->hsc_RespHeaders;
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionGetStatusCode(
    __REG__(a0, struct HttpConnection *conn))
{
    struct HtStreamConn *hst;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL) {
        return 0;
    }
    return hst->hsc_StatusCode;
}

STRPTR
__ASM__ __SAVE_DS__ HttpConnectionGetStatusLine(
    __REG__(a0, struct HttpConnection *conn))
{
    struct HtStreamConn *hst;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL) {
        return NULL;
    }
    return hst->hsc_StatusLine;
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionReadBodyChunk(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG buflen))
{
    return ht_conn_stub();
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionWriteBodyChunk(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG len))
{
    return ht_conn_stub();
}

BOOL
__ASM__ __SAVE_DS__ HttpConnectionIsAlive(
    __REG__(a0, struct HttpConnection *conn))
{
    struct HtStreamConn *hst;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL || hst->hsc_Conn == NULL) {
        return FALSE;
    }
    if (hst->hsc_Conn->hc_Sock < 0) {
        return FALSE;
    }
    return TRUE;
}

VOID
__ASM__ __SAVE_DS__ ResetHttpConnection(
    __REG__(a0, struct HttpConnection *conn))
{
    struct HtStreamConn *hst;

    hst = ht_stream_from_handle(conn);
    if (hst == NULL) {
        return;
    }
    ht_stream_clear_resp(hst);
    if (hst->hsc_Conn != NULL) {
        hst->hsc_Conn->hc_IoLen = 0;
        hst->hsc_Conn->hc_IoPos = 0;
    }
}
