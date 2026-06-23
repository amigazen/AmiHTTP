/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * transaction.c - Tier 2 HttpTransaction LVO implementations
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/tasks.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <proto/exec.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_debug.h"
#include "private/ht_internal.h"
#include "private/ht_hooks.h"
#include "private/ht_zlib.h"

extern struct AmiHttpBase *HttpBase;

static VOID ht_txn_abort_for_dispose(struct HttpTransaction *txn);

static VOID
ht_txn_clear_req_headers(struct HttpTransaction *txn)
{
    struct HttpHeader *hh;
    struct HttpHeader *next;

    for (hh = (struct HttpHeader *)txn->ht_ReqHeaders.lh_Head;
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
}

static VOID
ht_txn_free_peer_cert(struct HttpTransaction *txn)
{
    if (txn == NULL) {
        return;
    }
    if (txn->ht_CertSubject) {
        ht_free(txn->ht_CertSubject);
    }
    if (txn->ht_CertIssuer) {
        ht_free(txn->ht_CertIssuer);
    }
    if (txn->ht_CertCommonName) {
        ht_free(txn->ht_CertCommonName);
    }
    if (txn->ht_CertNotBefore) {
        ht_free(txn->ht_CertNotBefore);
    }
    if (txn->ht_CertNotAfter) {
        ht_free(txn->ht_CertNotAfter);
    }
    if (txn->ht_CertSerial) {
        ht_free(txn->ht_CertSerial);
    }
    txn->ht_CertSubject = NULL;
    txn->ht_CertIssuer = NULL;
    txn->ht_CertCommonName = NULL;
    txn->ht_CertNotBefore = NULL;
    txn->ht_CertNotAfter = NULL;
    txn->ht_CertSerial = NULL;
    txn->ht_CertPresent = FALSE;
    txn->ht_CertVerifyResult = 0;
}

static VOID
ht_txn_copy_peer_cert(struct HttpTransaction *txn, struct HtConnection *conn)
{
    struct HttpSslPeerCert tmp;

    if (txn == NULL || conn == NULL || conn->hc_SslCtx == NULL) {
        return;
    }
    ht_txn_free_peer_cert(txn);
    ht_ssl_peer_cert_copy(&tmp, conn->hc_SslCtx);
    txn->ht_CertPresent = (tmp.hpc_Subject != NULL) ? TRUE : FALSE;
    txn->ht_CertSubject = tmp.hpc_Subject;
    txn->ht_CertIssuer = tmp.hpc_Issuer;
    txn->ht_CertCommonName = tmp.hpc_CommonName;
    txn->ht_CertNotBefore = tmp.hpc_NotBefore;
    txn->ht_CertNotAfter = tmp.hpc_NotAfter;
    txn->ht_CertSerial = tmp.hpc_Serial;
    txn->ht_CertVerifyResult = tmp.hpc_VerifyResult;
}

static VOID
ht_txn_free_fields(struct HttpTransaction *txn)
{
    if (txn == NULL) {
        return;
    }
    ht_txn_clear_req_headers(txn);
    if (txn->ht_Url) {
        ht_free(txn->ht_Url);
    }
    if (txn->ht_Method) {
        ht_free(txn->ht_Method);
    }
    if (txn->ht_Referer) {
        ht_free(txn->ht_Referer);
    }
    if (txn->ht_UserAgent) {
        ht_free(txn->ht_UserAgent);
    }
    if (txn->ht_PostBody) {
        ht_free(txn->ht_PostBody);
    }
    if (txn->ht_IfModifiedSince) {
        ht_free(txn->ht_IfModifiedSince);
    }
    if (txn->ht_IfNoneMatch) {
        ht_free(txn->ht_IfNoneMatch);
    }
    if (txn->ht_AuthRealm) {
        ht_free(txn->ht_AuthRealm);
    }
    if (txn->ht_BasicAuth) {
        ht_free(txn->ht_BasicAuth);
    }
    if (txn->ht_BasicProxyAuth) {
        ht_free(txn->ht_BasicProxyAuth);
    }
    if (txn->ht_StatusLine) {
        ht_free(txn->ht_StatusLine);
    }
    if (txn->ht_RedirectUrl) {
        ht_free(txn->ht_RedirectUrl);
    }
    if (txn->ht_DecodeBuf) {
        ht_free(txn->ht_DecodeBuf);
    }
    ht_zlib_inflate_end(txn);
    ht_txn_free_peer_cert(txn);
}

static VOID
ht_txn_clear_resp_state(struct HttpTransaction *txn)
{
    struct HttpHeader *hh;
    struct HttpHeader *hnext;

    if (txn == NULL) {
        return;
    }
    if (txn->ht_StatusLine) {
        ht_free(txn->ht_StatusLine);
        txn->ht_StatusLine = NULL;
    }
    if (txn->ht_RedirectUrl) {
        ht_free(txn->ht_RedirectUrl);
        txn->ht_RedirectUrl = NULL;
    }
    for (hh = (struct HttpHeader *)txn->ht_RespHeaders.lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = hnext) {
        hnext = (struct HttpHeader *)hh->hh_Node.ln_Succ;
        Remove(&hh->hh_Node);
        if (hh->hh_Name) {
            ht_free(hh->hh_Name);
        }
        if (hh->hh_Value) {
            ht_free(hh->hh_Value);
        }
        ht_free(hh);
    }
    if (txn->ht_DecodeBuf) {
        ht_free(txn->ht_DecodeBuf);
        txn->ht_DecodeBuf = NULL;
    }
    txn->ht_DecodeLen = 0;
    txn->ht_DecodePos = 0;
    txn->ht_DecodeCap = 0;
    ht_zlib_inflate_end(txn);
    txn->ht_ZFinishing = FALSE;
    txn->ht_ZWindowBits = 0;
    txn->ht_WireReceived = 0;
    txn->ht_ChunkRemain = 0;
    txn->ht_BytesReceived = 0;
    txn->ht_ContentLength = -1;
    txn->ht_StatusCode = 0;
    txn->ht_Flags = 0;
    txn->ht_Complete = FALSE;
    Http_cc_reset_accum(&txn->ht_CcAccum);
    ht_txn_free_peer_cert(txn);
}

static VOID
ht_txn_switch_to_get(struct HttpTransaction *txn)
{
    if (txn == NULL) {
        return;
    }
    if (txn->ht_Method) {
        ht_free(txn->ht_Method);
        txn->ht_Method = NULL;
    }
    if (txn->ht_PostBody) {
        ht_free(txn->ht_PostBody);
        txn->ht_PostBody = NULL;
    }
    txn->ht_PostLength = 0;
}

static LONG
ht_txn_perform_once(struct HttpTransaction *txn)
{
    struct ParsedUrl pu;
    BOOL keepalive;
    LONG rc;

    htDbgPut("ht_txn_perform_once");
    if (txn->ht_Url == NULL) {
        return ERROR_HTTP_INVALID_URL;
    }
    rc = ht_url_parse(txn->ht_Url, &pu);
    if (rc != 0) {
        return rc;
    }
    if (pu.pu_Host == NULL) {
        ht_url_free_fields(&pu);
        return ERROR_HTTP_INVALID_URL;
    }
    if (pu.pu_Port == 0) {
        pu.pu_Port = pu.pu_IsSecure ? 443UL : 80UL;
    }
    htDbgPut("ht_txn_perform_once pool_acquire");
    txn->ht_Conn = ht_pool_acquire(HttpBase, txn->ht_Session,
        pu.pu_Host, pu.pu_Port, pu.pu_IsSecure);
    ht_url_free_fields(&pu);
    if (txn->ht_Conn == NULL) {
        return HttpBase ? HttpBase->ahb_LastError : ERROR_HTTP_CONNECT_FAILED;
    }
    htDbgPut("ht_txn_perform_once send_request");
    rc = ht_http_send_request(HttpBase, txn);
    if (rc < 0) {
        ht_pool_release(HttpBase, txn->ht_Conn, FALSE);
        txn->ht_Conn = NULL;
        return rc;
    }
    htDbgPut("ht_txn_perform_once read_headers");
    rc = ht_http_read_response_headers(HttpBase, txn);
    if (rc != 0) {
        ht_pool_release(HttpBase, txn->ht_Conn, FALSE);
        txn->ht_Conn = NULL;
        return rc;
    }
    if (txn->ht_Conn != NULL && txn->ht_Conn->hc_IsSsl) {
        ht_txn_copy_peer_cert(txn, txn->ht_Conn);
    }
    if (txn->ht_Session != NULL && txn->ht_Session->hs_CookieJar != NULL) {
        ht_cookie_ingest_headers(txn->ht_Session->hs_CookieJar, txn);
    }
    /*
     * Redirect hops close the socket without Readdata().
     * Final entity body stays on the open connection; HttpTransactionReadBody
     * drives Readdata() via hc_IoBuf (Readblock loop).
     */
    keepalive = FALSE;
    if (txn->ht_StatusCode >= 300 && txn->ht_StatusCode < 400) {
        ht_pool_release(HttpBase, txn->ht_Conn, FALSE);
        txn->ht_Conn = NULL;
    } else if (txn->ht_NoBody || txn->ht_ContentLength == 0) {
        if (txn->ht_Session != NULL && txn->ht_Session->hs_KeepAlive &&
            (txn->ht_Flags & HTF_KEEPALIVE) && (txn->ht_Flags & HTF_KEEPALIVE_REQ)) {
            keepalive = TRUE;
        }
        ht_pool_release(HttpBase, txn->ht_Conn, keepalive);
        txn->ht_Conn = NULL;
    }
    /* else: body read in HttpTransactionReadBody while ht_Conn remains open */
    txn->ht_Complete = TRUE;
    txn->ht_Flags |= HTF_COMPLETE;
    htDbgPut("ht_txn_perform_once done");
    return 0;
}

struct HttpTransaction *
__ASM__ __SAVE_DS__ NewHttpTransaction(
    __REG__(a0, struct HttpSession *session))
{
    struct HttpTransaction *txn;

    htDbgPut("NewHttpTransaction");
    if (session == NULL || !ht_check_handle(session->hs_Magic, HT_MAGIC_SESSION)) {
        ht_set_error(ERROR_HTTP_INVALID_HANDLE);
        return NULL;
    }
    txn = (struct HttpTransaction *)ht_alloc(sizeof(struct HttpTransaction), MEMF_CLEAR);
    if (txn == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
    }
    txn->ht_Magic = HT_MAGIC_TXN;
    txn->ht_Session = session;
    txn->ht_ContentLength = -1;
    txn->ht_RangeStart = -1;
    txn->ht_RangeEnd = -1;
    NewList(&txn->ht_ReqHeaders);
    NewList(&txn->ht_RespHeaders);
    Http_cc_reset_accum(&txn->ht_CcAccum);
    ht_set_error(0);
    return txn;
}

VOID
__ASM__ __SAVE_DS__ DisposeHttpTransaction(
    __REG__(a0, struct HttpTransaction *txn))
{
    struct HttpHeader *hh;
    struct HttpHeader *next;

    if (txn == NULL) {
        return;
    }
    if (!ht_check_handle(txn->ht_Magic, HT_MAGIC_TXN)) {
        return;
    }
    if (txn->ht_AsyncRunning) {
        ht_txn_abort_for_dispose(txn);
        ht_async_wait(txn, 30);
    }
    if (txn->ht_Conn != NULL) {
        ht_pool_release(HttpBase, txn->ht_Conn, FALSE);
        txn->ht_Conn = NULL;
    }
    for (hh = (struct HttpHeader *)txn->ht_RespHeaders.lh_Head;
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
    txn->ht_Magic = 0;
    ht_txn_free_fields(txn);
    ht_free(txn);
}

LONG
__ASM__ __SAVE_DS__ SetHttpTransactionAttrsA(
    __REG__(a0, struct HttpTransaction *txn),
    __REG__(a1, struct TagItem *tags))
{
    struct TagItem *t;

    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (tags == NULL) {
        return 1;
    }
    for (t = tags; t->ti_Tag != TAG_DONE; t++) {
        switch (t->ti_Tag) {
        case HTTA_URL:
            if (txn->ht_Url) {
                ht_free(txn->ht_Url);
            }
            txn->ht_Url = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTTA_METHOD:
            if (txn->ht_Method) {
                ht_free(txn->ht_Method);
            }
            txn->ht_Method = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTTA_POST_BODY:
            if (txn->ht_PostBody) {
                ht_free(txn->ht_PostBody);
            }
            txn->ht_PostBody = ht_strdup((STRPTR)t->ti_Data);
            if (txn->ht_PostBody != NULL) {
                txn->ht_PostLength = (ULONG)strlen((char *)txn->ht_PostBody);
            }
            break;
        case HTTA_POST_LENGTH:
            txn->ht_PostLength = (ULONG)t->ti_Data;
            break;
        case HTTA_RANGE_START:
            txn->ht_RangeStart = (LONG)t->ti_Data;
            break;
        case HTTA_RANGE_END:
            txn->ht_RangeEnd = (LONG)t->ti_Data;
            break;
        case HTTA_IF_MODIFIED_SINCE:
            if (txn->ht_IfModifiedSince) {
                ht_free(txn->ht_IfModifiedSince);
            }
            txn->ht_IfModifiedSince = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTTA_IF_NONE_MATCH:
            if (txn->ht_IfNoneMatch) {
                ht_free(txn->ht_IfNoneMatch);
            }
            txn->ht_IfNoneMatch = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTTA_NO_CACHE:
            txn->ht_NoCache = (BOOL)t->ti_Data;
            break;
        case HTTA_NO_BODY:
            txn->ht_NoBody = (BOOL)t->ti_Data;
            break;
        case HTTA_THROTTLE_BPS:
            txn->ht_ThrottleBps = (ULONG)t->ti_Data;
            break;
        case HTTA_REFERER:
            if (txn->ht_Referer) {
                ht_free(txn->ht_Referer);
            }
            txn->ht_Referer = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTTA_USERAGENT:
            if (txn->ht_UserAgent) {
                ht_free(txn->ht_UserAgent);
            }
            txn->ht_UserAgent = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTTA_RETRY_AUTH:
            txn->ht_RetryAuth = (BOOL)t->ti_Data;
            break;
        case HTTA_NOTIFY_TASK:
            txn->ht_NotifyTask = (struct Task *)t->ti_Data;
            break;
        case HTTA_NOTIFY_SIGNAL:
            txn->ht_NotifySignal = (ULONG)t->ti_Data;
            break;
        default:
            break;
        }
    }
    return 1;
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionAddHeader(
    __REG__(a0, struct HttpTransaction *txn),
    __REG__(a1, STRPTR hdr_name),
    __REG__(a2, STRPTR value))
{
    struct HttpTransaction *tx;
    STRPTR name;
    STRPTR val;
    struct HttpHeader *hh;

    tx = txn;
    name = hdr_name;
    val = value;
    if (!ht_check_handle(tx ? tx->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (name == NULL || val == NULL) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    hh = (struct HttpHeader *)ht_alloc(sizeof(struct HttpHeader), MEMF_CLEAR);
    if (hh == NULL) {
        return ht_lvo_status(ERROR_HTTP_OUT_OF_MEMORY);
    }
    hh->hh_Name = ht_strdup(name);
    hh->hh_Value = ht_strdup(val);
    if (hh->hh_Name == NULL || hh->hh_Value == NULL) {
        if (hh->hh_Name) {
            ht_free(hh->hh_Name);
        }
        if (hh->hh_Value) {
            ht_free(hh->hh_Value);
        }
        ht_free(hh);
        return ht_lvo_status(ERROR_HTTP_OUT_OF_MEMORY);
    }
    AddTail(&tx->ht_ReqHeaders, &hh->hh_Node);
    return 1;
}

VOID
__ASM__ __SAVE_DS__ HttpTransactionClearHeaders(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (txn == NULL || !ht_check_handle(txn->ht_Magic, HT_MAGIC_TXN)) {
        return;
    }
    ht_txn_clear_req_headers(txn);
}

LONG
ht_txn_perform_sync(struct HttpTransaction *txn)
{
    ULONG redirects;
    LONG rc;
    STRPTR newurl;

    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (HttpBase == NULL) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (ht_check_txn_abort(txn)) {
        ht_set_txn_error(txn, ERROR_HTTP_ABORTED);
        ht_hook_error(txn, ERROR_HTTP_ABORTED);
        return ht_lvo_status(ERROR_HTTP_ABORTED);
    }
    htDbgPut("ht_txn_perform_sync");
    redirects = 0;
    for (;;) {
        if (ht_check_txn_abort(txn)) {
            ht_set_txn_error(txn, ERROR_HTTP_ABORTED);
            ht_hook_error(txn, ERROR_HTTP_ABORTED);
            return ht_lvo_status(ERROR_HTTP_ABORTED);
        }
        rc = ht_txn_perform_once(txn);
        if (rc != 0) {
            ht_set_txn_error(txn, rc);
            ht_hook_error(txn, rc);
            return ht_lvo_status(rc);
        }
        if (txn->ht_StatusCode == 401 && txn->ht_Session != NULL &&
            txn->ht_Session->hs_Credentials != NULL &&
            txn->ht_RetryAuth && !txn->ht_AuthTried) {
            if (txn->ht_BasicAuth) {
                ht_free(txn->ht_BasicAuth);
            }
            txn->ht_BasicAuth = ht_auth_basic_encode(
                txn->ht_Session->hs_Credentials);
            if (txn->ht_BasicAuth == NULL) {
                ht_set_txn_error(txn, ERROR_HTTP_OUT_OF_MEMORY);
                ht_hook_error(txn, ERROR_HTTP_OUT_OF_MEMORY);
                return ht_lvo_status(ERROR_HTTP_OUT_OF_MEMORY);
            }
            txn->ht_AuthTried = TRUE;
            ht_txn_clear_resp_state(txn);
            continue;
        }
        if (txn->ht_StatusCode == 407 && txn->ht_Session != NULL &&
            txn->ht_Session->hs_ProxyAuth != NULL &&
            !txn->ht_ProxyAuthTried) {
            if (txn->ht_BasicProxyAuth) {
                ht_free(txn->ht_BasicProxyAuth);
            }
            txn->ht_BasicProxyAuth = ht_auth_basic_encode(
                txn->ht_Session->hs_ProxyAuth);
            if (txn->ht_BasicProxyAuth == NULL) {
                ht_set_txn_error(txn, ERROR_HTTP_OUT_OF_MEMORY);
                ht_hook_error(txn, ERROR_HTTP_OUT_OF_MEMORY);
                return ht_lvo_status(ERROR_HTTP_OUT_OF_MEMORY);
            }
            txn->ht_ProxyAuthTried = TRUE;
            ht_txn_clear_resp_state(txn);
            continue;
        }
        if (txn->ht_StatusCode < 300 || txn->ht_StatusCode >= 400) {
            break;
        }
        if (txn->ht_Session == NULL || !txn->ht_Session->hs_FollowRedirects) {
            break;
        }
        if (txn->ht_RedirectUrl == NULL || txn->ht_RedirectUrl[0] == '\0') {
            break;
        }
        redirects++;
        if (redirects > txn->ht_Session->hs_MaxRedirects) {
            ht_set_txn_error(txn, ERROR_HTTP_TOO_MANY_REDIRECTS);
            ht_hook_error(txn, ERROR_HTTP_TOO_MANY_REDIRECTS);
            return ht_lvo_status(ERROR_HTTP_TOO_MANY_REDIRECTS);
        }
        newurl = ht_join_uri(txn->ht_Url, txn->ht_RedirectUrl);
        if (newurl == NULL) {
            ht_set_txn_error(txn, ERROR_HTTP_OUT_OF_MEMORY);
            ht_hook_error(txn, ERROR_HTTP_OUT_OF_MEMORY);
            return ht_lvo_status(ERROR_HTTP_OUT_OF_MEMORY);
        }
        if (txn->ht_Url) {
            ht_free(txn->ht_Url);
        }
        txn->ht_Url = newurl;
        if (txn->ht_StatusCode == 301 || txn->ht_StatusCode == 302 ||
            txn->ht_StatusCode == 303) {
            ht_txn_switch_to_get(txn);
        }
        ht_txn_clear_resp_state(txn);
    }
    ht_set_txn_error(txn, 0);
    if (!txn->ht_Async) {
        ht_hook_complete(txn);
    }
    return 1;
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionPerform(
    __REG__(a0, struct HttpTransaction *txn))
{
    LONG rc;

    rc = ht_txn_perform_sync(txn);
    return rc;
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionPerformAsync(
    __REG__(a0, struct HttpTransaction *txn))
{
    LONG rc;

    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (txn->ht_NotifyTask == NULL || txn->ht_NotifySignal == 0) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    txn->ht_Async = TRUE;
    txn->ht_Complete = FALSE;
    txn->ht_Flags &= ~HTF_COMPLETE;
    rc = ht_async_start(txn);
    if (rc != 0) {
        ht_set_txn_error(txn, rc);
        return ht_lvo_status(rc);
    }
    return 1;
}

BOOL
__ASM__ __SAVE_DS__ HttpTransactionIsComplete(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (txn == NULL || !ht_check_handle(txn->ht_Magic, HT_MAGIC_TXN)) {
        return FALSE;
    }
    if (txn->ht_AsyncRunning) {
        return FALSE;
    }
    return txn->ht_Complete;
}

LONG
__ASM__ __SAVE_DS__ WaitHttpTransaction(
    __REG__(a0, struct HttpTransaction *txn),
    __REG__(d0, ULONG timeout_secs))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (txn->ht_Complete) {
        return txn->ht_AsyncResult ? 1 : ht_lvo_status(txn->ht_LastError);
    }
    if (txn->ht_AsyncRunning) {
        ht_async_wait(txn, timeout_secs);
    }
    if (txn->ht_Complete) {
        return txn->ht_AsyncResult ? 1 : ht_lvo_status(txn->ht_LastError);
    }
    return 0;
}

VOID
__ASM__ __SAVE_DS__ AbortHttpTransaction(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (txn == NULL || !ht_check_handle(txn->ht_Magic, HT_MAGIC_TXN)) {
        return;
    }
    ht_txn_abort_for_dispose(txn);
}

static VOID
ht_txn_abort_for_dispose(struct HttpTransaction *txn)
{
    if (txn == NULL) {
        return;
    }
    txn->ht_Flags |= HTF_ABORTED;
    ht_async_cancel(txn);
    if (txn->ht_Conn != NULL) {
        ht_pool_release(HttpBase, txn->ht_Conn, FALSE);
        txn->ht_Conn = NULL;
    }
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionGetStatusCode(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return 0;
    }
    return txn->ht_StatusCode;
}

STRPTR
__ASM__ __SAVE_DS__ HttpTransactionGetStatusLine(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return NULL;
    }
    return txn->ht_StatusLine;
}

STRPTR
__ASM__ __SAVE_DS__ HttpTransactionRespHeader(
    __REG__(a0, struct HttpTransaction *txn),
    __REG__(a1, STRPTR header_name))
{
    struct HttpHeader *hh;

    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return NULL;
    }
    if (header_name == NULL) {
        return NULL;
    }
    for (hh = (struct HttpHeader *)txn->ht_RespHeaders.lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = (struct HttpHeader *)hh->hh_Node.ln_Succ) {
        if (hh->hh_Name != NULL && stricmp((char *)hh->hh_Name, (char *)header_name) == 0) {
            return hh->hh_Value;
        }
    }
    return NULL;
}

struct List *
__ASM__ __SAVE_DS__ HttpTransactionRespHeaders(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return NULL;
    }
    return &txn->ht_RespHeaders;
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionReadBody(
    __REG__(a0, struct HttpTransaction *txn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG buflen))
{
    struct HttpTransaction *tx;
    APTR dest;
    ULONG blen;
    LONG rc;
    LONG n;

    /*
     * Copy a0 before touching a1/d0: SAS/C may use a0 as scratch when
     * spilling register parameters to locals.
     */
    tx = txn;
    dest = buffer;
    blen = buflen;
    if (blen > HT_IOBUF_SIZE) {
        blen = HT_IOBUF_SIZE;
    }
    if (!ht_check_handle(tx ? tx->ht_Magic : 0, HT_MAGIC_TXN)) {
        ht_set_txn_error(tx, ERROR_HTTP_INVALID_HANDLE);
        return 0;
    }
    if (dest == NULL || blen == 0) {
        return 0;
    }
    rc = ht_http_read_body(HttpBase, tx, dest, blen);
    if (rc <= 0) {
        return 0;
    }
    n = rc;
    if (n > (LONG)blen) {
        n = (LONG)blen;
    }
    return n;
}

STRPTR
__ASM__ __SAVE_DS__ HttpTransactionGetRedirectLocation(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return NULL;
    }
    return txn->ht_RedirectUrl;
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionGetContentLength(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return -1;
    }
    /*
     * Content-Length on the wire is the compressed octet count when
     * Content-Encoding is active; decoded size is unknown until ReadBody.
     */
    if (txn->ht_Flags & HTF_GZIP) {
        return -1;
    }
    return txn->ht_ContentLength;
}

ULONG
__ASM__ __SAVE_DS__ HttpTransactionGetBytesReceived(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return 0;
    }
    return txn->ht_BytesReceived;
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionGetTiming(
    __REG__(a0, struct HttpTransaction *txn),
    __REG__(a1, struct HttpTiming *timing))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (timing == NULL) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    *timing = txn->ht_Timing;
    return 1;
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionGetLastError(
    __REG__(a0, struct HttpTransaction *txn))
{
    if (!ht_check_handle(txn ? txn->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    return txn->ht_LastError;
}

LONG
__ASM__ __SAVE_DS__ SetHttpTransactionHook(
    __REG__(a0, struct HttpTransaction *txn),
    __REG__(d0, ULONG type),
    __REG__(a1, struct Hook *hook))
{
    struct HttpTransaction *tx;
    ULONG hooktype;
    struct Hook *hk;

    tx = txn;
    hooktype = type;
    hk = hook;
    if (!ht_check_handle(tx ? tx->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (hooktype < 1 || hooktype > 8) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    tx->ht_Hooks[hooktype - 1] = hk;
    return 1;
}

LONG
__ASM__ __SAVE_DS__ HttpTransactionGetPeerCert(
    __REG__(a0, struct HttpTransaction *txn),
    __REG__(a1, struct HttpSslPeerCert *cert))
{
    struct HttpTransaction *tx;
    struct HttpSslPeerCert *out;

    tx = txn;
    out = cert;
    if (!ht_check_handle(tx ? tx->ht_Magic : 0, HT_MAGIC_TXN)) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    if (out == NULL) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }
    out->hpc_Subject = NULL;
    out->hpc_Issuer = NULL;
    out->hpc_CommonName = NULL;
    out->hpc_NotBefore = NULL;
    out->hpc_NotAfter = NULL;
    out->hpc_Serial = NULL;
    out->hpc_VerifyResult = 0;
    if (!tx->ht_CertPresent) {
        return 0;
    }
    if (tx->ht_CertSubject) {
        out->hpc_Subject = ht_strdup(tx->ht_CertSubject);
    }
    if (tx->ht_CertIssuer) {
        out->hpc_Issuer = ht_strdup(tx->ht_CertIssuer);
    }
    if (tx->ht_CertCommonName) {
        out->hpc_CommonName = ht_strdup(tx->ht_CertCommonName);
    }
    if (tx->ht_CertNotBefore) {
        out->hpc_NotBefore = ht_strdup(tx->ht_CertNotBefore);
    }
    if (tx->ht_CertNotAfter) {
        out->hpc_NotAfter = ht_strdup(tx->ht_CertNotAfter);
    }
    if (tx->ht_CertSerial) {
        out->hpc_Serial = ht_strdup(tx->ht_CertSerial);
    }
    out->hpc_VerifyResult = tx->ht_CertVerifyResult;
    return 1;
}

VOID
__ASM__ __SAVE_DS__ HttpPeerCertFree(
    __REG__(a0, struct HttpSslPeerCert *cert))
{
    ht_peer_cert_free_fields(cert);
}
