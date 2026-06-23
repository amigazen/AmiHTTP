/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_hooks.c - CallHookPkt dispatch for session/transaction hooks
 */

#define __USE_SYSBASE

#include <exec/types.h>

#include <proto/exec.h>
#include <proto/utility.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "private/ht_internal.h"
#include "private/ht_hooks.h"

extern struct AmiHttpBase *HttpBase;

static VOID
ht_hook_call(struct HttpTransaction *txn, ULONG hooktype, APTR object, APTR message)
{
    struct Hook *hk;

    hk = NULL;
    if (txn != NULL && hooktype >= 1 && hooktype <= 8) {
        hk = txn->ht_Hooks[hooktype - 1];
    }
    if (hk == NULL && txn != NULL && txn->ht_Session != NULL &&
        hooktype >= 1 && hooktype <= 8) {
        hk = txn->ht_Session->hs_Hooks[hooktype - 1];
    }
    if (hk == NULL && HttpBase != NULL && hooktype == HTHK_LOG) {
        /* HTBT_LOG_HOOK is not a struct Hook slot; reserved for v2. */
    }
    if (hk != NULL) {
        CallHookPkt(hk, object, message);
    }
}

BOOL
ht_check_break(struct AmiHttpBase *base)
{
    ULONG pending;

    if (base == NULL || base->ahb_BreakMask == 0) {
        return FALSE;
    }
    pending = SetSignal(0L, base->ahb_BreakMask);
    if (pending & base->ahb_BreakMask) {
        return TRUE;
    }
    return FALSE;
}

BOOL
ht_check_txn_abort(struct HttpTransaction *txn)
{
    if (txn != NULL && (txn->ht_Flags & HTF_ABORTED)) {
        return TRUE;
    }
    if (HttpBase != NULL && ht_check_break(HttpBase)) {
        if (txn != NULL) {
            txn->ht_Flags |= HTF_ABORTED;
        }
        return TRUE;
    }
    return FALSE;
}

VOID
ht_hook_headers_done(struct HttpTransaction *txn)
{
    struct HttpHookHeadersDone msg;

    if (txn == NULL) {
        return;
    }
    msg.hhd_Transaction = txn;
    msg.hhd_StatusCode = txn->ht_StatusCode;
    ht_hook_call(txn, HTHK_HEADERS_DONE, (APTR)txn, (APTR)&msg);
}

VOID
ht_hook_body_chunk(struct HttpTransaction *txn, APTR data, ULONG len)
{
    struct HttpHookBodyChunk msg;

    if (txn == NULL || data == NULL || len == 0) {
        return;
    }
    msg.hbc_Transaction = txn;
    msg.hbc_Data = data;
    msg.hbc_Length = len;
    ht_hook_call(txn, HTHK_BODY_CHUNK, (APTR)txn, (APTR)&msg);
}

VOID
ht_hook_complete(struct HttpTransaction *txn)
{
    struct HttpHookComplete msg;

    if (txn == NULL) {
        return;
    }
    msg.hcp_Transaction = txn;
    msg.hcp_StatusCode = txn->ht_StatusCode;
    msg.hcp_LastError = txn->ht_LastError;
    ht_hook_call(txn, HTHK_COMPLETE, (APTR)txn, (APTR)&msg);
}

VOID
ht_hook_error(struct HttpTransaction *txn, LONG code)
{
    struct HttpHookError msg;

    if (txn == NULL) {
        return;
    }
    msg.her_Transaction = txn;
    msg.her_Code = code;
    ht_hook_call(txn, HTHK_ERROR, (APTR)txn, (APTR)&msg);
}

BOOL
ht_hook_cert_verify(struct HttpTransaction *txn, struct HtSsl *ssl,
    LONG verify_result)
{
    struct HttpHookCertVerify msg;
    struct Hook *hk;
    ULONG ret;

    if (txn == NULL || ssl == NULL) {
        return FALSE;
    }
    memset(&msg, 0, sizeof(msg));
    msg.hcv_Transaction = txn;
    msg.hcv_VerifyResult = verify_result;
    msg.hcv_Accept = FALSE;
    ht_ssl_peer_cert_copy(&msg.hcv_Cert, ssl);
    hk = txn->ht_Hooks[HTHK_CERT_VERIFY - 1];
    if (hk == NULL && txn->ht_Session != NULL) {
        hk = txn->ht_Session->hs_Hooks[HTHK_CERT_VERIFY - 1];
    }
    if (hk == NULL) {
        ht_peer_cert_free_fields(&msg.hcv_Cert);
        return FALSE;
    }
    ret = (ULONG)CallHookPkt(hk, (APTR)txn, (APTR)&msg);
    ht_peer_cert_free_fields(&msg.hcv_Cert);
    if (msg.hcv_Accept) {
        return TRUE;
    }
    return (BOOL)(ret != 0);
}
