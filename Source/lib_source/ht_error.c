/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 */

#define __USE_SYSBASE

#include <exec/types.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "private/ht_internal.h"

extern struct AmiHttpBase *HttpBase;

VOID
ht_lvo_bind(struct AmiHttpBase *base)
{
    HttpBase = base;
    ht_sync_proto_bases(base);
}

VOID
ht_set_error(LONG code)
{
    if (HttpBase != NULL) {
        HttpBase->ahb_LastError = code;
    }
}

VOID
ht_set_txn_error(struct HttpTransaction *txn, LONG code)
{
    ht_set_error(code);
    if (txn != NULL) {
        txn->ht_LastError = code;
    }
}

BOOL
ht_check_handle(ULONG magic, ULONG expected)
{
    if (magic != expected) {
        ht_set_error(ERROR_HTTP_INVALID_HANDLE);
        return FALSE;
    }
    return TRUE;
}

/*
 * Amiga convention (dos.library IoErr model): return FALSE on failure
 * after recording the ERROR_HTTP_* code via SetHttpError().
 */
LONG
ht_lvo_status(LONG rc)
{
    if (rc != 0) {
        ht_set_error(rc);
        return 0;
    }
    return 1;
}

/*
 * negative wire error -> positive ERROR_HTTP_*.
 */
LONG
ht_wire_to_status(LONG n)
{
    if (n < 0) {
        return -n;
    }
    return 0;
}
