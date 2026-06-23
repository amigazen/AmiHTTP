/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_zlib.c - gzip/deflate decode via z.library LVOs
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <string.h>

#include <proto/exec.h>
#include <proto/z.h>

#include <libraries/z.h>
#include <libraries/amihttp.h>
#include <amihttp/amihttpbase.h>

#include "private/ht_internal.h"
#include "private/ht_zlib.h"

extern struct Library *ZBase;
extern struct AmiHttpBase *HttpBase;

BOOL
ht_zlib_ensure(struct AmiHttpBase *base)
{
    if (base == NULL) {
        return FALSE;
    }
    if (base->ahb_ZBase == NULL) {
        base->ahb_ZBase = OpenLibrary((STRPTR)"z.library", 2);
        if (base->ahb_ZBase != NULL) {
            base->ahb_ZDecodeReady = TRUE;
            ZBase = base->ahb_ZBase;
        }
    }
    if (base->ahb_ZBase != NULL) {
        ZBase = base->ahb_ZBase;
    }
    if (base->ahb_ZDecodeReady && base->ahb_ZBase != NULL) {
        return TRUE;
    }
    return FALSE;
}

LONG
ht_zlib_inflate_begin(struct HttpTransaction *txn, LONG windowBits)
{
    LONG rc;

    if (txn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (txn->ht_ZInited) {
        return 0;
    }
    if (HttpBase == NULL || !ht_zlib_ensure(HttpBase)) {
        return ERROR_HTTP_NOT_IMPLEMENTED;
    }
    memset(&txn->ht_ZStream, 0, sizeof(txn->ht_ZStream));
    /* zalloc/zfree left NULL: z.library routes through its pooled malloc.c */
    rc = InflateInit2(&txn->ht_ZStream, windowBits);
    if (rc != Z_OK) {
        return ERROR_HTTP_PROTOCOL;
    }
    txn->ht_ZInited = TRUE;
    return 0;
}

/*
 * Allocate the wire buffer used as z_stream.next_in across ReadBody calls.
 * Stack storage is unsafe: inflate may retain unconsumed input after return.
 */
LONG
ht_zlib_wire_buf_ensure(struct HttpTransaction *txn)
{
    if (txn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (txn->ht_ZWireBuf != NULL) {
        return 0;
    }
    txn->ht_ZWireBuf = (UBYTE *)ht_alloc(HT_GZIP_WIRE_CHUNK, MEMF_CLEAR);
    if (txn->ht_ZWireBuf == NULL) {
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    return 0;
}

VOID
ht_zlib_inflate_end(struct HttpTransaction *txn)
{
    if (txn == NULL || !txn->ht_ZInited) {
        return;
    }
    InflateEnd(&txn->ht_ZStream);
    memset(&txn->ht_ZStream, 0, sizeof(txn->ht_ZStream));
    txn->ht_ZInited = FALSE;
    if (txn->ht_ZWireBuf != NULL) {
        ht_free(txn->ht_ZWireBuf);
        txn->ht_ZWireBuf = NULL;
    }
}
