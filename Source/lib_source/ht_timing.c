/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_timing.c - HttpTransactionGetTiming instrumentation
 *
 * ConnectMs  - TCP (+ TLS) setup for each non-pooled hop; 0 when keep-alive
 *              reuses an idle socket.
 * TtfbMs     - HttpTransactionPerform start to first response octet on the
 *              final hop (redirects overwrite intermediate values).
 * TotalMs    - HttpTransactionPerform start to entity-body EOF, or to the end
 *              of Perform when there is no body (HEAD, Content-Length: 0).
 */

#define __USE_SYSBASE

#include <exec/types.h>

#include <devices/timer.h>

#include <libraries/amihttp.h>

#include "private/ht_internal.h"

VOID
ht_timing_begin_sync(struct HttpTransaction *txn)
{
    struct timeval tv;

    if (txn == NULL) {
        return;
    }
    txn->ht_Timing.ht_ConnectMs = 0UL;
    txn->ht_Timing.ht_TtfbMs = 0UL;
    txn->ht_Timing.ht_TotalMs = 0UL;
    txn->ht_TvPerformSet = FALSE;
    txn->ht_TvHopConnectSet = FALSE;
    if (ht_timer_get_time(&tv)) {
        txn->ht_TvPerform = tv;
        txn->ht_TvPerformSet = TRUE;
    }
}

VOID
ht_timing_hop_begin(struct HttpTransaction *txn)
{
    struct timeval tv;

    if (txn == NULL) {
        return;
    }
    if (!ht_timer_get_time(&tv)) {
        txn->ht_TvHopConnectSet = FALSE;
        return;
    }
    txn->ht_TvHopConnect = tv;
    txn->ht_TvHopConnectSet = TRUE;
}

VOID
ht_timing_connect_done(struct HttpTransaction *txn, BOOL reused)
{
    struct timeval tv;
    ULONG ms;

    if (txn == NULL || !txn->ht_TvHopConnectSet) {
        return;
    }
    if (reused) {
        return;
    }
    if (!ht_timer_get_time(&tv)) {
        return;
    }
    ms = ht_timer_delta_ms(&txn->ht_TvHopConnect, &tv);
    txn->ht_Timing.ht_ConnectMs += ms;
}

VOID
ht_timing_first_byte(struct HttpTransaction *txn)
{
    struct timeval tv;

    if (txn == NULL || !txn->ht_TvPerformSet) {
        return;
    }
    if (!ht_timer_get_time(&tv)) {
        return;
    }
    txn->ht_Timing.ht_TtfbMs = ht_timer_delta_ms(&txn->ht_TvPerform, &tv);
}

VOID
ht_timing_no_body_done(struct HttpTransaction *txn)
{
    struct timeval tv;

    if (txn == NULL || !txn->ht_TvPerformSet) {
        return;
    }
    if (txn->ht_Timing.ht_TotalMs != 0UL) {
        return;
    }
    if (!ht_timer_get_time(&tv)) {
        return;
    }
    txn->ht_Timing.ht_TotalMs = ht_timer_delta_ms(&txn->ht_TvPerform, &tv);
}

VOID
ht_timing_body_done(struct HttpTransaction *txn)
{
    struct timeval tv;

    if (txn == NULL || !txn->ht_TvPerformSet) {
        return;
    }
    if (!ht_timer_get_time(&tv)) {
        return;
    }
    txn->ht_Timing.ht_TotalMs = ht_timer_delta_ms(&txn->ht_TvPerform, &tv);
}

ULONG
ht_timing_elapsed_ms(struct HttpTransaction *txn)
{
    struct timeval tv;

    if (txn == NULL || !txn->ht_TvPerformSet) {
        return 0UL;
    }
    if (!ht_timer_get_time(&tv)) {
        return 0UL;
    }
    return ht_timer_delta_ms(&txn->ht_TvPerform, &tv);
}

/*
 * Effective per-operation wait budget: min(per_op_secs, total timeout remaining).
 * Returns 0 when no per-op limit (legacy blocking recv) unless total timeout
 * has expired (handled by ht_check_txn_abort before I/O).
 */
ULONG
ht_timeout_resolve(struct HttpTransaction *txn, ULONG per_op_secs)
{
    ULONG total;
    ULONG elapsed;
    ULONG remain;

    if (txn == NULL || txn->ht_Session == NULL) {
        return per_op_secs;
    }
    total = txn->ht_Session->hs_TotalTimeout;
    if (total == 0UL || !txn->ht_TvPerformSet) {
        return per_op_secs;
    }
    elapsed = ht_timing_elapsed_ms(txn) / 1000UL;
    if (elapsed >= total) {
        return 0UL;
    }
    remain = total - elapsed;
    if (per_op_secs == 0UL || remain < per_op_secs) {
        return remain;
    }
    return per_op_secs;
}
