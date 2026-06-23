/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_async.c - Worker task for HttpTransactionPerformAsync / WaitHttpTransaction
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/tasks.h>
#include <string.h>

#include <proto/exec.h>
#include <proto/alib.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "private/ht_internal.h"
#include "private/ht_hooks.h"

#define HT_ASYNC_STACK  8192

extern struct AmiHttpBase *HttpBase;

struct HtAsyncJob
{
    struct HttpTransaction *hj_Txn;
    struct AmiHttpBase     *hj_Base;
    struct Task            *hj_Worker;
    LONG                    hj_Result;
};

/* Forward from transaction.c */
LONG ht_txn_perform_sync(struct HttpTransaction *txn);

static VOID
ht_async_signal(struct HttpTransaction *txn)
{
    struct Task *task;
    ULONG sig;

    if (txn == NULL) {
        return;
    }
    task = txn->ht_NotifyTask;
    sig = txn->ht_NotifySignal;
    if (task != NULL && sig != 0) {
        Signal(task, 1UL << sig);
    }
}

static VOID
ht_async_worker(APTR args)
{
    struct HtAsyncJob *job;
    struct HttpTransaction *txn;

    job = (struct HtAsyncJob *)args;
    if (job == NULL) {
        RemTask(NULL);
        return;
    }
    ht_lvo_bind(job->hj_Base);
    txn = job->hj_Txn;
    job->hj_Result = ht_txn_perform_sync(txn);
    if (txn != NULL) {
        txn->ht_AsyncRunning = FALSE;
        txn->ht_AsyncResult = job->hj_Result;
        if (job->hj_Result) {
            ht_hook_complete(txn);
        }
        ht_async_signal(txn);
    }
    ht_free(job);
    RemTask(NULL);
}

LONG
ht_async_start(struct HttpTransaction *txn)
{
    struct HtAsyncJob *job;
    struct Task *task;
    BYTE name[24];

    if (txn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (txn->ht_AsyncRunning) {
        return ERROR_HTTP_PROTOCOL;
    }
    job = (struct HtAsyncJob *)ht_alloc(sizeof(struct HtAsyncJob), MEMF_CLEAR);
    if (job == NULL) {
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    job->hj_Txn = txn;
    job->hj_Base = HttpBase;
    strcpy((char *)name, "amihttp");
    task = CreateTask((STRPTR)name, 0, (APTR)ht_async_worker, HT_ASYNC_STACK,
        (APTR)job, 0);
    if (task == NULL) {
        ht_free(job);
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    job->hj_Worker = task;
    txn->ht_AsyncRunning = TRUE;
    txn->ht_Async = TRUE;
    txn->ht_WorkerTask = task;
    return 0;
}

VOID
ht_async_wait(struct HttpTransaction *txn, ULONG timeout_secs)
{
    ULONG mask;
    ULONG elapsed;
    ULONG tick;

    if (txn == NULL) {
        return;
    }
    if (txn->ht_Complete || !txn->ht_AsyncRunning) {
        return;
    }
    if (txn->ht_NotifyTask != NULL && txn->ht_NotifySignal != 0) {
        mask = 1UL << txn->ht_NotifySignal;
        if (timeout_secs == 0) {
            Wait(mask);
            return;
        }
        elapsed = 0;
        while (txn->ht_AsyncRunning && elapsed < timeout_secs) {
            if (Wait(mask | SIGBREAKF_CTRL_C) & mask) {
                return;
            }
            Delay(50);
            elapsed++;
        }
        return;
    }
    /* No notify signal: poll until complete or timeout. */
    elapsed = 0;
    tick = (timeout_secs == 0) ? 0xFFFFFFFFUL : timeout_secs;
    while (txn->ht_AsyncRunning && elapsed < tick) {
        Delay(50);
        elapsed++;
    }
}

VOID
ht_async_cancel(struct HttpTransaction *txn)
{
    if (txn == NULL) {
        return;
    }
    if (txn->ht_WorkerTask != NULL && txn->ht_AsyncRunning) {
        /*
         * AbortHttpTransaction drops the connection; worker may still exit
         * from ht_txn_perform_sync with an error.
         */
        txn->ht_WorkerTask = NULL;
    }
}
