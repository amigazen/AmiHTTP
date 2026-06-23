/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * async_demo.c - Tier 2 async HttpTransaction usage sketch (browser AJAX pattern)
 */

#include <exec/types.h>
#include <exec/exec.h>
#include <dos/dos.h>

#include <libraries/amihttp.h>
#include <proto/amihttp.h>
#include <proto/dos.h>
#include <proto/exec.h>

static VOID
ht_dbg(STRPTR step)
{
    Printf("async_demo: >>> %s\n", step);
    Flush(Output());
}

int main(int argc, char **argv)
{
    struct HttpSession *session;
    struct HttpTransaction *txn;
    LONG err;
    LONG status;
    LONG n;
    ULONG total;
    ULONG notify_sig;
    UBYTE buf[4096];
    STRPTR url;
    STRPTR ctype;

    ht_dbg("start");

    if (argc < 2) {
        Printf("Usage: async_demo <url>\n");
        return 20;
    }

    url = (STRPTR)argv[1];
    notify_sig = (ULONG)-1;
    Printf("async_demo: url='%s'\n", url);
    Flush(Output());

    ht_dbg("OpenLibrary(amihttp)");
    HttpBase = OpenLibrary(AMIHTTPNAME, AMIHTTPVERSION);
    if (HttpBase == NULL) {
        Printf("amihttp.library not found\n");
        return 20;
    }

    ht_dbg("NewHttpSession");
    session = NewHttpSession();
    if (session == NULL) {
        CloseLibrary(HttpBase);
        return 20;
    }

    ht_dbg("SetHttpSessionAttrs");
    SetHttpSessionAttrs(
        session,
        HTSA_USERAGENT,        (ULONG)"async_demo/1.0",
        HTSA_FOLLOW_REDIRECTS, (ULONG)FALSE,
        HTSA_ACCEPT_ENCODING,  (ULONG)"gzip",
        TAG_DONE);

    ht_dbg("NewHttpTransaction");
    txn = NewHttpTransaction(session);
    if (txn == NULL) {
        DisposeHttpSession(session);
        CloseLibrary(HttpBase);
        return 20;
    }

    ht_dbg("SetHttpTransactionAttrs");
    notify_sig = AllocSignal(-1L);
    if (notify_sig == (ULONG)-1) {
        Printf("async_demo: AllocSignal failed\n");
        DisposeHttpTransaction(txn);
        DisposeHttpSession(session);
        CloseLibrary(HttpBase);
        return 20;
    }
    SetHttpTransactionAttrs(
        txn,
        HTTA_URL,             (ULONG)url,
        HTTA_METHOD,          (ULONG)"GET",
        HTTA_NOTIFY_TASK,     (ULONG)FindTask(NULL),
        HTTA_NOTIFY_SIGNAL,   notify_sig,
        TAG_DONE);

    ht_dbg("HttpTransactionPerformAsync");
    err = HttpTransactionPerformAsync(txn);
    ht_dbg("HttpTransactionPerformAsync returned");
    if (!err) {
        char errbuf[128];

        HttpFault(HttpError(), (STRPTR)"HttpTransactionPerformAsync",
            (STRPTR)errbuf, (LONG)sizeof(errbuf));
        Printf("%s\n", errbuf);
        DisposeHttpTransaction(txn);
        DisposeHttpSession(session);
        CloseLibrary(HttpBase);
        return 20;
    }

    ht_dbg("wait loop");
    while (!HttpTransactionIsComplete(txn)) {
        err = WaitHttpTransaction(txn, 1);
        if (HttpError() == ERROR_HTTP_ABORTED) {
            break;
        }
    }
    ht_dbg("wait loop done");

    status = HttpTransactionGetStatusCode(txn);
    ctype = HttpTransactionRespHeader(txn, (STRPTR)"Content-Type");
    Printf("HTTP %ld", status);
    if (ctype != NULL) {
        Printf(" (%s)", ctype);
    }
    Printf("\n");

    if (status >= 300 && status < 400) {
        Printf("Redirect to: %s\n",
            HttpTransactionGetRedirectLocation(txn));
    } else if (status == 200) {
        total = 0;
        ht_dbg("ReadBody loop");
        for (;;) {
            n = HttpTransactionReadBody(txn, (APTR)buf, (ULONG)sizeof(buf));
            if (n == 0) {
                break;
            }
            total += (ULONG)n;
            /* AJAX runtime delivers buf chunk to script engine here */
        }
        Printf("Received %lu bytes\n", total);
    }

    ht_dbg("cleanup");
    if (notify_sig != (ULONG)-1) {
        FreeSignal(notify_sig);
    }
    DisposeHttpTransaction(txn);
    DisposeHttpSession(session);
    CloseLibrary(HttpBase);

    return 0;
}
