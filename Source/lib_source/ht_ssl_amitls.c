/*
 * ht_ssl_amitls.c - amitls.library TLS backend for amihttp.library
 *
 * Built when AMIHTTP_USE_AMITLS is defined (see private/ht_ssl_config.h).
 *
 * TlsWrite/TlsRead return byte counts below ERROR_TLS_NOT_IMPLEMENTED (8800).
 * ERROR_TLS_WANT_READ/WRITE mean WaitSelect on the raw TCP fd and retry (only
 * when ATTA_NON_BLOCKING is set on the connection).
 * Handshake completes on the first successful TlsWrite (deferred attach model).
 * amihttp leaves the TCP socket blocking so BearSSL can wait inside TlsWrite.
 *
 * --- DO NOT CHANGE (verified AGet + ATlsTest live HTTPS, Jun 2026) ---
 *
 * Deferred handshake: TlsAttachSocket only installs BearSSL on the blocking fd;
 * the TLS handshake runs inside the first ht_ssl_send()/TlsWrite(), same as
 * ATlsTest at_https_exchange(). Do NOT call TlsHandshake() at attach time.
 *
 * Blocking socket at attach: do NOT FIONBIO the fd or pass ATTA_NON_BLOCKING /
 * ATTA_EXTERNAL_WAIT on attach. Non-blocking + external-wait regressed AGet
 * (8704) and can wedge BearSSL in RECVREC while only WANT_WRITE is surfaced.
 *
 * Per-connection TlsContext: load trust with ATSA_CA_BUNDLE_PATH only on a
 * connection-local context (ht_ssl_create). Do NOT reuse one session-wide
 * TlsContext with ATSA_SSL_VERIFY baked in — that path regressed verify/8704.
 * Apply verify mode at attach via ATTA_SSL_VERIFY only.
 *
 * ht_ssl_wait_socket: must use blocking WaitSelect (tv_sec = timeout), bound
 * through ht_io_obtain(), not zero-timeout poll loops (ht_wait_socket_io).
 *
 * ht_ssl_send: must TlsTaskAttach() this task's bsdsocket before TlsWrite();
 * without it amitls returns ERROR_TLS_IO -> ERROR_HTTP_SSL_HANDSHAKE (8704).
 *
 * Do NOT mark hs_HandshakeOk or capture peer cert at TlsAttachSocket; cert
 * data is available only after the deferred handshake completes on TlsWrite.
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/semaphores.h>
#include <exec/tasks.h>

#include <proto/exec.h>
#include <proto/alib.h>

extern struct Library *SocketBase;
extern struct Library *TlsBase;

#include <utility/tagitem.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <libraries/amitls.h>
#include <proto/amitls.h>
#include <proto/bsdsocket.h>

#include "private/amihttpbase.h"
#include <libraries/amihttp.h>

#include "private/ht_debug.h"
#include "private/ht_internal.h"
#include "private/ht_hooks.h"
#include "private/ht_ssl.h"
#include "private/ht_ssl_config.h"

extern struct AmiHttpBase *HttpBase;

struct HtTaskSsl
{
    struct Node     ts_Node;
    struct Task    *ts_Task;
    ULONG           ts_RefCount;
    /* TRUE only after TlsTaskAttach() succeeded for this task entry. */
    BOOL            ts_InitOk;
};

static struct List ht_task_ssl_list;
static struct SignalSemaphore ht_task_ssl_sema;
static BOOL ht_task_ssl_inited = FALSE;
static struct SignalSemaphore ht_ssl_global_sema;
static BOOL ht_ssl_global_sema_inited = FALSE;

static void
ht_ssl_task_list_init(void)
{
    if (!ht_task_ssl_inited) {
        NewList(&ht_task_ssl_list);
        InitSemaphore(&ht_task_ssl_sema);
        ht_task_ssl_inited = TRUE;
    }
    if (!ht_ssl_global_sema_inited) {
        InitSemaphore(&ht_ssl_global_sema);
        ht_ssl_global_sema_inited = TRUE;
    }
}

static ULONG
ht_ssl_map_verify(ULONG verify_mode)
{
    if (verify_mode == HTSSL_VERIFY_NONE) {
        return ATSSL_VERIFY_NONE;
    }
    if (verify_mode == HTSSL_VERIFY_PEER_STRICT) {
        return ATSSL_VERIFY_PEER_STRICT;
    }
    return ATSSL_VERIFY_PEER;
}

static ULONG
ht_ssl_base_verify(struct AmiHttpBase *base)
{
    if (base == NULL) {
        return ATSSL_VERIFY_PEER;
    }
    return ht_ssl_map_verify(base->ahb_SslVerify);
}

static BOOL
ht_ssl_tls_ok(LONG rc)
{
    /*
     * TlsWrite/TlsRead success is a byte count below amihttp/amitls error
     * ranges (8700+ / 8800+).  Mapped ERROR_HTTP_* must not look like I/O.
     */
    if (rc <= 0 || rc >= (LONG)ERROR_HTTP_NOT_IMPLEMENTED) {
        return FALSE;
    }
    return TRUE;
}

static BOOL
ht_ssl_tls_want(LONG rc)
{
    if (rc == ERROR_TLS_WANT_READ || rc == ERROR_TLS_WANT_WRITE) {
        return TRUE;
    }
    return FALSE;
}

static LONG
ht_ssl_map_tls_error(LONG tls_rc)
{
    switch (tls_rc) {
    case ERROR_TLS_VERIFY:
        return ERROR_HTTP_SSL_VERIFY;
    case ERROR_TLS_OUT_OF_MEMORY:
        return ERROR_HTTP_OUT_OF_MEMORY;
    case ERROR_TLS_INVALID_HANDLE:
        return ERROR_HTTP_INVALID_HANDLE;
    case ERROR_TLS_READ_TIMEOUT:
        return ERROR_HTTP_READ_TIMEOUT;
    case ERROR_TLS_WRITE_FAILED:
        return ERROR_HTTP_WRITE_FAILED;
    case ERROR_TLS_READ_FAILED:
        return ERROR_HTTP_READ_FAILED;
    case ERROR_TLS_HANDSHAKE:
    case ERROR_TLS_PROTOCOL:
    case ERROR_TLS_IO:
    default:
        return ERROR_HTTP_SSL_HANDSHAKE;
    }
}

static LONG
ht_ssl_wait_socket(struct AmiHttpBase *base, LONG sock, BOOL want_write,
    ULONG timeout_secs)
{
    fd_set rfds;
    fd_set wfds;
    struct timeval tv;
    LONG nfds;
    LONG rc;

    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (sock < 0) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    if (want_write) {
        FD_SET((int)sock, &wfds);
    } else {
        FD_SET((int)sock, &rfds);
    }
    nfds = sock + 1;
    if (timeout_secs == 0) {
        timeout_secs = HT_SOCKET_IO_TIMEOUT;
    }
    tv.tv_sec = (long)timeout_secs;
    tv.tv_usec = 0;
    /*
     * Bind this task's bsdsocket handle before WaitSelect.  AWeb retrieve
     * subprocesses share amihttp's global SocketBase; calling WaitSelect on
     * another task's handle corrupts the TCP stack (hard lockup).  Hold
     * ahb_SocketSema only for the select, not across TlsRead/TlsWrite.
     *
     * Must stay a blocking select (tv_sec > 0).  Zero-timeout polling here
     * regressed HTTPS handshake completion (AGet 8704).
     */
    rc = ht_io_obtain(base);
    if (rc != 0) {
        return ERROR_HTTP_READ_TIMEOUT;
    }
    rc = WaitSelect((int)nfds,
        want_write ? NULL : &rfds,
        want_write ? &wfds : NULL,
        NULL, &tv, NULL);
    ht_io_release(base);
    if (rc <= 0) {
        return ERROR_HTTP_READ_TIMEOUT;
    }
    return 0;
}

static VOID
ht_ssl_apply_base_tags(struct AmiHttpBase *base)
{
    struct TagItem tags[4];
    ULONG n;

    if (base == NULL || TlsBase == NULL) {
        return;
    }
    n = 0;
    tags[n].ti_Tag = ATBT_ERRNOPTR;
    tags[n].ti_Data = (ULONG)(base->ahb_ErrnoPtr != NULL ?
        base->ahb_ErrnoPtr : (APTR)&errno);
    n++;
    tags[n].ti_Tag = ATBT_SSL_VERIFY;
    tags[n].ti_Data = (ULONG)ht_ssl_base_verify(base);
    n++;
    tags[n].ti_Tag = ATBT_CA_BUNDLE_PATH;
    tags[n].ti_Data = (ULONG)(base->ahb_CaBundlePath != NULL ?
        base->ahb_CaBundlePath : (STRPTR)"");
    n++;
    tags[n].ti_Tag = TAG_END;
    TlsBaseTagList(tags);
}

VOID
ht_ssl_sync_base_tags(struct AmiHttpBase *base)
{
    ht_ssl_apply_base_tags(base);
}

LONG
ht_transport_global_init(struct AmiHttpBase *base)
{
    LONG err;

    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    htDbgPut("ht_transport_global_init (amitls)");
    ht_ssl_task_list_init();
    err = ht_ensure_bsdsocket(base);
    if (err != 0) {
        return err;
    }
    ht_sync_proto_bases(base);
    if (base->ahb_SslGlobalOpen) {
        return 0;
    }
    ObtainSemaphore(&ht_ssl_global_sema);
    if (!base->ahb_SslGlobalOpen) {
        if (base->ahb_AmiTlsBase == NULL) {
            htDbgPut("ht_transport_global_init OpenLibrary amitls");
            base->ahb_AmiTlsBase = OpenLibrary(
                (STRPTR)AMITLSNAME, AMITLSVERSION);
            if (base->ahb_AmiTlsBase == NULL) {
                ReleaseSemaphore(&ht_ssl_global_sema);
                return ERROR_HTTP_SSL_HANDSHAKE;
            }
            ht_sync_proto_bases(base);
        }
        ht_ssl_apply_base_tags(base);
        base->ahb_SslGlobalOpen = TRUE;
        ht_sync_proto_bases(base);
    }
    ReleaseSemaphore(&ht_ssl_global_sema);
    return 0;
}

VOID
ht_transport_global_shutdown(struct AmiHttpBase *base)
{
    if (base == NULL) {
        return;
    }
    ObtainSemaphore(&ht_ssl_global_sema);
    base->ahb_SslGlobalOpen = FALSE;
    ReleaseSemaphore(&ht_ssl_global_sema);
}

LONG
ht_transport_task_ssl_ensure(struct AmiHttpBase *base)
{
    struct HtTaskSsl *ts;
    struct Task *task;
    struct Library *sockbase;
    APTR errp;
    LONG rc;

    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    rc = ht_transport_global_init(base);
    if (rc != 0) {
        return rc;
    }
    sockbase = ht_task_current_socket_base(base);
    if (sockbase == NULL) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    ht_ssl_task_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_ssl_sema);
    for (ts = (struct HtTaskSsl *)ht_task_ssl_list.lh_Head;
         ts != NULL && ts->ts_Node.ln_Succ != NULL;
         ts = (struct HtTaskSsl *)ts->ts_Node.ln_Succ) {
        if (ts->ts_Task == task) {
            ht_sync_proto_bases(base);
            errp = ht_task_errno_ptr(base);
            rc = TlsTaskAttach(sockbase, errp);
            if (rc != 0) {
                ReleaseSemaphore(&ht_task_ssl_sema);
                return ht_ssl_map_tls_error(rc);
            }
            ts->ts_RefCount++;
            ReleaseSemaphore(&ht_task_ssl_sema);
            return 0;
        }
    }
    ts = (struct HtTaskSsl *)ht_alloc(sizeof(struct HtTaskSsl), MEMF_CLEAR);
    if (ts == NULL) {
        ReleaseSemaphore(&ht_task_ssl_sema);
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    ts->ts_Task = task;
    ts->ts_RefCount = 1;
    ts->ts_InitOk = FALSE;
    AddHead(&ht_task_ssl_list, &ts->ts_Node);
    ReleaseSemaphore(&ht_task_ssl_sema);

    ht_sync_proto_bases(base);
    errp = ht_task_errno_ptr(base);
    rc = TlsTaskAttach(sockbase, errp);
    if (rc != 0) {
        ObtainSemaphore(&ht_task_ssl_sema);
        Remove(&ts->ts_Node);
        ReleaseSemaphore(&ht_task_ssl_sema);
        ht_free(ts);
        return ht_ssl_map_tls_error(rc);
    }
    ts->ts_InitOk = TRUE;
    return 0;
}

VOID
ht_transport_task_ssl_release(struct AmiHttpBase *base)
{
    struct HtTaskSsl *ts;
    struct Task *task;

    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_ssl_sema);
    for (ts = (struct HtTaskSsl *)ht_task_ssl_list.lh_Head;
         ts != NULL && ts->ts_Node.ln_Succ != NULL;
         ts = (struct HtTaskSsl *)ts->ts_Node.ln_Succ) {
        if (ts->ts_Task == task) {
            if (ts->ts_RefCount > 0) {
                ts->ts_RefCount--;
            }
            if (ts->ts_RefCount == 0) {
                BOOL init_ok;

                init_ok = ts->ts_InitOk;
                Remove(&ts->ts_Node);
                ReleaseSemaphore(&ht_task_ssl_sema);
                if (init_ok) {
                    TlsTaskDetach();
                }
                ht_free(ts);
                if (base != NULL) {
                    ht_transport_bind_socket(base);
                }
                return;
            }
            break;
        }
    }
    ReleaseSemaphore(&ht_task_ssl_sema);
}

VOID
ht_ssl_release_task(struct AmiHttpBase *base)
{
    struct HtTaskSsl *ts;
    struct Task *task;
    BOOL init_ok;

    ht_ssl_task_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_ssl_sema);
    for (ts = (struct HtTaskSsl *)ht_task_ssl_list.lh_Head;
         ts != NULL && ts->ts_Node.ln_Succ != NULL;
         ts = (struct HtTaskSsl *)ts->ts_Node.ln_Succ) {
        if (ts->ts_Task == task) {
            init_ok = ts->ts_InitOk;
            ts->ts_InitOk = FALSE;
            ts->ts_RefCount = 0;
            Remove(&ts->ts_Node);
            ReleaseSemaphore(&ht_task_ssl_sema);
            if (init_ok) {
                TlsTaskDetach();
            }
            ht_free(ts);
            if (base != NULL) {
                ht_transport_bind_socket(base);
            }
            return;
        }
    }
    ReleaseSemaphore(&ht_task_ssl_sema);
}

VOID
ht_transport_task_ssl_shutdown(struct AmiHttpBase *base)
{
    struct HtTaskSsl *ts;
    struct HtTaskSsl *next;

    (void)base;

    ht_ssl_task_list_init();
    ObtainSemaphore(&ht_task_ssl_sema);
    for (ts = (struct HtTaskSsl *)ht_task_ssl_list.lh_Head;
         ts != NULL && ts->ts_Node.ln_Succ != NULL;
         ts = next) {
        next = (struct HtTaskSsl *)ts->ts_Node.ln_Succ;
        Remove(&ts->ts_Node);
        ts->ts_InitOk = FALSE;
        ts->ts_RefCount = 0;
        ReleaseSemaphore(&ht_task_ssl_sema);
        ht_free(ts);
        ObtainSemaphore(&ht_task_ssl_sema);
    }
    ReleaseSemaphore(&ht_task_ssl_sema);
}

static VOID
ht_ssl_copy_peer_cert_fields(struct HtSsl *s, struct TlsPeerCert *src)
{
    if (s == NULL || src == NULL) {
        return;
    }
    ht_ssl_peer_cert_free(s);
    s->hs_CertVerifyResult = src->tpc_VerifyResult;
    if (src->tpc_Subject != NULL) {
        s->hs_CertSubject = ht_strdup(src->tpc_Subject);
    }
    if (src->tpc_Issuer != NULL) {
        s->hs_CertIssuer = ht_strdup(src->tpc_Issuer);
    }
    if (src->tpc_CommonName != NULL) {
        s->hs_CertCommonName = ht_strdup(src->tpc_CommonName);
    }
    if (src->tpc_NotBefore != NULL) {
        s->hs_CertNotBefore = ht_strdup(src->tpc_NotBefore);
    }
    if (src->tpc_NotAfter != NULL) {
        s->hs_CertNotAfter = ht_strdup(src->tpc_NotAfter);
    }
    if (src->tpc_Serial != NULL) {
        s->hs_CertSerial = ht_strdup(src->tpc_Serial);
    }
    s->hs_CertPresent = TRUE;
}

VOID
ht_ssl_capture_peer_cert(struct HtSsl *s)
{
    struct TlsPeerCert cert;

    if (s == NULL || s->hs_TlsConn == NULL) {
        return;
    }
    if (TlsGetPeerCert(s->hs_TlsConn, &cert) != 0) {
        return;
    }
    ht_ssl_copy_peer_cert_fields(s, &cert);
    TlsPeerCertFree(&cert);
}

struct HtSsl *
ht_ssl_create(STRPTR hostname, STRPTR ca_bundle_path)
{
    struct HtSsl *s;
    struct TagItem tags[2];

    /*
     * One TlsContext per connection.  Set ATSA_CA_BUNDLE_PATH here only;
     * do not add ATSA_SSL_VERIFY on the context (use ATTA_SSL_VERIFY at
     * attach).  Do not share a session-level TlsContext across connections.
     */
    if (HttpBase != NULL) {
        ht_sync_proto_bases(HttpBase);
        ht_ssl_sync_base_tags(HttpBase);
    }
    s = (struct HtSsl *)ht_alloc(sizeof(struct HtSsl), MEMF_CLEAR);
    if (s == NULL) {
        return NULL;
    }
    s->hs_Sock = -1;
    s->hs_HandshakeOk = FALSE;
    s->hs_LastTlsError = 0;
    s->hs_Hostname = ht_strdup(hostname);
    if (ca_bundle_path != NULL && ca_bundle_path[0] != '\0') {
        s->hs_TlsCtx = NewTlsContext(NULL);
        if (s->hs_TlsCtx == NULL) {
            if (s->hs_Hostname) {
                ht_free(s->hs_Hostname);
            }
            ht_free(s);
            return NULL;
        }
        tags[0].ti_Tag = ATSA_CA_BUNDLE_PATH;
        tags[0].ti_Data = (ULONG)ca_bundle_path;
        tags[1].ti_Tag = TAG_END;
        SetTlsContextAttrsA(s->hs_TlsCtx, tags);
        s->hs_TlsConn = NewTlsConnection(s->hs_TlsCtx);
    } else {
        s->hs_TlsConn = NewTlsConnection(NULL);
    }
    if (s->hs_TlsConn == NULL) {
        if (s->hs_TlsCtx != NULL) {
            DisposeTlsContext(s->hs_TlsCtx);
        }
        if (s->hs_Hostname) {
            ht_free(s->hs_Hostname);
        }
        ht_free(s);
        return NULL;
    }
    return s;
}

VOID
ht_ssl_destroy(struct HtSsl *s)
{
    if (s == NULL) {
        return;
    }
    ht_ssl_peer_cert_free(s);
    if (s->hs_TlsConn != NULL) {
        DisposeTlsConnection(s->hs_TlsConn);
        s->hs_TlsConn = NULL;
    }
    if (s->hs_TlsCtx != NULL) {
        DisposeTlsContext(s->hs_TlsCtx);
        s->hs_TlsCtx = NULL;
    }
    if (s->hs_Hostname) {
        ht_free(s->hs_Hostname);
    }
    ht_free(s);
}

LONG
ht_ssl_attach_socket(struct AmiHttpBase *base, struct HtSsl *s, LONG sock,
    STRPTR hostname, ULONG verify_mode, ULONG timeout_secs,
    struct HttpTransaction *txn)
{
    struct TagItem tags[2];
    LONG rc;
    LONG vr;

    (void)timeout_secs;

    if (s == NULL || sock < 0 || s->hs_TlsConn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (base != NULL) {
        ht_sync_proto_bases(base);
        ht_ssl_sync_base_tags(base);
    }
    s->hs_Sock = sock;
    s->hs_HandshakeOk = FALSE;
    if (hostname != NULL) {
        if (s->hs_Hostname) {
            ht_free(s->hs_Hostname);
        }
        s->hs_Hostname = ht_strdup(hostname);
    }
    if (verify_mode > HTSSL_VERIFY_PEER_STRICT) {
        verify_mode = HTSSL_VERIFY_PEER;
    }
    /*
     * Leave the TCP socket blocking (ht_tcp_connect() restores blocking mode).
     * BearSSL runs the deferred handshake inside TlsWrite using atls_sock_wait_*
     * loops, matching ATlsTest live HTTPS.  FIONBIO + ATTA_NON_BLOCKING breaks
     * handshake progress because br_sslio stalls on RECVREC while the shim only
     * surfaced WANT_WRITE to callers.
     */
    tags[0].ti_Tag = ATTA_SSL_VERIFY;
    tags[0].ti_Data = (ULONG)ht_ssl_map_verify(verify_mode);
    tags[1].ti_Tag = TAG_DONE;
    rc = TlsAttachSocket(s->hs_TlsConn, sock, s->hs_Hostname, tags);
    if (rc != 0) {
        vr = TlsGetLastError(s->hs_TlsConn);
        if (vr == 0) {
            vr = rc;
        }
        s->hs_CertVerifyResult = vr;
        if (rc == ERROR_TLS_VERIFY || vr == ERROR_TLS_VERIFY) {
            ht_ssl_capture_peer_cert(s);
            if (txn != NULL && ht_hook_cert_verify(txn, s, s->hs_CertVerifyResult)) {
                s->hs_HandshakeOk = TRUE;
                return 0;
            }
            return ERROR_HTTP_SSL_VERIFY;
        }
        return ht_ssl_map_tls_error(rc);
    }
    /* Handshake completes on first TlsWrite (see file header).  No TlsHandshake. */
    return 0;
}

VOID
ht_ssl_capture_cipher(struct HtSsl *s)
{
    (void)s;
}

LONG
ht_ssl_send(struct HtSsl *s, APTR data, ULONG len)
{
    struct AmiHttpBase *base;
    struct Library *sockbase;
    APTR errp;
    LONG n;
    LONG err;
    LONG rc;
    ULONG attempts;

    if (s == NULL || s->hs_TlsConn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    base = HttpBase;
    if (base != NULL) {
        ht_sync_proto_bases(base);
        sockbase = ht_task_current_socket_base(base);
        if (sockbase != NULL) {
            errp = ht_task_errno_ptr(base);
            /*
             * Required before every TlsWrite/TlsRead LVO.  Skipping this when
             * sockbase is NULL yields ERROR_TLS_IO -> 8704 on first request send.
             */
            rc = TlsTaskAttach(sockbase, errp);
            if (rc != 0) {
                s->hs_LastTlsError = rc;
                return ht_ssl_map_tls_error(rc);
            }
        }
    }
    attempts = 0;
    for (;;) {
        attempts++;
        if (attempts > 200) {
            return ERROR_HTTP_WRITE_FAILED;
        }
        n = TlsWrite(s->hs_TlsConn, data, len);
        if (ht_ssl_tls_ok(n)) {
            /*
             * Deferred handshake success: first successful TlsWrite completes
             * BearSSL client handshake and may run cert verify.
             */
            if (!s->hs_HandshakeOk) {
                s->hs_HandshakeOk = TRUE;
                ht_ssl_capture_peer_cert(s);
            }
            return n;
        }
        err = TlsGetLastError(s->hs_TlsConn);
        if (err == 0) {
            err = n;
        }
        if (ht_ssl_tls_want(err)) {
            if (ht_ssl_wait_socket(base, s->hs_Sock,
                (err == ERROR_TLS_WANT_WRITE) ? TRUE : FALSE,
                HT_SOCKET_IO_TIMEOUT) != 0) {
                return ERROR_HTTP_WRITE_FAILED;
            }
            continue;
        }
        s->hs_LastTlsError = err;
        rc = ht_ssl_map_tls_error(err);
        if (!s->hs_HandshakeOk &&
            (err == ERROR_TLS_VERIFY || rc == ERROR_HTTP_SSL_VERIFY)) {
            s->hs_CertVerifyResult = err;
            ht_ssl_capture_peer_cert(s);
        }
        return rc;
    }
}

LONG
ht_ssl_last_tls_error(struct HtSsl *s)
{
    if (s == NULL) {
        return 0;
    }
    return s->hs_LastTlsError;
}

LONG
ht_ssl_recv(struct AmiHttpBase *base, struct HtSsl *s, LONG sock,
    APTR buf, ULONG len, ULONG timeout_secs)
{
    struct Library *sockbase;
    APTR errp;
    LONG n;
    LONG err;
    LONG rc;
    ULONG attempts;

    if (s == NULL || s->hs_TlsConn == NULL || buf == NULL || len == 0) {
        return HT_IO_ERROR(ERROR_HTTP_INVALID_HANDLE);
    }
    if (base == NULL) {
        return HT_IO_ERROR(ERROR_HTTP_INVALID_HANDLE);
    }
    ht_sync_proto_bases(base);
    sockbase = ht_task_current_socket_base(base);
    if (sockbase != NULL) {
        errp = ht_task_errno_ptr(base);
        rc = TlsTaskAttach(sockbase, errp);
        if (rc != 0) {
            return HT_IO_ERROR(ht_ssl_map_tls_error(rc));
        }
    }
    if (sock < 0) {
        sock = s->hs_Sock;
    }
    /*
     * Do not hold ahb_SocketSema across TlsRead/WaitSelect (same rationale as
     * ht_transport_send TLS path).  Parallel image fetches must not wedge here.
     */
    attempts = 0;
    for (;;) {
        attempts++;
        if (attempts > 200) {
            return HT_IO_ERROR(ERROR_HTTP_READ_FAILED);
        }
        if (TlsPending(s->hs_TlsConn) <= 0 && sock >= 0 && timeout_secs > 0) {
            if (ht_ssl_wait_socket(base, sock, FALSE, timeout_secs) != 0) {
                return HT_IO_ERROR(ERROR_HTTP_READ_TIMEOUT);
            }
        }
        n = TlsRead(s->hs_TlsConn, buf, len, timeout_secs);
        if (ht_ssl_tls_ok(n)) {
            return n;
        }
        if (n == 0) {
            return 0;
        }
        err = TlsGetLastError(s->hs_TlsConn);
        if (err == 0) {
            err = n;
        }
        if (ht_ssl_tls_want(err)) {
            if (ht_ssl_wait_socket(base, sock,
                (err == ERROR_TLS_WANT_WRITE) ? TRUE : FALSE,
                timeout_secs) != 0) {
                return HT_IO_ERROR(ERROR_HTTP_READ_TIMEOUT);
            }
            continue;
        }
        if (err == ERROR_TLS_HANDSHAKE) {
            return HT_IO_ERROR(ERROR_HTTP_SSL_HANDSHAKE);
        }
        if (err == ERROR_TLS_READ_TIMEOUT) {
            return HT_IO_ERROR(ERROR_HTTP_READ_TIMEOUT);
        }
        return HT_IO_ERROR(ERROR_HTTP_READ_FAILED);
    }
}

BOOL
ht_ssl_idle(struct HtSsl *s)
{
    if (s == NULL || s->hs_TlsConn == NULL) {
        return TRUE;
    }
    if (TlsPending(s->hs_TlsConn) > 0) {
        return FALSE;
    }
    return TRUE;
}

VOID
ht_ssl_close(struct HtSsl *s)
{
    if (s == NULL || s->hs_Closed) {
        return;
    }
    if (s->hs_TlsConn != NULL) {
        DisposeTlsConnection(s->hs_TlsConn);
        s->hs_TlsConn = NULL;
    }
    s->hs_Closed = TRUE;
}
