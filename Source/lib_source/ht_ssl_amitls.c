/*
 * ht_ssl_amitls.c - amitls.library TLS backend for amihttp.library
 *
 * Built when AMIHTTP_USE_AMITLS is defined (see private/ht_ssl_config.h).
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
#include <proto/atls.h>
#include <proto/bsdsocket.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include <string.h>

#include "private/ht_debug.h"
#include "private/ht_internal.h"
#include "private/ht_hooks.h"
#include "private/ht_ssl.h"
#include "private/ht_ssl_config.h"

struct HtTaskSsl
{
    struct Node     ts_Node;
    struct Task    *ts_Task;
    ULONG           ts_RefCount;
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

static VOID
ht_ssl_apply_base_tags(struct AmiHttpBase *base)
{
    struct TagItem tags[3];

    if (base == NULL || TlsBase == NULL) {
        return;
    }
    tags[0].ti_Tag = ATBT_ERRNOPTR;
    tags[0].ti_Data = (ULONG)(base->ahb_ErrnoPtr != NULL ?
        base->ahb_ErrnoPtr : (APTR)&errno);
    tags[1].ti_Tag = ATBT_SSL_VERIFY;
    tags[1].ti_Data = (ULONG)ht_ssl_base_verify(base);
    tags[2].ti_Tag = TAG_END;
    TlsBaseTagList(tags);
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
    APTR errp;
    LONG rc;

    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    rc = ht_transport_global_init(base);
    if (rc != 0) {
        return rc;
    }
    ht_ssl_task_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_ssl_sema);
    for (ts = (struct HtTaskSsl *)ht_task_ssl_list.lh_Head;
         ts != NULL && ts->ts_Node.ln_Succ != NULL;
         ts = (struct HtTaskSsl *)ts->ts_Node.ln_Succ) {
        if (ts->ts_Task == task) {
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
    AddHead(&ht_task_ssl_list, &ts->ts_Node);
    ReleaseSemaphore(&ht_task_ssl_sema);

    ht_sync_proto_bases(base);
    errp = base->ahb_ErrnoPtr != NULL ? base->ahb_ErrnoPtr : (APTR)&errno;
    rc = TlsTaskAttach(base->ahb_SocketBase, errp);
    if (rc != 0) {
        ht_transport_task_ssl_release(base);
        return ht_ssl_map_tls_error(rc);
    }
    return 0;
}

VOID
ht_transport_task_ssl_release(struct AmiHttpBase *base)
{
    struct HtTaskSsl *ts;
    struct Task *task;

    (void)base;

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
                Remove(&ts->ts_Node);
                ReleaseSemaphore(&ht_task_ssl_sema);
                TlsTaskDetach();
                ht_free(ts);
                return;
            }
            break;
        }
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
    memset(&cert, 0, sizeof(cert));
    if (TlsGetPeerCert(s->hs_TlsConn, &cert) != 0) {
        return;
    }
    ht_ssl_copy_peer_cert_fields(s, &cert);
    TlsPeerCertFree(&cert);
}

struct HtSsl *
ht_ssl_create(STRPTR hostname)
{
    struct HtSsl *s;

    s = (struct HtSsl *)ht_alloc(sizeof(struct HtSsl), MEMF_CLEAR);
    if (s == NULL) {
        return NULL;
    }
    s->hs_Sock = -1;
    s->hs_Hostname = ht_strdup(hostname);
    s->hs_TlsConn = NewTlsConnection(NULL);
    if (s->hs_TlsConn == NULL) {
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
    }
    s->hs_Sock = sock;
    if (hostname != NULL) {
        if (s->hs_Hostname) {
            ht_free(s->hs_Hostname);
        }
        s->hs_Hostname = ht_strdup(hostname);
    }
    if (verify_mode > HTSSL_VERIFY_PEER_STRICT) {
        verify_mode = HTSSL_VERIFY_PEER;
    }
    tags[0].ti_Tag = ATTA_SSL_VERIFY;
    tags[0].ti_Data = (ULONG)ht_ssl_map_verify(verify_mode);
    tags[1].ti_Tag = TAG_END;
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
    s->hs_HandshakeOk = TRUE;
    ht_ssl_capture_peer_cert(s);
    if (verify_mode != HTSSL_VERIFY_NONE && s->hs_CertVerifyResult != 0) {
        if (txn != NULL && ht_hook_cert_verify(txn, s, s->hs_CertVerifyResult)) {
            s->hs_HandshakeOk = TRUE;
            return 0;
        }
        return ERROR_HTTP_SSL_VERIFY;
    }
    return 0;
}

LONG
ht_ssl_send(struct HtSsl *s, APTR data, ULONG len)
{
    LONG n;

    if (s == NULL || s->hs_TlsConn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    n = TlsWrite(s->hs_TlsConn, data, len);
    if (n <= 0) {
        return ERROR_HTTP_WRITE_FAILED;
    }
    return n;
}

LONG
ht_ssl_recv(struct AmiHttpBase *base, struct HtSsl *s, LONG sock,
    APTR buf, ULONG len, ULONG timeout_secs)
{
    LONG n;

    (void)sock;

    if (s == NULL || s->hs_TlsConn == NULL || buf == NULL || len == 0) {
        return HT_IO_ERROR(ERROR_HTTP_INVALID_HANDLE);
    }
    if (base != NULL) {
        ht_sync_proto_bases(base);
    }
    n = TlsRead(s->hs_TlsConn, buf, len, timeout_secs);
    if (n > 0) {
        return n;
    }
    if (n == 0) {
        return 0;
    }
    if (TlsGetLastError(s->hs_TlsConn) == ERROR_TLS_READ_TIMEOUT) {
        return HT_IO_ERROR(ERROR_HTTP_READ_TIMEOUT);
    }
    return HT_IO_ERROR(ERROR_HTTP_READ_FAILED);
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
