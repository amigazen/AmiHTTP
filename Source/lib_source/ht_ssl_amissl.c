/*
 * ht_ssl_amissl.c - AmiSSL / OpenSSL TLS backend for amihttp.library
 *
 * Built when AMIHTTP_USE_AMITLS is not defined (default).
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

#include <utility/tagitem.h>

/*
 * netinclude before OpenSSL: sys/socket.h pulls in
 * devices/timer.h timeval so e_ostime.h does not require sys/time.h.
 */
#include <sys/types.h>
#include <sys/socket.h>

#include <libraries/amisslmaster.h>
#include <libraries/amissl.h>
#include <proto/amisslmaster.h>
#include <proto/amissl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>
#include <proto/bsdsocket.h>

#include <string.h>
#include <stdio.h>

#include "private/ht_debug.h"
#include "private/ht_internal.h"
#include "private/ht_hooks.h"
#include "private/ht_ssl.h"

struct HtTaskSsl
{
    struct Node     ts_Node;
    struct Task    *ts_Task;
    ULONG           ts_RefCount;
    /* Per-task AmiSSL errno (InitAmiSSL ErrNoPtr; parallel retrieve tasks). */
    int             ts_Errno;
    /* TRUE only after InitAmiSSL() succeeded for this task entry. */
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

/*
 * AmiSSL/OpenAmiSSL is not safe for concurrent Init/Cleanup/handshake across
 * Exec tasks; serialize those entry points (mirrors AWeb amissl.c ssl_init_sema).
 */
static void
ht_ssl_global_enter(void)
{
    ht_ssl_task_list_init();
    ObtainSemaphore(&ht_ssl_global_sema);
}

static void
ht_ssl_global_leave(void)
{
    ReleaseSemaphore(&ht_ssl_global_sema);
}

LONG
ht_transport_global_init(struct AmiHttpBase *base)
{
    LONG err;

    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    htDbgPut("ht_transport_global_init");
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
        if (base->ahb_AmiSSLMasterBase == NULL) {
            htDbgPut("ht_transport_global_init OpenLibrary amisslmaster");
            base->ahb_AmiSSLMasterBase = OpenLibrary(
                "amisslmaster.library", AMISSLMASTER_MIN_VERSION);
            if (base->ahb_AmiSSLMasterBase == NULL) {
                ReleaseSemaphore(&ht_ssl_global_sema);
                return ERROR_HTTP_SSL_HANDSHAKE;
            }
            ht_sync_proto_bases(base);
        }
        htDbgPut("ht_transport_global_init OpenAmiSSLTags");
        err = OpenAmiSSLTags(
            AMISSL_CURRENT_VERSION,
            AmiSSL_UsesOpenSSLStructs, TRUE,
            AmiSSL_InitAmiSSL, FALSE,
            AmiSSL_GetAmiSSLBase, &base->ahb_AmiSSLBase,
            AmiSSL_GetAmiSSLExtBase, &base->ahb_AmiSSLExtBase,
            AmiSSL_SocketBase, base->ahb_SocketBase,
            AmiSSL_ErrNoPtr, (APTR)&base->ahb_SocketErrno,
            TAG_END);
        if (err == 0) {
            base->ahb_SslGlobalOpen = TRUE;
            base->ahb_AmiSSLInitCount = 0;
            ht_sync_proto_bases(base);
        } else {
            ReleaseSemaphore(&ht_ssl_global_sema);
            return ERROR_HTTP_SSL_HANDSHAKE;
        }
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
    ht_sync_proto_bases(base);
    ObtainSemaphore(&ht_ssl_global_sema);
    if (base->ahb_SslGlobalOpen) {
        CloseAmiSSL();
        base->ahb_AmiSSLBase = NULL;
        base->ahb_AmiSSLExtBase = NULL;
        base->ahb_SslGlobalOpen = FALSE;
        ht_sync_proto_bases(base);
    }
    ReleaseSemaphore(&ht_ssl_global_sema);
}

LONG
ht_transport_task_ssl_ensure(struct AmiHttpBase *base)
{
    struct HtTaskSsl *ts;
    struct Task *task;
    struct Library *sockbase;
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
    ts->ts_Errno = 0;
    ts->ts_InitOk = FALSE;
    AddHead(&ht_task_ssl_list, &ts->ts_Node);
    ReleaseSemaphore(&ht_task_ssl_sema);
    rc = ht_io_obtain(base);
    if (rc != 0) {
        ObtainSemaphore(&ht_task_ssl_sema);
        Remove(&ts->ts_Node);
        ReleaseSemaphore(&ht_task_ssl_sema);
        ht_free(ts);
        return rc;
    }
    ht_ssl_global_enter();
    rc = InitAmiSSL(
        AmiSSL_SocketBase, sockbase,
        AmiSSL_ErrNoPtr, (APTR)&ts->ts_Errno,
        TAG_END);
    ht_ssl_global_leave();
    ht_io_release(base);
    if (rc != 0) {
        ObtainSemaphore(&ht_task_ssl_sema);
        Remove(&ts->ts_Node);
        ReleaseSemaphore(&ht_task_ssl_sema);
        ht_free(ts);
        return ERROR_HTTP_SSL_HANDSHAKE;
    }
    ts->ts_InitOk = TRUE;
    return 0;
}

VOID
ht_transport_task_ssl_release(struct AmiHttpBase *base)
{
    struct HtTaskSsl *ts;
    struct Task *task;
    LONG rc;

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
                    rc = ht_io_obtain(base);
                    if (rc == 0) {
                        ht_ssl_global_enter();
                        CleanupAmiSSL(TAG_END);
                        ht_ssl_global_leave();
                        ht_io_release(base);
                    }
                } else {
                    (VOID)ht_io_obtain(base);
                    ht_io_release(base);
                }
                ht_free(ts);
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
    LONG rc;

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
                rc = ht_io_obtain(base);
                if (rc == 0) {
                    ht_ssl_global_enter();
                    CleanupAmiSSL(TAG_END);
                    ht_ssl_global_leave();
                    ht_io_release(base);
                }
            } else {
                (VOID)ht_io_obtain(base);
                ht_io_release(base);
            }
            ht_free(ts);
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

static STRPTR
ht_ssl_x509_oneline(X509_NAME *name)
{
    char buf[512];
    STRPTR out;

    if (name == NULL) {
        return NULL;
    }
    if (X509_NAME_oneline(name, buf, (int)sizeof(buf)) == NULL) {
        return NULL;
    }
    out = ht_strdup((STRPTR)buf);
    return out;
}

static STRPTR
ht_ssl_extract_cn(STRPTR oneline)
{
    STRPTR start;
    STRPTR end;
    STRPTR p;

    if (oneline == NULL) {
        return NULL;
    }
    p = strstr((const char *)oneline, "/CN=");
    if (p == NULL) {
        p = strstr((const char *)oneline, ", CN=");
    }
    if (p == NULL) {
        return NULL;
    }
    start = p;
    while (*start != '\0' && *start != '=') {
        start++;
    }
    if (*start == '=') {
        start++;
    }
    end = start;
    while (*end != '\0' && *end != '/' && *end != ',') {
        end++;
    }
    return ht_strndup(start, (LONG)(end - start));
}

static STRPTR
ht_ssl_asn1_time_str(const ASN1_TIME *t)
{
    BIO *bio;
    char buf[64];
    LONG n;
    STRPTR out;

    if (t == NULL) {
        return NULL;
    }
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NULL;
    }
    if (!ASN1_TIME_print(bio, t)) {
        BIO_free(bio);
        return NULL;
    }
    n = BIO_read(bio, buf, (int)sizeof(buf) - 1);
    BIO_free(bio);
    if (n <= 0) {
        return NULL;
    }
    buf[n] = '\0';
    out = ht_strdup((STRPTR)buf);
    return out;
}

VOID
ht_ssl_capture_cipher(struct HtSsl *s)
{
    const char *c;

    if (s == NULL || s->hs_Ssl == NULL) {
        return;
    }
    if (s->hs_Cipher) {
        ht_free(s->hs_Cipher);
        s->hs_Cipher = NULL;
    }
    c = SSL_get_cipher((SSL *)s->hs_Ssl);
    if (c != NULL && c[0] != '\0') {
        s->hs_Cipher = ht_strdup((STRPTR)c);
    }
}

VOID
ht_ssl_capture_peer_cert(struct HtSsl *s)
{
    SSL *ssl;
    X509 *cert;
    X509_NAME *subj;
    X509_NAME *issuer;
    ASN1_INTEGER *serial;
    BIGNUM *bn;
    char *hex;

    if (s == NULL || s->hs_Ssl == NULL) {
        return;
    }
    ssl = (SSL *)s->hs_Ssl;
    ht_ssl_peer_cert_free(s);
    s->hs_CertVerifyResult = (LONG)SSL_get_verify_result(ssl);
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        return;
    }
    s->hs_CertPresent = TRUE;
    subj = X509_get_subject_name(cert);
    issuer = X509_get_issuer_name(cert);
    s->hs_CertSubject = ht_ssl_x509_oneline(subj);
    s->hs_CertIssuer = ht_ssl_x509_oneline(issuer);
    s->hs_CertCommonName = ht_ssl_extract_cn(s->hs_CertSubject);
    s->hs_CertNotBefore = ht_ssl_asn1_time_str(X509_get0_notBefore(cert));
    s->hs_CertNotAfter = ht_ssl_asn1_time_str(X509_get0_notAfter(cert));
    serial = X509_get_serialNumber(cert);
    if (serial != NULL) {
        bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (bn != NULL) {
            hex = BN_bn2hex(bn);
            if (hex != NULL) {
                s->hs_CertSerial = ht_strdup((STRPTR)hex);
                OPENSSL_free(hex);
            }
            BN_free(bn);
        }
    }
    X509_free(cert);
}

/*
 * Map HTSSL_VERIFY_* to OpenSSL SSL_CTX_set_verify flags and load the
 * AmiSSL default CA store when peer verification is requested.
 */
static VOID
ht_ssl_configure_ctx(SSL_CTX *ctx, ULONG verify_mode)
{
    int verify_flags;

    if (ctx == NULL) {
        return;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (verify_mode == HTSSL_VERIFY_NONE) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        return;
    }
    SSL_CTX_set_default_verify_paths(ctx);
    verify_flags = SSL_VERIFY_PEER;
    if (verify_mode == HTSSL_VERIFY_PEER_STRICT) {
        verify_flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(ctx, verify_flags, NULL);
}

/*
 * RFC 6125 hostname check against peer certificate (SAN then CN).
 */
static BOOL
ht_ssl_check_hostname(X509 *cert, STRPTR hostname)
{
    int rc;

    if (cert == NULL || hostname == NULL || hostname[0] == '\0') {
        return FALSE;
    }
    rc = X509_check_host(cert, (const char *)hostname, 0, 0, NULL);
    return (BOOL)(rc == 1);
}

static LONG
ht_ssl_verify_peer(struct HtSsl *s, ULONG verify_mode,
    struct HttpTransaction *txn)
{
    SSL *ssl;
    LONG vr;
    X509 *cert;
    BOOL host_ok;

    if (s == NULL || s->hs_Ssl == NULL || verify_mode == HTSSL_VERIFY_NONE) {
        return 0;
    }
    ssl = (SSL *)s->hs_Ssl;
    vr = (LONG)SSL_get_verify_result(ssl);
    s->hs_CertVerifyResult = vr;
    if (vr != X509_V_OK) {
        if (txn != NULL && ht_hook_cert_verify(txn, s, vr)) {
            return 0;
        }
        return ERROR_HTTP_SSL_VERIFY;
    }
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        s->hs_CertVerifyResult = X509_V_ERR_UNSPECIFIED;
        if (txn != NULL && ht_hook_cert_verify(txn, s,
            s->hs_CertVerifyResult)) {
            return 0;
        }
        return ERROR_HTTP_SSL_VERIFY;
    }
    if (s->hs_Hostname != NULL) {
        host_ok = ht_ssl_check_hostname(cert, s->hs_Hostname);
        if (!host_ok) {
            s->hs_CertVerifyResult = X509_V_ERR_HOSTNAME_MISMATCH;
            X509_free(cert);
            if (txn != NULL && ht_hook_cert_verify(txn, s,
                s->hs_CertVerifyResult)) {
                return 0;
            }
            return ERROR_HTTP_SSL_VERIFY;
        }
    }
    X509_free(cert);
    return 0;
}

struct HtSsl *
ht_ssl_create(STRPTR hostname, STRPTR ca_bundle_path)
{
    struct HtSsl *s;

    (void)ca_bundle_path;

    s = (struct HtSsl *)ht_alloc(sizeof(struct HtSsl), MEMF_CLEAR);
    if (s == NULL) {
        return NULL;
    }
    s->hs_Sock = -1;
    s->hs_Hostname = ht_strdup(hostname);
    return s;
}

VOID
ht_ssl_destroy(struct HtSsl *s)
{
    if (s == NULL) {
        return;
    }
    ht_ssl_peer_cert_free(s);
    if (s->hs_Ssl != NULL && !s->hs_Closed) {
        SSL_free((SSL *)s->hs_Ssl);
        s->hs_Ssl = NULL;
    }
    if (s->hs_Ctx != NULL) {
        SSL_CTX_free((SSL_CTX *)s->hs_Ctx);
        s->hs_Ctx = NULL;
    }
    if (s->hs_Hostname) {
        ht_free(s->hs_Hostname);
    }
    ht_free(s);
}

/*
 * SSL_connect with WaitSelect bounds so a dead peer cannot wedge the machine.
 */
static LONG
ht_ssl_do_connect(struct AmiHttpBase *base, SSL *ssl, LONG sock,
    ULONG timeout_secs)
{
    int n;
    int err;
    fd_set rfds;
    fd_set wfds;
    struct timeval tv;
    LONG nfds;
    LONG rc;
    LONG iorc;

    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (timeout_secs == 0) {
        timeout_secs = 60;
    }
    iorc = ht_io_obtain(base);
    if (iorc != 0) {
        return iorc;
    }
    for (;;) {
        ht_ssl_global_enter();
        n = SSL_connect(ssl);
        if (n > 0) {
            ht_ssl_global_leave();
            ht_io_release(base);
            return 0;
        }
        err = SSL_get_error(ssl, n);
        ht_ssl_global_leave();
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            ht_io_release(base);
            return ERROR_HTTP_SSL_HANDSHAKE;
        }
        if (sock < 0) {
            ht_io_release(base);
            return ERROR_HTTP_SSL_HANDSHAKE;
        }
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        if (err == SSL_ERROR_WANT_READ) {
            FD_SET((int)sock, &rfds);
        } else {
            FD_SET((int)sock, &wfds);
        }
        nfds = sock + 1;
        tv.tv_sec = (long)timeout_secs;
        tv.tv_usec = 0;
        rc = WaitSelect((int)nfds, &rfds, NULL, &wfds, &tv, NULL);
        if (rc <= 0) {
            ht_io_release(base);
            return ERROR_HTTP_CONNECT_TIMEOUT;
        }
    }
}

LONG
ht_ssl_attach_socket(struct AmiHttpBase *base, struct HtSsl *s, LONG sock,
    STRPTR hostname, ULONG verify_mode, ULONG timeout_secs,
    struct HttpTransaction *txn)
{
    SSL_CTX *ctx;
    SSL *ssl;
    LONG rc;
    LONG vr;

    if (s == NULL || sock < 0) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (timeout_secs == 0) {
        timeout_secs = 60;
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
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        return ERROR_HTTP_SSL_HANDSHAKE;
    }
    s->hs_Ctx = (APTR)ctx;
    ht_ssl_configure_ctx(ctx, verify_mode);
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        return ERROR_HTTP_SSL_HANDSHAKE;
    }
    s->hs_Ssl = (APTR)ssl;
    if (s->hs_Hostname != NULL) {
        SSL_set_tlsext_host_name(ssl, (const char *)s->hs_Hostname);
    }
    SSL_set_fd(ssl, (int)sock);
    rc = ht_ssl_do_connect(base, ssl, sock, timeout_secs);
    if (rc != 0) {
        if (rc == ERROR_HTTP_SSL_HANDSHAKE && verify_mode != HTSSL_VERIFY_NONE) {
            vr = (LONG)SSL_get_verify_result(ssl);
            if (vr != X509_V_OK) {
                ht_ssl_capture_peer_cert(s);
                if (txn != NULL && ht_hook_cert_verify(txn, s, vr)) {
                    s->hs_HandshakeOk = TRUE;
                    return 0;
                }
                return ERROR_HTTP_SSL_VERIFY;
            }
        }
        return rc;
    }
    s->hs_HandshakeOk = TRUE;
    ht_ssl_capture_peer_cert(s);
    ht_ssl_capture_cipher(s);
    rc = ht_ssl_verify_peer(s, verify_mode, txn);
    if (rc != 0) {
        return rc;
    }
    return 0;
}

LONG
ht_ssl_send(struct HtSsl *s, APTR data, ULONG len)
{
    int n;

    if (s == NULL || s->hs_Ssl == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    ht_ssl_global_enter();
    n = SSL_write((SSL *)s->hs_Ssl, data, (int)len);
    ht_ssl_global_leave();
    if (n <= 0) {
        return ERROR_HTTP_WRITE_FAILED;
    }
    return (LONG)n;
}

LONG
ht_ssl_recv(struct AmiHttpBase *base, struct HtSsl *s, LONG sock,
    APTR buf, ULONG len, ULONG timeout_secs)
{
    SSL *ssl;
    int n;
    int err;
    int attempts;
    fd_set rfds;
    fd_set wfds;
    struct timeval tv;
    LONG nfds;
    LONG rc;
    LONG iorc;
    LONG rv;

    if (s == NULL || s->hs_Ssl == NULL || buf == NULL || len == 0) {
        return HT_IO_ERROR(ERROR_HTTP_INVALID_HANDLE);
    }
    if (base == NULL) {
        return HT_IO_ERROR(ERROR_HTTP_INVALID_HANDLE);
    }
    iorc = ht_io_obtain(base);
    if (iorc != 0) {
        return HT_IO_ERROR(iorc);
    }
    ssl = (SSL *)s->hs_Ssl;
    attempts = 0;
    rv = 0;
    for (;;) {
        attempts++;
        if (attempts > 200) {
            rv = HT_IO_ERROR(ERROR_HTTP_READ_FAILED);
            goto done;
        }
        if (SSL_pending(ssl) <= 0 && sock >= 0 && timeout_secs > 0) {
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            FD_SET((int)sock, &rfds);
            nfds = sock + 1;
            tv.tv_sec = (long)timeout_secs;
            tv.tv_usec = 0;
            rc = WaitSelect((int)nfds, &rfds, NULL, &wfds, &tv, NULL);
            if (rc <= 0) {
                rv = HT_IO_ERROR(ERROR_HTTP_READ_TIMEOUT);
                goto done;
            }
        }
        ht_ssl_global_enter();
        n = SSL_read(ssl, buf, (int)len);
        if (n > 0) {
            ht_ssl_global_leave();
            if ((ULONG)n > len) {
                n = (int)len;
            }
            rv = (LONG)n;
            goto done;
        }
        if (n == 0) {
            ht_ssl_global_leave();
            rv = 0;
            goto done;
        }
        err = SSL_get_error(ssl, n);
        ht_ssl_global_leave();
        if (err == SSL_ERROR_WANT_READ) {
            continue;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            if (sock >= 0 && timeout_secs > 0) {
                FD_ZERO(&rfds);
                FD_ZERO(&wfds);
                FD_SET((int)sock, &wfds);
                nfds = sock + 1;
                tv.tv_sec = (long)timeout_secs;
                tv.tv_usec = 0;
                rc = WaitSelect((int)nfds, NULL, &wfds, NULL, &tv, NULL);
                if (rc <= 0) {
                    rv = HT_IO_ERROR(ERROR_HTTP_READ_TIMEOUT);
                    goto done;
                }
            }
            continue;
        }
        rv = HT_IO_ERROR(ERROR_HTTP_READ_FAILED);
        goto done;
    }
done:
    ht_io_release(base);
    return rv;
}

BOOL
ht_ssl_idle(struct HtSsl *s)
{
    if (s == NULL || s->hs_Ssl == NULL) {
        return TRUE;
    }
    if (SSL_pending((SSL *)s->hs_Ssl) > 0) {
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
    if (s->hs_Ssl != NULL) {
        SSL_free((SSL *)s->hs_Ssl);
        s->hs_Ssl = NULL;
    }
    if (s->hs_Ctx != NULL) {
        SSL_CTX_free((SSL_CTX *)s->hs_Ctx);
        s->hs_Ctx = NULL;
    }
    s->hs_Closed = TRUE;
}

LONG
ht_ssl_last_tls_error(struct HtSsl *s)
{
    (void)s;
    return 0;
}
