/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_ssl.c - AmiSSL wrapper (per-connection SSL, global OpenAmiSSLTags)
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
#include <openssl/bio.h>
#include <openssl/bn.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>
#include <proto/bsdsocket.h>

#include <string.h>
#include <stdio.h>

#include "private/ht_debug.h"
#include "private/ht_internal.h"

struct HtSsl
{
    SSL_CTX    *hs_Ctx;
    SSL        *hs_Ssl;
    STRPTR      hs_Hostname;
    LONG        hs_Sock;
    BOOL        hs_Closed;
    BOOL        hs_CertPresent;
    STRPTR      hs_CertSubject;
    STRPTR      hs_CertIssuer;
    STRPTR      hs_CertCommonName;
    STRPTR      hs_CertNotBefore;
    STRPTR      hs_CertNotAfter;
    STRPTR      hs_CertSerial;
    LONG        hs_CertVerifyResult;
};

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
            AmiSSL_ErrNoPtr, &errno,
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
    if (InitAmiSSL(
            AmiSSL_SocketBase, base->ahb_SocketBase,
            AmiSSL_ErrNoPtr, &errno,
            TAG_END) != 0) {
        ht_transport_task_ssl_release(base);
        return ERROR_HTTP_SSL_HANDSHAKE;
    }
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
                Remove(&ts->ts_Node);
                ReleaseSemaphore(&ht_task_ssl_sema);
                CleanupAmiSSL(TAG_END);
                ht_free(ts);
                return;
            }
            break;
        }
    }
    ReleaseSemaphore(&ht_task_ssl_sema);
}

static VOID
ht_ssl_peer_cert_free(struct HtSsl *s)
{
    if (s == NULL) {
        return;
    }
    if (s->hs_CertSubject) {
        ht_free(s->hs_CertSubject);
    }
    if (s->hs_CertIssuer) {
        ht_free(s->hs_CertIssuer);
    }
    if (s->hs_CertCommonName) {
        ht_free(s->hs_CertCommonName);
    }
    if (s->hs_CertNotBefore) {
        ht_free(s->hs_CertNotBefore);
    }
    if (s->hs_CertNotAfter) {
        ht_free(s->hs_CertNotAfter);
    }
    if (s->hs_CertSerial) {
        ht_free(s->hs_CertSerial);
    }
    s->hs_CertSubject = NULL;
    s->hs_CertIssuer = NULL;
    s->hs_CertCommonName = NULL;
    s->hs_CertNotBefore = NULL;
    s->hs_CertNotAfter = NULL;
    s->hs_CertSerial = NULL;
    s->hs_CertPresent = FALSE;
    s->hs_CertVerifyResult = 0;
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
ht_ssl_capture_peer_cert(struct HtSsl *s)
{
    X509 *cert;
    X509_NAME *subj;
    X509_NAME *issuer;
    ASN1_INTEGER *serial;
    BIGNUM *bn;
    char *hex;

    if (s == NULL || s->hs_Ssl == NULL) {
        return;
    }
    ht_ssl_peer_cert_free(s);
    s->hs_CertVerifyResult = (LONG)SSL_get_verify_result(s->hs_Ssl);
    cert = SSL_get_peer_certificate(s->hs_Ssl);
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

VOID
ht_ssl_peer_cert_copy(struct HttpSslPeerCert *dst, struct HtSsl *s)
{
    if (dst == NULL) {
        return;
    }
    dst->hpc_Subject = NULL;
    dst->hpc_Issuer = NULL;
    dst->hpc_CommonName = NULL;
    dst->hpc_NotBefore = NULL;
    dst->hpc_NotAfter = NULL;
    dst->hpc_Serial = NULL;
    dst->hpc_VerifyResult = 0;
    if (s == NULL || !s->hs_CertPresent) {
        return;
    }
    if (s->hs_CertSubject) {
        dst->hpc_Subject = ht_strdup(s->hs_CertSubject);
    }
    if (s->hs_CertIssuer) {
        dst->hpc_Issuer = ht_strdup(s->hs_CertIssuer);
    }
    if (s->hs_CertCommonName) {
        dst->hpc_CommonName = ht_strdup(s->hs_CertCommonName);
    }
    if (s->hs_CertNotBefore) {
        dst->hpc_NotBefore = ht_strdup(s->hs_CertNotBefore);
    }
    if (s->hs_CertNotAfter) {
        dst->hpc_NotAfter = ht_strdup(s->hs_CertNotAfter);
    }
    if (s->hs_CertSerial) {
        dst->hpc_Serial = ht_strdup(s->hs_CertSerial);
    }
    dst->hpc_VerifyResult = s->hs_CertVerifyResult;
}

VOID
ht_ssl_peer_cert_clear(struct HtSsl *s)
{
    ht_ssl_peer_cert_free(s);
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
        SSL_shutdown(s->hs_Ssl);
        SSL_free(s->hs_Ssl);
        s->hs_Ssl = NULL;
    }
    if (s->hs_Ctx != NULL) {
        SSL_CTX_free(s->hs_Ctx);
        s->hs_Ctx = NULL;
    }
    if (s->hs_Hostname) {
        ht_free(s->hs_Hostname);
    }
    ht_free(s);
}

LONG
ht_ssl_attach_socket(struct HtSsl *s, LONG sock, STRPTR hostname)
{
    if (s == NULL || sock < 0) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    s->hs_Sock = sock;
    if (hostname != NULL) {
        if (s->hs_Hostname) {
            ht_free(s->hs_Hostname);
        }
        s->hs_Hostname = ht_strdup(hostname);
    }
    s->hs_Ctx = SSL_CTX_new(TLS_client_method());
    if (s->hs_Ctx == NULL) {
        return ERROR_HTTP_SSL_HANDSHAKE;
    }
    s->hs_Ssl = SSL_new(s->hs_Ctx);
    if (s->hs_Ssl == NULL) {
        return ERROR_HTTP_SSL_HANDSHAKE;
    }
    if (s->hs_Hostname != NULL) {
        SSL_set_tlsext_host_name(s->hs_Ssl, (const char *)s->hs_Hostname);
    }
    SSL_set_fd(s->hs_Ssl, (int)sock);
    if (SSL_connect(s->hs_Ssl) <= 0) {
        return ERROR_HTTP_SSL_HANDSHAKE;
    }
    ht_ssl_capture_peer_cert(s);
    return 0;
}

LONG
ht_ssl_send(struct HtSsl *s, APTR data, ULONG len)
{
    int n;

    if (s == NULL || s->hs_Ssl == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    n = SSL_write(s->hs_Ssl, data, (int)len);
    if (n <= 0) {
        return ERROR_HTTP_WRITE_FAILED;
    }
    return (LONG)n;
}

/*
 * SSL_read with WaitSelect on WANT_READ/WANT_WRITE.
 * Single SSL_read without waiting can return short/garbage on Roadshow.
 */
LONG
ht_ssl_recv(struct AmiHttpBase *base, struct HtSsl *s, LONG sock,
    APTR buf, ULONG len, ULONG timeout_secs)
{
    int n;
    int err;
    int attempts;
    fd_set rfds;
    fd_set wfds;
    struct timeval tv;
    LONG nfds;
    LONG rc;

    if (s == NULL || s->hs_Ssl == NULL || buf == NULL || len == 0) {
        return HT_IO_ERROR(ERROR_HTTP_INVALID_HANDLE);
    }
    attempts = 0;
    for (;;) {
        attempts++;
        if (attempts > 200) {
            return HT_IO_ERROR(ERROR_HTTP_READ_FAILED);
        }
        if (SSL_pending(s->hs_Ssl) <= 0 && sock >= 0 && timeout_secs > 0) {
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            FD_SET((int)sock, &rfds);
            nfds = sock + 1;
            tv.tv_sec = (long)timeout_secs;
            tv.tv_usec = 0;
            if (base != NULL) {
                ht_sync_proto_bases(base);
            }
            rc = WaitSelect((int)nfds, &rfds, NULL, &wfds, &tv, NULL);
            if (rc <= 0) {
                return HT_IO_ERROR(ERROR_HTTP_READ_TIMEOUT);
            }
        }
        n = SSL_read(s->hs_Ssl, buf, (int)len);
        if (n > 0) {
            if ((ULONG)n > len) {
                n = (int)len;
            }
            return (LONG)n;
        }
        if (n == 0) {
            return 0;
        }
        err = SSL_get_error(s->hs_Ssl, n);
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
                if (base != NULL) {
                    ht_sync_proto_bases(base);
                }
                rc = WaitSelect((int)nfds, NULL, &wfds, NULL, &tv, NULL);
                if (rc <= 0) {
                    return HT_IO_ERROR(ERROR_HTTP_READ_TIMEOUT);
                }
            }
            continue;
        }
        return HT_IO_ERROR(ERROR_HTTP_READ_FAILED);
    }
}

BOOL
ht_ssl_idle(struct HtSsl *s)
{
    if (s == NULL || s->hs_Ssl == NULL) {
        return TRUE;
    }
    if (SSL_pending(s->hs_Ssl) > 0) {
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
        SSL_shutdown(s->hs_Ssl);
        SSL_free(s->hs_Ssl);
        s->hs_Ssl = NULL;
    }
    if (s->hs_Ctx != NULL) {
        SSL_CTX_free(s->hs_Ctx);
        s->hs_Ctx = NULL;
    }
    s->hs_Closed = TRUE;
}
