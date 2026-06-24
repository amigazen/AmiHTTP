/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_transport.c - TCP via bsdsocket
 *
 * No global SocketBase swapping: set library SocketBase once via
 * ht_sync_proto_bases() before socket calls.  Configure errno/h_errno
 * with SocketBaseTagList() at open (AmiSSL SDK expects this).
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/semaphores.h>

#include <utility/tagitem.h>

#include <proto/exec.h>

extern struct Library *SocketBase;
extern int errno;
extern int h_errno;

#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <libraries/bsdsocket.h>
#include <proto/bsdsocket.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "private/ht_debug.h"
#include "private/ht_internal.h"

#define HT_HOSTENT_BUF  1024

static BOOL ht_has_gethost_r;

/*
 * bsdsocket errno is redirected via SocketBaseTagList.  amitls/AmiSSL attach
 * paths configure the caller's HTBT_ERRNOPTR slot; plain TCP must read/write
 * the same location or connect() mis-classifies EINPROGRESS after TLS I/O.
 */
static APTR
ht_socket_errno_ptr(struct AmiHttpBase *base)
{
    if (base != NULL && base->ahb_ErrnoPtr != NULL) {
        return base->ahb_ErrnoPtr;
    }
    return (APTR)&errno;
}

static VOID
ht_socket_configure_base(struct AmiHttpBase *base)
{
    struct TagItem tags[3];
    APTR errp;

    if (SocketBase == NULL) {
        return;
    }
    errp = ht_socket_errno_ptr(base);
    tags[0].ti_Tag = SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(errno)));
    tags[0].ti_Data = (ULONG)errp;
    tags[1].ti_Tag = SBTM_SETVAL(SBTC_HERRNOLONGPTR);
    tags[1].ti_Data = (ULONG)&h_errno;
    tags[2].ti_Tag = TAG_END;
    SocketBaseTagList(tags);
}

static LONG
ht_socket_get_errno(struct AmiHttpBase *base)
{
    APTR errp;

    errp = ht_socket_errno_ptr(base);
    if (errp == (APTR)&errno) {
        return (LONG)errno;
    }
    return (LONG)(*(int *)errp);
}

static VOID
ht_socket_clear_errno(struct AmiHttpBase *base)
{
    APTR errp;

    errp = ht_socket_errno_ptr(base);
    if (errp == (APTR)&errno) {
        errno = 0;
    } else {
        *(int *)errp = 0;
    }
    h_errno = 0;
}

VOID
ht_transport_bind_socket(struct AmiHttpBase *base)
{
    if (base != NULL) {
        ht_sync_proto_bases(base);
        if (base->ahb_SocketBase != NULL) {
            ht_socket_configure_base(base);
        }
    }
}

static VOID
ht_bind_socketbase(struct AmiHttpBase *base)
{
    ht_transport_bind_socket(base);
}

/*
 * bsdsocket.library may return fd 0 (stdin).  Reserve a real socket fd so
 * WaitSelect/FIONBIO and TLS I/O do not collide with console handles.
 */
static LONG
ht_socket_stream(struct AmiHttpBase *base)
{
    LONG sock;
    LONG fd;

    ht_bind_socketbase(base);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return sock;
    }
    if (sock == 0) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        CloseSocket(sock);
        if (fd < 0) {
            return fd;
        }
        sock = fd;
    }
    return sock;
}

/*
 * IPv4-only connect path (sockaddr_in).  Reject non-AF_INET hostent results
 * instead of truncating v6 addresses into sin_addr.
 */
static struct hostent *
ht_lookup_host_ipv4(struct AmiHttpBase *base, STRPTR host, struct hostent *he,
    char *hbuf, LONG *herr_out)
{
    struct hostent *hent;

    if (host == NULL || host[0] == '\0' || he == NULL || hbuf == NULL) {
        return NULL;
    }
    ht_bind_socketbase(base);
    hent = NULL;
    if (ht_has_gethost_r) {
        if (herr_out != NULL) {
            *herr_out = 0;
        }
        hent = gethostbyname_r((char *)host, he, hbuf,
            (ULONG)HT_HOSTENT_BUF, herr_out);
    } else {
        hent = gethostbyname((char *)host);
    }
    if (hent == NULL || hent->h_addr_list == NULL ||
        hent->h_addr_list[0] == NULL) {
        return NULL;
    }
    if (hent->h_addrtype != AF_INET) {
        return NULL;
    }
    return hent;
}

static VOID
ht_socket_probe_api(VOID)
{
    struct TagItem tags[2];
    ULONG have_r;

    have_r = 0;
    tags[0].ti_Tag = SBTM_GETVAL(SBTC_HAVE_GETHOSTADDR_R_API);
    tags[0].ti_Data = (ULONG)&have_r;
    tags[1].ti_Tag = TAG_END;
    SocketBaseTagList(tags);
    ht_has_gethost_r = (BOOL)(have_r != 0);
}

/*
 * Lazy bsdsocket open (Roadshow: OpenLibrary + SocketBaseTagList).
 */
LONG
ht_ensure_bsdsocket(struct AmiHttpBase *base)
{
    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (base->ahb_SocketBase != NULL) {
        return 0;
    }
    htDbgPut("ht_ensure_bsdsocket");
    ObtainSemaphore(&base->ahb_SocketSema);
    if (base->ahb_SocketBase == NULL) {
        htDbgPut("ht_ensure_bsdsocket OpenLibrary");
        base->ahb_SocketBase = OpenLibrary("bsdsocket.library", 4);
        if (base->ahb_SocketBase == NULL) {
            htDbgPut("ht_ensure_bsdsocket failed");
            ReleaseSemaphore(&base->ahb_SocketSema);
            return ERROR_HTTP_CONNECT_FAILED;
        }
        ht_bind_socketbase(base);
        ht_socket_clear_errno(base);
        ht_socket_probe_api();
        htDbgPutHex("ht_ensure_bsdsocket ok=", (ULONG)base->ahb_SocketBase);
    }
    ReleaseSemaphore(&base->ahb_SocketSema);
    return 0;
}

static LONG
ht_tcp_connect(struct AmiHttpBase *base, LONG sock, struct hostent *hent,
    ULONG port, ULONG timeout_secs)
{
    struct sockaddr_in sad;
    LONG result;
    ULONG one;
    fd_set wfds;
    struct timeval tv;
    LONG nfds;
    LONG rc;
    LONG soerr;
    LONG soerrlen;
    LONG sock_err;

    if (hent == NULL || hent->h_addr_list == NULL ||
        hent->h_addr_list[0] == NULL || hent->h_addrtype != AF_INET) {
        return ERROR_HTTP_DNS_FAILED;
    }
    memset(&sad, 0, sizeof(sad));
    sad.sin_len = sizeof(sad);
    sad.sin_family = AF_INET;
    sad.sin_port = htons((UWORD)port);
    memcpy(&sad.sin_addr, hent->h_addr_list[0], (size_t)hent->h_length);

    /*
     * Non-blocking connect + WaitSelect (connect timeout).  Restore blocking
     * mode before TLS attach (BearSSL/atls_sock_wait_* expect blocking I/O).
     */
    ht_socket_clear_errno(base);
    one = 1;
    IoctlSocket(sock, FIONBIO, (char *)&one);
    result = connect(sock, (struct sockaddr *)&sad, sizeof(sad));
    if (result == 0) {
        one = 0;
        IoctlSocket(sock, FIONBIO, (char *)&one);
        return 0;
    }
    sock_err = ht_socket_get_errno(base);
    if (sock_err != EINPROGRESS && sock_err != EWOULDBLOCK) {
        one = 0;
        IoctlSocket(sock, FIONBIO, (char *)&one);
        return ERROR_HTTP_CONNECT_FAILED;
    }
    FD_ZERO(&wfds);
    FD_SET((int)sock, &wfds);
    nfds = sock + 1;
    if (timeout_secs == 0) {
        timeout_secs = 60;
    }
    tv.tv_sec = (long)timeout_secs;
    tv.tv_usec = 0;
    rc = WaitSelect((int)nfds, NULL, &wfds, NULL, &tv, NULL);
    if (rc <= 0) {
        one = 0;
        IoctlSocket(sock, FIONBIO, (char *)&one);
        return ERROR_HTTP_CONNECT_TIMEOUT;
    }
    soerr = 0;
    soerrlen = (LONG)sizeof(soerr);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&soerr, &soerrlen);
    one = 0;
    IoctlSocket(sock, FIONBIO, (char *)&one);
    if (soerr != 0) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    return 0;
}

/*
 * Close a TCP socket without shutdown(2).  Graceful shutdown can block
 * indefinitely on Amiga bsdsocket when the peer or TLS stack left unread
 * data; ATlsTest and other clients use CloseSocket-only teardown.
 */
static VOID
ht_transport_close_socket(struct AmiHttpBase *base, LONG sock)
{
    struct linger lg;
    LONG lglen;

    if (sock < 0) {
        return;
    }
    ht_bind_socketbase(base);
    lg.l_onoff = 1;
    lg.l_linger = 0;
    lglen = (LONG)sizeof(lg);
    setsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&lg, &lglen);
    CloseSocket(sock);
}

LONG
ht_transport_connect(struct AmiHttpBase *base, struct HtConnection *conn,
    STRPTR host, ULONG port, BOOL ssl, ULONG timeout_secs, ULONG ssl_verify,
    STRPTR ca_bundle_path)
{
    struct hostent he;
    struct hostent *hent;
    char hbuf[HT_HOSTENT_BUF];
    LONG herr;
    LONG sock;
    LONG rc;

    if (base == NULL || conn == NULL || host == NULL || host[0] == '\0') {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (port == 0) {
        port = ssl ? 443UL : 80UL;
    }
    htDbgPut("ht_transport_connect");
    rc = ht_ensure_bsdsocket(base);
    if (rc != 0) {
        return rc;
    }
    htDbgPut("ht_transport_connect lookup");
    herr = 0;
    hent = ht_lookup_host_ipv4(base, host, &he, hbuf, &herr);
    if (hent == NULL) {
        return ERROR_HTTP_DNS_FAILED;
    }
    sock = ht_socket_stream(base);
    if (sock < 0) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    rc = ht_tcp_connect(base, sock, hent, port, timeout_secs);
    if (rc != 0) {
        CloseSocket(sock);
        return rc;
    }

    conn->hc_Sock = sock;
    conn->hc_IsSsl = ssl;
    conn->hc_Port = port;
    if (conn->hc_Host) {
        ht_free(conn->hc_Host);
    }
    conn->hc_Host = ht_strdup(host);

    if (ssl) {
        rc = ht_transport_task_ssl_ensure(base);
        if (rc != 0) {
            ht_transport_disconnect(base, conn);
            return rc;
        }
        conn->hc_SslTaskHeld = TRUE;
        conn->hc_SslCtx = ht_ssl_create(host, ca_bundle_path);
        if (conn->hc_SslCtx == NULL) {
            ht_transport_disconnect(base, conn);
            return ERROR_HTTP_OUT_OF_MEMORY;
        }
        rc = ht_ssl_attach_socket(base, conn->hc_SslCtx, sock, host, ssl_verify,
            timeout_secs, NULL);
        if (rc != 0) {
            ht_transport_disconnect(base, conn);
            return rc;
        }
    }
    return 0;
}

VOID
ht_transport_disconnect(struct AmiHttpBase *base, struct HtConnection *conn)
{
    if (conn == NULL) {
        return;
    }
    if (conn->hc_SslCtx != NULL) {
        ht_ssl_destroy(conn->hc_SslCtx);
        conn->hc_SslCtx = NULL;
    }
    if (conn->hc_SslTaskHeld) {
        if (base != NULL) {
            ht_transport_task_ssl_release(base);
        }
        conn->hc_SslTaskHeld = FALSE;
    }
    if (conn->hc_Sock >= 0) {
        ht_transport_close_socket(base, conn->hc_Sock);
        conn->hc_Sock = -1;
    }
    conn->hc_IoLen = 0;
    conn->hc_IoPos = 0;
}

LONG
ht_transport_send(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR data, ULONG len)
{
    LONG sent;
    LONG total;
    LONG n;

    if (base == NULL || conn == NULL || data == NULL || len == 0) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (conn->hc_Sock < 0) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    total = 0;
    while ((ULONG)total < len) {
        if (conn->hc_SslCtx != NULL) {
            n = ht_ssl_send(conn->hc_SslCtx, (UBYTE *)data + total, len - (ULONG)total);
        } else {
            ht_bind_socketbase(base);
            n = send(conn->hc_Sock, (char *)data + total, (int)(len - (ULONG)total), 0);
        }
        if (n <= 0) {
            return ERROR_HTTP_WRITE_FAILED;
        }
        total += n;
    }
    sent = total;
    return sent;
}

static LONG
ht_transport_raw_recv(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR buf, ULONG len, ULONG timeout_secs)
{
    fd_set rfds;
    struct timeval tv;
    LONG nfds;
    LONG rc;
    LONG n;

    if (timeout_secs > 0) {
        FD_ZERO(&rfds);
        FD_SET((int)conn->hc_Sock, &rfds);
        nfds = conn->hc_Sock + 1;
        tv.tv_sec = (long)timeout_secs;
        tv.tv_usec = 0;
        ht_bind_socketbase(base);
        rc = WaitSelect((int)nfds, &rfds, NULL, NULL, &tv, NULL);
        if (rc <= 0) {
            return -(LONG)ERROR_HTTP_READ_TIMEOUT;
        }
    }
    ht_bind_socketbase(base);
    n = recv(conn->hc_Sock, (char *)buf, (int)len, 0);
    if (n < 0) {
        return -(LONG)ERROR_HTTP_READ_FAILED;
    }
    if ((ULONG)n > len) {
        n = (LONG)len;
    }
    return n;
}

LONG
ht_transport_recv(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR buf, ULONG len, ULONG timeout_secs)
{
    LONG n;

    if (base == NULL || conn == NULL || buf == NULL || len == 0) {
        return -(LONG)ERROR_HTTP_INVALID_HANDLE;
    }
    if (conn->hc_Sock < 0) {
        return -(LONG)ERROR_HTTP_INVALID_HANDLE;
    }
    if (conn->hc_SslCtx != NULL) {
        n = ht_ssl_recv(base, conn->hc_SslCtx, conn->hc_Sock, buf, len,
            timeout_secs);
        return n;
    }
    return ht_transport_raw_recv(base, conn, buf, len, timeout_secs);
}

BOOL
ht_transport_conn_idle(struct AmiHttpBase *base, struct HtConnection *conn)
{
    fd_set rfds;
    fd_set efds;
    struct timeval tv;
    LONG nfds;
    LONG rc;

    if (conn == NULL || conn->hc_Sock < 0) {
        return TRUE;
    }
    if (conn->hc_SslCtx != NULL && !ht_ssl_idle(conn->hc_SslCtx)) {
        return FALSE;
    }
    FD_ZERO(&rfds);
    FD_ZERO(&efds);
    FD_SET((int)conn->hc_Sock, &rfds);
    FD_SET((int)conn->hc_Sock, &efds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    nfds = conn->hc_Sock + 1;
    ht_bind_socketbase(base);
    rc = WaitSelect((int)nfds, &rfds, NULL, &efds, &tv, NULL);
    if (rc != 0) {
        return FALSE;
    }
    return TRUE;
}
