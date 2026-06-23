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

static VOID
ht_bind_socketbase(struct AmiHttpBase *base)
{
    if (base != NULL) {
        ht_sync_proto_bases(base);
    }
}

static VOID
ht_socket_configure(VOID)
{
    struct TagItem tags[3];

    tags[0].ti_Tag = SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(errno)));
    tags[0].ti_Data = (ULONG)&errno;
    tags[1].ti_Tag = SBTM_SETVAL(SBTC_HERRNOLONGPTR);
    tags[1].ti_Data = (ULONG)&h_errno;
    tags[2].ti_Tag = TAG_END;
    SocketBaseTagList(tags);
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
        errno = 0;
        h_errno = 0;
        ht_socket_configure();
        ht_socket_probe_api();
        htDbgPutHex("ht_ensure_bsdsocket ok=", (ULONG)base->ahb_SocketBase);
    }
    ReleaseSemaphore(&base->ahb_SocketSema);
    return 0;
}

static LONG
ht_tcp_connect(LONG sock, struct hostent *hent, ULONG port, ULONG timeout_secs)
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

    sad.sin_len = sizeof(sad);
    sad.sin_family = hent->h_addrtype;
    sad.sin_port = htons((UWORD)port);
    sad.sin_addr.s_addr = *(ULONG *)(*hent->h_addr_list);
    /*
     * Avoid infinite blocking connect(): use non-blocking connect with WaitSelect.
     * Roadshow/bsdsocket uses IoctlSocket(FIONBIO).
     */
    one = 1;
    IoctlSocket(sock, FIONBIO, (char *)&one);
    result = connect(sock, (struct sockaddr *)&sad, sizeof(sad));
    if (result == 0) {
        one = 0;
        IoctlSocket(sock, FIONBIO, (char *)&one);
        return 0;
    }
    if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
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

LONG
ht_transport_connect(struct AmiHttpBase *base, struct HtConnection *conn,
    STRPTR host, ULONG port, BOOL ssl, ULONG timeout_secs, ULONG ssl_verify)
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
    ht_bind_socketbase(base);
    htDbgPut("ht_transport_connect lookup");
    hent = NULL;
    if (ht_has_gethost_r) {
        herr = 0;
        hent = gethostbyname_r((char *)host, &he, hbuf,
            (ULONG)sizeof(hbuf), &herr);
    } else {
        hent = gethostbyname((char *)host);
    }
    if (hent == NULL) {
        return ERROR_HTTP_DNS_FAILED;
    }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    rc = ht_tcp_connect(sock, hent, port, timeout_secs);
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
        conn->hc_SslCtx = ht_ssl_create(host);
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
        ht_ssl_close(conn->hc_SslCtx);
        ht_ssl_destroy(conn->hc_SslCtx);
        conn->hc_SslCtx = NULL;
        if (base != NULL) {
            ht_transport_task_ssl_release(base);
        }
    }
    if (conn->hc_Sock >= 0) {
        ht_bind_socketbase(base);
        shutdown(conn->hc_Sock, 2);
        CloseSocket(conn->hc_Sock);
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
