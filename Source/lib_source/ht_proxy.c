/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_proxy.c - HTTP proxy routing and CONNECT tunnel for HTTPS
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "private/ht_debug.h"
#include "private/ht_internal.h"

static STRPTR
ht_proxy_spec(struct AmiHttpBase *base, struct HttpSession *session)
{
    if (session != NULL && session->hs_Proxy != NULL &&
        session->hs_Proxy[0] != '\0') {
        return session->hs_Proxy;
    }
    if (base != NULL && base->ahb_DefaultProxy != NULL &&
        base->ahb_DefaultProxy[0] != '\0') {
        return base->ahb_DefaultProxy;
    }
    return NULL;
}

/*
 * Parse "host", "host:port", or "http://host:port" proxy strings.
 */
static LONG
ht_proxy_parse(STRPTR spec, STRPTR *out_host, ULONG *out_port)
{
    STRPTR host;
    STRPTR p;
    STRPTR colon;
    ULONG port;

    if (spec == NULL || out_host == NULL || out_port == NULL) {
        return ERROR_HTTP_INVALID_URL;
    }
    host = spec;
    if (Strnicmp(spec, (STRPTR)"http://", 7) == 0) {
        host = spec + 7;
    } else if (Strnicmp(spec, (STRPTR)"https://", 8) == 0) {
        host = spec + 8;
    }
    for (colon = host; *colon != '\0' && *colon != ':'; colon++) {
        ;
    }
    if (*colon == ':') {
        {
            LONG portl;

            portl = 0;
            if (StrToLong(colon + 1, &portl) >= 1 && portl > 0) {
                port = (ULONG)portl;
            } else {
                port = 8080UL;
            }
        }
        *out_host = ht_strndup(host, (LONG)(colon - host));
    } else {
        port = 8080UL;
        *out_host = ht_strdup(host);
    }
    if (*out_host == NULL) {
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    for (p = *out_host; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            break;
        }
    }
    *out_port = port;
    return 0;
}

static STRPTR
ht_route_build_request_uri(struct ParsedUrl *pu, STRPTR full_url, BOOL absolute)
{
    STRPTR uri;
    ULONG len;
    char portbuf[16];

    if (pu == NULL) {
        return NULL;
    }
    if (absolute) {
        if (full_url != NULL && full_url[0] != '\0') {
            return ht_strdup(full_url);
        }
        len = 8;
        if (pu->pu_Host) {
            len += ht_strlen(pu->pu_Host);
        }
        if (pu->pu_Path) {
            len += ht_strlen(pu->pu_Path);
        }
        if (pu->pu_Query) {
            len += ht_strlen(pu->pu_Query) + 1;
        }
        len += 16;
        uri = (STRPTR)ht_alloc(len, MEMF_CLEAR);
        if (uri == NULL) {
            return NULL;
        }
        portbuf[0] = '\0';
        if (pu->pu_Port != 0 &&
            !((pu->pu_IsSecure && pu->pu_Port == 443) ||
              (!pu->pu_IsSecure && pu->pu_Port == 80))) {
            SNPrintf((STRPTR)portbuf, (ULONG)sizeof(portbuf),
                (CONST_STRPTR)":%lu", pu->pu_Port);
        }
        if (pu->pu_Query != NULL && pu->pu_Query[0] != '\0') {
            SNPrintf((STRPTR)uri, len,
                (CONST_STRPTR)"%s://%s%s%s?%s",
                pu->pu_IsSecure ? (CONST_STRPTR)"https" : (CONST_STRPTR)"http",
                pu->pu_Host ? pu->pu_Host : (STRPTR)"",
                portbuf,
                pu->pu_Path ? pu->pu_Path : (STRPTR)"/",
                pu->pu_Query);
        } else {
            SNPrintf((STRPTR)uri, len,
                (CONST_STRPTR)"%s://%s%s%s",
                pu->pu_IsSecure ? (CONST_STRPTR)"https" : (CONST_STRPTR)"http",
                pu->pu_Host ? pu->pu_Host : (STRPTR)"",
                portbuf,
                pu->pu_Path ? pu->pu_Path : (STRPTR)"/");
        }
        return uri;
    }
    if (pu->pu_Query != NULL && pu->pu_Query[0] != '\0') {
        len = ht_strlen(pu->pu_Path) + ht_strlen(pu->pu_Query) + 2;
        uri = (STRPTR)ht_alloc(len, MEMF_CLEAR);
        if (uri == NULL) {
            return NULL;
        }
        SNPrintf((STRPTR)uri, len, (CONST_STRPTR)"%s?%s",
            pu->pu_Path ? pu->pu_Path : (STRPTR)"/",
            pu->pu_Query);
        return uri;
    }
    if (pu->pu_Path != NULL) {
        return ht_strdup(pu->pu_Path);
    }
    return ht_strdup((STRPTR)"/");
}

static STRPTR
ht_route_build_tunnel_target(struct ParsedUrl *pu)
{
    char buf[280];

    if (pu == NULL || pu->pu_Host == NULL) {
        return NULL;
    }
    if (pu->pu_Port == 0) {
        pu->pu_Port = pu->pu_IsSecure ? 443UL : 80UL;
    }
    if ((pu->pu_IsSecure && pu->pu_Port == 443) ||
        (!pu->pu_IsSecure && pu->pu_Port == 80)) {
        return ht_strdup(pu->pu_Host);
    }
    SNPrintf((STRPTR)buf, (ULONG)sizeof(buf),
        (CONST_STRPTR)"%s:%lu", pu->pu_Host, pu->pu_Port);
    return ht_strdup((STRPTR)buf);
}

LONG
ht_route_resolve(struct AmiHttpBase *base, struct HttpSession *session,
    struct ParsedUrl *pu, STRPTR full_url, struct HtRoute *route)
{
    STRPTR proxy;
    STRPTR proxy_host;
    ULONG proxy_port;
    LONG rc;

    if (pu == NULL || route == NULL || pu->pu_Host == NULL) {
        return ERROR_HTTP_INVALID_URL;
    }
    route->hr_ConnectHost = NULL;
    route->hr_ConnectPort = 0;
    route->hr_OriginHost = NULL;
    route->hr_OriginPort = 0;
    route->hr_OriginSsl = FALSE;
    route->hr_ViaProxy = FALSE;
    route->hr_SslTunnel = FALSE;
    route->hr_RequestUri = NULL;
    route->hr_TunnelTarget = NULL;
    if (pu->pu_Port == 0) {
        pu->pu_Port = pu->pu_IsSecure ? 443UL : 80UL;
    }
    route->hr_OriginHost = ht_strdup(pu->pu_Host);
    route->hr_OriginPort = pu->pu_Port;
    route->hr_OriginSsl = pu->pu_IsSecure;
    if (route->hr_OriginHost == NULL) {
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    proxy = ht_proxy_spec(base, session);
    if (proxy == NULL) {
        route->hr_ConnectHost = ht_strdup(pu->pu_Host);
        route->hr_ConnectPort = pu->pu_Port;
        route->hr_ViaProxy = FALSE;
        route->hr_SslTunnel = FALSE;
        route->hr_RequestUri = ht_route_build_request_uri(pu, full_url, FALSE);
        if (route->hr_ConnectHost == NULL || route->hr_RequestUri == NULL) {
            ht_route_free(route);
            return ERROR_HTTP_OUT_OF_MEMORY;
        }
        return 0;
    }
    proxy_host = NULL;
    proxy_port = 8080UL;
    rc = ht_proxy_parse(proxy, &proxy_host, &proxy_port);
    if (rc != 0) {
        ht_route_free(route);
        return rc;
    }
    route->hr_ViaProxy = TRUE;
    route->hr_ConnectHost = proxy_host;
    route->hr_ConnectPort = proxy_port;
    if (pu->pu_IsSecure) {
        route->hr_SslTunnel = TRUE;
        route->hr_TunnelTarget = ht_route_build_tunnel_target(pu);
        route->hr_RequestUri = ht_route_build_request_uri(pu, full_url, FALSE);
    } else {
        route->hr_SslTunnel = FALSE;
        route->hr_RequestUri = ht_route_build_request_uri(pu, full_url, TRUE);
    }
    if (route->hr_RequestUri == NULL ||
        (route->hr_SslTunnel && route->hr_TunnelTarget == NULL)) {
        ht_route_free(route);
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    return 0;
}

VOID
ht_route_free(struct HtRoute *route)
{
    if (route == NULL) {
        return;
    }
    if (route->hr_ConnectHost) {
        ht_free(route->hr_ConnectHost);
    }
    if (route->hr_OriginHost) {
        ht_free(route->hr_OriginHost);
    }
    if (route->hr_RequestUri) {
        ht_free(route->hr_RequestUri);
    }
    if (route->hr_TunnelTarget) {
        ht_free(route->hr_TunnelTarget);
    }
    route->hr_ConnectHost = NULL;
    route->hr_ConnectPort = 0;
    route->hr_OriginHost = NULL;
    route->hr_OriginPort = 0;
    route->hr_OriginSsl = FALSE;
    route->hr_ViaProxy = FALSE;
    route->hr_SslTunnel = FALSE;
    route->hr_RequestUri = NULL;
    route->hr_TunnelTarget = NULL;
}

/*
 * Read CONNECT response status; expect HTTP/1.x 200 before TLS handshake.
 */
static LONG
ht_proxy_parse_connect_status(UBYTE *buf, ULONG total, LONG *code_out)
{
    ULONG i;
    STRPTR p;
    LONG consumed;

    if (buf == NULL || code_out == NULL) {
        return ERROR_HTTP_PROTOCOL;
    }
    *code_out = 0;
    for (i = 0; i + 11 < total; i++) {
        if (buf[i] == 'H' && buf[i + 1] == 'T' && buf[i + 2] == 'T' &&
            buf[i + 3] == 'P' && buf[i + 4] == '/') {
            p = (STRPTR)(buf + i + 5);
            while (*p != ' ' && *p != '\0') {
                p++;
            }
            while (*p == ' ') {
                p++;
            }
            consumed = StrToLong(p, code_out);
            if (consumed >= 1) {
                return 0;
            }
            *code_out = 0;
            return ERROR_HTTP_PROTOCOL;
        }
    }
    return ERROR_HTTP_PROTOCOL;
}

static LONG
ht_proxy_read_connect_response(struct AmiHttpBase *base,
    struct HtConnection *conn, ULONG timeout_secs)
{
    UBYTE buf[512];
    ULONG total;
    ULONG i;
    LONG n;
    LONG code;

    total = 0;
    code = 0;
    for (;;) {
        if (total >= sizeof(buf) - 1) {
            return ERROR_HTTP_PROTOCOL;
        }
        n = ht_transport_recv(base, conn, buf + total, 1, timeout_secs);
        if (n < 0) {
            return ht_wire_to_status(n);
        }
        if (n == 0) {
            return ERROR_HTTP_PROTOCOL;
        }
        total += (ULONG)n;
        buf[total] = '\0';
        if (total >= 4 &&
            buf[total - 4] == '\r' && buf[total - 3] == '\n' &&
            buf[total - 2] == '\r' && buf[total - 1] == '\n') {
            break;
        }
        if (total >= 2 && buf[total - 2] == '\n' && buf[total - 1] == '\n') {
            break;
        }
    }
    for (i = 0; i + 11 < total; i++) {
        if (buf[i] == 'H' && buf[i + 1] == 'T' && buf[i + 2] == 'T' &&
            buf[i + 3] == 'P' && buf[i + 4] == '/') {
            if (ht_proxy_parse_connect_status(buf, total, &code) == 0) {
                break;
            }
        }
    }
    if (code == 407) {
        return ERROR_HTTP_PROXY_AUTH;
    }
    if (code != 200) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    return 0;
}

static LONG
ht_proxy_send_connect(struct AmiHttpBase *base, struct HtConnection *conn,
    struct HtRoute *route, struct HttpTransaction *txn, ULONG timeout_secs)
{
    UBYTE req[1024];
    ULONG len;
    LONG rc;

    if (route == NULL || route->hr_TunnelTarget == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    len = (ULONG)SNPrintf((STRPTR)req, (ULONG)sizeof(req),
        (CONST_STRPTR)"CONNECT %s HTTP/1.1\r\n"
        "Host: %s\r\n",
        route->hr_TunnelTarget,
        route->hr_TunnelTarget);
    if (txn != NULL && txn->ht_BasicProxyAuth != NULL &&
        txn->ht_BasicProxyAuth[0] != '\0') {
        len += (ULONG)SNPrintf((STRPTR)req + len, (ULONG)sizeof(req) - len,
            (CONST_STRPTR)"Proxy-Authorization: Basic %s\r\n",
            txn->ht_BasicProxyAuth);
    }
    Strncat((STRPTR)req, (CONST_STRPTR)"\r\n", (ULONG)sizeof(req));
    len = ht_strlen((STRPTR)req);
    rc = ht_transport_send(base, conn, req, len);
    if (rc < 0) {
        return rc;
    }
    return ht_proxy_read_connect_response(base, conn, timeout_secs);
}

LONG
ht_transport_connect_route(struct AmiHttpBase *base, struct HtConnection *conn,
    struct HtRoute *route, ULONG timeout_secs, ULONG ssl_verify,
    struct HttpTransaction *txn, STRPTR ca_bundle_path)
{
    LONG rc;
    BOOL use_ssl;

    if (base == NULL || conn == NULL || route == NULL ||
        route->hr_ConnectHost == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    rc = ht_transport_connect(base, conn, route->hr_ConnectHost,
        route->hr_ConnectPort, FALSE, timeout_secs, ssl_verify, ca_bundle_path);
    if (rc != 0) {
        return rc;
    }
    conn->hc_ViaProxy = route->hr_ViaProxy;
    if (conn->hc_OriginHost) {
        ht_free(conn->hc_OriginHost);
    }
    conn->hc_OriginHost = ht_strdup(route->hr_OriginHost);
    conn->hc_OriginPort = route->hr_OriginPort;
    if (route->hr_ViaProxy) {
        conn->hc_Flags |= HTF_VIA_PROXY;
    }
    if (route->hr_SslTunnel) {
        conn->hc_Flags |= HTF_SSL_TUNNEL;
        rc = ht_proxy_send_connect(base, conn, route, txn, timeout_secs);
        if (rc != 0) {
            ht_transport_disconnect(base, conn);
            return rc;
        }
        use_ssl = TRUE;
    } else {
        use_ssl = route->hr_OriginSsl;
    }
    conn->hc_IsSsl = use_ssl;
    if (use_ssl) {
        /*
         * HTTPS CONNECT tunnel: same deferred-handshake rules as direct TLS in
         * ht_transport_connect (ht_ssl_amitls.c file header).  No FIONBIO here.
         */
        if (conn->hc_SslCtx != NULL) {
            ht_ssl_close(conn->hc_SslCtx);
            ht_ssl_destroy(conn->hc_SslCtx);
            conn->hc_SslCtx = NULL;
        }
        rc = ht_transport_task_ssl_ensure(base);
        if (rc != 0) {
            ht_transport_disconnect(base, conn);
            return rc;
        }
        conn->hc_SslTaskHeld = TRUE;
        conn->hc_SslCtx = ht_ssl_create(route->hr_OriginHost, ca_bundle_path);
        if (conn->hc_SslCtx == NULL) {
            ht_transport_disconnect(base, conn);
            return ERROR_HTTP_OUT_OF_MEMORY;
        }
        rc = ht_ssl_attach_socket(base, conn->hc_SslCtx, conn->hc_Sock,
            route->hr_OriginHost, ssl_verify, timeout_secs, txn);
        if (rc != 0) {
            ht_transport_disconnect(base, conn);
            return rc;
        }
    }
    if (conn->hc_Host) {
        ht_free(conn->hc_Host);
    }
    conn->hc_Host = ht_strdup(route->hr_OriginHost);
    conn->hc_Port = route->hr_OriginPort;
    return 0;
}
