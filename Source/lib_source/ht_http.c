/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_http.c - HTTP/1.1 request build and response parse
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <proto/exec.h>
#include <proto/alib.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "private/ht_internal.h"
#include "private/ht_debug.h"
#include "private/ht_hooks.h"

#define HT_MAX_RESP_HEADERS 128

extern struct AmiHttpBase *HttpBase;

static int
ht_str_ieq(STRPTR a, STRPTR b)
{
    char ca;
    char cb;

    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        ca = *a++;
        cb = *b++;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return 0;
        }
    }
    return (*a == '\0' && *b == '\0');
}

static STRPTR
ht_header_value(struct HttpTransaction *txn, STRPTR name)
{
    struct HttpHeader *hh;

    for (hh = (struct HttpHeader *)txn->ht_RespHeaders.lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = (struct HttpHeader *)hh->hh_Node.ln_Succ) {
        if (ht_str_ieq(hh->hh_Name, name)) {
            return hh->hh_Value;
        }
    }
    return NULL;
}

static VOID
ht_clear_resp_headers(struct HttpTransaction *txn)
{
    struct HttpHeader *hh;
    struct HttpHeader *next;

    for (hh = (struct HttpHeader *)txn->ht_RespHeaders.lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = next) {
        next = (struct HttpHeader *)hh->hh_Node.ln_Succ;
        Remove(&hh->hh_Node);
        if (hh->hh_Name) {
            ht_free(hh->hh_Name);
        }
        if (hh->hh_Value) {
            ht_free(hh->hh_Value);
        }
        ht_free(hh);
    }
}

static VOID
ht_conn_compact(struct HtConnection *conn)
{
    ULONG remain;

    if (conn == NULL || conn->hc_IoBuf == NULL) {
        return;
    }
    if (conn->hc_IoPos > 0 && conn->hc_IoLen > conn->hc_IoPos) {
        remain = conn->hc_IoLen - conn->hc_IoPos;
        memmove(conn->hc_IoBuf, conn->hc_IoBuf + conn->hc_IoPos, remain);
        conn->hc_IoLen = remain;
        conn->hc_IoPos = 0;
    } else if (conn->hc_IoPos >= conn->hc_IoLen) {
        conn->hc_IoPos = 0;
        conn->hc_IoLen = 0;
    }
}

/*
 * Locate entity body after the header block.  Scan for the
 * blank line terminator (\r\n\r\n) in the full receive buffer so a partial
 * line parse cannot leave header tail bytes (e.g. ": private\r\n\r\n") in
 * front of the HTML body.
 */
static LONG
ht_conn_sync_body_start(struct HtConnection *conn, ULONG *body_start)
{
    ULONG i;

    if (conn == NULL || conn->hc_IoBuf == NULL || body_start == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    for (i = 0; i + 3 < conn->hc_IoLen; i++) {
        if (conn->hc_IoBuf[i] == '\r' && conn->hc_IoBuf[i + 1] == '\n' &&
            conn->hc_IoBuf[i + 2] == '\r' && conn->hc_IoBuf[i + 3] == '\n') {
            *body_start = i + 4;
            return 0;
        }
    }
    return ERROR_HTTP_PROTOCOL;
}

static LONG
ht_conn_fill(struct AmiHttpBase *base, struct HtConnection *conn,
    ULONG timeout_secs)
{
    ULONG space;
    LONG n;

    if (conn->hc_IoBuf == NULL) {
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    ht_conn_compact(conn);
    if (conn->hc_IoCap == 0) {
        return ERROR_HTTP_PROTOCOL;
    }
    space = conn->hc_IoCap - conn->hc_IoLen;
    if (space == 0) {
        return ERROR_HTTP_PROTOCOL;
    }
    n = ht_transport_recv(base, conn, conn->hc_IoBuf + conn->hc_IoLen,
        space, timeout_secs);
    if (n < 0) {
        return ht_wire_to_status(n);
    }
    if (n == 0) {
        return ERROR_HTTP_READ_FAILED;
    }
    if ((ULONG)n > space) {
        n = (LONG)space;
    }
    if (conn->hc_IoLen + (ULONG)n > conn->hc_IoCap) {
        return ERROR_HTTP_PROTOCOL;
    }
    conn->hc_IoLen += (ULONG)n;
    return 0;
}

static LONG
ht_conn_ensure_bytes(struct AmiHttpBase *base, struct HtConnection *conn,
    ULONG need, ULONG timeout_secs)
{
    LONG rc;

    while ((conn->hc_IoLen - conn->hc_IoPos) < need) {
        rc = ht_conn_fill(base, conn, timeout_secs);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

static LONG
ht_find_crlf(struct HtConnection *conn, ULONG *line_start, ULONG *line_len)
{
    ULONG i;
    ULONG avail;

    avail = conn->hc_IoLen - conn->hc_IoPos;
    for (i = 0; i + 1 < avail; i++) {
        if (conn->hc_IoBuf[conn->hc_IoPos + i] == '\r' &&
            conn->hc_IoBuf[conn->hc_IoPos + i + 1] == '\n') {
            *line_start = conn->hc_IoPos;
            *line_len = i;
            return 0;
        }
    }
    return ERROR_HTTP_READ_TIMEOUT;
}

static STRPTR
ht_copy_line(struct HtConnection *conn, ULONG line_start, ULONG line_len)
{
  return ht_strndup((STRPTR)(conn->hc_IoBuf + line_start), (LONG)line_len);
}

static LONG
ht_add_header_to_list(struct List *list, STRPTR name, STRPTR value)
{
    struct HttpHeader *hh;

    if (list == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    hh = (struct HttpHeader *)ht_alloc(sizeof(struct HttpHeader), MEMF_CLEAR);
    if (hh == NULL) {
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    hh->hh_Name = ht_strdup(name);
    hh->hh_Value = ht_strdup(value);
    if (hh->hh_Name == NULL || hh->hh_Value == NULL) {
        if (hh->hh_Name) {
            ht_free(hh->hh_Name);
        }
        if (hh->hh_Value) {
            ht_free(hh->hh_Value);
        }
        ht_free(hh);
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    AddTail(list, &hh->hh_Node);
    return 0;
}

static LONG
ht_add_resp_header(struct HttpTransaction *txn, STRPTR name, STRPTR value)
{
    if (txn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    return ht_add_header_to_list(&txn->ht_RespHeaders, name, value);
}

static STRPTR
ht_session_user_agent(struct HttpSession *session)
{
    if (session != NULL && session->hs_UserAgent != NULL &&
        session->hs_UserAgent[0] != '\0') {
        return session->hs_UserAgent;
    }
    if (HttpBase != NULL && HttpBase->ahb_DefaultUserAgent != NULL &&
        HttpBase->ahb_DefaultUserAgent[0] != '\0') {
        return HttpBase->ahb_DefaultUserAgent;
    }
    return (STRPTR)"amihttp/1.0";
}

STRPTR
ht_txn_user_agent(struct HttpTransaction *txn)
{
    if (txn != NULL && txn->ht_UserAgent != NULL &&
        txn->ht_UserAgent[0] != '\0') {
        return txn->ht_UserAgent;
    }
    if (txn != NULL) {
        return ht_session_user_agent(txn->ht_Session);
    }
    return ht_session_user_agent(NULL);
}

LONG
ht_http_build_request(struct HttpTransaction *txn, UBYTE **out_buf, ULONG *out_len)
{
    struct ParsedUrl pu;
    STRPTR method;
    STRPTR path;
    STRPTR cookie_hdr;
    ULONG cap;
    ULONG used;
    UBYTE *buf;
    UBYTE *p;
    struct HttpHeader *hh;
    LONG rc;
    char line[512];

    if (txn == NULL || out_buf == NULL || out_len == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (txn->ht_Url == NULL) {
        return ERROR_HTTP_INVALID_URL;
    }
    rc = ht_url_parse(txn->ht_Url, &pu);
    if (rc != 0) {
        return rc;
    }
    method = txn->ht_Method;
    if (method == NULL || method[0] == '\0') {
        if (txn->ht_PostBody != NULL || txn->ht_PostLength > 0) {
            method = (STRPTR)"POST";
        } else {
            method = (STRPTR)"GET";
        }
    }
    path = pu.pu_Path;
    if (path == NULL || path[0] == '\0') {
        path = (STRPTR)"/";
    }
    cap = HT_REQBUF_INIT;
    buf = (UBYTE *)ht_alloc(cap, MEMF_CLEAR);
    if (buf == NULL) {
        ht_url_free_fields(&pu);
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    used = 0;
    p = buf;
    if (pu.pu_Query != NULL && pu.pu_Query[0] != '\0') {
        sprintf((char *)line, "%s %s?%s HTTP/1.1\r\n", method, path, pu.pu_Query);
    } else {
        sprintf((char *)line, "%s %s HTTP/1.1\r\n", method, path);
    }
    used = (ULONG)strlen(line);
    memcpy(p, line, used);
    p += used;
    sprintf((char *)line, "Host: %s", pu.pu_Host);
    if (pu.pu_Port != 0 &&
        !((pu.pu_IsSecure && pu.pu_Port == 443) ||
          (!pu.pu_IsSecure && pu.pu_Port == 80))) {
        sprintf((char *)line + strlen(line), ":%lu", pu.pu_Port);
    }
    strcat((char *)line, "\r\n");
    used = (ULONG)strlen((char *)buf) + (ULONG)strlen(line);
    if (used + 1 > cap) {
        ht_free(buf);
        ht_url_free_fields(&pu);
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    strcat((char *)buf, line);
    p = buf + strlen((char *)buf);
    sprintf((char *)line, "User-Agent: %s\r\n", ht_txn_user_agent(txn));
    strcat((char *)buf, line);
    strcat((char *)buf, "Accept: */*\r\n");
    if (txn->ht_Session != NULL && txn->ht_Session->hs_KeepAlive) {
        strcat((char *)buf, "Connection: keep-alive\r\n");
        txn->ht_Flags |= HTF_KEEPALIVE_REQ;
    } else {
        strcat((char *)buf, "Connection: close\r\n");
    }
    if (txn->ht_Referer != NULL && txn->ht_Referer[0] != '\0') {
        sprintf((char *)line, "Referer: %s\r\n", txn->ht_Referer);
        strcat((char *)buf, line);
    }
    if (txn->ht_Session != NULL && txn->ht_Session->hs_AcceptEncoding != NULL &&
        txn->ht_Session->hs_AcceptEncoding[0] != '\0') {
        /*
         * Only advertise encodings we can actually decode.
         * For now, gzip/deflate require a valid open z.library handle.
         */
        if (HttpBase != NULL && HttpBase->ahb_ZDecodeReady) {
            if (HttpBase->ahb_ZBase == NULL) {
                HttpBase->ahb_ZBase = OpenLibrary((STRPTR)"z.library", 0);
            }
        }
        if (HttpBase != NULL && HttpBase->ahb_ZDecodeReady && HttpBase->ahb_ZBase != NULL) {
            sprintf((char *)line, "Accept-Encoding: %s\r\n",
                txn->ht_Session->hs_AcceptEncoding);
            strcat((char *)buf, line);
        }
    }
    if (txn->ht_RangeStart >= 0) {
        if (txn->ht_RangeEnd >= txn->ht_RangeStart) {
            sprintf((char *)line, "Range: bytes=%ld-%ld\r\n",
                txn->ht_RangeStart, txn->ht_RangeEnd);
        } else {
            sprintf((char *)line, "Range: bytes=%ld-\r\n", txn->ht_RangeStart);
        }
        strcat((char *)buf, line);
    }
    if (txn->ht_IfModifiedSince != NULL && txn->ht_IfModifiedSince[0] != '\0') {
        sprintf((char *)line, "If-Modified-Since: %s\r\n",
            txn->ht_IfModifiedSince);
        strcat((char *)buf, line);
    }
    if (txn->ht_IfNoneMatch != NULL && txn->ht_IfNoneMatch[0] != '\0') {
        sprintf((char *)line, "If-None-Match: %s\r\n", txn->ht_IfNoneMatch);
        strcat((char *)buf, line);
    }
    if (txn->ht_NoCache) {
        strcat((char *)buf, "Cache-Control: no-cache\r\n");
        strcat((char *)buf, "Pragma: no-cache\r\n");
    }
    if (txn->ht_Session != NULL && txn->ht_Session->hs_CookieJar != NULL) {
        cookie_hdr = ht_cookie_header_for_url(txn->ht_Session->hs_CookieJar,
            txn->ht_Url, pu.pu_IsSecure);
        if (cookie_hdr != NULL && cookie_hdr[0] != '\0') {
            sprintf((char *)line, "Cookie: %s\r\n", cookie_hdr);
            strcat((char *)buf, line);
        }
        if (cookie_hdr != NULL) {
            ht_free(cookie_hdr);
        }
    }
    if (txn->ht_BasicAuth != NULL && txn->ht_BasicAuth[0] != '\0') {
        sprintf((char *)line, "Authorization: Basic %s\r\n", txn->ht_BasicAuth);
        strcat((char *)buf, line);
    }
    if (txn->ht_BasicProxyAuth != NULL && txn->ht_BasicProxyAuth[0] != '\0') {
        sprintf((char *)line, "Proxy-Authorization: Basic %s\r\n",
            txn->ht_BasicProxyAuth);
        strcat((char *)buf, line);
    }
    if (txn->ht_PostBody != NULL && txn->ht_PostLength > 0) {
        sprintf((char *)line, "Content-Length: %lu\r\n", txn->ht_PostLength);
        strcat((char *)buf, line);
        strcat((char *)buf, "Content-Type: application/x-www-form-urlencoded\r\n");
    }
    for (hh = (struct HttpHeader *)txn->ht_ReqHeaders.lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = (struct HttpHeader *)hh->hh_Node.ln_Succ) {
        if (hh->hh_Name != NULL && hh->hh_Value != NULL) {
            sprintf((char *)line, "%s: %s\r\n", hh->hh_Name, hh->hh_Value);
            strcat((char *)buf, line);
        }
    }
    strcat((char *)buf, "\r\n");
    *out_buf = buf;
    *out_len = (ULONG)strlen((char *)buf);
    ht_url_free_fields(&pu);
    return 0;
}

LONG
ht_http_send_request(struct AmiHttpBase *base, struct HttpTransaction *txn)
{
    UBYTE *req;
    ULONG reqlen;
    LONG rc;

    if (txn == NULL || txn->ht_Conn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    rc = ht_http_build_request(txn, &req, &reqlen);
    if (rc != 0) {
        return rc;
    }
    rc = ht_transport_send(base, txn->ht_Conn, req, reqlen);
    ht_free(req);
    if (rc < 0) {
        return rc;
    }
    if (txn->ht_PostBody != NULL && txn->ht_PostLength > 0) {
        rc = ht_transport_send(base, txn->ht_Conn, txn->ht_PostBody,
            txn->ht_PostLength);
    }
    return rc;
}

LONG
ht_http_read_response_headers(struct AmiHttpBase *base, struct HttpTransaction *txn)
{
    ULONG timeout;
    ULONG line_start;
    ULONG line_len;
    STRPTR line;
    STRPTR colon;
    STRPTR name;
    STRPTR value;
    LONG rc;
    LONG code;
    STRPTR conn_val;
    STRPTR te_val;
    STRPTR cl_val;
    STRPTR ce_val;
    STRPTR loc_val;
    STRPTR cc_val;
    STRPTR auth_val;
    ULONG header_count;

    if (txn == NULL || txn->ht_Conn == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    timeout = txn->ht_Session ? txn->ht_Session->hs_ReadTimeout : 0;
    if (timeout == 0 && HttpBase != NULL) {
        timeout = HttpBase->ahb_DefaultTimeout;
    }
    ht_clear_resp_headers(txn);
    Http_cc_reset_accum(&txn->ht_CcAccum);
    txn->ht_ContentLength = -1;
    txn->ht_BytesReceived = 0;
    txn->ht_ChunkRemain = 0;
    txn->ht_Flags &= ~(HTF_CHUNKED | HTF_GZIP | HTF_BODY_DONE | HTF_BODY_BUFFERED);
    rc = ht_conn_ensure_bytes(base, txn->ht_Conn, 1, timeout);
    if (rc != 0) {
        return rc;
    }
    rc = ht_find_crlf(txn->ht_Conn, &line_start, &line_len);
    while (rc == ERROR_HTTP_READ_TIMEOUT) {
        rc = ht_conn_fill(base, txn->ht_Conn, timeout);
        if (rc != 0) {
            return rc;
        }
        rc = ht_find_crlf(txn->ht_Conn, &line_start, &line_len);
    }
    if (rc != 0) {
        return rc;
    }
    line = ht_copy_line(txn->ht_Conn, line_start, line_len);
    if (line == NULL) {
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    if (txn->ht_StatusLine) {
        ht_free(txn->ht_StatusLine);
    }
    txn->ht_StatusLine = line;
    txn->ht_Conn->hc_IoPos = line_start + line_len + 2;
    code = 0;
    sscanf(line, "HTTP/%*s %ld", &code);
    txn->ht_StatusCode = code;
    header_count = 0;
    for (;;) {
        if (header_count >= HT_MAX_RESP_HEADERS) {
            return ERROR_HTTP_PROTOCOL;
        }
        rc = ht_conn_ensure_bytes(base, txn->ht_Conn, 2, timeout);
        if (rc != 0) {
            return rc;
        }
        rc = ht_find_crlf(txn->ht_Conn, &line_start, &line_len);
        while (rc == ERROR_HTTP_READ_TIMEOUT) {
            rc = ht_conn_fill(base, txn->ht_Conn, timeout);
            if (rc != 0) {
                return rc;
            }
            rc = ht_find_crlf(txn->ht_Conn, &line_start, &line_len);
        }
        if (line_len == 0) {
            txn->ht_Conn->hc_IoPos = line_start + line_len + 2;
            break;
        }
        header_count++;
        line = ht_copy_line(txn->ht_Conn, line_start, line_len);
        txn->ht_Conn->hc_IoPos = line_start + line_len + 2;
        if (line == NULL) {
            return ERROR_HTTP_OUT_OF_MEMORY;
        }
        colon = strchr(line, ':');
        if (colon != NULL) {
            *colon = '\0';
            name = line;
            value = colon + 1;
            while (*value == ' ' || *value == '\t') {
                value++;
            }
            ht_add_resp_header(txn, name, value);
        }
        ht_free(line);
    }
    conn_val = ht_header_value(txn, (STRPTR)"Connection");
    if (conn_val != NULL && ht_str_ieq(conn_val, (STRPTR)"keep-alive")) {
        txn->ht_Flags |= HTF_KEEPALIVE;
    } else if (conn_val != NULL && ht_str_ieq(conn_val, (STRPTR)"close")) {
        txn->ht_Flags &= ~HTF_KEEPALIVE;
    } else if (code >= 100 && code < 200) {
        /* HTTP/1.1 default */
        txn->ht_Flags |= HTF_KEEPALIVE;
    }
    te_val = ht_header_value(txn, (STRPTR)"Transfer-Encoding");
    cl_val = ht_header_value(txn, (STRPTR)"Content-Length");
    if (cl_val != NULL) {
        txn->ht_ContentLength = (LONG)atol((char *)cl_val);
    } else {
        txn->ht_ContentLength = -1;
    }
    if (te_val != NULL && strstr(te_val, "chunked") != NULL) {
        /* Chunked overrides Content-Length (RFC 7230). */
        txn->ht_Flags |= HTF_CHUNKED;
        txn->ht_ContentLength = -1;
    }
    ce_val = ht_header_value(txn, (STRPTR)"Content-Encoding");
    if (ce_val != NULL &&
        (strstr(ce_val, "gzip") != NULL || strstr(ce_val, "deflate") != NULL)) {
        /* Decompression via z.library is not wired yet. */
        txn->ht_Flags |= HTF_GZIP;
    }
    loc_val = ht_header_value(txn, (STRPTR)"Location");
    if (loc_val != NULL) {
        if (txn->ht_RedirectUrl) {
            ht_free(txn->ht_RedirectUrl);
        }
        txn->ht_RedirectUrl = ht_strdup(loc_val);
    }
    cc_val = ht_header_value(txn, (STRPTR)"Cache-Control");
    if (cc_val != NULL) {
        struct Http_cc_accum line_cc;
        Http_cc_parse(cc_val, &line_cc);
        Http_cc_merge(&txn->ht_CcAccum, &line_cc);
    }
    if (code == 401) {
        auth_val = ht_header_value(txn, (STRPTR)"WWW-Authenticate");
        if (txn->ht_AuthRealm != NULL) {
            ht_free(txn->ht_AuthRealm);
            txn->ht_AuthRealm = NULL;
        }
        txn->ht_AuthRealm = ht_auth_parse_basic_realm(auth_val);
    } else if (code == 407) {
        auth_val = ht_header_value(txn, (STRPTR)"Proxy-Authenticate");
        if (txn->ht_AuthRealm != NULL) {
            ht_free(txn->ht_AuthRealm);
            txn->ht_AuthRealm = NULL;
        }
        txn->ht_AuthRealm = ht_auth_parse_basic_realm(auth_val);
    }
    txn->ht_Flags |= HTF_HEADERS_DONE;
    {
        ULONG body_start;

        rc = ht_conn_sync_body_start(txn->ht_Conn, &body_start);
        if (rc != 0) {
            return rc;
        }
        txn->ht_Conn->hc_IoPos = body_start;
    }
    ht_conn_compact(txn->ht_Conn);
    ht_hook_headers_done(txn);
    return 0;
}

static VOID
ht_clear_header_list(struct List *list)
{
    struct HttpHeader *hh;
    struct HttpHeader *next;

    if (list == NULL) {
        return;
    }
    for (hh = (struct HttpHeader *)list->lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = next) {
        next = (struct HttpHeader *)hh->hh_Node.ln_Succ;
        Remove(&hh->hh_Node);
        if (hh->hh_Name) {
            ht_free(hh->hh_Name);
        }
        if (hh->hh_Value) {
            ht_free(hh->hh_Value);
        }
        ht_free(hh);
    }
}

static STRPTR
ht_header_value_list(struct List *list, STRPTR name)
{
    struct HttpHeader *hh;

    for (hh = (struct HttpHeader *)list->lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = (struct HttpHeader *)hh->hh_Node.ln_Succ) {
        if (ht_str_ieq(hh->hh_Name, name)) {
            return hh->hh_Value;
        }
    }
    return NULL;
}

/*
 * Tier 3: parse response headers into caller-owned struct List (HttpHeader nodes).
 */
LONG
ht_http_read_stream_headers(struct AmiHttpBase *base,
    struct HttpSession *session, struct HtConnection *conn,
    struct List *resp_headers, STRPTR *status_line, LONG *status_code,
    LONG *content_length, ULONG *flags)
{
    ULONG timeout;
    ULONG line_start;
    ULONG line_len;
    STRPTR line;
    STRPTR colon;
    STRPTR name;
    STRPTR value;
    LONG rc;
    LONG code;
    STRPTR te_val;
    STRPTR cl_val;
    ULONG header_count;
    ULONG body_start;

    if (conn == NULL || resp_headers == NULL || status_line == NULL ||
        status_code == NULL || content_length == NULL || flags == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    timeout = session ? session->hs_ReadTimeout : 0;
    if (timeout == 0 && HttpBase != NULL) {
        timeout = HttpBase->ahb_DefaultTimeout;
    }
    ht_clear_header_list(resp_headers);
    *content_length = -1;
    *flags = 0;
    rc = ht_conn_ensure_bytes(base, conn, 1, timeout);
    if (rc != 0) {
        return rc;
    }
    rc = ht_find_crlf(conn, &line_start, &line_len);
    while (rc == ERROR_HTTP_READ_TIMEOUT) {
        rc = ht_conn_fill(base, conn, timeout);
        if (rc != 0) {
            return rc;
        }
        rc = ht_find_crlf(conn, &line_start, &line_len);
    }
    if (rc != 0) {
        return rc;
    }
    line = ht_copy_line(conn, line_start, line_len);
    if (line == NULL) {
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    if (*status_line != NULL) {
        ht_free(*status_line);
    }
    *status_line = line;
    conn->hc_IoPos = line_start + line_len + 2;
    code = 0;
    sscanf(line, "HTTP/%*s %ld", &code);
    *status_code = code;
    header_count = 0;
    for (;;) {
        if (header_count >= HT_MAX_RESP_HEADERS) {
            return ERROR_HTTP_PROTOCOL;
        }
        rc = ht_conn_ensure_bytes(base, conn, 2, timeout);
        if (rc != 0) {
            return rc;
        }
        rc = ht_find_crlf(conn, &line_start, &line_len);
        while (rc == ERROR_HTTP_READ_TIMEOUT) {
            rc = ht_conn_fill(base, conn, timeout);
            if (rc != 0) {
                return rc;
            }
            rc = ht_find_crlf(conn, &line_start, &line_len);
        }
        if (line_len == 0) {
            conn->hc_IoPos = line_start + line_len + 2;
            break;
        }
        header_count++;
        line = ht_copy_line(conn, line_start, line_len);
        conn->hc_IoPos = line_start + line_len + 2;
        if (line == NULL) {
            return ERROR_HTTP_OUT_OF_MEMORY;
        }
        colon = strchr(line, ':');
        if (colon != NULL) {
            *colon = '\0';
            name = line;
            value = colon + 1;
            while (*value == ' ' || *value == '\t') {
                value++;
            }
            rc = ht_add_header_to_list(resp_headers, name, value);
            if (rc != 0) {
                ht_free(line);
                return rc;
            }
        }
        ht_free(line);
    }
    te_val = ht_header_value_list(resp_headers, (STRPTR)"Transfer-Encoding");
    cl_val = ht_header_value_list(resp_headers, (STRPTR)"Content-Length");
    if (cl_val != NULL) {
        *content_length = (LONG)atol((char *)cl_val);
    }
    if (te_val != NULL && strstr(te_val, "chunked") != NULL) {
        *flags |= HTF_CHUNKED;
        *content_length = -1;
    }
    rc = ht_conn_sync_body_start(conn, &body_start);
    if (rc != 0) {
        return rc;
    }
    conn->hc_IoPos = body_start;
    ht_conn_compact(conn);
    return 0;
}

/*
 * Append next socket chunk to hc_IoBuf[hc_IoLen..].
 * Returns FALSE on EOF or hard read error.
 */
static BOOL
ht_conn_readblock(struct AmiHttpBase *base, struct HtConnection *conn,
    ULONG timeout_secs)
{
    ULONG space;
    LONG n;

    if (conn == NULL || conn->hc_IoBuf == NULL) {
        return FALSE;
    }
    ht_conn_compact(conn);
    if (conn->hc_IoCap == 0) {
        return FALSE;
    }
    space = conn->hc_IoCap - conn->hc_IoLen;
    if (space == 0) {
        return FALSE;
    }
    n = ht_transport_recv(base, conn, conn->hc_IoBuf + conn->hc_IoLen,
        space, timeout_secs);
    if (n < 0) {
        ht_set_error(ht_wire_to_status(n));
        return FALSE;
    }
    if (n == 0) {
        return FALSE;
    }
    if ((ULONG)n > space) {
        n = (LONG)space;
    }
    conn->hc_IoLen += (ULONG)n;
    return TRUE;
}

static VOID ht_http_body_finish(struct AmiHttpBase *base,
    struct HttpTransaction *txn);

/*
 * Chunked transfer helpers.
 */

static ULONG
ht_chunk_avail(struct HtConnection *conn)
{
    if (conn != NULL && conn->hc_IoLen > conn->hc_IoPos) {
        return conn->hc_IoLen - conn->hc_IoPos;
    }
    return 0;
}

static VOID
ht_chunk_skip_separators(struct HtConnection *conn)
{
    ULONG pos;
    ULONG avail;

    if (conn == NULL) {
        return;
    }
    pos = conn->hc_IoPos;
    avail = conn->hc_IoLen;
    while (pos < avail &&
        (conn->hc_IoBuf[pos] == '\r' || conn->hc_IoBuf[pos] == '\n')) {
        pos++;
    }
    while (pos < avail &&
        (conn->hc_IoBuf[pos] == ' ' || conn->hc_IoBuf[pos] == '\t')) {
        pos++;
    }
    conn->hc_IoPos = pos;
}

/*
 * Parse <hex-size>[;ext]\r\n from the wire buffer.  ERROR_HTTP_READ_TIMEOUT
 * when the header line is incomplete.
 */
static LONG
ht_chunk_read_size(struct HtConnection *conn, ULONG *out_size, BOOL *out_final)
{
    ULONG pos;
    ULONG avail;
    ULONG chunk_size;
    ULONG size_start;
    UBYTE c;
    LONG digit;
    BOOL got_digit;

    if (conn == NULL || out_size == NULL || out_final == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    ht_chunk_skip_separators(conn);
    pos = conn->hc_IoPos;
    avail = conn->hc_IoLen;
    if (pos >= avail) {
        return ERROR_HTTP_READ_TIMEOUT;
    }
    chunk_size = 0;
    size_start = pos;
    got_digit = FALSE;
    while (pos < avail) {
        c = conn->hc_IoBuf[pos];
        if (c >= '0' && c <= '9') {
            digit = (LONG)(c - '0');
        } else if (c >= 'A' && c <= 'F') {
            digit = (LONG)(c - 'A' + 10);
        } else if (c >= 'a' && c <= 'f') {
            digit = (LONG)(c - 'a' + 10);
        } else {
            break;
        }
        got_digit = TRUE;
        chunk_size = chunk_size * 16UL + (ULONG)digit;
        pos++;
    }
    if (!got_digit || pos == size_start) {
        return ERROR_HTTP_READ_TIMEOUT;
    }
    while (pos < avail && conn->hc_IoBuf[pos] != '\r' &&
        conn->hc_IoBuf[pos] != '\n') {
        pos++;
    }
    if (pos >= avail) {
        return ERROR_HTTP_READ_TIMEOUT;
    }
    if (conn->hc_IoBuf[pos] == '\r') {
        pos++;
        if (pos >= avail) {
            return ERROR_HTTP_READ_TIMEOUT;
        }
    }
    if (conn->hc_IoBuf[pos] != '\n') {
        return ERROR_HTTP_PROTOCOL;
    }
    pos++;
    conn->hc_IoPos = pos;
    *out_size = chunk_size;
    *out_final = (chunk_size == 0) ? TRUE : FALSE;
    return 0;
}

static LONG
ht_chunk_skip_data_crlf(struct AmiHttpBase *base, struct HtConnection *conn,
    ULONG timeout_secs)
{
    ULONG avail;
    LONG rc;

    avail = ht_chunk_avail(conn);
    if (avail >= 2 && conn->hc_IoBuf[conn->hc_IoPos] == '\r' &&
        conn->hc_IoBuf[conn->hc_IoPos + 1] == '\n') {
        conn->hc_IoPos += 2;
        return 0;
    }
    if (avail >= 1 && conn->hc_IoBuf[conn->hc_IoPos] == '\n') {
        conn->hc_IoPos += 1;
        return 0;
    }
    if (avail == 0) {
        if (!ht_conn_readblock(base, conn, timeout_secs)) {
            return ERROR_HTTP_READ_FAILED;
        }
        return ht_chunk_skip_data_crlf(base, conn, timeout_secs);
    }
    if (avail == 1 && conn->hc_IoBuf[conn->hc_IoPos] == '\r') {
        if (!ht_conn_readblock(base, conn, timeout_secs)) {
            return ERROR_HTTP_READ_FAILED;
        }
        if (conn->hc_IoPos < conn->hc_IoLen &&
            conn->hc_IoBuf[conn->hc_IoPos] == '\n') {
            conn->hc_IoPos += 1;
            return 0;
        }
        return ERROR_HTTP_PROTOCOL;
    }
    rc = ht_conn_ensure_bytes(base, conn, 2, timeout_secs);
    if (rc != 0) {
        return rc;
    }
    return ht_chunk_skip_data_crlf(base, conn, timeout_secs);
}

static LONG
ht_chunk_consume_trailers(struct AmiHttpBase *base, struct HtConnection *conn,
    ULONG timeout_secs)
{
    ULONG line_start;
    ULONG line_len;
    LONG rc;

    for (;;) {
        rc = ht_conn_ensure_bytes(base, conn, 2, timeout_secs);
        if (rc != 0) {
            return rc;
        }
        rc = ht_find_crlf(conn, &line_start, &line_len);
        while (rc == ERROR_HTTP_READ_TIMEOUT) {
            if (!ht_conn_readblock(base, conn, timeout_secs)) {
                return ERROR_HTTP_READ_FAILED;
            }
            rc = ht_find_crlf(conn, &line_start, &line_len);
        }
        if (rc != 0) {
            return rc;
        }
        conn->hc_IoPos = line_start + line_len + 2;
        if (line_len == 0) {
            break;
        }
    }
    return 0;
}

/*
 * Stream decoded chunk payloads to the caller.
 */
static LONG
ht_http_read_body_chunked(struct AmiHttpBase *base, struct HttpTransaction *txn,
    APTR dest, ULONG buflen)
{
    struct HtConnection *conn;
    UBYTE *out;
    ULONG timeout;
    ULONG copied;
    ULONG avail;
    ULONG take;
    ULONG chunk_size;
    BOOL final_chunk;
    LONG rc;

    conn = txn->ht_Conn;
    out = (UBYTE *)dest;
    timeout = txn->ht_Session ? txn->ht_Session->hs_ReadTimeout : 0;
    if (timeout == 0 && HttpBase != NULL) {
        timeout = HttpBase->ahb_DefaultTimeout;
    }
    copied = 0;
    while (copied < buflen) {
        if (txn->ht_ChunkRemain > 0) {
            avail = ht_chunk_avail(conn);
            if (avail == 0) {
                if (!ht_conn_readblock(base, conn, timeout)) {
                    ht_set_txn_error(txn, ERROR_HTTP_READ_FAILED);
                    return (LONG)copied;
                }
                avail = ht_chunk_avail(conn);
            }
            take = txn->ht_ChunkRemain;
            if (take > avail) {
                take = avail;
            }
            if (take > buflen - copied) {
                take = buflen - copied;
            }
            if (take > 0) {
                CopyMem(conn->hc_IoBuf + conn->hc_IoPos, out + copied, take);
                conn->hc_IoPos += take;
                txn->ht_ChunkRemain -= take;
                txn->ht_BytesReceived += take;
                copied += take;
                ht_hook_body_chunk(txn, out + copied - take, take);
            }
            if (txn->ht_ChunkRemain == 0) {
                rc = ht_chunk_skip_data_crlf(base, conn, timeout);
                if (rc != 0) {
                    ht_set_txn_error(txn, rc);
                    return (LONG)copied;
                }
            }
            continue;
        }
        rc = ht_chunk_read_size(conn, &chunk_size, &final_chunk);
        while (rc == ERROR_HTTP_READ_TIMEOUT) {
            if (!ht_conn_readblock(base, conn, timeout)) {
                ht_set_txn_error(txn, ERROR_HTTP_READ_FAILED);
                return (LONG)copied;
            }
            rc = ht_chunk_read_size(conn, &chunk_size, &final_chunk);
        }
        if (rc != 0) {
            ht_set_txn_error(txn, rc);
            return (LONG)copied;
        }
        if (final_chunk) {
            txn->ht_Flags &= ~HTF_CHUNKED;
            rc = ht_chunk_consume_trailers(base, conn, timeout);
            if (rc != 0) {
                ht_set_txn_error(txn, rc);
                return (LONG)copied;
            }
            ht_http_body_finish(base, txn);
            ht_set_txn_error(txn, 0);
            return (LONG)copied;
        }
        txn->ht_ChunkRemain = chunk_size;
    }
    ht_set_txn_error(txn, 0);
    return (LONG)copied;
}

/*
 * Release connection back to pool after body fully read.
 */
static VOID
ht_http_body_finish(struct AmiHttpBase *base, struct HttpTransaction *txn)
{
    BOOL keepalive;

    if (txn == NULL) {
        return;
    }
    if (txn->ht_Conn != NULL) {
        /*
         * discard any buffered bytes so they cannot
         * be mistaken for the next response on keep-alive.
         */
        txn->ht_Conn->hc_IoLen = 0;
        txn->ht_Conn->hc_IoPos = 0;
        keepalive = FALSE;
        if (txn->ht_Session != NULL && txn->ht_Session->hs_KeepAlive &&
            (txn->ht_Flags & HTF_KEEPALIVE) && (txn->ht_Flags & HTF_KEEPALIVE_REQ)) {
            keepalive = TRUE;
        }
        ht_pool_release(base, txn->ht_Conn, keepalive);
        txn->ht_Conn = NULL;
    }
    txn->ht_Flags |= HTF_BODY_DONE;
}

/*
 * Copy from hc_IoBuf, Readblock when empty,
 * clamp to Content-Length, finish when done_after_send.
 */
LONG
ht_http_read_body(struct AmiHttpBase *base, struct HttpTransaction *txn,
    APTR buffer, ULONG buflen)
{
    struct HtConnection *conn;
    APTR dest;
    ULONG timeout;
    ULONG blocklength;
    ULONG copy;
    LONG remaining;
    BOOL done_after_send;

    dest = buffer;
    if (txn == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_HANDLE);
        return 0;
    }
    if (txn->ht_NoBody) {
        ht_set_error(0);
        return 0;
    }
    if (!(txn->ht_Flags & HTF_HEADERS_DONE)) {
        ht_set_txn_error(txn, ERROR_HTTP_PROTOCOL);
        return 0;
    }
    if (txn->ht_Flags & HTF_BODY_DONE) {
        ht_set_txn_error(txn, 0);
        return 0;
    }
    if (ht_check_txn_abort(txn)) {
        ht_set_txn_error(txn, ERROR_HTTP_ABORTED);
        return 0;
    }
    if (txn->ht_Flags & HTF_GZIP) {
        ht_set_txn_error(txn, ERROR_HTTP_NOT_IMPLEMENTED);
        return 0;
    }
    if (dest == NULL || buflen == 0) {
        return 0;
    }
    if (buflen > HT_IOBUF_SIZE) {
        buflen = HT_IOBUF_SIZE;
    }
    conn = txn->ht_Conn;
    if (conn == NULL) {
        ht_set_txn_error(txn, ERROR_HTTP_PROTOCOL);
        return 0;
    }
    if (txn->ht_Flags & HTF_CHUNKED) {
        return ht_http_read_body_chunked(base, txn, dest, buflen);
    }

    timeout = txn->ht_Session ? txn->ht_Session->hs_ReadTimeout : 0;
    if (timeout == 0 && HttpBase != NULL) {
        timeout = HttpBase->ahb_DefaultTimeout;
    }

    blocklength = conn->hc_IoLen - conn->hc_IoPos;
    if (blocklength == 0) {
        if (txn->ht_ContentLength > 0 &&
            (LONG)txn->ht_BytesReceived >= txn->ht_ContentLength) {
            ht_http_body_finish(base, txn);
            return 0;
        }
        if (!ht_conn_readblock(base, conn, timeout)) {
            if (txn->ht_ContentLength < 0) {
                ht_http_body_finish(base, txn);
                return 0;
            }
            if (txn->ht_ContentLength > 0 &&
                (LONG)txn->ht_BytesReceived < txn->ht_ContentLength) {
                ht_set_txn_error(txn, ERROR_HTTP_READ_FAILED);
                return 0;
            }
            ht_http_body_finish(base, txn);
            ht_set_txn_error(txn, 0);
            return 0;
        }
        blocklength = conn->hc_IoLen - conn->hc_IoPos;
        if (blocklength == 0) {
            ht_http_body_finish(base, txn);
            return 0;
        }
    }

    copy = blocklength;
    done_after_send = FALSE;
    if (txn->ht_ContentLength > 0) {
        remaining = txn->ht_ContentLength - (LONG)txn->ht_BytesReceived;
        if (remaining <= 0) {
            ht_http_body_finish(base, txn);
            return 0;
        }
        if (copy > (ULONG)remaining) {
            copy = (ULONG)remaining;
            done_after_send = TRUE;
        } else if (copy == (ULONG)remaining) {
            done_after_send = TRUE;
        }
    }
    if (copy > buflen) {
        copy = buflen;
    }
    if (copy == 0) {
        ht_http_body_finish(base, txn);
        return 0;
    }

    CopyMem(conn->hc_IoBuf + conn->hc_IoPos, dest, copy);
    conn->hc_IoPos += copy;
    txn->ht_BytesReceived += copy;
    ht_hook_body_chunk(txn, dest, copy);

    if (done_after_send) {
        ht_http_body_finish(base, txn);
    }
    ht_set_txn_error(txn, 0);
    return (LONG)copy;
}
