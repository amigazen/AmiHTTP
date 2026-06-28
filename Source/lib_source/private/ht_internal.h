/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_internal.h - Private structures for amihttp.library
 */

#ifndef AMIHTTP_PRIVATE_HT_INTERNAL_H
#define AMIHTTP_PRIVATE_HT_INTERNAL_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef EXEC_LISTS_H
#include <exec/lists.h>
#endif
#ifndef EXEC_SEMAPHORES_H
#include <exec/semaphores.h>
#endif
#ifndef UTILITY_HOOKS_H
#include <utility/hooks.h>
#endif
#ifndef LIBRARIES_AMIHTTP_H
#include <libraries/amihttp.h>
#endif
#ifndef LIBRARIES_Z_H
#include <libraries/z.h>
#endif
#ifndef DEVICES_TIMER_H
#include <devices/timer.h>
#endif

#define HT_MAGIC_SESSION    0x48545353UL
#define HT_MAGIC_TXN        0x48545458UL
#define HT_MAGIC_CONN       0x4854434EUL
#define HT_MAGIC_STREAM     0x48545343UL
#define HT_MAGIC_JAR        0x48544A52UL
#define HT_MAGIC_URL        0x48545552UL

#define HT_IOBUF_SIZE       8192
/* Wire read chunk for gzip inflate — keep off the client stack (see ht_http.c). */
#define HT_GZIP_WIRE_CHUNK  1024
#define HT_REQBUF_INIT      4096
#define HT_REQBUF_MAX       262144
#define HT_POOL_TIMEOUT     15
#define HT_POOL_MAX_IDLE    8
#define HT_SOCKET_IO_TIMEOUT  15UL

#define HTF_KEEPALIVE_REQ   0x0001
#define HTF_KEEPALIVE       0x0002
#define HTF_SSL             0x0004
#define HTF_SSL_TUNNEL      0x0008
#define HTF_CHUNKED         0x0010
#define HTF_GZIP            0x0020
#define HTF_HEADERS_DONE    0x0040
#define HTF_COMPLETE        0x0080
#define HTF_ABORTED         0x0100
#define HTF_CONN_REUSED     0x0200
#define HTF_KA_REUSED       0x2000
#define HTF_KA_RETRYED      0x4000
#define HTF_BODY_BUFFERED   0x0400
#define HTF_BODY_DONE       0x0800
#define HTF_VIA_PROXY       0x1000

/*
 * Resolved TCP route for one transaction (direct or via HTTP proxy).
 */
struct HtRoute
{
    STRPTR  hr_ConnectHost;
    ULONG   hr_ConnectPort;
    STRPTR  hr_OriginHost;
    ULONG   hr_OriginPort;
    BOOL    hr_OriginSsl;
    BOOL    hr_ViaProxy;
    BOOL    hr_SslTunnel;
    STRPTR  hr_RequestUri;
    STRPTR  hr_TunnelTarget;
};

/*
 * Error conventions (dos.library IoErr / SetIoErr model):
 *   ERROR_HTTP_*     codes from HttpError() / SetHttpError()
 *   LVO status       FALSE/0 failure (then HttpError()), TRUE/1 success
 *   Wire recv        >0 bytes, 0 EOF, negative -ERROR_HTTP_* on failure
 *   Internal ht_*    0 ok, positive ERROR_HTTP_* on failure
 */
#define HT_IO_ERROR(e)      (-(LONG)(e))

struct HtSsl;

/* httpcch.c */
struct Http_cc_accum
{
    BOOL    forbid_disk;
    BOOL    saw_positive_max_age;
    LONG    min_max_age;
    BOOL    must_revalidate;
};

void Http_cc_reset_accum(struct Http_cc_accum *a);
void Http_cc_parse(STRPTR v, struct Http_cc_accum *out);
void Http_cc_merge(struct Http_cc_accum *dst, struct Http_cc_accum *src);

/*
 * Tier 3 public HttpConnection handle (opaque to callers).
 */
struct HtStreamConn
{
    ULONG               hsc_Magic;
    struct HttpSession *hsc_Session;
    struct HtConnection *hsc_Conn;
    STRPTR              hsc_StatusLine;
    LONG                hsc_StatusCode;
    struct List         hsc_RespHeaders;
    LONG                hsc_ContentLength;
    ULONG               hsc_BytesReceived;
    ULONG               hsc_Flags;
};

struct HtConnection
{
    struct Node         hc_Node;
    struct Node         hc_ActiveNode;
    ULONG               hc_Magic;
    STRPTR              hc_Host;
    ULONG               hc_Port;
    BOOL                hc_IsSsl;
    ULONG               hc_OwnerSerial;
    LONG                hc_Sock;
    struct Library     *hc_SocketBase; /* bsdsocket handle snapshot at connect */
    struct HtSsl       *hc_SslCtx;
    ULONG               hc_LastUsed;
    BOOL                hc_InUse;
    ULONG               hc_Flags;
    BOOL                hc_ViaProxy;
    STRPTR              hc_OriginHost;
    ULONG               hc_OriginPort;
    /*
     * TRUE after ht_transport_task_ssl_ensure() for this connection.
     * Paired with ht_transport_task_ssl_release() in disconnect even when
     * hc_SslCtx was never created (create/attach failure paths).
     */
    BOOL                hc_SslTaskHeld;
    UBYTE              *hc_IoBuf;
    ULONG               hc_IoLen;
    ULONG               hc_IoPos;
    ULONG               hc_IoCap;
    struct HtConnection *hc_DeadNext; /* pool dead-list */
};

struct HttpSession
{
    ULONG               hs_Magic;
    STRPTR              hs_UserAgent;
    STRPTR              hs_Proxy;
    STRPTR              hs_ProxyAuth;
    STRPTR              hs_Credentials;
    STRPTR              hs_AcceptEncoding;
    ULONG               hs_MaxRedirects;
    BOOL                hs_FollowRedirects;
    BOOL                hs_KeepAlive;
    ULONG               hs_MaxConnections;
    ULONG               hs_ConnectTimeout;
    ULONG               hs_ReadTimeout;
    ULONG               hs_TotalTimeout;
    ULONG               hs_SslVerify;
    STRPTR              hs_CaBundlePath;
    ULONG               hs_RefererPolicy;
    ULONG               hs_TaskSerial;
    struct HttpCookieJar *hs_CookieJar;
    struct Hook          *hs_Hooks[8];
};

struct HttpTransaction
{
    ULONG               ht_Magic;
    struct HttpSession *ht_Session;
    struct HtConnection *ht_Conn;
    STRPTR              ht_Url;
    STRPTR              ht_RequestUri;
    STRPTR              ht_Method;
    STRPTR              ht_Referer;
    STRPTR              ht_UserAgent;
    APTR                ht_PostBody;
    APTR                ht_ReqBodySrc;
    ULONG               ht_PostLength;
    BOOL                ht_PostBodyBinary;
    STRPTR              ht_ContentType;
    STRPTR              ht_IfModifiedSince;
    STRPTR              ht_IfNoneMatch;
    LONG                ht_RangeStart;
    LONG                ht_RangeEnd;
    ULONG               ht_ThrottleBps;
    BOOL                ht_NoCache;
    BOOL                ht_NoBody;
    BOOL                ht_RetryAuth;
    BOOL                ht_RetryCert;
    BOOL                ht_CertRetryTried;
    BOOL                ht_CertAccepted;
    struct Hook        *ht_PostStreamHook;
    struct List        *ht_FormParts;
    STRPTR              ht_MultipartBody;
    ULONG               ht_MultipartLen;
    STRPTR              ht_MultipartBoundary;
    STRPTR              ht_AuthRealm;
    STRPTR              ht_BasicAuth;
    STRPTR              ht_BasicProxyAuth;
    BOOL                ht_AuthTried;
    BOOL                ht_ProxyAuthTried;
    struct List         ht_ReqHeaders;
    STRPTR              ht_StatusLine;
    LONG                ht_StatusCode;
    struct List         ht_RespHeaders;
    STRPTR              ht_RedirectUrl;
    LONG                ht_ContentLength;
    ULONG               ht_BytesReceived;
    ULONG               ht_Flags;
    LONG                ht_LastError;
    BOOL                ht_Async;
    BOOL                ht_AsyncRunning;
    LONG                ht_AsyncResult;
    struct Task        *ht_NotifyTask;
    ULONG               ht_NotifySignal;
    struct Task        *ht_WorkerTask;
    BOOL                ht_Complete;
    struct Hook         *ht_Hooks[8];
    struct HttpTiming   ht_Timing;
    struct timeval      ht_TvPerform;
    struct timeval      ht_TvHopConnect;
    BOOL                ht_TvPerformSet;
    BOOL                ht_TvHopConnectSet;
    struct Http_cc_accum ht_CcAccum;
    z_stream            ht_ZStream;
    BOOL                ht_ZInited;
    BOOL                ht_ZFinishing;
    LONG                ht_ZWindowBits;
    UBYTE              *ht_ZWireBuf;    /* persistent inflate input (gzip+chunked) */
    ULONG               ht_WireReceived;
    UBYTE              *ht_DecodeBuf;
    ULONG               ht_DecodeLen;
    ULONG               ht_DecodePos;
    ULONG               ht_DecodeCap;
    ULONG               ht_ChunkRemain;   /* payload bytes left in current chunk */
    BOOL                ht_CertPresent;
    STRPTR              ht_CertSubject;
    STRPTR              ht_CertIssuer;
    STRPTR              ht_CertCommonName;
    STRPTR              ht_CertNotBefore;
    STRPTR              ht_CertNotAfter;
    STRPTR              ht_CertSerial;
    LONG                ht_CertVerifyResult;
    STRPTR              ht_Cipher;
};

struct HttpCookieJar
{
    ULONG               hj_Magic;
    struct List         hj_Cookies;
    struct SignalSemaphore hj_Sema;
    struct Hook        *hj_RequestHook;
    struct Hook        *hj_ResponseHook;
};

/*
 * Debug output (private/ht_debug.h): build with DEFINE=AMIHTTP_DEBUG in SCOPTIONS.
 */

VOID ht_sync_proto_bases(struct AmiHttpBase *base);
VOID ht_lvo_bind(struct AmiHttpBase *base);

/* ht_alloc.c */
APTR ht_alloc(ULONG size, ULONG flags);
VOID ht_free(APTR p);
ULONG ht_strlen(STRPTR s);
STRPTR ht_strdup(STRPTR s);
STRPTR ht_strndup(STRPTR s, LONG n);

/* ht_error.c */
VOID ht_set_error(LONG code);
VOID ht_set_txn_error(struct HttpTransaction *txn, LONG code);
BOOL ht_check_handle(ULONG magic, ULONG expected);
LONG ht_lvo_status(LONG rc);
LONG ht_wire_to_status(LONG n);

/* ht_transport.c */
LONG ht_bsd_open(struct AmiHttpBase *base);
VOID ht_bsd_close(struct AmiHttpBase *base);
VOID ht_bsd_set_errno_ptr(struct AmiHttpBase *base);
LONG ht_ensure_bsdsocket(struct AmiHttpBase *base);
VOID ht_transport_bind_socket(struct AmiHttpBase *base);
LONG ht_io_obtain(struct AmiHttpBase *base);
VOID ht_io_release(struct AmiHttpBase *base);
LONG ht_transport_task_bsd_bind(struct AmiHttpBase *base, struct Library *socketbase);
APTR ht_task_errno_ptr(struct AmiHttpBase *base);
struct Library *ht_task_current_socket_base(struct AmiHttpBase *base);
VOID ht_transport_apply_io_timeouts(struct AmiHttpBase *base, struct HtConnection *conn);
VOID ht_bsd_release_task(struct AmiHttpBase *base);
VOID ht_transport_task_bsd_shutdown(struct AmiHttpBase *base);
VOID ht_transport_global_shutdown(struct AmiHttpBase *base);
LONG ht_transport_task_ssl_ensure(struct AmiHttpBase *base);
VOID ht_transport_task_ssl_release(struct AmiHttpBase *base);
VOID ht_ssl_release_task(struct AmiHttpBase *base);
VOID ht_transport_task_ssl_shutdown(struct AmiHttpBase *base);
LONG ht_transport_connect(struct AmiHttpBase *base, struct HtConnection *conn,
    STRPTR host, ULONG port, BOOL ssl, ULONG timeout_secs, ULONG ssl_verify,
    STRPTR ca_bundle_path);
LONG ht_transport_connect_route(struct AmiHttpBase *base, struct HtConnection *conn,
    struct HtRoute *route, ULONG timeout_secs, ULONG ssl_verify,
    struct HttpTransaction *txn, STRPTR ca_bundle_path);
VOID ht_transport_disconnect(struct AmiHttpBase *base, struct HtConnection *conn);
LONG ht_transport_send(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR data, ULONG len);
LONG ht_transport_recv(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR buf, ULONG len, ULONG timeout_secs);
BOOL ht_transport_conn_idle(struct AmiHttpBase *base, struct HtConnection *conn);

/* ht_ssl_*.c - TLS backends (AmiSSL default, amitls when AMIHTTP_USE_AMITLS) */
#ifdef AMIHTTP_USE_AMITLS
VOID ht_ssl_sync_base_tags(struct AmiHttpBase *base);
#endif

struct HtSsl *ht_ssl_create(STRPTR hostname, STRPTR ca_bundle_path);
VOID ht_ssl_destroy(struct HtSsl *s);
LONG ht_ssl_attach_socket(struct AmiHttpBase *base, struct HtSsl *s,
    LONG sock, STRPTR hostname, ULONG verify_mode, ULONG timeout_secs,
    struct HttpTransaction *txn);
LONG ht_ssl_send(struct HtSsl *s, APTR data, ULONG len);
LONG ht_ssl_recv(struct AmiHttpBase *base, struct HtSsl *s, LONG sock,
    APTR buf, ULONG len, ULONG timeout_secs);
BOOL ht_ssl_idle(struct HtSsl *s);
VOID ht_ssl_close(struct HtSsl *s);
VOID ht_ssl_capture_peer_cert(struct HtSsl *s);
VOID ht_ssl_peer_cert_copy(struct HttpSslPeerCert *dst, struct HtSsl *s);
VOID ht_ssl_peer_cert_clear(struct HtSsl *s);
STRPTR ht_ssl_cipher_dup(struct HtSsl *s);
VOID ht_ssl_capture_cipher(struct HtSsl *s);
LONG ht_ssl_last_tls_error(struct HtSsl *s);
BOOL ht_ssl_cert_hook_accept(struct HttpTransaction *txn, struct HtSsl *s);

/* ht_proxy.c */
LONG ht_route_resolve(struct AmiHttpBase *base, struct HttpSession *session,
    struct ParsedUrl *pu, STRPTR full_url, struct HtRoute *route);
VOID ht_route_free(struct HtRoute *route);

/* ht_pool.c */
struct HtConnection *ht_pool_acquire(struct AmiHttpBase *base,
    struct HttpSession *session, struct HtRoute *route,
    struct HttpTransaction *txn);
VOID ht_pool_release(struct AmiHttpBase *base, struct HtConnection *conn,
    BOOL keepalive);
VOID ht_pool_flush(struct AmiHttpBase *base);
VOID ht_pool_shutdown(struct AmiHttpBase *base);
VOID ht_timer_shutdown(VOID);
BOOL ht_timer_get_time(struct timeval *tv);
ULONG ht_timer_delta_ms(struct timeval *start, struct timeval *end);
struct HtConnection *ht_connection_new(struct AmiHttpBase *base);
VOID ht_connection_free(struct AmiHttpBase *base, struct HtConnection *conn);

/* ht_url.c */
STRPTR ht_url_build_from_parsed(struct ParsedUrl *url);
LONG ht_url_parse(STRPTR url, struct ParsedUrl *out);
VOID ht_url_free_fields(struct ParsedUrl *pu);
STRPTR ht_url_encode(STRPTR str);
STRPTR ht_url_decode(STRPTR str);
STRPTR ht_path_encode(STRPTR path);
STRPTR ht_build_query_string(struct List *pairs);
STRPTR ht_uri_scheme_part(STRPTR url);
STRPTR ht_uri_host_part(STRPTR url);
STRPTR ht_uri_path_part(STRPTR url);
STRPTR ht_uri_file_part(STRPTR url);
STRPTR ht_uri_query_part(STRPTR url);
STRPTR ht_uri_parent_part(STRPTR url);
STRPTR ht_uri_authority_part(STRPTR url);
STRPTR ht_join_uri(STRPTR base_url, STRPTR relative_url);
VOID ht_peer_cert_free_fields(struct HttpSslPeerCert *cert);

/* ht_auth.c */
STRPTR ht_auth_basic_encode(STRPTR userpass);
STRPTR ht_auth_parse_basic_realm(STRPTR value);

/* ht_cookie.c */
VOID ht_cookie_jar_clear(struct HttpCookieJar *jar);
VOID ht_cookie_jar_trim(struct HttpCookieJar *jar, ULONG max_count);
LONG ht_cookie_store_line(struct HttpCookieJar *jar, STRPTR url, STRPTR spec,
    BOOL from_response);
STRPTR ht_cookie_header_for_url(struct HttpCookieJar *jar, STRPTR url,
    BOOL secure);
VOID ht_cookie_ingest_headers(struct HttpCookieJar *jar,
    struct HttpTransaction *txn);
LONG ht_cookie_append_request(struct HttpCookieJar *jar,
    struct HttpTransaction *txn, BOOL secure, STRPTR buf, ULONG buflen);
VOID ht_cookie_dispatch_response(struct HttpCookieJar *jar,
    struct HttpTransaction *txn);

/* ht_http.c */
LONG ht_http_build_request(struct HttpTransaction *txn, UBYTE **out_buf,
    ULONG *out_len);
LONG ht_http_send_request(struct AmiHttpBase *base, struct HttpTransaction *txn);
LONG ht_http_read_response_headers(struct AmiHttpBase *base,
    struct HttpTransaction *txn);
LONG ht_http_read_body(struct AmiHttpBase *base, struct HttpTransaction *txn,
    APTR buffer, ULONG buflen);
LONG ht_http_read_stream_headers(struct AmiHttpBase *base,
    struct HttpSession *session, struct HtConnection *conn,
    struct List *resp_headers, STRPTR *status_line, LONG *status_code,
    LONG *content_length, ULONG *flags);
STRPTR ht_txn_user_agent(struct HttpTransaction *txn);

/* ht_async.c */
LONG ht_async_start(struct HttpTransaction *txn);
VOID ht_async_wait(struct HttpTransaction *txn, ULONG timeout_secs);
VOID ht_async_cancel(struct HttpTransaction *txn);

/* transaction.c - shared sync perform for worker task */
LONG ht_txn_perform_sync(struct HttpTransaction *txn);

/* ht_timing.c */
VOID ht_timing_begin_sync(struct HttpTransaction *txn);
VOID ht_timing_hop_begin(struct HttpTransaction *txn);
VOID ht_timing_connect_done(struct HttpTransaction *txn, BOOL reused);
VOID ht_timing_first_byte(struct HttpTransaction *txn);
VOID ht_timing_no_body_done(struct HttpTransaction *txn);
VOID ht_timing_body_done(struct HttpTransaction *txn);
ULONG ht_timing_elapsed_ms(struct HttpTransaction *txn);
ULONG ht_timeout_resolve(struct HttpTransaction *txn, ULONG per_op_secs);

/* session.c / transaction.c - LVO bodies declared in amihttp_funcs.h */

#endif /* AMIHTTP_PRIVATE_HT_INTERNAL_H */
