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

#define HT_MAGIC_SESSION    0x48545353UL
#define HT_MAGIC_TXN        0x48545458UL
#define HT_MAGIC_CONN       0x4854434EUL
#define HT_MAGIC_JAR        0x48544A52UL
#define HT_MAGIC_URL        0x48545552UL

#define HT_IOBUF_SIZE       8192
#define HT_REQBUF_INIT      4096
#define HT_REQBUF_MAX       262144
#define HT_POOL_TIMEOUT     15
#define HT_POOL_MAX_IDLE    8

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
#define HTF_BODY_BUFFERED   0x0400
#define HTF_BODY_DONE       0x0800

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

struct HtConnection
{
    struct Node         hc_Node;
    ULONG               hc_Magic;
    STRPTR              hc_Host;
    ULONG               hc_Port;
    BOOL                hc_IsSsl;
    ULONG               hc_OwnerSerial;
    LONG                hc_Sock;
    struct HtSsl       *hc_SslCtx;
    ULONG               hc_LastUsed;
    BOOL                hc_InUse;
    ULONG               hc_Flags;
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
    STRPTR              ht_Method;
    STRPTR              ht_Referer;
    STRPTR              ht_UserAgent;
    STRPTR              ht_PostBody;
    ULONG               ht_PostLength;
    STRPTR              ht_IfModifiedSince;
    STRPTR              ht_IfNoneMatch;
    LONG                ht_RangeStart;
    LONG                ht_RangeEnd;
    ULONG               ht_ThrottleBps;
    BOOL                ht_NoCache;
    BOOL                ht_NoBody;
    BOOL                ht_RetryAuth;
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
    BOOL                ht_Complete;
    struct Hook         *ht_Hooks[8];
    struct HttpTiming   ht_Timing;
    struct Http_cc_accum ht_CcAccum;
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
};

struct HttpCookieJar
{
    ULONG               hj_Magic;
    struct List         hj_Cookies;
    struct SignalSemaphore hj_Sema;
};

/*
 * Debug output (private/ht_debug.h): build with DEFINE=AMIHTTP_DEBUG in SCOPTIONS.
 */

VOID ht_sync_proto_bases(struct AmiHttpBase *base);

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
LONG ht_ensure_bsdsocket(struct AmiHttpBase *base);
LONG ht_transport_global_init(struct AmiHttpBase *base);
VOID ht_transport_global_shutdown(struct AmiHttpBase *base);
LONG ht_transport_task_ssl_ensure(struct AmiHttpBase *base);
VOID ht_transport_task_ssl_release(struct AmiHttpBase *base);
LONG ht_transport_connect(struct AmiHttpBase *base, struct HtConnection *conn,
    STRPTR host, ULONG port, BOOL ssl, ULONG timeout_secs);
VOID ht_transport_disconnect(struct AmiHttpBase *base, struct HtConnection *conn);
LONG ht_transport_send(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR data, ULONG len);
LONG ht_transport_recv(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR buf, ULONG len, ULONG timeout_secs);
BOOL ht_transport_conn_idle(struct AmiHttpBase *base, struct HtConnection *conn);

/* ht_ssl.c */
struct HtSsl *ht_ssl_create(STRPTR hostname);
VOID ht_ssl_destroy(struct HtSsl *s);
LONG ht_ssl_attach_socket(struct HtSsl *s, LONG sock, STRPTR hostname);
LONG ht_ssl_send(struct HtSsl *s, APTR data, ULONG len);
LONG ht_ssl_recv(struct AmiHttpBase *base, struct HtSsl *s, LONG sock,
    APTR buf, ULONG len, ULONG timeout_secs);
BOOL ht_ssl_idle(struct HtSsl *s);
VOID ht_ssl_close(struct HtSsl *s);
VOID ht_ssl_capture_peer_cert(struct HtSsl *s);
VOID ht_ssl_peer_cert_copy(struct HttpSslPeerCert *dst, struct HtSsl *s);
VOID ht_ssl_peer_cert_clear(struct HtSsl *s);

/* ht_pool.c */
struct HtConnection *ht_pool_acquire(struct AmiHttpBase *base,
    struct HttpSession *session, STRPTR host, ULONG port, BOOL ssl);
VOID ht_pool_release(struct AmiHttpBase *base, struct HtConnection *conn,
    BOOL keepalive);
VOID ht_pool_shutdown(struct AmiHttpBase *base);
VOID ht_timer_shutdown(VOID);
struct HtConnection *ht_connection_new(struct AmiHttpBase *base);
VOID ht_connection_free(struct AmiHttpBase *base, struct HtConnection *conn);

/* ht_url.c */
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

/* ht_http.c */
LONG ht_http_build_request(struct HttpTransaction *txn, UBYTE **out_buf,
    ULONG *out_len);
LONG ht_http_send_request(struct AmiHttpBase *base, struct HttpTransaction *txn);
LONG ht_http_read_response_headers(struct AmiHttpBase *base,
    struct HttpTransaction *txn);
LONG ht_http_read_body(struct AmiHttpBase *base, struct HttpTransaction *txn,
    APTR buffer, ULONG buflen);
STRPTR ht_txn_user_agent(struct HttpTransaction *txn);

/* session.c / transaction.c - LVO bodies declared in amihttp_funcs.h */

#endif /* AMIHTTP_PRIVATE_HT_INTERNAL_H */
