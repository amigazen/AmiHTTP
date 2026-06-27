/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amihttp.h - Public constants, tags, hooks, and opaque types for amihttp.library
 */

#ifndef LIBRARIES_AMIHTTP_H
#define LIBRARIES_AMIHTTP_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef EXEC_LISTS_H
#include <exec/lists.h>
#endif
#ifndef UTILITY_HOOKS_H
#include <utility/hooks.h>
#endif
#ifndef UTILITY_TAGITEM_H
#include <utility/tagitem.h>
#endif

/****************************************************************************/
/* Library identity                                                         */
/****************************************************************************/

#define AMIHTTPNAME     "amihttp.library"
#define AMIHTTPVERSION  1

/****************************************************************************/
/* Opaque handles - internal layout is private to the library               */
/****************************************************************************/

struct HttpSession;
struct HttpTransaction;
struct HttpConnection;
struct HttpCookieJar;
struct ParsedUrl;

/****************************************************************************/
/* Error model (intentionally separate fields)                                */
/*   HttpTransactionGetLastError() / HttpError() - transport/protocol codes   */
/*     (ERROR_HTTP_*). Set when Perform/ReadBody fails.                       */
/*   HttpTransactionGetStatusCode() - HTTP wire status (200, 404, 304…).      */
/*     A 404 response may still be a successful Perform; check status code.   */
/* LVO BOOL routines: TRUE/1 success, FALSE/0 failure then HttpError().       */
/* HttpTransactionReadBody: >0 bytes copied, 0 at EOF or failure.             */
/****************************************************************************/

#define ERROR_HTTP_NOT_IMPLEMENTED      8700
#define ERROR_HTTP_DNS_FAILED           8701
#define ERROR_HTTP_CONNECT_FAILED       8702
#define ERROR_HTTP_CONNECT_TIMEOUT      8703
#define ERROR_HTTP_SSL_HANDSHAKE        8704
#define ERROR_HTTP_SSL_VERIFY           8705
#define ERROR_HTTP_READ_TIMEOUT         8706
#define ERROR_HTTP_WRITE_FAILED         8707
#define ERROR_HTTP_READ_FAILED          8708
#define ERROR_HTTP_ABORTED              8709
#define ERROR_HTTP_PROTOCOL             8710
#define ERROR_HTTP_OUT_OF_MEMORY        8711
#define ERROR_HTTP_INVALID_URL          8712
#define ERROR_HTTP_INVALID_HANDLE       8713
#define ERROR_HTTP_PROXY_AUTH           8714
#define ERROR_HTTP_TOO_MANY_REDIRECTS   8715
#define ERROR_HTTP_DECODE               8716

/****************************************************************************/
/* HttpBaseTagList tags (Tier 0 - per-process / per-library defaults)         */
/****************************************************************************/

#define HTBT_BREAKMASK              (TAG_USER + 0x01)
/* Exec signal mask (e.g. SIGBREAKF_CTRL_C) polled during blocking Perform and */
/* ReadBody. Distinct from HTTA_NOTIFY_SIGNAL used for async completion.      */
#define HTBT_ERRNOPTR               (TAG_USER + 0x02)
#define HTBT_DEFAULT_USERAGENT      (TAG_USER + 0x03)
#define HTBT_DEFAULT_PROXY          (TAG_USER + 0x04)
#define HTBT_DEFAULT_TIMEOUT        (TAG_USER + 0x05)
#define HTBT_MAX_IDLE_CONNECTIONS   (TAG_USER + 0x06)
#define HTBT_IDLE_TIMEOUT           (TAG_USER + 0x07)
#define HTBT_SSL_VERIFY             (TAG_USER + 0x08)
#define HTBT_LOG_HOOK               (TAG_USER + 0x09)
#define HTBT_HTTP2_ENABLED          (TAG_USER + 0x0A)  /* reserved, v2 */
/* PEM CA bundle for VERIFY_PEER when using amitls (mirrors ATBT_CA_BUNDLE_PATH). */
#define HTBT_CA_BUNDLE_PATH         (TAG_USER + 0x0B)
/* Per-task bsdsocket handle (AWeb Opentcp); pair with HTBT_TASK_SOCKET_RELEASE. */
#define HTBT_TASK_SOCKETBASE        (TAG_USER + 0x0C)
#define HTBT_TASK_SOCKET_RELEASE    (TAG_USER + 0x0D)
/* Drop per-task AmiSSL state for the calling Exec task (pair with SOCKET_RELEASE). */
#define HTBT_TASK_SSL_RELEASE       (TAG_USER + 0x0E)
/* Return ht_alloc/ht_strdup pointer to the library pool (e.g. after HttpJoinUri). */
#define HTBT_FREE_POOL_MEM          (TAG_USER + 0x0F)
/* Close idle pooled keep-alive connections (AWeb CloseIdleKeepAliveConnections). */
#define HTBT_POOL_FLUSH             (TAG_USER + 0x10)

/****************************************************************************/
/* SetHttpSessionAttrsA tags (Tier 1)                                         */
/****************************************************************************/

#define HTSA_USERAGENT              (TAG_USER + 0x100)
#define HTSA_REFERER_POLICY         (TAG_USER + 0x101)
#define HTSA_PROXY                  (TAG_USER + 0x102)
#define HTSA_PROXY_AUTH             (TAG_USER + 0x103)
#define HTSA_CREDENTIALS            (TAG_USER + 0x104)
#define HTSA_MAX_REDIRECTS          (TAG_USER + 0x105)
#define HTSA_FOLLOW_REDIRECTS       (TAG_USER + 0x106)
#define HTSA_ACCEPT_ENCODING        (TAG_USER + 0x107)
#define HTSA_KEEPALIVE              (TAG_USER + 0x108)
#define HTSA_MAX_CONNECTIONS        (TAG_USER + 0x109)
#define HTSA_CONNECT_TIMEOUT        (TAG_USER + 0x10A)
#define HTSA_READ_TIMEOUT           (TAG_USER + 0x10B)
#define HTSA_TOTAL_TIMEOUT          (TAG_USER + 0x10C)
#define HTSA_SSL_CIPHER_LIST        (TAG_USER + 0x10D)
#define HTSA_SSL_VERIFY             (TAG_USER + 0x10E)
#define HTSA_SSL_CERT_HOOK          (TAG_USER + 0x10F)
#define HTSA_COOKIE_JAR             (TAG_USER + 0x110)
#define HTSA_TASK_SERIAL            (TAG_USER + 0x111)
#define HTSA_PROXY_PAC_URL          (TAG_USER + 0x112)  /* reserved, v2 */
#define HTSA_ALPN                   (TAG_USER + 0x113)  /* reserved, v2 */
/* Per-session PEM CA bundle override (mirrors ATSA_CA_BUNDLE_PATH). */
#define HTSA_CA_BUNDLE_PATH         (TAG_USER + 0x114)

/****************************************************************************/
/* SetHttpTransactionAttrsA tags (Tier 2)                                     */
/****************************************************************************/

#define HTTA_URL                    (TAG_USER + 0x200)
#define HTTA_BASE_URL               (TAG_USER + 0x201)
#define HTTA_METHOD                 (TAG_USER + 0x202)
#define HTTA_POST_BODY              (TAG_USER + 0x203)
#define HTTA_POST_LENGTH            (TAG_USER + 0x204)
#define HTTA_POST_STREAM_HOOK       (TAG_USER + 0x205)
#define HTTA_RANGE_START            (TAG_USER + 0x206)
#define HTTA_RANGE_END              (TAG_USER + 0x207)
#define HTTA_IF_MODIFIED_SINCE      (TAG_USER + 0x208)
#define HTTA_IF_NONE_MATCH          (TAG_USER + 0x209)
#define HTTA_NO_CACHE               (TAG_USER + 0x20A)
#define HTTA_NO_BODY                (TAG_USER + 0x20B)
#define HTTA_FORM_MULTIPART         (TAG_USER + 0x20C)
#define HTTA_SOURCE_ADDRESS         (TAG_USER + 0x20D)
#define HTTA_THROTTLE_BPS           (TAG_USER + 0x20E)
#define HTTA_CHECKSUM               (TAG_USER + 0x20F)
#define HTTA_REFERER                (TAG_USER + 0x210)
#define HTTA_RETRY_AUTH             (TAG_USER + 0x211)
#define HTTA_USERAGENT              (TAG_USER + 0x212)
/* Async: Exec task + signal bit (0-31) signalled when PerformAsync completes. */
#define HTTA_NOTIFY_TASK            (TAG_USER + 0x213)
#define HTTA_NOTIFY_SIGNAL          (TAG_USER + 0x214)
/* Binary request entity (APTR); pair with HTTA_POST_LENGTH. Copied into txn. */
#define HTTA_REQUEST_BODY           (TAG_USER + 0x215)
/* Request Content-Type when a body is sent; omit for POST default form type only. */
#define HTTA_CONTENT_TYPE           (TAG_USER + 0x216)
/* After ERROR_HTTP_SSL_VERIFY, retry once if cert hook now accepts the peer. */
#define HTTA_RETRY_CERT_VERIFY      (TAG_USER + 0x217)

/****************************************************************************/
/* Tier 2 body streaming (HttpTransactionReadBody)                            */
/*   HttpTransactionPerform leaves the entity body on the wire; the caller     */
/*   loops ReadBody until it returns 0. Caller supplies the buffer each call;  */
/*   the library never requires the full entity in RAM. Chunked/gzip decode    */
/*   is applied inside ReadBody when negotiated.                               */
/* STRPTR lifetime: HttpTransactionGetStatusLine(), HttpTransactionRespHeader(), */
/*   HttpTransactionRespHeaderNext(), HttpTransactionRespHeaderByIndex(),        */
/*   HttpTransactionGetRedirectLocation() point at library-owned storage valid   */
/*   until DisposeHttpTransaction(). Do not FreeVec() these pointers.            */
/*   HttpTransactionRespHeaders() returns an internal list — do not walk nodes. */
/* Async: HttpTransactionPerformAsync requires HTTA_NOTIFY_TASK and            */
/*   HTTA_NOTIFY_SIGNAL; work runs on an internal worker task. WaitHttpTransaction */
/*   waits on the notify signal (or polls if unset).                           */
/****************************************************************************/

/****************************************************************************/
/* HttpConnectionSendRequest tags (Tier 3)                                    */
/****************************************************************************/

#define HTTR_HOST                   (TAG_USER + 0x300)
#define HTTR_HEADERS                (TAG_USER + 0x301)
#define HTTR_CONTENT_LENGTH         (TAG_USER + 0x302)
#define HTTR_CHUNKED                (TAG_USER + 0x303)
#define HTTR_USERAGENT              (TAG_USER + 0x304)

/****************************************************************************/
/* Hook types for SetHttpSessionHook / SetHttpTransactionHook                 */
/****************************************************************************/

#define HTHK_PROGRESS               1
#define HTHK_CERT_VERIFY            2
#define HTHK_REDIRECT               3
#define HTHK_HEADERS_DONE           4
#define HTHK_BODY_CHUNK             5
#define HTHK_COMPLETE               6
#define HTHK_ERROR                  7
#define HTHK_LOG                    8

/****************************************************************************/
/* HttpSslPeerCert - filled by HttpTransactionGetPeerCert()                 */
/****************************************************************************/

struct HttpSslPeerCert
{
    STRPTR  hpc_Subject;
    STRPTR  hpc_Issuer;
    STRPTR  hpc_CommonName;
    STRPTR  hpc_NotBefore;
    STRPTR  hpc_NotAfter;
    STRPTR  hpc_Serial;
    LONG    hpc_VerifyResult;
};

/****************************************************************************/
/* Hook message packets (passed as CallHookPkt message / h_Data).             */
/****************************************************************************/

struct HttpHookHeadersDone
{
    struct HttpTransaction *hhd_Transaction;
    LONG                    hhd_StatusCode;
};

struct HttpHookBodyChunk
{
    struct HttpTransaction *hbc_Transaction;
    APTR                    hbc_Data;
    ULONG                   hbc_Length;
};

struct HttpHookComplete
{
    struct HttpTransaction *hcp_Transaction;
    LONG                    hcp_StatusCode;
    LONG                    hcp_LastError;
};

struct HttpHookError
{
    struct HttpTransaction *her_Transaction;
    LONG                    her_Code;
};

/*
 * HTHK_CERT_VERIFY — invoked when chain or hostname verification fails.
 * Return non-zero (or set hcv_Accept TRUE) to trust the peer and continue.
 */
struct HttpHookCertVerify
{
    struct HttpTransaction *hcv_Transaction;
    struct HttpSslPeerCert  hcv_Cert;
    LONG                    hcv_VerifyResult;
    BOOL                    hcv_Accept;
};

/*
 * HTTA_POST_STREAM_HOOK — fill hps_Buffer up to hps_MaxLen at hps_Offset.
 * Return byte count copied; 0 marks EOF.
 */
struct HttpHookPostStream
{
    struct HttpTransaction *hps_Transaction;
    APTR                    hps_Buffer;
    ULONG                   hps_MaxLen;
    ULONG                   hps_Offset;
};

/*
 * NewHttpCookieJarTags — HTCJ_REQUEST_HOOK / HTCJ_RESPONSE_HOOK.
 * When either hook is set the jar does not store cookies internally; the
 * application owns policy and persistence (AWeb cookie.c).
 */
struct HttpHookCookieRequest
{
    struct HttpTransaction *hcr_Transaction;
    STRPTR                  hcr_Url;
    BOOL                    hcr_Secure;
    STRPTR                  hcr_Value;      /* OUT: "n=v; n2=v2" without Cookie: */
};

struct HttpHookCookieResponse
{
    struct HttpTransaction *hcs_Transaction;
    STRPTR                  hcs_Url;
    STRPTR                  hcs_SetCookieLine; /* value after Set-Cookie: */
    STRPTR                  hcs_DateHeader;    /* raw Date field-value or NULL */
};

/*
 * HTTA_FORM_MULTIPART — struct List of HttpFormPart nodes (multipart body).
 */
struct HttpFormPart
{
    struct Node hfp_Node;
    STRPTR      hfp_Name;
    STRPTR      hfp_Value;
    STRPTR      hfp_Filename;
    APTR        hfp_Data;
    ULONG       hfp_Length;
};

/****************************************************************************/
/* Tier 3 response headers (HttpConnectionReadResponseHeaders)                */
/*   Parsed headers live in a struct List of HttpHeader nodes (same layout as */
/*   Tier 2). HttpConnectionRespHeader() / HttpConnectionRespHeaders() return */
/*   library-owned STRPTR / List* valid until CloseHttpConnection().          */
/****************************************************************************/

/****************************************************************************/
/* Referer policy values (HTSA_REFERER_POLICY)                              */
/****************************************************************************/

#define HTRP_NEVER                  0
#define HTRP_ORIGIN                 1
#define HTRP_ALWAYS                 2

/****************************************************************************/
/* SSL verify policy (HTBT_SSL_VERIFY / HTSA_SSL_VERIFY)                    */
/****************************************************************************/

#define HTSSL_VERIFY_NONE           0
#define HTSSL_VERIFY_PEER           1
#define HTSSL_VERIFY_PEER_STRICT    2

/****************************************************************************/
/* ParsedUrl - public read-only fields after ParseHttpUrl()                   */
/****************************************************************************/

struct ParsedUrl
{
    STRPTR  pu_Scheme;
    STRPTR  pu_Host;
    ULONG   pu_Port;        /* 0 means use default for scheme */
    STRPTR  pu_Path;
    STRPTR  pu_Query;
    STRPTR  pu_User;
    STRPTR  pu_Password;
    BOOL    pu_IsSecure;
};

/****************************************************************************/
/* HttpTiming - filled by HttpTransactionGetTiming()                          */
/****************************************************************************/

struct HttpTiming
{
    ULONG   ht_ConnectMs;
    ULONG   ht_TtfbMs;
    ULONG   ht_TotalMs;
};

/****************************************************************************/
/* HttpHeader - key/value pair for HttpTransactionRespHeaders()               */
/****************************************************************************/

struct HttpHeader
{
    struct Node hh_Node;
    STRPTR      hh_Name;
    STRPTR      hh_Value;
};

/****************************************************************************/
/* NewHttpCookieJarTags tags                                                  */
/****************************************************************************/

#define HTCJ_REQUEST_HOOK           (TAG_USER + 0x400)
#define HTCJ_RESPONSE_HOOK          (TAG_USER + 0x401)

/****************************************************************************/
/* HttpQueryPair - node for HttpBuildQueryString()                            */
/****************************************************************************/

struct HttpQueryPair
{
    struct Node hqp_Node;
    STRPTR      hqp_Name;
    STRPTR      hqp_Value;
};

/****************************************************************************/
/* HttpBaseTags / SetHttpSessionAttrs / SetHttpTransactionAttrs /             */
/* HttpCookieJarTags are static inline wrappers in <proto/amihttp.h>.         */
/****************************************************************************/

#endif /* LIBRARIES_AMIHTTP_H */
