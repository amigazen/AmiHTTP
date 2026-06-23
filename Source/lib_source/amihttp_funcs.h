/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amihttp_funcs.h - LVO function declarations for FuncTab (SAS/C __ASM__)
 */

#ifndef AMIHTTP_FUNCS_H
#define AMIHTTP_FUNCS_H

#include <exec/types.h>
#include <libraries/amihttp.h>
#include "compiler.h"

LONG __ASM__ __SAVE_DS__ HttpBaseTagList(__REG__(a0, struct TagItem *tags));
LONG __ASM__ __SAVE_DS__ HttpError(void);
STRPTR __ASM__ __SAVE_DS__ HttpGetErrorString(__REG__(d0, LONG code));

struct HttpSession *__ASM__ __SAVE_DS__ NewHttpSession(void);
VOID __ASM__ __SAVE_DS__ DisposeHttpSession(__REG__(a0, struct HttpSession *session));
LONG __ASM__ __SAVE_DS__ SetHttpSessionAttrsA(__REG__(a0, struct HttpSession *session), __REG__(a1, struct TagItem *tags));
LONG __ASM__ __SAVE_DS__ HttpSessionAttachCookieJar(__REG__(a0, struct HttpSession *session), __REG__(a1, struct HttpCookieJar *jar));
VOID __ASM__ __SAVE_DS__ HttpSessionDetachCookieJar(__REG__(a0, struct HttpSession *session));
LONG __ASM__ __SAVE_DS__ SetHttpSessionHook(__REG__(a0, struct HttpSession *session), __REG__(d0, ULONG type), __REG__(a1, struct Hook *hook));

struct HttpTransaction *__ASM__ __SAVE_DS__ NewHttpTransaction(__REG__(a0, struct HttpSession *session));
VOID __ASM__ __SAVE_DS__ DisposeHttpTransaction(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ SetHttpTransactionAttrsA(__REG__(a0, struct HttpTransaction *txn), __REG__(a1, struct TagItem *tags));
LONG __ASM__ __SAVE_DS__ HttpTransactionAddHeader(__REG__(a0, struct HttpTransaction *txn), __REG__(a1, STRPTR hdr_name), __REG__(a2, STRPTR value));
VOID __ASM__ __SAVE_DS__ HttpTransactionClearHeaders(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ HttpTransactionPerform(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ HttpTransactionPerformAsync(__REG__(a0, struct HttpTransaction *txn));
BOOL __ASM__ __SAVE_DS__ HttpTransactionIsComplete(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ WaitHttpTransaction(__REG__(a0, struct HttpTransaction *txn), __REG__(d0, ULONG timeout_secs));
VOID __ASM__ __SAVE_DS__ AbortHttpTransaction(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ HttpTransactionGetStatusCode(__REG__(a0, struct HttpTransaction *txn));
STRPTR __ASM__ __SAVE_DS__ HttpTransactionGetStatusLine(__REG__(a0, struct HttpTransaction *txn));
STRPTR __ASM__ __SAVE_DS__ HttpTransactionRespHeader(__REG__(a0, struct HttpTransaction *txn), __REG__(a1, STRPTR header_name));
struct List *__ASM__ __SAVE_DS__ HttpTransactionRespHeaders(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ HttpTransactionReadBody(__REG__(a0, struct HttpTransaction *txn), __REG__(a1, APTR buffer), __REG__(d0, ULONG buflen));
STRPTR __ASM__ __SAVE_DS__ HttpTransactionGetRedirectLocation(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ HttpTransactionGetContentLength(__REG__(a0, struct HttpTransaction *txn));
ULONG __ASM__ __SAVE_DS__ HttpTransactionGetBytesReceived(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ HttpTransactionGetTiming(__REG__(a0, struct HttpTransaction *txn), __REG__(a1, struct HttpTiming *timing));
LONG __ASM__ __SAVE_DS__ HttpTransactionGetLastError(__REG__(a0, struct HttpTransaction *txn));
LONG __ASM__ __SAVE_DS__ SetHttpTransactionHook(__REG__(a0, struct HttpTransaction *txn), __REG__(d0, ULONG type), __REG__(a1, struct Hook *hook));

struct HttpConnection *__ASM__ __SAVE_DS__ OpenHttpConnection(__REG__(a0, struct HttpSession *session), __REG__(a1, STRPTR host), __REG__(d0, ULONG port), __REG__(d1, BOOL ssl));
VOID __ASM__ __SAVE_DS__ CloseHttpConnection(__REG__(a0, struct HttpConnection *conn));
LONG __ASM__ __SAVE_DS__ HttpConnectionWrite(__REG__(a0, struct HttpConnection *conn), __REG__(a1, APTR buffer), __REG__(d0, ULONG len));
LONG __ASM__ __SAVE_DS__ HttpConnectionRead(__REG__(a0, struct HttpConnection *conn), __REG__(a1, APTR buffer), __REG__(d0, ULONG len));
LONG __ASM__ __SAVE_DS__ HttpConnectionSendRequest(__REG__(a0, struct HttpConnection *conn), __REG__(a1, STRPTR method), __REG__(a2, STRPTR path), __REG__(a3, struct TagItem *tags));
LONG __ASM__ __SAVE_DS__ HttpConnectionReadResponseLine(__REG__(a0, struct HttpConnection *conn), __REG__(a1, STRPTR buffer), __REG__(d0, ULONG buflen));
LONG __ASM__ __SAVE_DS__ HttpConnectionReadResponseHeaders(__REG__(a0, struct HttpConnection *conn));
LONG __ASM__ __SAVE_DS__ HttpConnectionReadBodyChunk(__REG__(a0, struct HttpConnection *conn), __REG__(a1, APTR buffer), __REG__(d0, ULONG buflen));
LONG __ASM__ __SAVE_DS__ HttpConnectionWriteBodyChunk(__REG__(a0, struct HttpConnection *conn), __REG__(a1, APTR buffer), __REG__(d0, ULONG len));
BOOL __ASM__ __SAVE_DS__ HttpConnectionIsAlive(__REG__(a0, struct HttpConnection *conn));
VOID __ASM__ __SAVE_DS__ ResetHttpConnection(__REG__(a0, struct HttpConnection *conn));
STRPTR __ASM__ __SAVE_DS__ HttpConnectionRespHeader(__REG__(a0, struct HttpConnection *conn), __REG__(a1, STRPTR header_name));
struct List *__ASM__ __SAVE_DS__ HttpConnectionRespHeaders(__REG__(a0, struct HttpConnection *conn));
LONG __ASM__ __SAVE_DS__ HttpConnectionGetStatusCode(__REG__(a0, struct HttpConnection *conn));
STRPTR __ASM__ __SAVE_DS__ HttpConnectionGetStatusLine(__REG__(a0, struct HttpConnection *conn));

struct ParsedUrl *__ASM__ __SAVE_DS__ ParseHttpUrl(__REG__(a0, STRPTR url));
VOID __ASM__ __SAVE_DS__ DisposeHttpUrl(__REG__(a0, struct ParsedUrl *url));
STRPTR __ASM__ __SAVE_DS__ BuildHttpUrl(__REG__(a0, struct ParsedUrl *url));
STRPTR __ASM__ __SAVE_DS__ HttpUrlEncode(__REG__(a0, STRPTR str));
STRPTR __ASM__ __SAVE_DS__ HttpUrlDecode(__REG__(a0, STRPTR str));
STRPTR __ASM__ __SAVE_DS__ HttpPathEncode(__REG__(a0, STRPTR path));
STRPTR __ASM__ __SAVE_DS__ HttpBuildQueryString(__REG__(a0, struct List *pairs));

struct HttpCookieJar *__ASM__ __SAVE_DS__ NewHttpCookieJar(void);
VOID __ASM__ __SAVE_DS__ DisposeHttpCookieJar(__REG__(a0, struct HttpCookieJar *jar));
LONG __ASM__ __SAVE_DS__ LoadHttpCookieJar(__REG__(a0, struct HttpCookieJar *jar), __REG__(a1, STRPTR filename));
LONG __ASM__ __SAVE_DS__ SaveHttpCookieJar(__REG__(a0, struct HttpCookieJar *jar), __REG__(a1, STRPTR filename));
VOID __ASM__ __SAVE_DS__ FlushHttpCookieJar(__REG__(a0, struct HttpCookieJar *jar), __REG__(d0, ULONG max_count));
LONG __ASM__ __SAVE_DS__ SetHttpCookie(__REG__(a0, struct HttpCookieJar *jar), __REG__(a1, STRPTR cookie_line));
STRPTR __ASM__ __SAVE_DS__ GetHttpCookieString(__REG__(a0, struct HttpCookieJar *jar), __REG__(a1, STRPTR url));

LONG __ASM__ __SAVE_DS__ SetHttpError(__REG__(d0, LONG code));
LONG __ASM__ __SAVE_DS__ HttpFault(__REG__(d0, LONG code), __REG__(a0, STRPTR header), __REG__(a1, STRPTR buffer), __REG__(d1, LONG buflen));

STRPTR __ASM__ __SAVE_DS__ HttpUriSchemePart(__REG__(a0, STRPTR url));
STRPTR __ASM__ __SAVE_DS__ HttpUriHostPart(__REG__(a0, STRPTR url));
STRPTR __ASM__ __SAVE_DS__ HttpUriPathPart(__REG__(a0, STRPTR url));
STRPTR __ASM__ __SAVE_DS__ HttpUriFilePart(__REG__(a0, STRPTR url));
STRPTR __ASM__ __SAVE_DS__ HttpUriQueryPart(__REG__(a0, STRPTR url));
STRPTR __ASM__ __SAVE_DS__ HttpUriParentPart(__REG__(a0, STRPTR url));
STRPTR __ASM__ __SAVE_DS__ HttpUriAuthorityPart(__REG__(a0, STRPTR url));
STRPTR __ASM__ __SAVE_DS__ HttpJoinUri(__REG__(a0, STRPTR base_url), __REG__(a1, STRPTR relative_url));

LONG __ASM__ __SAVE_DS__ HttpTransactionGetPeerCert(__REG__(a0, struct HttpTransaction *txn), __REG__(a1, struct HttpSslPeerCert *cert));
VOID __ASM__ __SAVE_DS__ HttpPeerCertFree(__REG__(a0, struct HttpSslPeerCert *cert));

#endif /* AMIHTTP_FUNCS_H */
