/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amihttp_protos.h - Plain C prototypes for amihttp.library LVO functions
 *
 * Generated from SDK/SFD/amihttp_lib.sfd.  Do not edit by hand; regenerate
 * from SFD when the public API changes.
 */

#ifndef CLIB_AMIHTTP_PROTOS_H
#define CLIB_AMIHTTP_PROTOS_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef LIBRARIES_AMIHTTP_H
#include <libraries/amihttp.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Tier 0 */
LONG HttpBaseTagList( struct TagItem *tags );
LONG HttpError( VOID );
LONG SetHttpError( LONG code );
STRPTR HttpGetErrorString( LONG code );
LONG HttpFault( LONG code, STRPTR header, STRPTR buffer, LONG len );

/* Tier 1 */
struct HttpSession *NewHttpSession( VOID );
VOID DisposeHttpSession( struct HttpSession *session );
LONG SetHttpSessionAttrsA( struct HttpSession *session, struct TagItem *tags );
LONG HttpSessionAttachCookieJar( struct HttpSession *session, struct HttpCookieJar *jar );
VOID HttpSessionDetachCookieJar( struct HttpSession *session );
LONG SetHttpSessionHook( struct HttpSession *session, ULONG type, struct Hook *hook );

/* Tier 2 */
struct HttpTransaction *NewHttpTransaction( struct HttpSession *session );
VOID DisposeHttpTransaction( struct HttpTransaction *txn );
LONG SetHttpTransactionAttrsA( struct HttpTransaction *txn, struct TagItem *tags );
LONG HttpTransactionAddHeader( struct HttpTransaction *txn, STRPTR name, STRPTR value );
VOID HttpTransactionClearHeaders( struct HttpTransaction *txn );
LONG HttpTransactionPerform( struct HttpTransaction *txn );
LONG HttpTransactionPerformAsync( struct HttpTransaction *txn );
BOOL HttpTransactionIsComplete( struct HttpTransaction *txn );
LONG WaitHttpTransaction( struct HttpTransaction *txn, ULONG timeout_secs );
VOID AbortHttpTransaction( struct HttpTransaction *txn );
LONG HttpTransactionGetStatusCode( struct HttpTransaction *txn );
STRPTR HttpTransactionGetStatusLine( struct HttpTransaction *txn );
STRPTR HttpTransactionRespHeader( struct HttpTransaction *txn, STRPTR header_name );
struct List *HttpTransactionRespHeaders( struct HttpTransaction *txn );
LONG HttpTransactionReadBody( struct HttpTransaction *txn, APTR buffer, ULONG buflen );
STRPTR HttpTransactionGetRedirectLocation( struct HttpTransaction *txn );
LONG HttpTransactionGetContentLength( struct HttpTransaction *txn );
ULONG HttpTransactionGetBytesReceived( struct HttpTransaction *txn );
LONG HttpTransactionGetTiming( struct HttpTransaction *txn, struct HttpTiming *timing );
LONG HttpTransactionGetLastError( struct HttpTransaction *txn );
LONG SetHttpTransactionHook( struct HttpTransaction *txn, ULONG type, struct Hook *hook );
LONG HttpTransactionGetPeerCert( struct HttpTransaction *txn, struct HttpSslPeerCert *cert );
VOID HttpPeerCertFree( struct HttpSslPeerCert *cert );

/* Tier 3 */
struct HttpConnection *OpenHttpConnection( struct HttpSession *session, STRPTR host, ULONG port, BOOL ssl );
VOID CloseHttpConnection( struct HttpConnection *conn );
LONG HttpConnectionWrite( struct HttpConnection *conn, APTR buffer, ULONG len );
LONG HttpConnectionRead( struct HttpConnection *conn, APTR buffer, ULONG len );
LONG HttpConnectionSendRequest( struct HttpConnection *conn, STRPTR method, STRPTR path, struct TagItem *tags );
LONG HttpConnectionReadResponseLine( struct HttpConnection *conn, STRPTR buffer, ULONG buflen );
LONG HttpConnectionReadResponseHeaders( struct HttpConnection *conn );
LONG HttpConnectionReadBodyChunk( struct HttpConnection *conn, APTR buffer, ULONG buflen );
LONG HttpConnectionWriteBodyChunk( struct HttpConnection *conn, APTR buffer, ULONG len );
BOOL HttpConnectionIsAlive( struct HttpConnection *conn );
VOID ResetHttpConnection( struct HttpConnection *conn );

/* URL utilities */
struct ParsedUrl *ParseHttpUrl( STRPTR url );
VOID DisposeHttpUrl( struct ParsedUrl *url );
STRPTR BuildHttpUrl( struct ParsedUrl *url );
STRPTR HttpUrlEncode( STRPTR str );
STRPTR HttpUrlDecode( STRPTR str );
STRPTR HttpPathEncode( STRPTR path );
STRPTR HttpBuildQueryString( struct List *pairs );
STRPTR HttpUriSchemePart( STRPTR url );
STRPTR HttpUriHostPart( STRPTR url );
STRPTR HttpUriPathPart( STRPTR url );
STRPTR HttpUriFilePart( STRPTR url );
STRPTR HttpUriQueryPart( STRPTR url );
STRPTR HttpUriParentPart( STRPTR url );
STRPTR HttpUriAuthorityPart( STRPTR url );
STRPTR HttpJoinUri( STRPTR base_url, STRPTR relative_url );

/* Cookie jar */
struct HttpCookieJar *NewHttpCookieJar( VOID );
VOID DisposeHttpCookieJar( struct HttpCookieJar *jar );
LONG LoadHttpCookieJar( struct HttpCookieJar *jar, STRPTR filename );
LONG SaveHttpCookieJar( struct HttpCookieJar *jar, STRPTR filename );
VOID FlushHttpCookieJar( struct HttpCookieJar *jar, ULONG max_count );
LONG SetHttpCookie( struct HttpCookieJar *jar, STRPTR cookie_line );
STRPTR GetHttpCookieString( struct HttpCookieJar *jar, STRPTR url );

#ifdef __cplusplus
}
#endif

#endif /* CLIB_AMIHTTP_PROTOS_H */
