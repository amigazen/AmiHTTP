/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amihttp_protos.h - Plain C prototypes for amihttp.library LVO functions
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

LONG HttpBaseTagList( struct TagItem *tags );
LONG HttpError( VOID );
STRPTR HttpGetErrorString( LONG code );

struct HttpSession *NewHttpSession( VOID );
VOID DisposeHttpSession( struct HttpSession *session );
LONG SetHttpSessionAttrsA( struct HttpSession *session, struct TagItem *tags );
LONG HttpSessionAttachCookieJar( struct HttpSession *session, struct HttpCookieJar *jar );
VOID HttpSessionDetachCookieJar( struct HttpSession *session );
LONG SetHttpSessionHook( struct HttpSession *session, ULONG type, struct Hook *hook );

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
STRPTR HttpTransactionRespHeaderNext( struct HttpTransaction *txn, STRPTR header_name, STRPTR prev_value );
BOOL HttpTransactionRespHeaderByIndex( struct HttpTransaction *txn, ULONG index, STRPTR *name_out, STRPTR *value_out );
struct List *HttpTransactionRespHeaders( struct HttpTransaction *txn );
LONG HttpTransactionReadBody( struct HttpTransaction *txn, APTR buffer, ULONG buflen );
STRPTR HttpTransactionGetRedirectLocation( struct HttpTransaction *txn );
LONG HttpTransactionGetContentLength( struct HttpTransaction *txn );
ULONG HttpTransactionGetBytesReceived( struct HttpTransaction *txn );
LONG HttpTransactionGetTiming( struct HttpTransaction *txn, struct HttpTiming *timing );
LONG HttpTransactionGetCipher( struct HttpTransaction *txn, STRPTR buf, ULONG buflen );
LONG HttpTransactionGetLastError( struct HttpTransaction *txn );
LONG SetHttpTransactionHook( struct HttpTransaction *txn, ULONG type, struct Hook *hook );

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
STRPTR HttpConnectionRespHeader( struct HttpConnection *conn, STRPTR header_name );
struct List *HttpConnectionRespHeaders( struct HttpConnection *conn );
LONG HttpConnectionGetStatusCode( struct HttpConnection *conn );
STRPTR HttpConnectionGetStatusLine( struct HttpConnection *conn );

struct ParsedUrl *ParseHttpUrl( STRPTR url );
VOID DisposeHttpUrl( struct ParsedUrl *url );
STRPTR BuildHttpUrl( struct ParsedUrl *url );
STRPTR HttpUrlEncode( STRPTR str );
STRPTR HttpUrlDecode( STRPTR str );
STRPTR HttpPathEncode( STRPTR path );
STRPTR HttpBuildQueryString( struct List *pairs );

struct HttpCookieJar *NewHttpCookieJar( VOID );
struct HttpCookieJar *NewHttpCookieJarTags( struct TagItem *tags );
VOID DisposeHttpCookieJar( struct HttpCookieJar *jar );
LONG LoadHttpCookieJar( struct HttpCookieJar *jar, STRPTR filename );
LONG SaveHttpCookieJar( struct HttpCookieJar *jar, STRPTR filename );
VOID FlushHttpCookieJar( struct HttpCookieJar *jar, ULONG max_count );
LONG SetHttpCookie( struct HttpCookieJar *jar, STRPTR cookie_line );
STRPTR GetHttpCookieString( struct HttpCookieJar *jar, STRPTR url );

LONG SetHttpError( LONG code );
LONG HttpFault( LONG code, STRPTR header, STRPTR buffer, LONG len );

STRPTR HttpUriSchemePart( STRPTR url );
STRPTR HttpUriHostPart( STRPTR url );
STRPTR HttpUriPathPart( STRPTR url );
STRPTR HttpUriFilePart( STRPTR url );
STRPTR HttpUriQueryPart( STRPTR url );
STRPTR HttpUriParentPart( STRPTR url );
STRPTR HttpUriAuthorityPart( STRPTR url );
STRPTR HttpJoinUri( STRPTR base_url, STRPTR relative_url );

LONG HttpTransactionGetPeerCert( struct HttpTransaction *txn, struct HttpSslPeerCert *cert );
VOID HttpPeerCertFree( struct HttpSslPeerCert *cert );

#ifdef __cplusplus
}
#endif

#endif /* CLIB_AMIHTTP_PROTOS_H */
