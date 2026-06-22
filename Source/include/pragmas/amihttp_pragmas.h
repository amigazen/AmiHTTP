/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amihttp_pragmas.h - SAS/C pragmas for amihttp.library
 *
 * Register masks follow NDK conventions (e.g. 09803 = a0,a1,d0 like GetGBuffers).
 */

#ifndef PRAGMAS_AMIHTTP_H
#define PRAGMAS_AMIHTTP_H

#ifndef CLIB_AMIHTTP_PROTOS_H
#include <clib/amihttp_protos.h>
#endif

#pragma libcall HttpBase HttpBaseTagList                 1e 801
#pragma libcall HttpBase HttpError                       24 00
#pragma libcall HttpBase HttpGetErrorString              2a 001
#pragma libcall HttpBase NewHttpSession                  30 00
#pragma libcall HttpBase DisposeHttpSession              36 801
#pragma libcall HttpBase SetHttpSessionAttrsA            3c 9802
#pragma libcall HttpBase HttpSessionAttachCookieJar      42 9802
#pragma libcall HttpBase HttpSessionDetachCookieJar      48 801
#pragma libcall HttpBase SetHttpSessionHook              4e 90803
#pragma libcall HttpBase NewHttpTransaction              54 801
#pragma libcall HttpBase DisposeHttpTransaction          5a 801
#pragma libcall HttpBase SetHttpTransactionAttrsA        60 9802
#pragma libcall HttpBase HttpTransactionAddHeader        66 A9803
#pragma libcall HttpBase HttpTransactionClearHeaders     6c 801
#pragma libcall HttpBase HttpTransactionPerform          72 801
#pragma libcall HttpBase HttpTransactionPerformAsync     78 801
#pragma libcall HttpBase HttpTransactionIsComplete       7e 801
#pragma libcall HttpBase WaitHttpTransaction             84 8002
#pragma libcall HttpBase AbortHttpTransaction            8a 801
#pragma libcall HttpBase HttpTransactionGetStatusCode    90 801
#pragma libcall HttpBase HttpTransactionGetStatusLine    96 801
#pragma libcall HttpBase HttpTransactionRespHeader 9c 9802
#pragma libcall HttpBase HttpTransactionRespHeaders a2 801
#pragma libcall HttpBase HttpTransactionReadBody         a8 09803
#pragma libcall HttpBase HttpTransactionGetRedirectLocation ae 801
#pragma libcall HttpBase HttpTransactionGetContentLength b4 801
#pragma libcall HttpBase HttpTransactionGetBytesReceived ba 801
#pragma libcall HttpBase HttpTransactionGetTiming        c0 9802
#pragma libcall HttpBase HttpTransactionGetLastError     c6 801
#pragma libcall HttpBase SetHttpTransactionHook          cc 90803
#pragma libcall HttpBase OpenHttpConnection              d2 098004
#pragma libcall HttpBase CloseHttpConnection             d8 801
#pragma libcall HttpBase HttpConnectionWrite             de 09803
#pragma libcall HttpBase HttpConnectionRead              e4 09803
#pragma libcall HttpBase HttpConnectionSendRequest       ea BA9804
#pragma libcall HttpBase HttpConnectionReadResponseLine  f0 09803
#pragma libcall HttpBase HttpConnectionReadResponseHeaders f6 801
#pragma libcall HttpBase HttpConnectionReadBodyChunk     fc 09803
#pragma libcall HttpBase HttpConnectionWriteBodyChunk   102 09803
#pragma libcall HttpBase HttpConnectionIsAlive          108 801
#pragma libcall HttpBase ResetHttpConnection            10e 801
#pragma libcall HttpBase ParseHttpUrl                   114 801
#pragma libcall HttpBase DisposeHttpUrl                 11a 801
#pragma libcall HttpBase BuildHttpUrl                   120 801
#pragma libcall HttpBase HttpUrlEncode                  126 801
#pragma libcall HttpBase HttpUrlDecode                  12c 801
#pragma libcall HttpBase HttpPathEncode                 132 801
#pragma libcall HttpBase HttpBuildQueryString           138 801
#pragma libcall HttpBase NewHttpCookieJar               13e 00
#pragma libcall HttpBase DisposeHttpCookieJar           144 801
#pragma libcall HttpBase LoadHttpCookieJar              14a 9802
#pragma libcall HttpBase SaveHttpCookieJar              150 9802
#pragma libcall HttpBase FlushHttpCookieJar             156 8002
#pragma libcall HttpBase SetHttpCookie                  15c 9802
#pragma libcall HttpBase GetHttpCookieString            162 9802
#pragma libcall HttpBase SetHttpError                   168 001
#pragma libcall HttpBase HttpFault                      16e 198004
#pragma libcall HttpBase HttpUriSchemePart              174 801
#pragma libcall HttpBase HttpUriHostPart                17a 801
#pragma libcall HttpBase HttpUriPathPart                180 801
#pragma libcall HttpBase HttpUriFilePart                186 801
#pragma libcall HttpBase HttpUriQueryPart               18c 801
#pragma libcall HttpBase HttpUriParentPart              192 801
#pragma libcall HttpBase HttpUriAuthorityPart           198 801
#pragma libcall HttpBase HttpJoinUri                    19e 9802
#pragma libcall HttpBase HttpTransactionGetPeerCert     1a4 9802
#pragma libcall HttpBase HttpPeerCertFree               1aa 801

#endif /* PRAGMAS_AMIHTTP_H */
