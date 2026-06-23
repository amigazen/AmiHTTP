/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * StartUp.c - LVO trap and function vector table for amihttp.library
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <exec/resident.h>
#include <exec/initializers.h>
#include <exec/lists.h>
#include <exec/semaphores.h>

#include <proto/exec.h>
#include <proto/alib.h>
#include <proto/dos.h>

#include <amihttp/amihttpbase.h>
#include "private/ht_build.h"
#include "private/ht_debug.h"
#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_internal.h"

extern ULONG L_OpenLibs(struct AmiHttpBase *HttpBase);
extern VOID L_CloseLibs(VOID);

extern struct Resident ROMTag;
extern const char HT_LibName[];
extern const char HT_LibID[];
extern struct MyDataInit DataTab;

struct AmiHttpBase *HttpBase = NULL;

struct ExecBase *SysBase = NULL;
struct DosLibrary *DOSBase = NULL;

LONG __ASM__ LibStart(void);
struct AmiHttpBase * __ASM__ __SAVE_DS__ InitLib(
    __REG__(a6, struct ExecBase *sysbase),
    __REG__(a0, BPTR seglist),
    __REG__(d0, struct AmiHttpBase *base));
struct AmiHttpBase * __ASM__ __SAVE_DS__ OpenLib(
    __REG__(a6, struct AmiHttpBase *base));
BPTR __ASM__ __SAVE_DS__ CloseLib(
    __REG__(a6, struct AmiHttpBase *base));
BPTR __ASM__ __SAVE_DS__ ExpungeLib(
    __REG__(a6, struct AmiHttpBase *base));
ULONG __ASM__ ExtFuncLib(void);

APTR FuncTab[];

struct InitTable InitTab = {
    (ULONG)sizeof(struct AmiHttpBase),
    (APTR *)FuncTab,
    (APTR)&DataTab,
    (APTR)InitLib
};

APTR FuncTab[] = {
    (APTR)OpenLib,
    (APTR)CloseLib,
    (APTR)ExpungeLib,
    (APTR)ExtFuncLib,
    /* Tier 0 */
    (APTR)HttpBaseTagList,
    (APTR)HttpError,
    (APTR)HttpGetErrorString,
    /* Tier 1 */
    (APTR)NewHttpSession,
    (APTR)DisposeHttpSession,
    (APTR)SetHttpSessionAttrsA,
    (APTR)HttpSessionAttachCookieJar,
    (APTR)HttpSessionDetachCookieJar,
    (APTR)SetHttpSessionHook,
    /* Tier 2 */
    (APTR)NewHttpTransaction,
    (APTR)DisposeHttpTransaction,
    (APTR)SetHttpTransactionAttrsA,
    (APTR)HttpTransactionAddHeader,
    (APTR)HttpTransactionClearHeaders,
    (APTR)HttpTransactionPerform,
    (APTR)HttpTransactionPerformAsync,
    (APTR)HttpTransactionIsComplete,
    (APTR)WaitHttpTransaction,
    (APTR)AbortHttpTransaction,
    (APTR)HttpTransactionGetStatusCode,
    (APTR)HttpTransactionGetStatusLine,
    (APTR)HttpTransactionRespHeader,
    (APTR)HttpTransactionRespHeaders,
    (APTR)HttpTransactionReadBody,
    (APTR)HttpTransactionGetRedirectLocation,
    (APTR)HttpTransactionGetContentLength,
    (APTR)HttpTransactionGetBytesReceived,
    (APTR)HttpTransactionGetTiming,
    (APTR)HttpTransactionGetLastError,
    (APTR)SetHttpTransactionHook,
    /* Tier 3 */
    (APTR)OpenHttpConnection,
    (APTR)CloseHttpConnection,
    (APTR)HttpConnectionWrite,
    (APTR)HttpConnectionRead,
    (APTR)HttpConnectionSendRequest,
    (APTR)HttpConnectionReadResponseLine,
    (APTR)HttpConnectionReadResponseHeaders,
    (APTR)HttpConnectionReadBodyChunk,
    (APTR)HttpConnectionWriteBodyChunk,
    (APTR)HttpConnectionIsAlive,
    (APTR)ResetHttpConnection,
    (APTR)HttpConnectionRespHeader,
    (APTR)HttpConnectionRespHeaders,
    (APTR)HttpConnectionGetStatusCode,
    (APTR)HttpConnectionGetStatusLine,
    /* URL utilities */
    (APTR)ParseHttpUrl,
    (APTR)DisposeHttpUrl,
    (APTR)BuildHttpUrl,
    (APTR)HttpUrlEncode,
    (APTR)HttpUrlDecode,
    (APTR)HttpPathEncode,
    (APTR)HttpBuildQueryString,
    /* Cookie jar */
    (APTR)NewHttpCookieJar,
    (APTR)DisposeHttpCookieJar,
    (APTR)LoadHttpCookieJar,
    (APTR)SaveHttpCookieJar,
    (APTR)FlushHttpCookieJar,
    (APTR)SetHttpCookie,
    (APTR)GetHttpCookieString,
    (APTR)SetHttpError,
    (APTR)HttpFault,
    (APTR)HttpUriSchemePart,
    (APTR)HttpUriHostPart,
    (APTR)HttpUriPathPart,
    (APTR)HttpUriFilePart,
    (APTR)HttpUriQueryPart,
    (APTR)HttpUriParentPart,
    (APTR)HttpUriAuthorityPart,
    (APTR)HttpJoinUri,
    (APTR)HttpTransactionGetPeerCert,
    (APTR)HttpPeerCertFree,
    (APTR)((LONG)-1)
};

LONG
__ASM__ LibStart(void)
{
    return -1;
}

struct AmiHttpBase *
__ASM__ __SAVE_DS__ InitLib(
    __REG__(a6, struct ExecBase *sysbase),
    __REG__(a0, BPTR seglist),
    __REG__(d0, struct AmiHttpBase *base))
{
    htDbgPut("InitLib: enter");
    htDbgPutHex("InitLib: base=", (ULONG)base);

    HttpBase = base;

    base->ahb_LibNode.lib_Node.ln_Type = NT_LIBRARY;
    base->ahb_LibNode.lib_Flags = LIBF_SUMUSED | LIBF_CHANGED;
    base->ahb_LibNode.lib_Version = HT_LIB_VERSION;
    base->ahb_LibNode.lib_Revision = HT_LIB_REVISION;
    base->ahb_LibNode.lib_IdString = (STRPTR)HT_LibID;

    base->ahb_SysBase = sysbase;
    base->ahb_SegList = seglist;
    base->ahb_LastError = 0;
    base->ahb_MaxIdleConnections = 8;
    base->ahb_IdleTimeout = 15;
    base->ahb_SslVerify = HTSSL_VERIFY_PEER;
    base->ahb_DefaultTimeout = 60;
    base->ahb_ZBase = NULL;
    base->ahb_ZDecodeReady = FALSE;

    if (L_OpenLibs(base) != 0) {
        htDbgPut("InitLib: L_OpenLibs failed");
        return (struct AmiHttpBase *)NULL;
    }

    NewList(&base->ahb_PoolList);
    InitSemaphore(&base->ahb_PoolSema);
    InitSemaphore(&base->ahb_SocketSema);
    base->ahb_SslGlobalOpen = FALSE;

    htDbgPut("InitLib: success");
    return base;
}

struct AmiHttpBase *
__ASM__ __SAVE_DS__ OpenLib(__REG__(a6, struct AmiHttpBase *base))
{
    base->ahb_LibNode.lib_OpenCnt++;
    base->ahb_LibNode.lib_Flags &= ~LIBF_DELEXP;
    /* Clear stale IoErr-style state from a previous client open. */
    base->ahb_LastError = 0;
    return base;
}

BPTR
__ASM__ __SAVE_DS__ CloseLib(__REG__(a6, struct AmiHttpBase *base))
{
    base->ahb_LibNode.lib_OpenCnt--;

    if (base->ahb_LibNode.lib_OpenCnt == 0) {
        if (base->ahb_LibNode.lib_Flags & LIBF_DELEXP) {
            return ExpungeLib(base);
        }
    }

    return 0;
}

BPTR
__ASM__ __SAVE_DS__ ExpungeLib(__REG__(a6, struct AmiHttpBase *base))
{
    BPTR seg;

    if (base->ahb_LibNode.lib_OpenCnt != 0) {
        base->ahb_LibNode.lib_Flags |= LIBF_DELEXP;
        return 0;
    }

    seg = base->ahb_SegList;

    ht_pool_shutdown(base);
    L_CloseLibs();

    Remove(&base->ahb_LibNode.lib_Node);
    FreeMem((APTR)((BYTE *)base - base->ahb_LibNode.lib_NegSize),
        base->ahb_LibNode.lib_NegSize + base->ahb_LibNode.lib_PosSize);

    HttpBase = NULL;

    return seg;
}

ULONG
__ASM__ ExtFuncLib(void)
{
    return 0;
}
