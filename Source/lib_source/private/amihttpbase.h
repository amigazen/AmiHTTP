/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amihttpbase.h - amihttp.library base structure (lib_source/private only)
 */

#ifndef AMIHTTP_AMIHTTPBASE_H
#define AMIHTTP_AMIHTTPBASE_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef DOS_DOS_H
#include <dos/dos.h>
#endif
#ifndef EXEC_LIBRARIES_H
#include <exec/libraries.h>
#endif
#ifndef EXEC_LISTS_H
#include <exec/lists.h>
#endif
#ifndef EXEC_SEMAPHORES_H
#include <exec/semaphores.h>
#endif

struct AmiHttpBase
{
    struct Library          ahb_LibNode;
    BPTR                    ahb_SegList;
    struct ExecBase        *ahb_SysBase;

    /* Wrapped dependencies - never exposed to callers */
    struct Library         *ahb_SocketBase;
#ifdef AMIHTTP_USE_AMITLS
    struct Library         *ahb_AmiTlsBase;
#else
    struct Library         *ahb_AmiSSLMasterBase;
    struct Library         *ahb_AmiSSLBase;
    struct Library         *ahb_AmiSSLExtBase;
    ULONG                   ahb_AmiSSLInitCount;
#endif
    struct Library         *ahb_DOSBase;
    struct Library         *ahb_UtilityBase;
    struct Library         *ahb_ZBase;          /* z.library (inflate) */
    BOOL                    ahb_ZDecodeReady;   /* TRUE only when decode is wired */

    /* Global connection pool */
    struct List             ahb_PoolList;
    struct List             ahb_ActiveList; /* checked-out connections (in-use) */
    struct SignalSemaphore  ahb_PoolSema;
    struct SignalSemaphore  ahb_SocketSema;
    BOOL                    ahb_SslGlobalOpen;

    /* Shared bsdsocket handle; errno configured once in ht_bsd_open(). */
    int                     ahb_SocketErrno;
    BOOL                    ahb_SocketConfigured;

    /* Per-process defaults (HttpBaseTagsA) */
    ULONG                   ahb_BreakMask;
    APTR                    ahb_ErrnoPtr;
    STRPTR                  ahb_DefaultUserAgent;
    STRPTR                  ahb_DefaultProxy;
    ULONG                   ahb_DefaultTimeout;
    ULONG                   ahb_MaxIdleConnections;
    ULONG                   ahb_IdleTimeout;
    ULONG                   ahb_SslVerify;
    STRPTR                  ahb_CaBundlePath;

    /* Library-wide error state */
    LONG                    ahb_LastError;
    UBYTE                   ahb_ErrorString[256];
};

#endif /* AMIHTTP_AMIHTTPBASE_H */
