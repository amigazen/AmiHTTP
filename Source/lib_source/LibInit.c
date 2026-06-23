/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * LibInit.c - ROMTag, DataTab, and dependency open/close for amihttp.library
 *
 * bsdsocket and amisslmaster open lazily on first HTTP/HTTPS use.
 * utility.library v47+ is required for SNPrintf/Strncpy/Strncat in ht_url.c.
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <exec/resident.h>
#include <exec/initializers.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <amihttp/amihttpbase.h>
#include "private/ht_build.h"
#include "private/ht_debug.h"
#include "private/ht_internal.h"
#include "compiler.h"

#define HTLIBNAME "amihttp"
#define HTLIBVER  " 1.0 (22.6.2026)"

const char HT_LibName[] = HTLIBNAME ".library";
const char HT_LibID[]   = HTLIBNAME HTLIBVER;
const char HT_VerString[] = "\0$VER: " HTLIBNAME HTLIBVER;

extern struct ExecBase *SysBase;
extern struct AmiHttpBase *HttpBase;
extern struct DosLibrary *DOSBase;
extern struct Library *UtilityBase;
extern struct Library *ZBase;

ULONG __SAVE_DS__
L_OpenLibs(struct AmiHttpBase *base)
{
    htDbgPut("L_OpenLibs: enter");

    SysBase = *((struct ExecBase **)4);

    if (base != NULL) {
        base->ahb_SocketBase = NULL;
        base->ahb_AmiSSLMasterBase = NULL;
        base->ahb_AmiSSLBase = NULL;
        base->ahb_AmiSSLExtBase = NULL;
        base->ahb_DOSBase = NULL;
        base->ahb_UtilityBase = NULL;
        base->ahb_AmiSSLInitCount = 0;
        base->ahb_ZBase = NULL;
        base->ahb_ZDecodeReady = FALSE;
    }
    ZBase = NULL;

    UtilityBase = OpenLibrary("utility.library", 47);
    if (UtilityBase == NULL) {
        return 1;
    }
    if (base != NULL) {
        base->ahb_UtilityBase = UtilityBase;
    }

    DOSBase = (struct DosLibrary *)OpenLibrary("dos.library", 37);
    if (DOSBase == NULL) {
        if (UtilityBase != NULL) {
            CloseLibrary(UtilityBase);
            UtilityBase = NULL;
            if (base != NULL) {
                base->ahb_UtilityBase = NULL;
            }
        }
        return 1;
    }
    if (DOSBase == NULL) {
        return 1;
    }
    if (base != NULL) {
        base->ahb_DOSBase = (struct Library *)DOSBase;
    }

    if (base != NULL) {
        base->ahb_ZBase = OpenLibrary((STRPTR)"z.library", 2);
        if (base->ahb_ZBase != NULL) {
            base->ahb_ZDecodeReady = TRUE;
            ZBase = base->ahb_ZBase;
        } else {
            base->ahb_ZDecodeReady = FALSE;
        }
    }

    ht_sync_proto_bases(base);
    htDbgPut("L_OpenLibs: dos.library ok");
    htDbgPut("L_OpenLibs: success");
    return 0;
}

VOID __SAVE_DS__
L_CloseLibs(VOID)
{

    if (HttpBase == NULL) {
        return;
    }

    ht_transport_global_shutdown(HttpBase);
    ht_timer_shutdown();

    if (HttpBase->ahb_AmiSSLMasterBase != NULL) {
        CloseLibrary(HttpBase->ahb_AmiSSLMasterBase);
        HttpBase->ahb_AmiSSLMasterBase = NULL;
    }

    if (HttpBase->ahb_SocketBase != NULL) {
        CloseLibrary(HttpBase->ahb_SocketBase);
        HttpBase->ahb_SocketBase = NULL;
    }

    if (HttpBase->ahb_DOSBase != NULL) {
        CloseLibrary(HttpBase->ahb_DOSBase);
        HttpBase->ahb_DOSBase = NULL;
        DOSBase = NULL;
    }

    if (HttpBase->ahb_UtilityBase != NULL) {
        CloseLibrary(HttpBase->ahb_UtilityBase);
        HttpBase->ahb_UtilityBase = NULL;
        UtilityBase = NULL;
    }
    if (HttpBase->ahb_ZBase != NULL) {
        CloseLibrary(HttpBase->ahb_ZBase);
        HttpBase->ahb_ZBase = NULL;
        ZBase = NULL;
    }

    ht_sync_proto_bases(HttpBase);
}

extern struct InitTable InitTab;
extern APTR EndResident;

struct Resident ROMTag = {
    RTC_MATCHWORD,
    &ROMTag,
    &EndResident,
    RTF_AUTOINIT,
    HT_LIB_VERSION,
    NT_LIBRARY,
    0,
    (APTR)HT_LibName,
    (APTR)HT_LibID,
    (APTR)&InitTab
};

APTR EndResident;

struct MyDataInit DataTab = {
    0xE000, 8,  NT_LIBRARY,
    0x80,   10, (ULONG)HT_LibName,
    0xE000, 14, LIBF_SUMUSED | LIBF_CHANGED,
    0xE000, 20, HT_LIB_VERSION,
    0xE000, 22, HT_LIB_REVISION,
    0x80,   24, (ULONG)HT_LibID,
    (ULONG)0
};

#ifdef __SASC
void __regargs __chkabort(void) { }
void __regargs _CXBRK(void)     { }
#endif
