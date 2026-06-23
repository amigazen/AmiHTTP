/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * libbases.c - Global bases required by proto/ pragmas at link time.
 */

#define __USE_SYSBASE

#include <exec/types.h>

#include <proto/exec.h>

#include <amihttp/amihttpbase.h>

extern struct DosLibrary *DOSBase;

struct Library *UtilityBase;
struct Library *ZBase;
struct Library *SocketBase;
struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
struct Library *AmiSSLExtBase;

/* bsdsocket.library resolver/errno */
int errno;
int h_errno;

/* timer.device base for GetSysTime() */
struct Device *TimerBase;

VOID
ht_sync_proto_bases(struct AmiHttpBase *base)
{
    if (base == NULL) {
        return;
    }
    UtilityBase = base->ahb_UtilityBase;
    ZBase = base->ahb_ZBase;
    SocketBase = base->ahb_SocketBase;
    DOSBase = (struct DosLibrary *)base->ahb_DOSBase;
    AmiSSLMasterBase = base->ahb_AmiSSLMasterBase;
    AmiSSLBase = base->ahb_AmiSSLBase;
    AmiSSLExtBase = base->ahb_AmiSSLExtBase;
}
