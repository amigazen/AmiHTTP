/*
 * libbases.c - Global bases required by proto/ pragmas at link time.
 */

#define __USE_SYSBASE

#include <exec/types.h>

#include <proto/exec.h>

#include <amihttp/amihttpbase.h>
#include "private/ht_ssl_config.h"

extern struct DosLibrary *DOSBase;

struct Library *UtilityBase;
struct Library *ZBase;
struct Library *SocketBase;
#ifdef AMIHTTP_USE_AMITLS
struct Library *TlsBase;
#else
struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
struct Library *AmiSSLExtBase;
#endif

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
#ifdef AMIHTTP_USE_AMITLS
    TlsBase = base->ahb_AmiTlsBase;
#else
    AmiSSLMasterBase = base->ahb_AmiSSLMasterBase;
    AmiSSLBase = base->ahb_AmiSSLBase;
    AmiSSLExtBase = base->ahb_AmiSSLExtBase;
#endif
}
