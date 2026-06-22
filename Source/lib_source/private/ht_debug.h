/*
 * ht_debug.h - conditional trace output for amihttp.library
 *
 * Enable in Source/lib_source/SCOPTIONS with DEFINE=AMIHTTP_DEBUG.
 */

#ifndef AMIHTTP_PRIVATE_HT_DEBUG_H
#define AMIHTTP_PRIVATE_HT_DEBUG_H

#include <proto/dos.h>

extern struct DosLibrary *DOSBase;

#ifdef AMIHTTP_DEBUG

static VOID htDbgFlush(VOID)
{
    BPTR out;

    if (DOSBase) {
        out = Output();
        if (out) {
            Flush(out);
        }
    }
}

static VOID htDbgPut(STRPTR text)
{
    if (DOSBase && text) {
        PutStr("[amihttp] ");
        PutStr(text);
        PutStr("\n");
        htDbgFlush();
    }
}

static VOID htDbgPutLong(STRPTR label, LONG value)
{
    if (DOSBase && label) {
        Printf("[amihttp] %s%ld\n", (LONG)label, value);
        htDbgFlush();
    }
}

static VOID htDbgPutHex(STRPTR label, ULONG value)
{
    if (DOSBase && label) {
        Printf("[amihttp] %s0x%08lx\n", (LONG)label, (ULONG)value);
        htDbgFlush();
    }
}

#else

#define htDbgPut(text)              ((void)0)
#define htDbgPutLong(label, val)    ((void)0)
#define htDbgPutHex(label, val)     ((void)0)

#endif

#endif /* AMIHTTP_PRIVATE_HT_DEBUG_H */
