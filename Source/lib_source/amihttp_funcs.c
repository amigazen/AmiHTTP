/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amihttp_funcs.c - library-global settings/errors
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <utility/tagitem.h>
#include <string.h>
#include <stdio.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_debug.h"
#include "private/ht_internal.h"

extern struct AmiHttpBase *HttpBase;

LONG
__ASM__ __SAVE_DS__ HttpBaseTagList(
    __REG__(a0, struct TagItem *tags))
{
    struct TagItem *t;

    htDbgPut("HttpBaseTagList");
    if (HttpBase == NULL) {
        return ht_lvo_status(ERROR_HTTP_INVALID_HANDLE);
    }

    if (tags == NULL) {
        return 1;
    }

    for (t = tags; t->ti_Tag != TAG_DONE; t++) {
        switch (t->ti_Tag) {
        case HTBT_BREAKMASK:
            HttpBase->ahb_BreakMask = (ULONG)t->ti_Data;
            break;
        case HTBT_ERRNOPTR:
            HttpBase->ahb_ErrnoPtr = (APTR)t->ti_Data;
            break;
        case HTBT_DEFAULT_USERAGENT:
            if (HttpBase->ahb_DefaultUserAgent) {
                ht_free(HttpBase->ahb_DefaultUserAgent);
            }
            HttpBase->ahb_DefaultUserAgent = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTBT_DEFAULT_PROXY:
            if (HttpBase->ahb_DefaultProxy) {
                ht_free(HttpBase->ahb_DefaultProxy);
            }
            HttpBase->ahb_DefaultProxy = ht_strdup((STRPTR)t->ti_Data);
            break;
        case HTBT_MAX_IDLE_CONNECTIONS:
            HttpBase->ahb_MaxIdleConnections = (ULONG)t->ti_Data;
            break;
        case HTBT_IDLE_TIMEOUT:
            HttpBase->ahb_IdleTimeout = (ULONG)t->ti_Data;
            break;
        case HTBT_SSL_VERIFY:
            HttpBase->ahb_SslVerify = (ULONG)t->ti_Data;
            break;
        case HTBT_DEFAULT_TIMEOUT:
            HttpBase->ahb_DefaultTimeout = (ULONG)t->ti_Data;
            break;
        default:
            break;
        }
    }

    return 1;
}

/*
 * IoErr() equivalent: extra error detail after an LVO returned FALSE/0.
 */
LONG
__ASM__ __SAVE_DS__ HttpError(void)
{
    if (HttpBase == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    return HttpBase->ahb_LastError;
}

/*
 * SetIoErr() equivalent: set library error state, return previous value.
 */
LONG
__ASM__ __SAVE_DS__ SetHttpError(
    __REG__(d0, LONG code))
{
    LONG prev;

    if (HttpBase == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    prev = HttpBase->ahb_LastError;
    HttpBase->ahb_LastError = code;
    return prev;
}

/*
 * Catalog text for ERROR_HTTP_* codes.  Returns NULL when code is unknown.
 */
static STRPTR
ht_http_error_catalog(LONG code)
{
    switch (code) {
    case 0:
        return (STRPTR)"No error";
    case ERROR_HTTP_NOT_IMPLEMENTED:
        return (STRPTR)"Not implemented";
    case ERROR_HTTP_DNS_FAILED:
        return (STRPTR)"DNS lookup failed";
    case ERROR_HTTP_CONNECT_FAILED:
        return (STRPTR)"Connection failed";
    case ERROR_HTTP_CONNECT_TIMEOUT:
        return (STRPTR)"Connection timed out";
    case ERROR_HTTP_SSL_HANDSHAKE:
        return (STRPTR)"SSL handshake failed";
    case ERROR_HTTP_SSL_VERIFY:
        return (STRPTR)"SSL certificate verification failed";
    case ERROR_HTTP_READ_TIMEOUT:
        return (STRPTR)"Read timed out";
    case ERROR_HTTP_WRITE_FAILED:
        return (STRPTR)"Write failed";
    case ERROR_HTTP_READ_FAILED:
        return (STRPTR)"Read failed";
    case ERROR_HTTP_ABORTED:
        return (STRPTR)"Operation aborted";
    case ERROR_HTTP_PROTOCOL:
        return (STRPTR)"HTTP protocol error";
    case ERROR_HTTP_OUT_OF_MEMORY:
        return (STRPTR)"Out of memory";
    case ERROR_HTTP_INVALID_URL:
        return (STRPTR)"Invalid URL";
    case ERROR_HTTP_INVALID_HANDLE:
        return (STRPTR)"Invalid handle";
    case ERROR_HTTP_PROXY_AUTH:
        return (STRPTR)"Proxy authentication required";
    case ERROR_HTTP_TOO_MANY_REDIRECTS:
        return (STRPTR)"Too many redirects";
    case ERROR_HTTP_DECODE:
        return (STRPTR)"Content decode failed";
    default:
        return NULL;
    }
}

STRPTR
__ASM__ __SAVE_DS__ HttpGetErrorString(
    __REG__(d0, LONG code))
{
    STRPTR text;

    if (HttpBase == NULL) {
        return (STRPTR)"";
    }

    text = ht_http_error_catalog(code);
    if (text != NULL) {
        return text;
    }
    return (STRPTR)"Unknown error";
}

/*
 * Fault() equivalent: format "header: message" into caller buffer.
 * Sets HttpError() to code.  Returns character count (0 when code is 0).
 */
LONG
__ASM__ __SAVE_DS__ HttpFault(
    __REG__(d0, LONG code),
    __REG__(a0, STRPTR header),
    __REG__(a1, STRPTR buffer),
    __REG__(d1, LONG buflen))
{
    STRPTR text;
    char fallback[40];
    ULONG used;
    ULONG copy;
    ULONG hdr_len;
    ULONG txt_len;
    STRPTR p;

    if (HttpBase == NULL) {
        return 0;
    }

    if (code == 0 || buffer == NULL || buflen <= 0) {
        if (buffer != NULL && buflen > 0) {
            buffer[0] = '\0';
        }
        HttpBase->ahb_LastError = code;
        return 0;
    }

    HttpBase->ahb_LastError = code;

    text = ht_http_error_catalog(code);
    if (text == NULL) {
        sprintf(fallback, "Error code %ld\n", code);
        text = fallback;
    }

    used = 0;
    p = buffer;

    if (header != NULL && header[0] != '\0') {
        hdr_len = (ULONG)strlen(header);
        copy = hdr_len;
        if (used + copy + 2 >= (ULONG)buflen) {
            copy = (ULONG)buflen - used - 1;
        }
        if (copy > 0) {
            memcpy(p, header, copy);
            used += copy;
            p += copy;
        }
        if (used + 2 < (ULONG)buflen) {
            p[0] = ':';
            p[1] = ' ';
            used += 2;
            p += 2;
        }
    }

    txt_len = (ULONG)strlen(text);
    copy = txt_len;
    if (used + copy >= (ULONG)buflen) {
        copy = (ULONG)buflen - used - 1;
    }
    if (copy > 0) {
        memcpy(p, text, copy);
        used += copy;
    }
    buffer[used] = '\0';
    return (LONG)used;
}
