/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * connection.c - Tier 3 streaming HttpConnection LVOs
 */

#define __USE_SYSBASE

#include <exec/types.h>

#include <libraries/amihttp.h>

#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_internal.h"

static LONG
ht_conn_stub(void)
{
    ht_set_error(ERROR_HTTP_NOT_IMPLEMENTED);
    return ht_lvo_status(ERROR_HTTP_NOT_IMPLEMENTED);
}

struct HttpConnection *
__ASM__ __SAVE_DS__ OpenHttpConnection(
    __REG__(a0, struct HttpSession *session),
    __REG__(a1, STRPTR host),
    __REG__(d0, ULONG port),
    __REG__(d1, BOOL ssl))
{
    ht_set_error(ERROR_HTTP_NOT_IMPLEMENTED);
    return NULL;
}

VOID
__ASM__ __SAVE_DS__ CloseHttpConnection(
    __REG__(a0, struct HttpConnection *conn))
{
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionWrite(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG len))
{
    return ht_conn_stub();
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionRead(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG len))
{
    return ht_conn_stub();
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionSendRequest(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, STRPTR method),
    __REG__(a2, STRPTR path),
    __REG__(a3, struct TagItem *tags))
{
    return ht_conn_stub();
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionReadResponseLine(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, STRPTR buffer),
    __REG__(d0, ULONG buflen))
{
    return ht_conn_stub();
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionReadResponseHeaders(
    __REG__(a0, struct HttpConnection *conn))
{
    return ht_conn_stub();
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionReadBodyChunk(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG buflen))
{
    return ht_conn_stub();
}

LONG
__ASM__ __SAVE_DS__ HttpConnectionWriteBodyChunk(
    __REG__(a0, struct HttpConnection *conn),
    __REG__(a1, APTR buffer),
    __REG__(d0, ULONG len))
{
    return ht_conn_stub();
}

BOOL
__ASM__ __SAVE_DS__ HttpConnectionIsAlive(
    __REG__(a0, struct HttpConnection *conn))
{
    return FALSE;
}

VOID
__ASM__ __SAVE_DS__ ResetHttpConnection(
    __REG__(a0, struct HttpConnection *conn))
{
}
