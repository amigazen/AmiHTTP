/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_pool.c - Keep-alive connection pool
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/semaphores.h>
#include <exec/tasks.h>
#include <exec/ports.h>
#include <exec/io.h>
#include <exec/devices.h>

#include <devices/timer.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/timer.h>
#include <proto/alib.h>

#include <amihttp/amihttpbase.h>
#include <libraries/amihttp.h>

#include "private/ht_debug.h"
#include "private/ht_internal.h"

extern struct Device *TimerBase;

/* Lazy timer.device open for GetSysTime(); guarded for parallel pool scans. */
static struct MsgPort *ht_timer_port;
static struct timerequest *ht_timer_req;
static BOOL ht_timer_open;
static struct SignalSemaphore ht_timer_sema;
static BOOL ht_timer_sema_inited;

static BOOL
ht_ensure_timer(void)
{
    if (!ht_timer_sema_inited) {
        InitSemaphore(&ht_timer_sema);
        ht_timer_sema_inited = TRUE;
    }
    ObtainSemaphore(&ht_timer_sema);
    if (ht_timer_open) {
        ReleaseSemaphore(&ht_timer_sema);
        return TRUE;
    }
    ht_timer_port = CreateMsgPort();
    if (ht_timer_port == NULL) {
        ReleaseSemaphore(&ht_timer_sema);
        return FALSE;
    }
    ht_timer_req = (struct timerequest *)CreateExtIO(
        ht_timer_port, (LONG)sizeof(struct timerequest));
    if (ht_timer_req == NULL) {
        DeleteMsgPort(ht_timer_port);
        ht_timer_port = NULL;
        ReleaseSemaphore(&ht_timer_sema);
        return FALSE;
    }
    if (OpenDevice((STRPTR)TIMERNAME, (ULONG)UNIT_MICROHZ,
            (struct IORequest *)ht_timer_req, 0) != 0) {
        DeleteExtIO((struct IORequest *)ht_timer_req);
        ht_timer_req = NULL;
        DeleteMsgPort(ht_timer_port);
        ht_timer_port = NULL;
        ReleaseSemaphore(&ht_timer_sema);
        return FALSE;
    }
    TimerBase = ht_timer_req->tr_node.io_Device;
    ht_timer_open = TRUE;
    ReleaseSemaphore(&ht_timer_sema);
    return TRUE;
}

VOID
ht_timer_shutdown(VOID)
{
    if (!ht_timer_sema_inited) {
        return;
    }
    ObtainSemaphore(&ht_timer_sema);
    if (ht_timer_req != NULL) {
        if (ht_timer_open) {
            CloseDevice((struct IORequest *)ht_timer_req);
        }
        DeleteExtIO((struct IORequest *)ht_timer_req);
        ht_timer_req = NULL;
    }
    if (ht_timer_port != NULL) {
        DeleteMsgPort(ht_timer_port);
        ht_timer_port = NULL;
    }
    TimerBase = NULL;
    ht_timer_open = FALSE;
    ReleaseSemaphore(&ht_timer_sema);
}

static ULONG
ht_current_seconds(void)
{
    struct timeval tv;

    if (!ht_ensure_timer()) {
        return 0UL;
    }
    GetSysTime(&tv);
    return (ULONG)tv.tv_secs;
}

BOOL
ht_timer_get_time(struct timeval *tv)
{
    if (tv == NULL) {
        return FALSE;
    }
    if (!ht_ensure_timer()) {
        return FALSE;
    }
    GetSysTime(tv);
    return TRUE;
}

ULONG
ht_timer_delta_ms(struct timeval *start, struct timeval *end)
{
    ULONG sec;
    ULONG usec;

    if (start == NULL || end == NULL) {
        return 0UL;
    }
    if (end->tv_secs < start->tv_secs) {
        return 0UL;
    }
    sec = end->tv_secs - start->tv_secs;
    if (end->tv_micro >= start->tv_micro) {
        usec = end->tv_micro - start->tv_micro;
    } else {
        if (sec == 0UL) {
            return 0UL;
        }
        sec--;
        usec = (end->tv_micro + 1000000UL) - start->tv_micro;
    }
    return sec * 1000UL + usec / 1000UL;
}

static BOOL
ht_host_match(STRPTR a, STRPTR b)
{
    char ca;
    char cb;

    if (a == NULL || b == NULL) {
        return FALSE;
    }
    while (*a != '\0' && *b != '\0') {
        ca = *a++;
        cb = *b++;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return FALSE;
        }
    }
    return (BOOL)(*a == '\0' && *b == '\0');
}

struct HtConnection *
ht_connection_new(struct AmiHttpBase *base)
{
    struct HtConnection *conn;

    conn = (struct HtConnection *)ht_alloc(sizeof(struct HtConnection), MEMF_CLEAR);
    if (conn == NULL) {
        return NULL;
    }
    conn->hc_Magic = HT_MAGIC_CONN;
    conn->hc_Sock = -1;
    conn->hc_IoCap = HT_IOBUF_SIZE;
    conn->hc_IoBuf = (UBYTE *)ht_alloc(conn->hc_IoCap, MEMF_CLEAR);
    if (conn->hc_IoBuf == NULL) {
        ht_free(conn);
        return NULL;
    }
    return conn;
}

VOID
ht_connection_free(struct AmiHttpBase *base, struct HtConnection *conn)
{
    if (conn == NULL) {
        return;
    }
    ht_transport_disconnect(base, conn);
    if (conn->hc_Host) {
        ht_free(conn->hc_Host);
    }
    if (conn->hc_OriginHost) {
        ht_free(conn->hc_OriginHost);
    }
    if (conn->hc_IoBuf) {
        ht_free(conn->hc_IoBuf);
    }
    ht_free(conn);
}

static VOID
ht_pool_close_conn(struct AmiHttpBase *base, struct HtConnection *conn)
{
    if (conn == NULL) {
        return;
    }
    Remove(&conn->hc_Node);
    ht_connection_free(base, conn);
}

struct HtConnection *
ht_pool_acquire(struct AmiHttpBase *base, struct HttpSession *session,
    struct HtRoute *route, struct HttpTransaction *txn)
{
    struct HtConnection *conn;
    struct HtConnection *next;
    struct HtConnection *found;
    struct HtConnection *dead;
    ULONG now;
    ULONG owner;
    ULONG max_idle;
    ULONG idle_timeout;
    ULONG timeout;
    STRPTR ca_bundle_path;
    LONG rc;

    if (base == NULL || session == NULL || route == NULL ||
        route->hr_OriginHost == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_HANDLE);
        return NULL;
    }
    htDbgPut("ht_pool_acquire");
    owner = session->hs_TaskSerial;
    if (owner == 0) {
        owner = (ULONG)FindTask(NULL);
        session->hs_TaskSerial = owner;
    }
    max_idle = base->ahb_MaxIdleConnections;
    if (max_idle == 0) {
        max_idle = HT_POOL_MAX_IDLE;
    }
    idle_timeout = base->ahb_IdleTimeout;
    if (idle_timeout == 0) {
        idle_timeout = HT_POOL_TIMEOUT;
    }
    found = NULL;
    dead = NULL;
    /*
     * Proxy connections are never pooled (OWNERSHIP.md): each hop gets a
     * fresh TCP socket to the proxy.
     */
    if (!route->hr_ViaProxy) {
        htDbgPut("ht_pool_acquire pool lock");
        ObtainSemaphore(&base->ahb_PoolSema);
        now = ht_current_seconds();
        for (conn = (struct HtConnection *)base->ahb_PoolList.lh_Head;
             conn != NULL && conn->hc_Node.ln_Succ != NULL;
             conn = next) {
            next = (struct HtConnection *)conn->hc_Node.ln_Succ;
            if (!conn->hc_InUse &&
                !conn->hc_ViaProxy &&
                conn->hc_OwnerSerial == owner &&
                conn->hc_Port == route->hr_OriginPort &&
                conn->hc_IsSsl == route->hr_OriginSsl &&
                conn->hc_Host != NULL &&
                ht_host_match(conn->hc_Host, route->hr_OriginHost)) {
                if ((now - conn->hc_LastUsed) < idle_timeout) {
                    BOOL idle_ok;

                    ReleaseSemaphore(&base->ahb_PoolSema);
                    idle_ok = ht_transport_conn_idle(base, conn);
                    ObtainSemaphore(&base->ahb_PoolSema);
                    if (idle_ok) {
                        conn->hc_InUse = TRUE;
                        conn->hc_LastUsed = now;
                        conn->hc_IoLen = 0;
                        conn->hc_IoPos = 0;
                        conn->hc_Flags |= HTF_CONN_REUSED;
                        Remove(&conn->hc_Node);
                        found = conn;
                        break;
                    }
                }
                Remove(&conn->hc_Node);
                conn->hc_DeadNext = dead;
                dead = conn;
            }
        }
        ReleaseSemaphore(&base->ahb_PoolSema);
        while (dead != NULL) {
            conn = dead;
            dead = conn->hc_DeadNext;
            conn->hc_DeadNext = NULL;
            ht_pool_close_conn(base, conn);
        }
        if (found != NULL) {
            htDbgPut("ht_pool_acquire reused");
            return found;
        }
    }
    conn = ht_connection_new(base);
    if (conn == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
    }
    conn->hc_OwnerSerial = owner;
    conn->hc_InUse = TRUE;
    conn->hc_Flags = 0;
    conn->hc_ViaProxy = route->hr_ViaProxy;
    htDbgPut("ht_pool_acquire connect");
    if (session->hs_ConnectTimeout == 0) {
        timeout = base->ahb_DefaultTimeout;
    } else {
        timeout = session->hs_ConnectTimeout;
    }
    ca_bundle_path = session->hs_CaBundlePath;
    if (ca_bundle_path == NULL || ca_bundle_path[0] == '\0') {
        ca_bundle_path = base->ahb_CaBundlePath;
    }
    rc = ht_transport_connect_route(base, conn, route, timeout,
        session->hs_SslVerify, txn, ca_bundle_path);
    if (rc != 0) {
        ht_set_error(rc);
        ht_connection_free(base, conn);
        return NULL;
    }
    conn->hc_LastUsed = ht_current_seconds();
    return conn;
}

VOID
ht_pool_release(struct AmiHttpBase *base, struct HtConnection *conn, BOOL keepalive)
{
    struct HtConnection *node;
    ULONG count;
    ULONG max_idle;
    ULONG now;

    if (base == NULL || conn == NULL) {
        return;
    }
    if (conn->hc_ViaProxy) {
        keepalive = FALSE;
    }
    conn->hc_InUse = FALSE;
    if (!keepalive || conn->hc_Sock < 0) {
        ht_connection_free(base, conn);
        return;
    }
    if (!ht_transport_conn_idle(base, conn)) {
        ht_connection_free(base, conn);
        return;
    }
    max_idle = base->ahb_MaxIdleConnections;
    if (max_idle == 0) {
        max_idle = HT_POOL_MAX_IDLE;
    }
    now = ht_current_seconds();
    conn->hc_LastUsed = now;
    ObtainSemaphore(&base->ahb_PoolSema);
    count = 0;
    for (node = (struct HtConnection *)base->ahb_PoolList.lh_Head;
         node != NULL && node->hc_Node.ln_Succ != NULL;
         node = (struct HtConnection *)node->hc_Node.ln_Succ) {
        if (!node->hc_InUse) {
            count++;
        }
    }
    if (count >= max_idle) {
        ReleaseSemaphore(&base->ahb_PoolSema);
        ht_connection_free(base, conn);
        return;
    }
    AddTail(&base->ahb_PoolList, &conn->hc_Node);
    ReleaseSemaphore(&base->ahb_PoolSema);
}

VOID
ht_pool_flush(struct AmiHttpBase *base)
{
    struct HtConnection *conn;
    struct HtConnection *next;

    if (base == NULL) {
        return;
    }
    ObtainSemaphore(&base->ahb_PoolSema);
    for (conn = (struct HtConnection *)base->ahb_PoolList.lh_Head;
         conn != NULL && conn->hc_Node.ln_Succ != NULL;
         conn = next) {
        next = (struct HtConnection *)conn->hc_Node.ln_Succ;
        Remove(&conn->hc_Node);
        ht_connection_free(base, conn);
    }
    ReleaseSemaphore(&base->ahb_PoolSema);
}

VOID
ht_pool_shutdown(struct AmiHttpBase *base)
{
    struct HtConnection *conn;
    struct HtConnection *next;

    if (base == NULL) {
        return;
    }
    ObtainSemaphore(&base->ahb_PoolSema);
    for (conn = (struct HtConnection *)base->ahb_PoolList.lh_Head;
         conn != NULL && conn->hc_Node.ln_Succ != NULL;
         conn = next) {
        next = (struct HtConnection *)conn->hc_Node.ln_Succ;
        Remove(&conn->hc_Node);
        ht_connection_free(base, conn);
    }
    ReleaseSemaphore(&base->ahb_PoolSema);
    ht_transport_task_bsd_shutdown(base);
    ht_transport_task_ssl_shutdown(base);
    ht_transport_global_shutdown(base);
    ht_timer_shutdown();
}
