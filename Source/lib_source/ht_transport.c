/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_transport.c - TCP via bsdsocket
 *
 * bsdsocket.library is opened per Exec task (many stacks are task-affine).
 * AWeb retrieve subprocesses bind an Opentcp() handle via HTBT_TASK_SOCKETBASE;
 * standalone clients (AGet) lazily open a handle on first I/O.
 *
 * Socket I/O uses SAS/C stubs with a local parameter named SocketBase (same
 * pattern as awebamitcp.c) so parallel Httptasks do not serialize on
 * ahb_SocketSema.  That sema is only for non-reentrant gethostbyname.
 *
 * --- TLS connect path: DO NOT CHANGE (verified AGet HTTPS, Jun 2026) ---
 *
 * ht_transport_connect(ssl): wrap TlsTaskAttach + TlsAttachSocket in
 * ht_io_obtain()/ht_io_release() so SocketBase matches this task's handle.
 * Do not skip that pair or replace ht_io_obtain with non-blocking sema
 * attempts only — attach without a bound task regressed 8704.
 *
 * Do not apply SO_RCVTIMEO/SO_SNDTIMEO to the fd before TLS handshake completes
 * (see ht_transport_apply_io_timeouts comment).  Do not FIONBIO the TLS fd at
 * connect; blocking TCP + deferred TlsWrite matches ATlsTest.
 *
 * ht_transport_send(TLS): do not wrap ht_ssl_send in ahb_SocketSema; parallel
 * Httptask subprocesses would serialize and appear deadlocked.  amitls snapshots
 * per-connection SocketBase after TlsTaskAttach.
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/semaphores.h>
#include <exec/lists.h>
#include <exec/tasks.h>

#include <utility/tagitem.h>

#include <proto/exec.h>
#include <proto/alib.h>

extern struct Library *SocketBase;
extern int errno;
extern int h_errno;

#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

/* Forward decls: defined later; used from apply_timeouts before their bodies. */
static LONG ht_sb_socket(struct Library *SocketBase, LONG domain, LONG type,
    LONG proto);
static LONG ht_sb_close(struct Library *SocketBase, LONG sock);
static LONG ht_sb_connect(struct Library *SocketBase, LONG sock,
    struct sockaddr *sa, LONG len);
static LONG ht_sb_send(struct Library *SocketBase, LONG sock, char *buf,
    LONG len, LONG flags);
static LONG ht_sb_recv(struct Library *SocketBase, LONG sock, char *buf,
    LONG len, LONG flags);
static LONG ht_sb_setsockopt(struct Library *SocketBase, LONG sock, LONG level,
    LONG optname, char *optval, LONG optlen);
static LONG ht_task_bsd_activate(struct AmiHttpBase *base);
static struct hostent *ht_sb_gethostbyname_r(struct Library *SocketBase,
    char *host, struct hostent *he, char *buf, ULONG buflen, LONG *herr);
static struct hostent *ht_sb_gethostbyname(struct Library *SocketBase,
    char *host);

#include <libraries/bsdsocket.h>
#include <proto/bsdsocket.h>

#include "private/amihttpbase.h"
#include <libraries/amihttp.h>

#include "private/ht_debug.h"
#include "private/ht_internal.h"

#define HT_HOSTENT_BUF  1024

/*
 * SO_RCVTIMEO / SO_SNDTIMEO on bsdsocket.library bound each blocking
 * connect/send/recv (and AmiSSL I/O on the fd).  Without this, a hung
 * peer holds an AWeb netslot until the user cancels from net status.
 */
static VOID
ht_transport_apply_timeouts(struct AmiHttpBase *base, LONG sock, ULONG secs)
{
    struct timeval tv;
    LONG tlen;
    LONG rc;
    struct Library *SocketBase;

    if (base == NULL || sock < 0) {
        return;
    }
    if (secs == 0) {
        secs = HT_SOCKET_IO_TIMEOUT;
    }
    rc = ht_task_bsd_activate(base);
    if (rc != 0) {
        return;
    }
    SocketBase = ht_task_current_socket_base(base);
    if (SocketBase == NULL) {
        return;
    }
    tv.tv_sec = (long)secs;
    tv.tv_usec = 0;
    tlen = (LONG)sizeof(tv);
    ht_sb_setsockopt(SocketBase, sock, SOL_SOCKET, SO_RCVTIMEO,
        (char *)&tv, tlen);
    ht_sb_setsockopt(SocketBase, sock, SOL_SOCKET, SO_SNDTIMEO,
        (char *)&tv, tlen);
}

/*
 * Per-operation SO_RCVTIMEO/SO_SNDTIMEO (15s default).  For TLS, call only
 * after the deferred handshake completes on the first TlsWrite — same rule
 * as classic AWeb http.c Connect() and ATlsTest (no rcv timeout during HS).
 */
VOID
ht_transport_apply_io_timeouts(struct AmiHttpBase *base, struct HtConnection *conn)
{
    if (conn == NULL || conn->hc_Sock < 0) {
        return;
    }
    ht_transport_apply_timeouts(base, conn->hc_Sock, HT_SOCKET_IO_TIMEOUT);
}

static VOID
ht_transport_clear_io_timeouts(struct AmiHttpBase *base, LONG sock)
{
    struct timeval tv;
    LONG tlen;
    LONG rc;
    struct Library *SocketBase;

    if (base == NULL || sock < 0) {
        return;
    }
    rc = ht_task_bsd_activate(base);
    if (rc != 0) {
        return;
    }
    SocketBase = ht_task_current_socket_base(base);
    if (SocketBase == NULL) {
        return;
    }
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    tlen = (LONG)sizeof(tv);
    ht_sb_setsockopt(SocketBase, sock, SOL_SOCKET, SO_RCVTIMEO,
        (char *)&tv, tlen);
    ht_sb_setsockopt(SocketBase, sock, SOL_SOCKET, SO_SNDTIMEO,
        (char *)&tv, tlen);
}

static BOOL ht_has_gethost_r;

struct HtTaskBsd
{
    struct Node     tb_Node;
    struct Task    *tb_Task;
    ULONG           tb_RefCount;
    struct Library *tb_SocketBase;
    int             tb_Errno;
    BOOL            tb_Owned;
};

static struct List ht_task_bsd_list;
static struct SignalSemaphore ht_task_bsd_sema;
static BOOL ht_task_bsd_inited = FALSE;
static struct HtTaskBsd *ht_active_task_bsd = NULL;

static VOID
ht_task_bsd_list_init(VOID)
{
    if (!ht_task_bsd_inited) {
        NewList(&ht_task_bsd_list);
        InitSemaphore(&ht_task_bsd_sema);
        ht_task_bsd_inited = TRUE;
    }
}

static struct HtTaskBsd *
ht_task_bsd_find_locked(struct Task *task)
{
    struct HtTaskBsd *tb;

    for (tb = (struct HtTaskBsd *)ht_task_bsd_list.lh_Head;
         tb != NULL && tb->tb_Node.ln_Succ != NULL;
         tb = (struct HtTaskBsd *)tb->tb_Node.ln_Succ) {
        if (tb->tb_Task == task) {
            return tb;
        }
    }
    return NULL;
}

static VOID
ht_sync_io_bases(struct AmiHttpBase *base, struct HtTaskBsd *tb)
{
    ht_sync_proto_bases(base);
    if (tb != NULL && tb->tb_SocketBase != NULL) {
        SocketBase = tb->tb_SocketBase;
        if (base != NULL) {
            base->ahb_SocketBase = tb->tb_SocketBase;
        }
    }
}

static VOID
ht_task_bsd_configure(struct HtTaskBsd *tb)
{
    struct TagItem tags[3];
    struct Library *SocketBase;

    if (tb == NULL || tb->tb_SocketBase == NULL) {
        return;
    }
    SocketBase = tb->tb_SocketBase;
    tags[0].ti_Tag = SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(errno)));
    tags[0].ti_Data = (ULONG)&tb->tb_Errno;
    tags[1].ti_Tag = SBTM_SETVAL(SBTC_HERRNOLONGPTR);
    tags[1].ti_Data = (ULONG)&h_errno;
    tags[2].ti_Tag = TAG_END;
    SocketBaseTagList(tags);
    tb->tb_Errno = 0;
    h_errno = 0;
}

static LONG
ht_task_bsd_open_owned(struct HtTaskBsd *tb)
{
    struct Library *SocketBase;

    if (tb == NULL) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    tb->tb_SocketBase = OpenLibrary("bsdsocket.library", 4);
    if (tb->tb_SocketBase == NULL) {
        htDbgPut("ht_task_bsd_open_owned failed");
        return ERROR_HTTP_CONNECT_FAILED;
    }
    tb->tb_Owned = TRUE;
    SocketBase = tb->tb_SocketBase;
    ht_task_bsd_configure(tb);
    htDbgPutHex("ht_task_bsd_open_owned ok=", (ULONG)tb->tb_SocketBase);
    return 0;
}

static VOID
ht_socket_probe_api(struct Library *SocketBase)
{
    struct TagItem tags[2];
    ULONG have_r;

    if (ht_has_gethost_r || SocketBase == NULL) {
        return;
    }
    have_r = 0;
    tags[0].ti_Tag = SBTM_GETVAL(SBTC_HAVE_GETHOSTADDR_R_API);
    tags[0].ti_Data = (ULONG)&have_r;
    tags[1].ti_Tag = TAG_END;
    SocketBaseTagList(tags);
    ht_has_gethost_r = (BOOL)(have_r != 0);
}

static LONG
ht_task_bsd_activate(struct AmiHttpBase *base)
{
    struct HtTaskBsd *tb;
    struct Task *task;
    LONG rc;

    if (base == NULL) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    ht_task_bsd_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_bsd_sema);
    tb = ht_task_bsd_find_locked(task);
    if (tb == NULL) {
        tb = (struct HtTaskBsd *)ht_alloc(sizeof(struct HtTaskBsd), MEMF_CLEAR);
        if (tb == NULL) {
            ReleaseSemaphore(&ht_task_bsd_sema);
            return ERROR_HTTP_OUT_OF_MEMORY;
        }
        tb->tb_Task = task;
        tb->tb_RefCount = 0;
        tb->tb_Owned = TRUE;
        AddHead(&ht_task_bsd_list, &tb->tb_Node);
        ReleaseSemaphore(&ht_task_bsd_sema);
        rc = ht_task_bsd_open_owned(tb);
        if (rc != 0) {
            ObtainSemaphore(&ht_task_bsd_sema);
            Remove(&tb->tb_Node);
            ReleaseSemaphore(&ht_task_bsd_sema);
            ht_free(tb);
            return rc;
        }
        ObtainSemaphore(&ht_task_bsd_sema);
    }
    ht_active_task_bsd = tb;
    ht_sync_io_bases(base, tb);
    ht_socket_probe_api(tb->tb_SocketBase);
    ReleaseSemaphore(&ht_task_bsd_sema);
    return 0;
}

APTR
ht_task_errno_ptr(struct AmiHttpBase *base)
{
    struct HtTaskBsd *tb;
    struct Task *task;

    ht_task_bsd_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_bsd_sema);
    tb = ht_task_bsd_find_locked(task);
    ReleaseSemaphore(&ht_task_bsd_sema);
    if (tb != NULL) {
        return (APTR)&tb->tb_Errno;
    }
    if (base != NULL && base->ahb_ErrnoPtr != NULL) {
        return base->ahb_ErrnoPtr;
    }
    return (APTR)&errno;
}

/*
 * Per Exec task bsdsocket handle (HTBT_TASK_SOCKETBASE).  Do not use
 * AmiHttpBase->ahb_SocketBase for TlsTaskAttach: concurrent AWeb fetches
 * overwrite that global when another subprocess binds its Opentcp() handle.
 */
struct Library *
ht_task_current_socket_base(struct AmiHttpBase *base)
{
    struct HtTaskBsd *tb;
    struct Task *task;

    ht_task_bsd_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_bsd_sema);
    tb = ht_task_bsd_find_locked(task);
    ReleaseSemaphore(&ht_task_bsd_sema);
    if (tb != NULL && tb->tb_SocketBase != NULL) {
        return tb->tb_SocketBase;
    }
    if (base != NULL) {
        return base->ahb_SocketBase;
    }
    return NULL;
}

LONG
ht_transport_task_bsd_bind(struct AmiHttpBase *base, struct Library *socketbase)
{
    struct HtTaskBsd *tb;
    struct Task *task;

    if (base == NULL || socketbase == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    ht_task_bsd_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_bsd_sema);
    tb = ht_task_bsd_find_locked(task);
    if (tb != NULL) {
        tb->tb_SocketBase = socketbase;
        tb->tb_RefCount++;
        ReleaseSemaphore(&ht_task_bsd_sema);
        /* Configure on this handle only; globals sync in ht_io_obtain(). */
        SocketBase = socketbase;
        ht_task_bsd_configure(tb);
        return 0;
    }
    tb = (struct HtTaskBsd *)ht_alloc(sizeof(struct HtTaskBsd), MEMF_CLEAR);
    if (tb == NULL) {
        ReleaseSemaphore(&ht_task_bsd_sema);
        return ERROR_HTTP_OUT_OF_MEMORY;
    }
    tb->tb_Task = task;
    tb->tb_RefCount = 1;
    tb->tb_SocketBase = socketbase;
    tb->tb_Owned = FALSE;
    AddHead(&ht_task_bsd_list, &tb->tb_Node);
    ReleaseSemaphore(&ht_task_bsd_sema);
    SocketBase = socketbase;
    ht_task_bsd_configure(tb);
    ObtainSemaphore(&base->ahb_SocketSema);
    ht_socket_probe_api(socketbase);
    ReleaseSemaphore(&base->ahb_SocketSema);
    return 0;
}

VOID
ht_bsd_release_task(struct AmiHttpBase *base)
{
    struct HtTaskBsd *tb;
    struct Task *task;
    struct Library *sock;
    BOOL owned;

    if (base == NULL) {
        return;
    }
    ht_task_bsd_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_bsd_sema);
    tb = ht_task_bsd_find_locked(task);
    if (tb == NULL) {
        ReleaseSemaphore(&ht_task_bsd_sema);
        return;
    }
    if (tb->tb_RefCount > 0) {
        tb->tb_RefCount--;
    }
    if (tb->tb_RefCount > 0) {
        ReleaseSemaphore(&ht_task_bsd_sema);
        return;
    }
    if (tb->tb_RefCount == 0 && tb->tb_Owned) {
        /* Lazy-owned entry: keep until library shutdown. */
        ReleaseSemaphore(&ht_task_bsd_sema);
        return;
    }
    sock = tb->tb_SocketBase;
    owned = tb->tb_Owned;
    Remove(&tb->tb_Node);
    ReleaseSemaphore(&ht_task_bsd_sema);
    if (owned && sock != NULL) {
        CloseLibrary(sock);
    }
    ht_free(tb);
}

VOID
ht_transport_task_bsd_shutdown(struct AmiHttpBase *base)
{
    struct HtTaskBsd *tb;
    struct HtTaskBsd *next;
    struct Library *sock;
    struct Task *self;
    BOOL owned;
    BOOL same_task;

    ht_task_bsd_list_init();
    self = FindTask(NULL);
    ObtainSemaphore(&ht_task_bsd_sema);
    for (tb = (struct HtTaskBsd *)ht_task_bsd_list.lh_Head;
         tb != NULL && tb->tb_Node.ln_Succ != NULL;
         tb = next) {
        next = (struct HtTaskBsd *)tb->tb_Node.ln_Succ;
        sock = tb->tb_SocketBase;
        owned = tb->tb_Owned;
        same_task = (BOOL)(tb->tb_Task == self);
        Remove(&tb->tb_Node);
        ReleaseSemaphore(&ht_task_bsd_sema);
        /*
         * AmiTCP/Roadshow: CloseLibrary(bsdsocket) must run on the same Exec
         * task that opened it.  AWeb Httptask subprocesses open their own
         * handles; closing them from the main task on exit crashes.  Dead
         * tasks' sockets are reclaimed with the process — leak the Library *.
         */
        if (owned && sock != NULL && same_task) {
            CloseLibrary(sock);
        }
        ht_free(tb);
        ObtainSemaphore(&ht_task_bsd_sema);
    }
    ReleaseSemaphore(&ht_task_bsd_sema);
    if (base != NULL) {
        base->ahb_SocketBase = NULL;
        base->ahb_SocketConfigured = FALSE;
    }
}

VOID
ht_io_release(struct AmiHttpBase *base)
{
    (void)base;
    ht_active_task_bsd = NULL;
}

/*
 * WaitSelect on this task's bsdsocket.  Local SocketBase feeds SAS/C
 * #pragma libcall A6 (awebamitcp.c pattern) so parallel Httptasks do not
 * serialize on ahb_SocketSema / one global base.
 * Do NOT pass HTBT_BREAKMASK — it wedges WaitSelect on several stacks.
 */
LONG
ht_wait_select(struct AmiHttpBase *base, int nfds,
    void *readfds, void *writefds, void *exceptfds,
    struct timeval *timeout)
{
    struct Library *SocketBase;

    SocketBase = ht_task_current_socket_base(base);
    if (SocketBase == NULL) {
        return -1;
    }
    return WaitSelect(nfds, (fd_set *)readfds, (fd_set *)writefds,
        (fd_set *)exceptfds, timeout, NULL);
}

static APTR
ht_errno_slot(struct AmiHttpBase *base)
{
    APTR errp;

    errp = ht_task_errno_ptr(base);
    if (errp != (APTR)&errno) {
        return errp;
    }
    if (base != NULL && base->ahb_ErrnoPtr != NULL) {
        return base->ahb_ErrnoPtr;
    }
    if (base != NULL) {
        return (APTR)&base->ahb_SocketErrno;
    }
    return (APTR)&errno;
}

/*
 * Ensure per-task bsdsocket is open.  Does NOT hold ahb_SocketSema — holding
 * it across connect/WaitSelect serialized AWeb image fetches (Aminet 8/8
 * queue stall, 8706 storms).
 */
LONG
ht_io_obtain(struct AmiHttpBase *base)
{
    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    return ht_task_bsd_activate(base);
}

/* Parameter name SocketBase is required for SAS/C bsdsocket pragmas (A6). */
static LONG
ht_sb_socket(struct Library *SocketBase, LONG domain, LONG type, LONG proto)
{
    return (LONG)socket((int)domain, (int)type, (int)proto);
}

static LONG
ht_sb_close(struct Library *SocketBase, LONG sock)
{
    return (LONG)CloseSocket((int)sock);
}

static LONG
ht_sb_connect(struct Library *SocketBase, LONG sock,
    struct sockaddr *sa, LONG len)
{
    return (LONG)connect((int)sock, sa, (int)len);
}

static LONG
ht_sb_send(struct Library *SocketBase, LONG sock, char *buf, LONG len, LONG flags)
{
    return (LONG)send((int)sock, buf, (int)len, (int)flags);
}

static LONG
ht_sb_recv(struct Library *SocketBase, LONG sock, char *buf, LONG len, LONG flags)
{
    return (LONG)recv((int)sock, buf, (int)len, (int)flags);
}

static LONG
ht_sb_setsockopt(struct Library *SocketBase, LONG sock, LONG level, LONG optname,
    char *optval, LONG optlen)
{
    return (LONG)setsockopt((int)sock, (int)level, (int)optname, optval,
        (int)optlen);
}

static struct hostent *
ht_sb_gethostbyname_r(struct Library *SocketBase, char *host,
    struct hostent *he, char *buf, ULONG buflen, LONG *herr)
{
    return gethostbyname_r(host, he, buf, buflen, herr);
}

static struct hostent *
ht_sb_gethostbyname(struct Library *SocketBase, char *host)
{
    return gethostbyname(host);
}

static LONG
ht_socket_get_errno(struct AmiHttpBase *base)
{
    APTR errp;

    errp = ht_errno_slot(base);
    if (errp == (APTR)&errno) {
        return (LONG)errno;
    }
    return (LONG)(*(int *)errp);
}

static VOID
ht_socket_clear_errno(struct AmiHttpBase *base)
{
    APTR errp;

    errp = ht_errno_slot(base);
    if (errp == (APTR)&errno) {
        errno = 0;
    } else {
        *(int *)errp = 0;
    }
    h_errno = 0;
}

/*
 * Legacy single-base open (unused after per-task transport; kept for callers).
 */
LONG
ht_bsd_open(struct AmiHttpBase *base)
{
    if (base == NULL) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    return ht_task_bsd_activate(base);
}

VOID
ht_bsd_close(struct AmiHttpBase *base)
{
    ht_transport_task_bsd_shutdown(base);
}

VOID
ht_bsd_set_errno_ptr(struct AmiHttpBase *base)
{
    struct HtTaskBsd *tb;
    struct Task *task;

    if (base == NULL) {
        return;
    }
    ht_task_bsd_list_init();
    task = FindTask(NULL);
    ObtainSemaphore(&ht_task_bsd_sema);
    tb = ht_task_bsd_find_locked(task);
    if (tb != NULL && tb->tb_SocketBase != NULL) {
        ht_active_task_bsd = tb;
        ht_sync_io_bases(base, tb);
        ht_task_bsd_configure(tb);
        ht_active_task_bsd = NULL;
    }
    ReleaseSemaphore(&ht_task_bsd_sema);
}

VOID
ht_transport_bind_socket(struct AmiHttpBase *base)
{
    /* Sync globals to this task's bsdsocket; pair with ht_io_obtain for I/O. */
    if (base != NULL) {
        (VOID)ht_task_bsd_activate(base);
    }
}

LONG
ht_ensure_bsdsocket(struct AmiHttpBase *base)
{
    return ht_task_bsd_activate(base);
}

static LONG
ht_socket_stream(struct AmiHttpBase *base)
{
    LONG sock;
    LONG fd;
    LONG rc;
    struct Library *SocketBase;

    rc = ht_task_bsd_activate(base);
    if (rc != 0) {
        return rc;
    }
    SocketBase = ht_task_current_socket_base(base);
    if (SocketBase == NULL) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    sock = ht_sb_socket(SocketBase, AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return sock;
    }
    if (sock == 0) {
        fd = ht_sb_socket(SocketBase, AF_INET, SOCK_STREAM, 0);
        ht_sb_close(SocketBase, sock);
        if (fd < 0) {
            return fd;
        }
        sock = fd;
    }
    return sock;
}

static struct hostent *
ht_lookup_host_ipv4(struct AmiHttpBase *base, STRPTR host, struct hostent *he,
    char *hbuf, LONG *herr_out)
{
    struct hostent *hent;
    LONG rc;
    char *ap;
    char **alist;
    struct Library *SocketBase;

    if (host == NULL || host[0] == '\0' || he == NULL || hbuf == NULL) {
        return NULL;
    }
    rc = ht_task_bsd_activate(base);
    if (rc != 0) {
        return NULL;
    }
    SocketBase = ht_task_current_socket_base(base);
    if (SocketBase == NULL) {
        return NULL;
    }
    /*
     * DNS under ahb_SocketSema with this task's SocketBase in A6.  Parallel
     * lookups without the base caused mass 8701 on Aminet image bursts.
     */
    ObtainSemaphore(&base->ahb_SocketSema);
    hent = NULL;
    if (ht_has_gethost_r) {
        if (herr_out != NULL) {
            *herr_out = 0;
        }
        hent = ht_sb_gethostbyname_r(SocketBase, (char *)host, he, hbuf,
            (ULONG)HT_HOSTENT_BUF, herr_out);
        if (hent == NULL || hent->h_addr_list == NULL ||
            hent->h_addr_list[0] == NULL || hent->h_addrtype != AF_INET) {
            hent = NULL;
        }
    } else {
        hent = ht_sb_gethostbyname(SocketBase, (char *)host);
        if (hent == NULL || hent->h_addr_list == NULL ||
            hent->h_addr_list[0] == NULL || hent->h_addrtype != AF_INET ||
            hent->h_length <= 0 || hent->h_length > 16) {
            hent = NULL;
        } else {
            ap = hbuf;
            CopyMem(hent->h_addr_list[0], ap, (ULONG)hent->h_length);
            he->h_name = NULL;
            he->h_aliases = NULL;
            he->h_addrtype = AF_INET;
            he->h_length = hent->h_length;
            alist = (char **)(hbuf + 16);
            alist[0] = ap;
            alist[1] = NULL;
            he->h_addr_list = alist;
            hent = he;
        }
    }
    ReleaseSemaphore(&base->ahb_SocketSema);
    return hent;
}

/*
 * Blocking TCP connect (matches AWeb http.c / amitcp_connect).  Non-blocking
 * connect + WaitSelect + SO_ERROR is unreliable on bsdsocket.library and
 * produced spurious 8702 on hosts such as www.amiga.com while the bare name
 * on the same IP succeeded.
 */
static LONG
ht_tcp_connect(struct AmiHttpBase *base, LONG sock, struct hostent *hent,
    ULONG port, ULONG timeout_secs)
{
    struct sockaddr_in sad;
    LONG result;
    LONG rc;
    struct Library *SocketBase;

    (void)timeout_secs;

    if (hent == NULL || hent->h_addr_list == NULL ||
        hent->h_addr_list[0] == NULL || hent->h_addrtype != AF_INET) {
        return ERROR_HTTP_DNS_FAILED;
    }
    sad.sin_len = sizeof(sad);
    sad.sin_family = AF_INET;
    sad.sin_port = htons((UWORD)port);
    CopyMem(hent->h_addr_list[0], (APTR)&sad.sin_addr, (ULONG)hent->h_length);

    rc = ht_task_bsd_activate(base);
    if (rc != 0) {
        return rc;
    }
    SocketBase = ht_task_current_socket_base(base);
    if (SocketBase == NULL) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    ht_socket_clear_errno(base);
    /* Blocking connect on this task's SocketBase — no ahb_SocketSema. */
    result = ht_sb_connect(SocketBase, sock, (struct sockaddr *)&sad,
        (LONG)sizeof(sad));
    if (result == 0) {
        return 0;
    }
    return ERROR_HTTP_CONNECT_FAILED;
}

static VOID
ht_transport_close_socket(struct AmiHttpBase *base, LONG sock,
    struct Library *sockbase)
{
    struct linger lg;
    LONG lglen;
    struct Library *SocketBase;

    if (sock < 0) {
        return;
    }
    /*
     * Prefer the creating task's bsdsocket handle.  Pool flush / CloseLib run
     * on AWeb's main task; CloseSocket must still target the Library that
     * issued the fd (AmiTCP is per-task).
     */
    SocketBase = sockbase;
    if (SocketBase == NULL) {
        if (ht_task_bsd_activate(base) != 0) {
            return;
        }
        SocketBase = ht_task_current_socket_base(base);
    }
    if (SocketBase == NULL) {
        return;
    }
    lg.l_onoff = 1;
    lg.l_linger = 0;
    lglen = (LONG)sizeof(lg);
    ht_sb_setsockopt(SocketBase, sock, SOL_SOCKET, SO_LINGER,
        (char *)&lg, lglen);
    ht_sb_close(SocketBase, sock);
}

LONG
ht_transport_connect(struct AmiHttpBase *base, struct HtConnection *conn,
    STRPTR host, ULONG port, BOOL ssl, ULONG timeout_secs, ULONG ssl_verify,
    STRPTR ca_bundle_path)
{
    struct hostent he;
    struct hostent *hent;
    char hbuf[HT_HOSTENT_BUF];
    LONG herr;
    LONG sock;
    LONG rc;

    if (base == NULL || conn == NULL || host == NULL || host[0] == '\0') {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (port == 0) {
        port = ssl ? 443UL : 80UL;
    }
    htDbgPut("ht_transport_connect");
    rc = ht_ensure_bsdsocket(base);
    if (rc != 0) {
        return rc;
    }
    ht_active_task_bsd = NULL;
    htDbgPut("ht_transport_connect lookup");
    herr = 0;
    hent = ht_lookup_host_ipv4(base, host, &he, hbuf, &herr);
    if (hent == NULL) {
        return ERROR_HTTP_DNS_FAILED;
    }
    sock = ht_socket_stream(base);
    if (sock < 0) {
        return ERROR_HTTP_CONNECT_FAILED;
    }
    if (timeout_secs == 0) {
        timeout_secs = base->ahb_DefaultTimeout;
    }
    if (timeout_secs == 0) {
        timeout_secs = 60;
    }
    if (!ssl) {
        ht_transport_apply_timeouts(base, sock, timeout_secs);
    }
    rc = ht_tcp_connect(base, sock, hent, port, timeout_secs);
    if (rc != 0) {
        ht_transport_close_socket(base, sock, ht_task_current_socket_base(base));
        return rc;
    }
    /*
     * Do not touch SO_RCVTIMEO/SO_SNDTIMEO for TLS before the handshake
     * completes (classic AWeb http.c).  {0,0} is not "infinite" on every
     * bsdsocket stack and breaks BearSSL recv during ClientHello exchange.
     */
    if (!ssl) {
        ht_transport_apply_timeouts(base, sock, HT_SOCKET_IO_TIMEOUT);
    }

    conn->hc_Sock = sock;
    conn->hc_SocketBase = ht_task_current_socket_base(base);
    conn->hc_IsSsl = ssl;
    conn->hc_Port = port;
    if (conn->hc_Host) {
        ht_free(conn->hc_Host);
    }
    conn->hc_Host = ht_strdup(host);

    if (ssl) {
        /*
         * TlsTaskAttach + TlsAttachSocket must run under ht_io_obtain (see file
         * header).  Handshake is deferred to ht_transport_send -> ht_ssl_send.
         */
        rc = ht_io_obtain(base);
        if (rc != 0) {
            ht_transport_disconnect(base, conn);
            return rc;
        }
        rc = ht_transport_task_ssl_ensure(base);
        if (rc != 0) {
            ht_io_release(base);
            ht_transport_disconnect(base, conn);
            return rc;
        }
        conn->hc_SslTaskHeld = TRUE;
        conn->hc_SslCtx = ht_ssl_create(host, ca_bundle_path);
        if (conn->hc_SslCtx == NULL) {
            ht_io_release(base);
            ht_transport_disconnect(base, conn);
            return ERROR_HTTP_OUT_OF_MEMORY;
        }
        rc = ht_ssl_attach_socket(base, conn->hc_SslCtx, sock, host, ssl_verify,
            timeout_secs, NULL);
        ht_io_release(base);
        if (rc != 0) {
            ht_transport_disconnect(base, conn);
            return rc;
        }
    } else {
        ht_transport_apply_timeouts(base, conn->hc_Sock, HT_SOCKET_IO_TIMEOUT);
    }
    return 0;
}

VOID
ht_transport_disconnect(struct AmiHttpBase *base, struct HtConnection *conn)
{
    if (conn == NULL) {
        return;
    }
    if (conn->hc_SslCtx != NULL) {
        ht_ssl_destroy(conn->hc_SslCtx);
        conn->hc_SslCtx = NULL;
    }
    if (conn->hc_SslTaskHeld) {
        if (base != NULL) {
            ht_transport_task_ssl_release(base);
        }
        conn->hc_SslTaskHeld = FALSE;
    }
    if (conn->hc_Sock >= 0) {
        ht_transport_close_socket(base, conn->hc_Sock, conn->hc_SocketBase);
        conn->hc_Sock = -1;
    }
    conn->hc_SocketBase = NULL;
    conn->hc_IoLen = 0;
    conn->hc_IoPos = 0;
}

LONG
ht_transport_send(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR data, ULONG len)
{
    LONG sent;
    LONG total;
    LONG n;
    LONG rc;
    struct Library *SocketBase;

    if (base == NULL || conn == NULL || data == NULL || len == 0) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    if (conn->hc_Sock < 0) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    total = 0;
    /*
     * TLS write/handshake may block for seconds with no socket timeout.
     * Do not hold ahb_SocketSema across ht_ssl_send: parallel AWeb Httptask
     * subprocesses would serialize on ObtainSemaphore and appear deadlocked.
     * Per-task bsdsocket + amitls tc_SocketBase snapshots are safe without it.
     */
    if (conn->hc_SslCtx != NULL) {
        while ((ULONG)total < len) {
            n = ht_ssl_send(conn->hc_SslCtx, (UBYTE *)data + total,
                len - (ULONG)total);
            if (n >= (LONG)ERROR_HTTP_NOT_IMPLEMENTED) {
                return n;
            }
            if (n <= 0) {
                return ERROR_HTTP_WRITE_FAILED;
            }
            total += n;
        }
        return total;
    }
    SocketBase = conn->hc_SocketBase;
    if (SocketBase == NULL) {
        rc = ht_task_bsd_activate(base);
        if (rc != 0) {
            return rc;
        }
        SocketBase = ht_task_current_socket_base(base);
    }
    if (SocketBase == NULL) {
        return ERROR_HTTP_WRITE_FAILED;
    }
    while ((ULONG)total < len) {
        n = ht_sb_send(SocketBase, conn->hc_Sock, (char *)data + total,
            (LONG)(len - (ULONG)total), 0);
        if (n <= 0) {
            return ERROR_HTTP_WRITE_FAILED;
        }
        total += n;
    }
    sent = total;
    return sent;
}

static LONG
ht_transport_raw_recv(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR buf, ULONG len, ULONG timeout_secs)
{
    fd_set rfds;
    struct timeval tv;
    LONG nfds;
    LONG rc;
    LONG n;
    struct Library *SocketBase;

    SocketBase = conn->hc_SocketBase;
    if (SocketBase == NULL) {
        rc = ht_task_bsd_activate(base);
        if (rc != 0) {
            return -(LONG)rc;
        }
        SocketBase = ht_task_current_socket_base(base);
    }
    if (SocketBase == NULL) {
        return -(LONG)ERROR_HTTP_INVALID_HANDLE;
    }

    if (timeout_secs > 0) {
        FD_ZERO(&rfds);
        FD_SET((int)conn->hc_Sock, &rfds);
        nfds = conn->hc_Sock + 1;
        tv.tv_sec = (long)timeout_secs;
        tv.tv_usec = 0;
        /* WaitSelect via ht_wait_select (task SocketBase, no socket sema). */
        rc = ht_wait_select(base, (int)nfds, &rfds, NULL, NULL, &tv);
        if (rc <= 0) {
            return -(LONG)ERROR_HTTP_READ_TIMEOUT;
        }
    }
    n = ht_sb_recv(SocketBase, conn->hc_Sock, (char *)buf, (LONG)len, 0);
    if (n < 0) {
        return -(LONG)ERROR_HTTP_READ_FAILED;
    }
    if ((ULONG)n > len) {
        n = (LONG)len;
    }
    return n;
}

LONG
ht_transport_recv(struct AmiHttpBase *base, struct HtConnection *conn,
    APTR buf, ULONG len, ULONG timeout_secs)
{
    LONG n;

    if (base == NULL || conn == NULL || buf == NULL || len == 0) {
        return -(LONG)ERROR_HTTP_INVALID_HANDLE;
    }
    if (conn->hc_Sock < 0) {
        return -(LONG)ERROR_HTTP_INVALID_HANDLE;
    }
    if (conn->hc_SslCtx != NULL) {
        n = ht_ssl_recv(base, conn->hc_SslCtx, conn->hc_Sock, buf, len,
            timeout_secs);
        return n;
    }
    return ht_transport_raw_recv(base, conn, buf, len, timeout_secs);
}

BOOL
ht_transport_conn_idle(struct AmiHttpBase *base, struct HtConnection *conn)
{
    fd_set rfds;
    fd_set efds;
    struct timeval tv;
    LONG nfds;
    LONG rc;
    struct Library *SocketBase;

    if (conn == NULL || conn->hc_Sock < 0) {
        return TRUE;
    }
    if (conn->hc_SslCtx != NULL && !ht_ssl_idle(conn->hc_SslCtx)) {
        return FALSE;
    }
    FD_ZERO(&rfds);
    FD_ZERO(&efds);
    FD_SET((int)conn->hc_Sock, &rfds);
    FD_SET((int)conn->hc_Sock, &efds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    nfds = conn->hc_Sock + 1;
    SocketBase = conn->hc_SocketBase;
    if (SocketBase == NULL) {
        if (ht_task_bsd_activate(base) != 0) {
            return FALSE;
        }
        SocketBase = ht_task_current_socket_base(base);
    }
    if (SocketBase == NULL) {
        return FALSE;
    }
    rc = WaitSelect((int)nfds, &rfds, NULL, &efds, &tv, NULL);
    if (rc != 0) {
        return FALSE;
    }
    return TRUE;
}