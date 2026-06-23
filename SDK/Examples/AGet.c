/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * AGet.c - wget-style HTTP/HTTPS client for AmigaOS (amihttp.library).
 *
 * ReadArgs template (must match ag_usage_msg):
 *   URL,TO/K,USERAGENT/K,HEAD/S,NOREDIR/S,ASYNC/S,VERBOSE/S,QUIET/S,
 *   TEST/S,COOKIEFILE/K,HEADERS/S,HEADER/K/M
 *
 * Output routing (AmigaDOS):
 *   - Response body  -> stdout, or TO/K file when given
 *   - Status/errors  -> stderr (ErrorOutput), never mixed into body stream
 *
 * Modes (QUIET and VERBOSE are mutually exclusive; TEST implies VERBOSE):
 *   Default  - one-line HTTP status on stderr; TLS cert summary for https;
 *              body to stdout or TO/K
 *   QUIET/S  - body (or TO file) only; stderr used for errors only
 *   HEADERS/S- request/response header dump on stderr (no API trace)
 *   VERBOSE/S- step-by-step amihttp API trace on stderr
 *   TEST/S   - offline amihttp API self-test (no network); URL/K ignored
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/lists.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include <proto/dos.h>
#include <proto/exec.h>

#include <devices/timer.h>

#include <libraries/amihttp.h>
#include <proto/amihttp.h>
#include <proto/alib.h>
#include <proto/lowlevel.h>


static const char version_tag[] = "\0$VER: AGet 1.0 (22.6.26)";
static const char stack_cookie[] = "$STACK: 16384";

#define AGET_TEMPLATE \
    "URL," \
    "TO/K," \
    "USERAGENT/K," \
    "HEAD/S," \
    "NOREDIR/S," \
    "ASYNC/S," \
    "VERBOSE/S," \
    "QUIET/S," \
    "TEST/S," \
    "COOKIEFILE/K," \
    "HEADERS/S," \
    "HEADER/K/M"

struct AGetArgs
{
    STRPTR  URL;
    STRPTR  TO;
    STRPTR  USERAGENT;
    LONG    HEAD;
    LONG    NOREDIR;
    LONG    ASYNC;
    LONG    VERBOSE;
    LONG    QUIET;
    LONG    TEST;
    STRPTR  COOKIEFILE;
    LONG    HEADERS;
    STRPTR *HEADER;
};

static ULONG  ag_step;
static LONG   ag_errno_slot;
static BPTR   ag_msgfh;
static BPTR   ag_bodyfh;
static BOOL   ag_verbose;
static BOOL   ag_quiet;
static BOOL   ag_headers;
static BOOL   ag_test_mode;
static BOOL   ag_body_console;
static LONG   ag_body_last_byte;
static LONG   ag_test_fails;

/* lowlevel.library/ElapsedTime (V40) — see NDK Autodocs/lowlevel.doc */
static struct EClockVal ag_et_ctx;
static struct EClockVal ag_et_log_ctx;

#define AG_EMPTY_STR    ((STRPTR)"")
#define AG_TEST_URL     ((STRPTR)"http://example.com/test?a=1")
#define AG_TEST_COOKIE  ((STRPTR)"test=value; Domain=example.com; Path=/test")

static VOID ag_printf(STRPTR fmt, ...);
static VOID ag_flush_msg(void);
static LONG ag_selftest(void);
static VOID ag_test_fail(STRPTR name, STRPTR detail);
static VOID ag_test_expect_true(STRPTR label, LONG rv);
static VOID ag_test_expect_false(STRPTR label, LONG rv);
static VOID ag_test_expect_long(STRPTR label, LONG got, LONG want);
static VOID ag_test_expect_nonnull(STRPTR label, APTR p);
static VOID ag_test_expect_null(STRPTR label, APTR p);
static VOID ag_test_expect_str(STRPTR label, STRPTR got, STRPTR want);
static VOID ag_test_expect_substr(STRPTR label, STRPTR got, STRPTR needle);
static VOID ag_test_expect_http_error(STRPTR label, LONG want);
static VOID ag_et_init(void);
static VOID ag_et_fini(void);
static ULONG ag_et_delta_ms(void);
static VOID ag_et_log(STRPTR label);
static VOID ag_et_summary(ULONG perform_ms, ULONG body_ms, ULONG total_ms, LONG bytes);

/*
 * Open lowlevel.library and prime ElapsedTime().  The first call after zeroing
 * EClockVal returns an undefined value and must be discarded (per autodoc).
 */
static VOID
ag_et_init(void)
{
    if (LowLevelBase != NULL) {
        return;
    }
    LowLevelBase = OpenLibrary("lowlevel.library", 40);
    if (LowLevelBase == NULL) {
        return;
    }
    ag_et_ctx.ev_hi = 0UL;
    ag_et_ctx.ev_lo = 0UL;
    ag_et_log_ctx.ev_hi = 0UL;
    ag_et_log_ctx.ev_lo = 0UL;
    (void)ElapsedTime(&ag_et_ctx);
    (void)ElapsedTime(&ag_et_log_ctx);
}

static VOID
ag_et_fini(void)
{
    if (LowLevelBase != NULL) {
        CloseLibrary(LowLevelBase);
        LowLevelBase = NULL;
    }
}

/*
 * Return milliseconds elapsed since the previous ElapsedTime() on ag_et_ctx.
 * Fixed-point 16.16 seconds from ElapsedTime are converted to ms.
 */
static ULONG
ag_et_delta_ms(void)
{
    ULONG et;
    ULONG sec;
    ULONG frac;

    if (LowLevelBase == NULL) {
        return 0UL;
    }
    et = ElapsedTime(&ag_et_ctx);
    sec = (et >> 16) & 0xFFFFUL;
    frac = et & 0xFFFFUL;
    return (sec * 1000UL) + ((frac * 1000UL) / 65536UL);
}

/*
 * Verbose trace helper: log +sec.mmm since the previous ElapsedTime() call.
 */
static VOID
ag_et_log(STRPTR label)
{
    char etbuf[24];
    ULONG et;
    ULONG sec;
    ULONG frac;
    ULONG ms;

    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    if (LowLevelBase == NULL || label == NULL) {
        return;
    }
    et = ElapsedTime(&ag_et_log_ctx);
    sec = (et >> 16) & 0xFFFFUL;
    frac = et & 0xFFFFUL;
    ms = (frac * 1000UL) / 65536UL;
    sprintf(etbuf, "+%lu.%03lu", (unsigned long)sec, (unsigned long)ms);
    ag_printf("AGet: %s %s\n", etbuf, label);
    ag_flush_msg();
}

/*
 * One-line timing summary on stderr (default mode).  Suppressed only in QUIET.
 */
static VOID
ag_et_summary(ULONG perform_ms, ULONG body_ms, ULONG total_ms, LONG bytes)
{
    ULONG kbps_x10;

    if (ag_quiet) {
        return;
    }
    if (LowLevelBase == NULL) {
        return;
    }
    ag_printf("AGet: timing: perform=%lu ms body=%lu ms total=%lu ms",
        (unsigned long)perform_ms,
        (unsigned long)body_ms,
        (unsigned long)total_ms);
    if (bytes > 0 && total_ms > 0UL) {
        kbps_x10 = (ULONG)(((ULONG)bytes * 10000UL) / total_ms / 1024UL);
        ag_printf(" (%ld bytes, %lu.%01lu KB/s)",
            bytes,
            (unsigned long)(kbps_x10 / 10UL),
            (unsigned long)(kbps_x10 % 10UL));
    } else if (bytes > 0) {
        ag_printf(" (%ld bytes)", bytes);
    }
    ag_printf("\n");
    ag_flush_msg();
}

/*
 * Prepend http:// when the user omits a scheme (e.g. "amigaworld.net").
 * Caller must FreeVec() the result.
 */
static STRPTR
ag_normalize_url(STRPTR url)
{
    STRPTR p;
    STRPTR out;
    ULONG len;

    if (url == NULL) {
        return NULL;
    }
    p = url;
    while (p[0] == ' ' || p[0] == '\t') {
        p++;
    }
    if (p[0] == '\0') {
        return NULL;
    }
    if (strstr((const char *)p, "://") != NULL) {
        len = (ULONG)strlen((const char *)p);
        out = (STRPTR)AllocMem(len + 1, MEMF_CLEAR);
        if (out != NULL) {
            strcpy((char *)out, (const char *)p);
        }
        return out;
    }
    len = 7 + (ULONG)strlen((const char *)p);
    out = (STRPTR)AllocMem(len + 1, MEMF_CLEAR);
    if (out != NULL) {
        sprintf((char *)out, "http://%s", p);
    }
    return out;
}

static VOID
ag_flush_msg(void)
{
    if (ag_msgfh != 0) {
        Flush(ag_msgfh);
    }
}

static VOID
ag_flush_body(void)
{
    if (ag_bodyfh != 0) {
        Flush(ag_bodyfh);
    }
}

static VOID
ag_printf(STRPTR fmt, ...)
{
    char buf[1024];
    va_list ap;
    LONG n;

    va_start(ap, fmt);
    vsprintf(buf, (const char *)fmt, ap);
    va_end(ap);
    n = (LONG)strlen(buf);
    if (n > 0 && ag_msgfh != 0) {
        Write(ag_msgfh, buf, n);
    }
}

/*
 * ag_msgfh  - status, TLS, errors (stderr when available)
 * ag_bodyfh - entity body (stdout or TO/K file)
 * Returns 0 or ERROR_HTTP_WRITE_FAILED if TO/K cannot be created.
 */
static LONG
ag_open_output(struct AGetArgs *args, BPTR *outfh, BOOL *close_out)
{
    ag_msgfh = (BPTR)ErrorOutput();
    if (ag_msgfh == 0) {
        ag_msgfh = Output();
    }
    *outfh = 0;
    *close_out = FALSE;
    ag_body_console = FALSE;
    ag_body_last_byte = -1;
    if (args->TO != NULL && args->TO[0] != '\0') {
        *outfh = Open(args->TO, MODE_NEWFILE);
        if (*outfh == 0) {
            ag_printf("AGet: cannot create output file \"%s\"\n", args->TO);
            ag_bodyfh = 0;
            return ERROR_HTTP_WRITE_FAILED;
        }
        *close_out = TRUE;
        ag_bodyfh = *outfh;
    } else {
        ag_bodyfh = Output();
        ag_body_console = TRUE;
    }
    return 0;
}

static VOID
ag_step_log(STRPTR label)
{
    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    ag_step++;
    ag_printf("AGet[%04ld] %s\n", (LONG)ag_step, label);
    ag_flush_msg();
}

static VOID
ag_log_errno(STRPTR where)
{
    LONG code;
    STRPTR s;

    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    code = HttpError();
    s = HttpGetErrorString(code);
    ag_printf("AGet:     %s: HttpError()=%ld (%s)\n", where, code, s);
    ag_flush_msg();
}

static VOID
ag_log_fail(STRPTR label, LONG code)
{
    char buf[128];

    HttpFault(code, label, (STRPTR)buf, (LONG)sizeof(buf));
    ag_printf("AGet: %s\n", buf);
    ag_flush_msg();
}

static VOID
ag_log_ptr(STRPTR api, STRPTR name, APTR p)
{
    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    ag_printf("AGet:     %s %s -> %lx\n", api, name, (ULONG)p);
    ag_flush_msg();
}

static VOID
ag_log_long(STRPTR api, LONG rv)
{
    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    ag_printf("AGet:     %s -> %ld\n", api, rv);
    ag_flush_msg();
}

static VOID
ag_log_bool(STRPTR api, LONG rv)
{
    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    ag_printf("AGet:     %s -> %s\n", api, rv ? "TRUE" : "FALSE");
    ag_flush_msg();
}

static VOID
ag_log_str(STRPTR api, STRPTR rv)
{
    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    if (rv != NULL) {
        ag_printf("AGet:     %s -> \"%s\"\n", api, rv);
    } else {
        ag_printf("AGet:     %s -> NULL\n", api);
    }
    ag_flush_msg();
}

static VOID
ag_free_str(STRPTR s)
{
    if (s != NULL) {
        FreeMem(s, (ULONG)strlen((const char *)s) + 1);
    }
}

static VOID
ag_test_fail(STRPTR name, STRPTR detail)
{
    ag_test_fails++;
    ag_printf("AGet: FAIL %s", name);
    if (detail != NULL && detail[0] != '\0') {
        ag_printf(": %s", detail);
    }
    ag_printf("\n");
    ag_flush_msg();
}

static VOID
ag_test_expect_true(STRPTR label, LONG rv)
{
    if (!rv) {
        ag_test_fail(label, (STRPTR)"expected TRUE");
    }
}

static VOID
ag_test_expect_false(STRPTR label, LONG rv)
{
    if (rv) {
        ag_test_fail(label, (STRPTR)"expected FALSE");
    }
}

static VOID
ag_test_expect_long(STRPTR label, LONG got, LONG want)
{
    char buf[64];

    if (got != want) {
        sprintf(buf, "got %ld want %ld", got, want);
        ag_test_fail(label, (STRPTR)buf);
    }
}

static VOID
ag_test_expect_nonnull(STRPTR label, APTR p)
{
    if (p == NULL) {
        ag_test_fail(label, (STRPTR)"expected non-NULL");
    }
}

static VOID
ag_test_expect_null(STRPTR label, APTR p)
{
    if (p != NULL) {
        ag_test_fail(label, (STRPTR)"expected NULL");
    }
}

static VOID
ag_test_expect_str(STRPTR label, STRPTR got, STRPTR want)
{
    if (got == NULL || want == NULL) {
        ag_test_fail(label, (STRPTR)"NULL string");
        return;
    }
    if (strcmp((const char *)got, (const char *)want) != 0) {
        ag_test_fail(label, got);
    }
}

static VOID
ag_test_expect_substr(STRPTR label, STRPTR got, STRPTR needle)
{
    if (got == NULL || needle == NULL) {
        ag_test_fail(label, (STRPTR)"NULL string");
        return;
    }
    if (strstr((const char *)got, (const char *)needle) == NULL) {
        ag_test_fail(label, got);
    }
}

static VOID
ag_test_expect_http_error(STRPTR label, LONG want)
{
    char buf[64];
    LONG code;

    code = HttpError();
    if (code != want) {
        sprintf(buf, "HttpError()=%ld want %ld", code, want);
        ag_test_fail(label, (STRPTR)buf);
    }
}

static VOID
ag_log_header_list(struct List *headers)
{
    struct HttpHeader *hh;

    if (headers == NULL) {
        return;
    }
    for (hh = (struct HttpHeader *)headers->lh_Head;
         hh != NULL && hh->hh_Node.ln_Succ != NULL;
         hh = (struct HttpHeader *)hh->hh_Node.ln_Succ) {
        if (hh->hh_Name != NULL && hh->hh_Value != NULL) {
            ag_printf("AGet: %s: %s\n", hh->hh_Name, hh->hh_Value);
        }
    }
    ag_flush_msg();
}

static VOID
ag_log_request_headers(STRPTR url, STRPTR method,
    STRPTR user_agent, struct HttpCookieJar *jar, STRPTR *custom_headers)
{
    STRPTR cstr;
    LONG i;

    if (!ag_headers) {
        return;
    }
    ag_printf("AGet: --- Request ---\n");
    ag_printf("AGet: %s %s HTTP/1.1\n", method, url);
    ag_printf("AGet: User-Agent: %s\n", user_agent);
    ag_printf("AGet: Cache-Control: no-cache\n");
    ag_printf("AGet: Pragma: no-cache\n");
    if (jar != NULL) {
        cstr = GetHttpCookieString(jar, url);
        if (cstr != NULL && cstr[0] != '\0') {
            ag_printf("AGet: Cookie: %s\n", cstr);
        }
        if (cstr != NULL) {
            ag_free_str(cstr);
        }
    }
    if (custom_headers != NULL) {
        for (i = 0; custom_headers[i] != NULL; i++) {
            ag_printf("AGet: %s\n", custom_headers[i]);
        }
    }
    ag_flush_msg();
}

static VOID
ag_log_response_headers(struct HttpTransaction *txn)
{
    STRPTR sl;

    if (!ag_headers) {
        return;
    }
    ag_printf("AGet: --- Response ---\n");
    sl = HttpTransactionGetStatusLine(txn);
    if (sl != NULL) {
        ag_printf("AGet: %s\n", sl);
    }
    ag_log_header_list(HttpTransactionRespHeaders(txn));
}

static VOID
ag_log_headers(STRPTR title, struct List *headers)
{
    struct HttpHeader *hh;
    LONG count;

    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    ag_printf("AGet:     %s:\n", title);
    count = 0;
    if (headers != NULL) {
        for (hh = (struct HttpHeader *)headers->lh_Head;
             hh != NULL && hh->hh_Node.ln_Succ != NULL;
             hh = (struct HttpHeader *)hh->hh_Node.ln_Succ) {
            count++;
            if (hh->hh_Name != NULL && hh->hh_Value != NULL) {
                ag_printf("AGet:       [%ld] %s: %s\n",
                    count, hh->hh_Name, hh->hh_Value);
            }
        }
    }
    ag_printf("AGet:     (%ld header lines)\n", count);
    ag_flush_msg();
}

static VOID
ag_log_parsed_url(struct ParsedUrl *pu)
{
    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    if (pu == NULL) {
        ag_printf("AGet:     ParsedUrl NULL\n");
        ag_flush_msg();
        return;
    }
    ag_printf("AGet:     scheme=\"%s\" host=\"%s\" port=%ld path=\"%s\"\n",
        pu->pu_Scheme ? pu->pu_Scheme : AG_EMPTY_STR,
        pu->pu_Host ? pu->pu_Host : AG_EMPTY_STR,
        (LONG)pu->pu_Port,
        pu->pu_Path ? pu->pu_Path : AG_EMPTY_STR);
    ag_printf("AGet:     query=\"%s\" user=\"%s\" secure=%s\n",
        pu->pu_Query ? pu->pu_Query : AG_EMPTY_STR,
        pu->pu_User ? pu->pu_User : AG_EMPTY_STR,
        pu->pu_IsSecure ? (STRPTR)"YES" : (STRPTR)"NO");
    ag_flush_msg();
}

static VOID
ag_log_timing(struct HttpTiming *t)
{
    if (!ag_verbose && !ag_test_mode) {
        return;
    }
    if (t == NULL) {
        ag_printf("AGet:     HttpTiming NULL\n");
    } else {
        ag_printf("AGet:     connect=%ld ms ttfb=%ld ms total=%ld ms\n",
            (LONG)t->ht_ConnectMs, (LONG)t->ht_TtfbMs, (LONG)t->ht_TotalMs);
    }
    ag_flush_msg();
}

static VOID
ag_log_txn_getters(struct HttpTransaction *txn, STRPTR phase)
{
    LONG status;
    LONG clen;
    ULONG received;
    LONG last_err;
    BOOL complete;
    STRPTR sl;
    STRPTR loc;
    STRPTR ctype;
    STRPTR cl_hdr;
    struct List *rh;
    struct HttpTiming timing;
    LONG trv;

    ag_step_log(phase);
    status = HttpTransactionGetStatusCode(txn);
    ag_log_long("HttpTransactionGetStatusCode", status);
    ag_log_errno("after GetStatusCode");

    sl = HttpTransactionGetStatusLine(txn);
    ag_log_str("HttpTransactionGetStatusLine", sl);

    ctype = HttpTransactionRespHeader(txn, (STRPTR)"Content-Type");
    ag_log_str("HttpTransactionRespHeader(Content-Type)", ctype);

    cl_hdr = HttpTransactionRespHeader(txn, (STRPTR)"Content-Length");
    ag_log_str("HttpTransactionRespHeader(Content-Length)", cl_hdr);

    clen = HttpTransactionGetContentLength(txn);
    ag_log_long("HttpTransactionGetContentLength", clen);

    received = HttpTransactionGetBytesReceived(txn);
    ag_printf("AGet:     HttpTransactionGetBytesReceived -> %ld\n",
        (LONG)received);
    ag_flush_msg();

    loc = HttpTransactionGetRedirectLocation(txn);
    ag_log_str("HttpTransactionGetRedirectLocation", loc);

    rh = HttpTransactionRespHeaders(txn);
    ag_log_ptr("HttpTransactionRespHeaders", "list", rh);
    ag_log_headers("response headers", rh);

    trv = HttpTransactionGetTiming(txn, &timing);
    ag_log_bool("HttpTransactionGetTiming", trv);
    ag_log_timing(&timing);

    last_err = HttpTransactionGetLastError(txn);
    ag_log_long("HttpTransactionGetLastError", last_err);

    complete = HttpTransactionIsComplete(txn);
    ag_log_bool("HttpTransactionIsComplete", complete ? 1 : 0);
    ag_log_errno("after txn getters");
}

static VOID
ag_log_peer_cert(struct HttpTransaction *txn, STRPTR url)
{
    struct HttpSslPeerCert cert;
    struct ParsedUrl *pu;
    LONG rv;

    if (ag_quiet && !ag_verbose && !ag_headers) {
        return;
    }
    pu = ParseHttpUrl(url);
    if (pu == NULL || !pu->pu_IsSecure) {
        if (pu != NULL) {
            DisposeHttpUrl(pu);
        }
        return;
    }
    DisposeHttpUrl(pu);

    rv = HttpTransactionGetPeerCert(txn, &cert);
    if (!rv) {
        ag_printf("AGet: TLS: no peer certificate\n");
        ag_flush_msg();
        return;
    }
    ag_printf("AGet: TLS certificate (verify=%ld):\n", cert.hpc_VerifyResult);
    if (cert.hpc_CommonName != NULL) {
        ag_printf("AGet:   CN: %s\n", cert.hpc_CommonName);
    }
    if (cert.hpc_Subject != NULL) {
        ag_printf("AGet:   subject: %s\n", cert.hpc_Subject);
    }
    if (cert.hpc_Issuer != NULL) {
        ag_printf("AGet:   issuer: %s\n", cert.hpc_Issuer);
    }
    if (cert.hpc_NotBefore != NULL) {
        ag_printf("AGet:   notBefore: %s\n", cert.hpc_NotBefore);
    }
    if (cert.hpc_NotAfter != NULL) {
        ag_printf("AGet:   notAfter: %s\n", cert.hpc_NotAfter);
    }
    if (cert.hpc_Serial != NULL) {
        ag_printf("AGet:   serial: %s\n", cert.hpc_Serial);
    }
    ag_flush_msg();
    HttpPeerCertFree(&cert);
}

static VOID
ag_test_tier0(void)
{
    LONG prev;
    LONG code;
    char fbuf[128];
    LONG flen;
    LONG rv;

    ag_step_log("Tier0: HttpError baseline");
    ag_log_errno("initial");
    ag_test_expect_http_error("HttpError initial", 0);

    ag_step_log("Tier0: SetHttpError round-trip");
    prev = SetHttpError(ERROR_HTTP_PROTOCOL);
    ag_log_long("SetHttpError(PROTOCOL) prev", prev);
    code = HttpError();
    ag_log_long("HttpError after set", code);
    ag_test_expect_long("SetHttpError round-trip", code, ERROR_HTTP_PROTOCOL);
    prev = SetHttpError(0);
    ag_log_long("SetHttpError(0) prev", prev);
    ag_test_expect_http_error("SetHttpError clear", 0);

    ag_step_log("Tier0: HttpGetErrorString samples");
    ag_log_str("HttpGetErrorString(0)", HttpGetErrorString(0));
    ag_test_expect_str("HttpGetErrorString(0)", HttpGetErrorString(0),
        (STRPTR)"No error");
    ag_log_str("HttpGetErrorString(8713)",
        HttpGetErrorString(ERROR_HTTP_INVALID_HANDLE));
    ag_test_expect_str("HttpGetErrorString(8713)",
        HttpGetErrorString(ERROR_HTTP_INVALID_HANDLE),
        (STRPTR)"Invalid handle");

    ag_step_log("Tier0: HttpFault formatting");
    flen = HttpFault(ERROR_HTTP_DNS_FAILED, (STRPTR)"lookup",
        (STRPTR)fbuf, (LONG)sizeof(fbuf));
    ag_printf("AGet:     HttpFault -> len=%ld \"%s\"\n", flen, fbuf);
    if (flen <= 0) {
        ag_test_fail("HttpFault length", (STRPTR)"len <= 0");
    }
    if (strstr(fbuf, "DNS") == NULL) {
        ag_test_fail("HttpFault text", (STRPTR)fbuf);
    }
    ag_test_expect_http_error("after HttpFault", ERROR_HTTP_DNS_FAILED);
    SetHttpError(0);

    ag_step_log("Tier0: HttpBaseTags");
    rv = HttpBaseTags(
        HTBT_DEFAULT_USERAGENT, (ULONG)"AGet-selftest/1.0",
        HTBT_DEFAULT_TIMEOUT,   (ULONG)60,
        HTBT_MAX_IDLE_CONNECTIONS, (ULONG)2,
        HTBT_IDLE_TIMEOUT,      (ULONG)30,
        TAG_DONE);
    ag_log_bool("HttpBaseTags", rv);
    ag_test_expect_true("HttpBaseTags", rv);
    ag_test_expect_http_error("after HttpBaseTags", 0);
}

static VOID
ag_test_url_utils(STRPTR url)
{
    struct ParsedUrl *pu;
    struct ParsedUrl *bad;
    STRPTR rebuilt;
    STRPTR enc;
    STRPTR dec;
    STRPTR penc;
    STRPTR part;
    STRPTR joined;
    struct List pairs;
    struct HttpQueryPair qp1;
    struct HttpQueryPair qp2;
    STRPTR qstr;

    ag_step_log("URL: ParseHttpUrl invalid");
    bad = ParseHttpUrl((STRPTR)"not-a-valid-url");
    ag_log_ptr("ParseHttpUrl(bad)", "pu", bad);
    ag_test_expect_null("ParseHttpUrl(invalid)", bad);

    ag_step_log("URL: ParseHttpUrl");
    pu = ParseHttpUrl(url);
    ag_log_ptr("ParseHttpUrl", "pu", pu);
    ag_test_expect_nonnull("ParseHttpUrl", pu);
    ag_test_expect_http_error("after ParseHttpUrl", 0);
    ag_log_parsed_url(pu);

    if (pu != NULL) {
        ag_step_log("URL: BuildHttpUrl round-trip");
        rebuilt = BuildHttpUrl(pu);
        ag_log_str("BuildHttpUrl", rebuilt);
        ag_test_expect_nonnull("BuildHttpUrl", rebuilt);
        if (rebuilt != NULL) {
            ag_test_expect_str("BuildHttpUrl round-trip", rebuilt, url);
            ag_free_str(rebuilt);
        }

        ag_step_log("URL: URI part helpers");
        part = HttpUriSchemePart(url);
        ag_log_str("HttpUriSchemePart", part);
        ag_test_expect_str("HttpUriSchemePart", part, (STRPTR)"http");
        ag_free_str(part);
        part = HttpUriHostPart(url);
        ag_log_str("HttpUriHostPart", part);
        ag_test_expect_str("HttpUriHostPart", part, (STRPTR)"example.com");
        ag_free_str(part);
        part = HttpUriAuthorityPart(url);
        ag_log_str("HttpUriAuthorityPart", part);
        ag_test_expect_str("HttpUriAuthorityPart", part, (STRPTR)"example.com");
        ag_free_str(part);
        part = HttpUriPathPart(url);
        ag_log_str("HttpUriPathPart", part);
        ag_test_expect_str("HttpUriPathPart", part, (STRPTR)"/test");
        ag_free_str(part);
        part = HttpUriFilePart(url);
        ag_log_str("HttpUriFilePart", part);
        ag_test_expect_str("HttpUriFilePart", part, (STRPTR)"test");
        ag_free_str(part);
        part = HttpUriParentPart(url);
        ag_log_str("HttpUriParentPart", part);
        ag_test_expect_str("HttpUriParentPart", part, (STRPTR)"/");
        ag_free_str(part);
        part = HttpUriQueryPart(url);
        ag_log_str("HttpUriQueryPart", part);
        ag_test_expect_str("HttpUriQueryPart", part, (STRPTR)"a=1");
        ag_free_str(part);

        ag_step_log("URL: HttpJoinUri");
        joined = HttpJoinUri((STRPTR)"http://example.com/a/b", (STRPTR)"c");
        ag_log_str("HttpJoinUri", joined);
        ag_test_expect_nonnull("HttpJoinUri", joined);
        if (joined != NULL) {
            ag_free_str(joined);
        }

        ag_step_log("URL: encode/decode helpers");
        enc = HttpUrlEncode((STRPTR)"hello world&foo=bar");
        ag_log_str("HttpUrlEncode", enc);
        ag_test_expect_nonnull("HttpUrlEncode", enc);
        if (enc != NULL) {
            ag_test_expect_str("HttpUrlEncode", enc,
                (STRPTR)"hello%20world%26foo%3Dbar");
            dec = HttpUrlDecode(enc);
            ag_log_str("HttpUrlDecode", dec);
            ag_test_expect_str("HttpUrlDecode round-trip", dec,
                (STRPTR)"hello world&foo=bar");
            ag_free_str(dec);
            ag_free_str(enc);
        }
        penc = HttpPathEncode((STRPTR)"/a path/file.html");
        ag_log_str("HttpPathEncode", penc);
        ag_test_expect_str("HttpPathEncode", penc,
            (STRPTR)"%2Fa%20path%2Ffile.html");
        ag_free_str(penc);

        ag_step_log("URL: HttpBuildQueryString");
        NewList(&pairs);
        qp1.hqp_Name = (STRPTR)"a";
        qp1.hqp_Value = (STRPTR)"1";
        qp2.hqp_Name = (STRPTR)"b";
        qp2.hqp_Value = (STRPTR)"two & more";
        AddTail(&pairs, &qp1.hqp_Node);
        AddTail(&pairs, &qp2.hqp_Node);
        qstr = HttpBuildQueryString(&pairs);
        ag_log_str("HttpBuildQueryString", qstr);
        ag_test_expect_str("HttpBuildQueryString", qstr,
            (STRPTR)"a=1&b=two%20%26%20more");
        ag_free_str(qstr);

        ag_step_log("URL: DisposeHttpUrl");
        DisposeHttpUrl(pu);
        ag_test_expect_http_error("after DisposeHttpUrl", 0);
    }
}

static VOID
ag_test_cookies(struct HttpSession *session, STRPTR url)
{
    struct HttpCookieJar *jar;
    STRPTR cstr;
    LONG rv;

    ag_step_log("Cookie: NewHttpCookieJar");
    jar = NewHttpCookieJar();
    ag_log_ptr("NewHttpCookieJar", "jar", jar);
    ag_test_expect_nonnull("NewHttpCookieJar", jar);
    if (jar == NULL) {
        return;
    }

    ag_step_log("Cookie: SetHttpCookie");
    rv = SetHttpCookie(jar, AG_TEST_COOKIE);
    ag_log_bool("SetHttpCookie", rv);
    ag_test_expect_true("SetHttpCookie", rv);

    ag_step_log("Cookie: GetHttpCookieString");
    cstr = GetHttpCookieString(jar, url);
    ag_log_str("GetHttpCookieString", cstr);
    ag_test_expect_nonnull("GetHttpCookieString", cstr);
    if (cstr != NULL) {
        ag_test_expect_substr("GetHttpCookieString value", cstr,
            (STRPTR)"test=value");
        ag_free_str(cstr);
    }

    ag_step_log("Cookie: SaveHttpCookieJar (not implemented)");
    SetHttpError(0);
    rv = SaveHttpCookieJar(jar, (STRPTR)"T:aget_cookies.txt");
    ag_log_bool("SaveHttpCookieJar", rv);
    ag_test_expect_false("SaveHttpCookieJar", rv);
    ag_test_expect_http_error("SaveHttpCookieJar",
        ERROR_HTTP_NOT_IMPLEMENTED);

    ag_step_log("Cookie: LoadHttpCookieJar (not implemented)");
    SetHttpError(0);
    rv = LoadHttpCookieJar(jar, (STRPTR)"T:aget_cookies.txt");
    ag_log_bool("LoadHttpCookieJar", rv);
    ag_test_expect_false("LoadHttpCookieJar", rv);
    ag_test_expect_http_error("LoadHttpCookieJar",
        ERROR_HTTP_NOT_IMPLEMENTED);

    ag_step_log("Cookie: FlushHttpCookieJar(0)");
    SetHttpError(0);
    FlushHttpCookieJar(jar, 0UL);
    cstr = GetHttpCookieString(jar, url);
    ag_log_str("GetHttpCookieString after flush", cstr);
    if (cstr != NULL) {
        ag_test_expect_str("FlushHttpCookieJar(0)", cstr, (STRPTR)"");
        ag_free_str(cstr);
    }

    ag_step_log("Cookie: SetHttpCookie re-store");
    rv = SetHttpCookie(jar, AG_TEST_COOKIE);
    ag_test_expect_true("SetHttpCookie re-store", rv);

    ag_step_log("Cookie: HttpSessionAttachCookieJar");
    rv = HttpSessionAttachCookieJar(session, jar);
    ag_log_bool("HttpSessionAttachCookieJar", rv);
    ag_test_expect_true("HttpSessionAttachCookieJar", rv);

    ag_step_log("Cookie: HttpSessionDetachCookieJar");
    HttpSessionDetachCookieJar(session);

    ag_step_log("Cookie: DisposeHttpCookieJar");
    DisposeHttpCookieJar(jar);
}

static VOID
ag_test_session(struct HttpSession *session)
{
    LONG rv;

    ag_step_log("Tier1: SetHttpSessionAttrs");
    rv = SetHttpSessionAttrs(
        session,
        HTSA_USERAGENT,        (ULONG)"AGet-selftest/1.0",
        HTSA_FOLLOW_REDIRECTS, (ULONG)TRUE,
        HTSA_MAX_REDIRECTS,    (ULONG)5,
        HTSA_KEEPALIVE,        (ULONG)TRUE,
        HTSA_CONNECT_TIMEOUT,  (ULONG)30,
        HTSA_READ_TIMEOUT,     (ULONG)60,
        HTSA_REFERER_POLICY,   (ULONG)HTRP_ORIGIN,
        HTSA_SSL_VERIFY,       (ULONG)HTSSL_VERIFY_PEER,
        TAG_DONE);
    ag_log_bool("SetHttpSessionAttrs", rv);
    ag_test_expect_true("SetHttpSessionAttrs", rv);
    ag_test_expect_http_error("after SetHttpSessionAttrs", 0);

    ag_step_log("Tier1: SetHttpSessionHook");
    rv = SetHttpSessionHook(session, HTHK_PROGRESS, NULL);
    ag_log_bool("SetHttpSessionHook", rv);
    ag_test_expect_true("SetHttpSessionHook", rv);
}

static VOID
ag_test_transaction(struct HttpSession *session, STRPTR url)
{
    struct HttpTransaction *txn;
    struct HttpSslPeerCert cert;
    struct HttpTiming timing;
    struct List *rh;
    LONG rv;
    LONG status;
    LONG clen;
    ULONG received;
    LONG last_err;
    BOOL complete;
    STRPTR sl;
    STRPTR rhdr;

    ag_step_log("Tier2: NewHttpTransaction");
    txn = NewHttpTransaction(session);
    ag_log_ptr("NewHttpTransaction", "txn", txn);
    ag_test_expect_nonnull("NewHttpTransaction", txn);
    if (txn == NULL) {
        return;
    }

    ag_step_log("Tier2: SetHttpTransactionAttrs");
    rv = SetHttpTransactionAttrs(
        txn,
        HTTA_URL,        (ULONG)url,
        HTTA_METHOD,     (ULONG)"GET",
        HTTA_USERAGENT,  (ULONG)"AGet-selftest/1.0",
        HTTA_NO_CACHE,   (ULONG)TRUE,
        TAG_DONE);
    ag_log_bool("SetHttpTransactionAttrs", rv);
    ag_test_expect_true("SetHttpTransactionAttrs", rv);

    ag_step_log("Tier2: HttpTransactionAddHeader");
    rv = HttpTransactionAddHeader(txn,
        (STRPTR)"X-AGet-Test", (STRPTR)"1");
    ag_log_bool("HttpTransactionAddHeader", rv);
    ag_test_expect_true("HttpTransactionAddHeader", rv);
    rv = HttpTransactionAddHeader(txn,
        (STRPTR)"X-Second", (STRPTR)"two");
    ag_test_expect_true("HttpTransactionAddHeader(2)", rv);

    ag_step_log("Tier2: HttpTransactionClearHeaders");
    HttpTransactionClearHeaders(txn);
    ag_test_expect_http_error("after HttpTransactionClearHeaders", 0);

    ag_step_log("Tier2: getters before Perform");
    status = HttpTransactionGetStatusCode(txn);
    ag_log_long("HttpTransactionGetStatusCode", status);
    ag_test_expect_long("GetStatusCode pre-perform", status, 0);

    sl = HttpTransactionGetStatusLine(txn);
    ag_log_str("HttpTransactionGetStatusLine", sl);

    rhdr = HttpTransactionRespHeader(txn, (STRPTR)"Content-Type");
    ag_log_str("HttpTransactionRespHeader", rhdr);
    ag_test_expect_null("RespHeader pre-perform", rhdr);

    rh = HttpTransactionRespHeaders(txn);
    ag_log_ptr("HttpTransactionRespHeaders", "list", rh);

    clen = HttpTransactionGetContentLength(txn);
    ag_log_long("HttpTransactionGetContentLength", clen);
    ag_test_expect_long("GetContentLength pre-perform", clen, -1);

    received = HttpTransactionGetBytesReceived(txn);
    ag_log_long("HttpTransactionGetBytesReceived", (LONG)received);
    ag_test_expect_long("GetBytesReceived pre-perform", (LONG)received, 0);

    rv = HttpTransactionGetTiming(txn, &timing);
    ag_log_bool("HttpTransactionGetTiming", rv);
    ag_test_expect_true("GetTiming pre-perform", rv);

    last_err = HttpTransactionGetLastError(txn);
    ag_log_long("HttpTransactionGetLastError", last_err);
    ag_test_expect_long("GetLastError pre-perform", last_err, 0);

    complete = HttpTransactionIsComplete(txn);
    ag_log_bool("HttpTransactionIsComplete", complete ? 1 : 0);
    ag_test_expect_long("IsComplete pre-perform", (LONG)complete, 0);

    ag_step_log("Tier2: GetPeerCert before HTTPS");
    rv = HttpTransactionGetPeerCert(txn, &cert);
    ag_log_bool("HttpTransactionGetPeerCert", rv);
    ag_test_expect_false("GetPeerCert pre-perform", rv);
    HttpPeerCertFree(&cert);

    ag_step_log("Tier2: SetHttpTransactionHook");
    rv = SetHttpTransactionHook(txn, HTHK_PROGRESS, NULL);
    ag_log_bool("SetHttpTransactionHook", rv);
    ag_test_expect_true("SetHttpTransactionHook", rv);

    ag_step_log("Tier2: AbortHttpTransaction");
    AbortHttpTransaction(txn);
    ag_test_expect_http_error("after AbortHttpTransaction", 0);

    ag_step_log("Tier2: DisposeHttpTransaction");
    DisposeHttpTransaction(txn);
}

static VOID
ag_test_tier3_offline(struct HttpSession *session)
{
    struct HttpConnection *conn;
    LONG rv;
    char linebuf[128];

    ag_step_log("Tier3: OpenHttpConnection(NULL session)");
    SetHttpError(0);
    conn = OpenHttpConnection(NULL, (STRPTR)"example.com", 80, FALSE);
    ag_log_ptr("OpenHttpConnection", "conn", conn);
    ag_test_expect_null("OpenHttpConnection(NULL)", conn);
    ag_test_expect_http_error("OpenHttpConnection(NULL)",
        ERROR_HTTP_INVALID_HANDLE);

    ag_step_log("Tier3: OpenHttpConnection(empty host)");
    SetHttpError(0);
    conn = OpenHttpConnection(session, NULL, 80, FALSE);
    ag_log_ptr("OpenHttpConnection", "conn", conn);
    ag_test_expect_null("OpenHttpConnection(NULL host)", conn);
    ag_test_expect_http_error("OpenHttpConnection(NULL host)",
        ERROR_HTTP_INVALID_URL);

    ag_step_log("Tier3: OpenHttpConnection(empty string host)");
    SetHttpError(0);
    conn = OpenHttpConnection(session, (STRPTR)"", 80, FALSE);
    ag_log_ptr("OpenHttpConnection", "conn", conn);
    ag_test_expect_null("OpenHttpConnection(empty host)", conn);
    ag_test_expect_http_error("OpenHttpConnection(empty host)",
        ERROR_HTTP_INVALID_URL);

    ag_step_log("Tier3: CloseHttpConnection(NULL)");
    CloseHttpConnection(NULL);

    ag_step_log("Tier3: HttpConnectionSendRequest (stub)");
    SetHttpError(0);
    rv = HttpConnectionSendRequest(NULL, (STRPTR)"GET", (STRPTR)"/", NULL);
    ag_log_bool("HttpConnectionSendRequest", rv);
    ag_test_expect_false("HttpConnectionSendRequest", rv);
    ag_test_expect_http_error("HttpConnectionSendRequest",
        ERROR_HTTP_NOT_IMPLEMENTED);

    ag_step_log("Tier3: HttpConnectionReadBodyChunk (stub)");
    SetHttpError(0);
    rv = HttpConnectionReadBodyChunk(NULL, NULL, 64);
    ag_log_long("HttpConnectionReadBodyChunk", rv);
    ag_test_expect_false("HttpConnectionReadBodyChunk", rv);
    ag_test_expect_http_error("HttpConnectionReadBodyChunk",
        ERROR_HTTP_NOT_IMPLEMENTED);

    ag_step_log("Tier3: HttpConnectionWriteBodyChunk (stub)");
    SetHttpError(0);
    rv = HttpConnectionWriteBodyChunk(NULL, NULL, 0);
    ag_log_long("HttpConnectionWriteBodyChunk", rv);
    ag_test_expect_false("HttpConnectionWriteBodyChunk", rv);
    ag_test_expect_http_error("HttpConnectionWriteBodyChunk",
        ERROR_HTTP_NOT_IMPLEMENTED);

    ag_step_log("Tier3: HttpConnectionReadResponseLine(NULL)");
    rv = HttpConnectionReadResponseLine(NULL, (STRPTR)linebuf,
        (ULONG)sizeof(linebuf));
    ag_log_long("HttpConnectionReadResponseLine", rv);
    ag_test_expect_long("ReadResponseLine(NULL)", rv, 0);

    ag_step_log("Tier3: HttpConnectionIsAlive(NULL)");
    rv = (LONG)HttpConnectionIsAlive(NULL);
    ag_log_bool("HttpConnectionIsAlive", rv);
    ag_test_expect_long("HttpConnectionIsAlive(NULL)", rv, 0);

    ag_step_log("Tier3: ResetHttpConnection(NULL)");
    ResetHttpConnection(NULL);
}

static struct HttpCookieJar *
ag_setup_cookie_jar(struct HttpSession *session, STRPTR url, STRPTR cookiefile)
{
    struct HttpCookieJar *jar;
    LONG rv;

    (void)url;

    ag_step_log("Cookie: NewHttpCookieJar");
    jar = NewHttpCookieJar();
    ag_log_ptr("NewHttpCookieJar", "jar", jar);
    if (jar == NULL) {
        ag_log_errno("after NewHttpCookieJar");
        return NULL;
    }

    if (cookiefile != NULL) {
        ag_step_log("Cookie: LoadHttpCookieJar");
        rv = LoadHttpCookieJar(jar, cookiefile);
        ag_log_bool("LoadHttpCookieJar", rv);
    }

    ag_step_log("Cookie: FlushHttpCookieJar(0)");
    FlushHttpCookieJar(jar, 0);

    ag_step_log("Cookie: HttpSessionAttachCookieJar");
    rv = HttpSessionAttachCookieJar(session, jar);
    ag_log_bool("HttpSessionAttachCookieJar", rv);
    if (!rv) {
        DisposeHttpCookieJar(jar);
        return NULL;
    }
    return jar;
}

/*
 * ag_selftest - offline amihttp.library API coverage (no HttpTransactionPerform).
 */
static LONG
ag_selftest(void)
{
    struct HttpSession *session;
    STRPTR fixture;
    LONG err;
    LONG rv;

    session = NULL;
    err = 0;
    ag_step = 0;
    ag_test_fails = 0;
    fixture = AG_TEST_URL;

    ag_msgfh = (BPTR)ErrorOutput();
    if (ag_msgfh == 0) {
        ag_msgfh = Output();
    }

    ag_printf("AGet: self-test fixture=\"%s\"\n", fixture);
    ag_flush_msg();

    HttpBase = OpenLibrary(AMIHTTPNAME, AMIHTTPVERSION);
    if (HttpBase == NULL) {
        ag_printf("AGet: cannot open %s\n", AMIHTTPNAME);
        return 20;
    }

    rv = HttpBaseTags(
        HTBT_ERRNOPTR, (ULONG)&ag_errno_slot,
        TAG_DONE);
    if (!rv) {
        ag_log_fail("HttpBaseTagList", HttpError());
        err = HttpError();
        goto st_cleanup;
    }
    SetHttpError(0);

    ag_test_tier0();
    ag_test_url_utils(fixture);

    ag_step_log("Tier1: NewHttpSession");
    session = NewHttpSession();
    ag_log_ptr("NewHttpSession", "session", session);
    ag_test_expect_nonnull("NewHttpSession", session);
    if (session == NULL) {
        err = HttpError();
        goto st_cleanup;
    }

    ag_test_session(session);
    ag_test_cookies(session, fixture);
    ag_test_transaction(session, fixture);
    ag_test_tier3_offline(session);

st_cleanup:
    if (session != NULL) {
        DisposeHttpSession(session);
    }
    if (HttpBase != NULL) {
        CloseLibrary((struct Library *)HttpBase);
        HttpBase = NULL;
    }

    if (ag_test_fails > 0) {
        ag_printf("AGet: self-test FAILED (%ld failures)\n", ag_test_fails);
        return ERROR_HTTP_PROTOCOL;
    }
    ag_printf("AGet: self-test OK (%ld steps)\n", (LONG)ag_step);
    return err;
}

static LONG
ag_write_all(BPTR fh, APTR data, LONG len)
{
    LONG written;
    LONG total;
    LONG n;

    total = 0;
    while (total < len) {
        n = len - total;
        written = Write(fh, (UBYTE *)data + total, n);
        if (written < 0 || written == 0) {
            return ERROR_HTTP_WRITE_FAILED;
        }
        total += written;
    }
    return 0;
}

/*
 * Console body output should end with a newline so the shell prompt does not
 * run onto the last line of the fetched content.  File output (TO/K) is left
 * byte-for-byte; only append when the body did not already end with '\n'.
 */
static VOID
ag_finish_console_body(void)
{
    static const char nl[] = "\n";

    if (!ag_body_console || ag_bodyfh == 0) {
        return;
    }
    if (ag_body_last_byte >= 0 && ag_body_last_byte != '\n') {
        Write(ag_bodyfh, (APTR)nl, 1);
    }
    ag_flush_body();
}

static LONG
ag_read_body(struct HttpTransaction *txn, LONG expect_cl, LONG *out_total)
{
    UBYTE buf[8192];
    LONG n;
    LONG body_total;
    LONG chunk;

    body_total = 0;
    chunk = 0;
    ag_body_last_byte = -1;
    ag_step_log("Tier2: HttpTransactionReadBody loop");

    /*
     * expect_cl is the decoded entity length when identity-coded.  With
     * Content-Encoding (gzip/deflate) the header length is wire bytes only.
     */
    if (expect_cl >= 0) {
        STRPTR ce;

        ce = HttpTransactionRespHeader(txn, "Content-Encoding");
        if (ce != NULL && ce[0] != '\0') {
            expect_cl = -1;
        }
    }

    for (;;) {
        chunk++;
        if (ag_verbose || ag_test_mode) {
            ag_printf("AGet:     ReadBody chunk %ld buf=%ld txn=%lx\n",
                chunk, (LONG)sizeof(buf), (ULONG)txn);
            ag_flush_msg();
        }

        n = HttpTransactionReadBody(txn, (APTR)buf, (ULONG)sizeof(buf));
        if (ag_verbose || ag_test_mode) {
            char chunkbuf[64];

            ag_printf("AGet:     HttpTransactionReadBody -> %ld\n", n);
            ag_printf("AGet:     HttpTransactionGetBytesReceived -> %ld\n",
                (LONG)HttpTransactionGetBytesReceived(txn));
            ag_log_errno("after ReadBody");
            if (n > 0) {
                sprintf(chunkbuf, "ReadBody chunk %ld (%ld bytes)",
                    chunk, n);
                ag_et_log(chunkbuf);
            }
        }

        if (n == 0) {
            if (HttpError() != 0) {
                return HttpError();
            }
            if (ag_verbose || ag_test_mode) {
                ag_printf("AGet:     ReadBody EOF body_total=%ld\n", body_total);
                ag_flush_msg();
            }
            break;
        }
        if (n > (LONG)sizeof(buf)) {
            return ERROR_HTTP_PROTOCOL;
        }
        if (expect_cl >= 0 && body_total + n > expect_cl) {
            return ERROR_HTTP_PROTOCOL;
        }
        if (ag_write_all(ag_bodyfh, (APTR)buf, n) != 0) {
            return ERROR_HTTP_WRITE_FAILED;
        }
        ag_body_last_byte = (LONG)buf[n - 1];
        body_total += n;
    }
    if (out_total != NULL) {
        *out_total = body_total;
    }
    return 0;
}

static VOID
ag_log_status_line(LONG status, LONG clen, BOOL head)
{
    if (ag_quiet && !ag_verbose && !ag_headers) {
        return;
    }
    if (ag_headers) {
        return;
    }
    ag_printf("AGet: HTTP %ld", status);
    if (head) {
        ag_printf(" (HEAD)");
    }
    if (clen >= 0) {
        ag_printf(" Content-Length=%ld", clen);
    }
    ag_printf("\n");
    ag_flush_msg();
}

static VOID
ag_log_head_summary(struct HttpTransaction *txn)
{
    STRPTR sl;
    STRPTR ctype;
    STRPTR clen_hdr;
    STRPTR enc;

    if (ag_quiet && !ag_verbose && !ag_headers) {
        return;
    }
    if (ag_headers) {
        return;
    }
    sl = HttpTransactionGetStatusLine(txn);
    if (sl != NULL) {
        ag_printf("AGet: %s\n", sl);
    }
    ctype = HttpTransactionRespHeader(txn, (STRPTR)"Content-Type");
    if (ctype != NULL) {
        ag_printf("AGet: Content-Type: %s\n", ctype);
    }
    clen_hdr = HttpTransactionRespHeader(txn, (STRPTR)"Content-Length");
    if (clen_hdr != NULL) {
        ag_printf("AGet: Content-Length: %s\n", clen_hdr);
    }
    enc = HttpTransactionRespHeader(txn, (STRPTR)"Content-Encoding");
    if (enc != NULL) {
        ag_printf("AGet: Content-Encoding: %s\n", enc);
    }
    ag_flush_msg();
}

static LONG
ag_download(struct AGetArgs *args)
{
    struct HttpSession *session;
    struct HttpTransaction *txn;
    struct HttpCookieJar *cookie_jar;
    STRPTR user_agent;
    STRPTR method;
    STRPTR fetch_url;
    STRPTR hdr;
    STRPTR colon;
    LONG err;
    LONG status;
    LONG body_total;
    LONG clen;
    LONG rv;
    LONG wait_iter;
    LONG i;
    ULONG notify_sig;
    BOOL performed;
    BPTR outfh;
    BOOL close_out;
    ULONG et_perform_ms;
    ULONG et_body_ms;
    ULONG et_total_ms;

    session = NULL;
    txn = NULL;
    cookie_jar = NULL;
    fetch_url = NULL;
    outfh = 0;
    close_out = FALSE;
    err = 0;
    body_total = 0;
    notify_sig = (ULONG)-1;
    et_perform_ms = 0UL;
    et_body_ms = 0UL;
    et_total_ms = 0UL;
    ag_step = 0;
    method = (STRPTR)"GET";

    user_agent = args->USERAGENT;
    if (user_agent == NULL || user_agent[0] == '\0') {
        user_agent = (STRPTR)"AGet/1.0 (amihttp)";
    }

    err = ag_open_output(args, &outfh, &close_out);
    if (err != 0) {
        return err;
    }

    fetch_url = ag_normalize_url(args->URL);
    if (fetch_url == NULL) {
        ag_printf("AGet: invalid URL\n");
        ag_flush_msg();
        return ERROR_HTTP_INVALID_URL;
    }

    if (ag_verbose || ag_test_mode) {
        ag_printf("AGet: url=\"%s\" to=%s ua=\"%s\"\n",
            fetch_url,
            args->TO ? args->TO : (STRPTR)"(stdout)",
            user_agent);
        ag_flush_msg();
    }

    HttpBase = OpenLibrary(AMIHTTPNAME, AMIHTTPVERSION);
    if (HttpBase == NULL) {
        ag_printf("AGet: cannot open %s\n", AMIHTTPNAME);
        return 20;
    }

    rv = HttpBaseTags(
        HTBT_DEFAULT_USERAGENT, (ULONG)user_agent,
        HTBT_DEFAULT_TIMEOUT,   (ULONG)120,
        HTBT_MAX_IDLE_CONNECTIONS, (ULONG)4,
        HTBT_IDLE_TIMEOUT,      (ULONG)60,
        HTBT_SSL_VERIFY,        (ULONG)HTSSL_VERIFY_NONE,
        HTBT_ERRNOPTR,          (ULONG)&ag_errno_slot,
        TAG_DONE);
    if (!rv) {
        ag_log_fail("HttpBaseTagList", HttpError());
        err = HttpError();
        goto dl_cleanup;
    }

    session = NewHttpSession();
    if (session == NULL) {
        ag_log_fail("NewHttpSession", HttpError());
        err = HttpError();
        goto dl_cleanup;
    }

    rv = SetHttpSessionAttrs(
        session,
        HTSA_USERAGENT,        (ULONG)user_agent,
        HTSA_FOLLOW_REDIRECTS, (ULONG)(args->NOREDIR ? FALSE : TRUE),
        HTSA_MAX_REDIRECTS,    (ULONG)10,
        HTSA_KEEPALIVE,        (ULONG)FALSE,
        HTSA_CONNECT_TIMEOUT,  (ULONG)60,
        HTSA_READ_TIMEOUT,     (ULONG)120,
        TAG_DONE);
    if (!rv) {
        ag_log_fail("SetHttpSessionAttrs", HttpError());
        err = HttpError();
        goto dl_cleanup;
    }

    cookie_jar = ag_setup_cookie_jar(session, fetch_url, args->COOKIEFILE);

    txn = NewHttpTransaction(session);
    if (txn == NULL) {
        ag_log_fail("NewHttpTransaction", HttpError());
        err = HttpError();
        goto dl_cleanup;
    }

    if (args->HEAD) {
        method = (STRPTR)"HEAD";
    }

    rv = SetHttpTransactionAttrs(
        txn,
        HTTA_URL,        (ULONG)fetch_url,
        HTTA_METHOD,     (ULONG)method,
        HTTA_USERAGENT,  (ULONG)user_agent,
        HTTA_NO_CACHE,   (ULONG)TRUE,
        TAG_DONE);
    if (args->HEAD) {
        SetHttpTransactionAttrs(txn, HTTA_NO_BODY, (ULONG)TRUE, TAG_DONE);
    }
    if (!rv) {
        ag_log_fail("SetHttpTransactionAttrs", HttpError());
        err = HttpError();
        goto dl_cleanup;
    }

    if (args->ASYNC) {
        notify_sig = AllocSignal(-1L);
        if (notify_sig == (ULONG)-1) {
            ag_printf("AGet: AllocSignal failed\n");
            err = 20;
            goto dl_cleanup;
        }
        SetHttpTransactionAttrs(
            txn,
            HTTA_NOTIFY_TASK,    (ULONG)FindTask(NULL),
            HTTA_NOTIFY_SIGNAL,  notify_sig,
            TAG_DONE);
    }

    if (args->HEADER != NULL) {
        for (i = 0; args->HEADER[i] != NULL; i++) {
            hdr = args->HEADER[i];
            colon = strchr((const char *)hdr, ':');
            if (colon == NULL) {
                ag_printf("AGet: bad header (missing ':'): %s\n", hdr);
                err = ERROR_HTTP_PROTOCOL;
                goto dl_cleanup;
            }
            *colon = '\0';
            rv = HttpTransactionAddHeader(txn, hdr, colon + 1);
            *colon = ':';
            if (!rv) {
                ag_log_fail("HttpTransactionAddHeader", HttpError());
                err = HttpError();
                goto dl_cleanup;
            }
        }
    }

    ag_log_request_headers(fetch_url, method, user_agent, cookie_jar, args->HEADER);

    if (ag_verbose || ag_test_mode) {
        ag_printf("AGet: --- Request ---\n");
        ag_printf("AGet: %s %s HTTP/1.1\n", method, fetch_url);
        ag_printf("AGet: User-Agent: %s\n", user_agent);
        ag_flush_msg();
    }

    ag_et_init();

    performed = FALSE;
    wait_iter = 0;
    if (args->ASYNC) {
        rv = HttpTransactionPerformAsync(txn);
        if (!rv) {
            ag_log_fail("HttpTransactionPerformAsync", HttpError());
            err = HttpError();
            goto dl_cleanup;
        }
        while (!HttpTransactionIsComplete(txn)) {
            wait_iter++;
            rv = WaitHttpTransaction(txn, 2);
            if (HttpError() == ERROR_HTTP_ABORTED) {
                break;
            }
        }
        performed = TRUE;
    } else {
        rv = HttpTransactionPerform(txn);
        if (!rv) {
            ag_log_fail("HttpTransactionPerform", HttpError());
            err = HttpError();
            goto dl_cleanup;
        }
        performed = TRUE;
    }

    et_perform_ms = ag_et_delta_ms();
    if (ag_verbose || ag_test_mode) {
        ag_et_log("HttpTransactionPerform complete");
    }

    if (!performed) {
        err = ERROR_HTTP_PROTOCOL;
        goto dl_cleanup;
    }

    status = HttpTransactionGetStatusCode(txn);
    clen = HttpTransactionGetContentLength(txn);
    ag_log_peer_cert(txn, fetch_url);

    ag_log_response_headers(txn);

    if (ag_verbose || ag_test_mode) {
        ag_printf("AGet: --- Response ---\n");
        ag_log_txn_getters(txn, "post-perform getters");
    } else {
        ag_log_status_line(status, clen, args->HEAD ? TRUE : FALSE);
    }

    if (status >= 300 && status < 400) {
        if (!ag_quiet || ag_verbose) {
            STRPTR loc;

            loc = HttpTransactionGetRedirectLocation(txn);
            ag_printf("AGet: redirect %ld", status);
            if (loc != NULL && loc[0] != '\0') {
                ag_printf(" -> %s", loc);
            }
            if (args->NOREDIR) {
                ag_printf(" (NOREDIR)");
            }
            ag_printf("\n");
            ag_flush_msg();
        }
        err = 0;
        goto dl_cleanup;
    }
    if (status < 200 || status >= 300) {
        ag_log_fail("HTTP status", ERROR_HTTP_PROTOCOL);
        err = ERROR_HTTP_PROTOCOL;
        goto dl_cleanup;
    }

    if (args->HEAD) {
        if (ag_verbose || ag_test_mode) {
            ag_printf("AGet: HEAD complete status=%ld\n", status);
        } else {
            ag_log_head_summary(txn);
        }
        ag_et_summary(et_perform_ms, 0UL, et_perform_ms, 0);
        err = 0;
        goto dl_cleanup;
    }

    err = ag_read_body(txn, clen, &body_total);
    et_body_ms = ag_et_delta_ms();
    et_total_ms = et_perform_ms + et_body_ms;
    if (err != 0) {
        ag_log_fail("ReadBody", err);
        goto dl_cleanup;
    }
    ag_finish_console_body();

    if (ag_verbose || ag_test_mode) {
        ag_log_txn_getters(txn, "post-body getters");
        ag_printf("AGet: --- End (%ld bytes", body_total);
        if (clen >= 0) {
            ag_printf(", Content-Length=%ld", clen);
        }
        ag_printf(") ---\n");
        ag_flush_msg();
    } else if (!ag_quiet && !ag_headers) {
        ag_printf("AGet: received %ld bytes", body_total);
        if (args->TO != NULL && args->TO[0] != '\0') {
            ag_printf(" -> %s", args->TO);
        }
        ag_printf("\n");
        ag_flush_msg();
    }
    if (err == 0) {
        ag_et_summary(et_perform_ms, et_body_ms, et_total_ms, body_total);
        if (!ag_quiet) {
            ag_printf("AGet: OK\n");
            ag_flush_msg();
        }
    }

dl_cleanup:
    if (notify_sig != (ULONG)-1) {
        FreeSignal(notify_sig);
        notify_sig = (ULONG)-1;
    }
    if (txn != NULL) {
        DisposeHttpTransaction(txn);
    }
    if (session != NULL) {
        if (cookie_jar != NULL) {
            HttpSessionDetachCookieJar(session);
        }
        DisposeHttpSession(session);
    }
    if (cookie_jar != NULL) {
        if (args->COOKIEFILE != NULL && err == 0) {
            SaveHttpCookieJar(cookie_jar, args->COOKIEFILE);
        }
        DisposeHttpCookieJar(cookie_jar);
    }
    if (fetch_url != NULL) {
        FreeMem(fetch_url, (ULONG)strlen((const char *)fetch_url) + 1);
        fetch_url = NULL;
    }
    if (close_out && outfh != 0) {
        Close(outfh);
    }
    if (HttpBase != NULL) {
        CloseLibrary((struct Library *)HttpBase);
        HttpBase = NULL;
    }
    ag_et_fini();
    return err;
}

static VOID
ag_usage(void)
{
    BPTR fh;
    static const char ag_usage_msg[] =
        "AGet - HTTP/HTTPS fetch client (amihttp.library)\n"
        "\n"
        "Usage:\n"
        "  AGet URL=<url> [options]\n"
        "\n"
        "ReadArgs template:\n"
        "  URL,TO/K,USERAGENT/K,HEAD/S,NOREDIR/S,ASYNC/S,VERBOSE/S,QUIET/S,"
        "TEST/S,COOKIEFILE/K,HEADERS/S,HEADER/K/M\n"
        "\n"
        "Required (fetch):\n"
        "  URL            URL to fetch (http:// or https://; scheme defaults to http)\n"
        "\n"
        "Output destination:\n"
        "  TO/K             write decoded body to this file (default: stdout)\n"
        "\n"
        "Request options:\n"
        "  USERAGENT/K      User-Agent request header (default: AGet/1.0)\n"
        "  HEADER/K/M       extra header(s); repeatable \"Name: value\" form\n"
        "  HEAD/S           send HEAD (headers only, no body read)\n"
        "  NOREDIR/S        do not follow 3xx Location redirects\n"
        "  COOKIEFILE/K     load cookies before request; save jar after success\n"
        "\n"
        "Behaviour:\n"
        "  ASYNC/S          HttpTransactionPerformAsync + WaitHttpTransaction\n"
        "\n"
        "Output modes (stderr vs stdout — body never mixed with messages):\n"
        "  (default)        stderr: HTTP status line + TLS cert (https)\n"
        "                   stdout: response body (or TO/K file)\n"
        "  QUIET/S          stderr: errors only; stdout/file: body only\n"
        "  HEADERS/S        stderr: request/response headers (no API trace)\n"
        "  VERBOSE/S        stderr: full amihttp API step trace\n"
        "  TEST/S           offline API self-test (URL/K ignored; fixed fixture)\n"
        "\n"
        "Examples:\n"
        "  AGet URL=https://www.amigazen.com\n"
        "  AGet URL=http://example.com TO=RAM:page.html QUIET\n"
        "  AGet URL=https://host/ HEAD VERBOSE\n"
        "  AGet TEST\n";

    fh = Output();
    Write(fh, (APTR)ag_usage_msg, (ULONG)(sizeof(ag_usage_msg) - 1));
}

int
main(int argc, char **argv)
{
    struct RDArgs *rdargs;
    struct AGetArgs args;
    LONG err;

    (void)argc;
    (void)argv;

    ag_verbose = FALSE;
    ag_quiet = FALSE;
    ag_headers = FALSE;
    ag_test_mode = FALSE;
    ag_errno_slot = 0;

    memset(&args, 0, sizeof(args));
    rdargs = ReadArgs((STRPTR)AGET_TEMPLATE, (LONG *)&args, NULL);
    if (rdargs == NULL) {
        ag_usage();
        return 20;
    }

    if (args.TEST) {
        ag_test_mode = TRUE;
        ag_verbose = TRUE;
        err = ag_selftest();
        FreeArgs(rdargs);
        if (err != 0) {
            ag_msgfh = (BPTR)ErrorOutput();
            if (ag_msgfh == 0) {
                ag_msgfh = Output();
            }
            if (ag_test_fails == 0) {
                ag_log_fail("AGet", err);
            }
            return (err > 0 && err < 256) ? err : 20;
        }
        return 0;
    }

    if (args.URL == NULL || args.URL[0] == '\0') {
        ag_usage();
        FreeArgs(rdargs);
        return 20;
    }

    ag_verbose = FALSE;
    ag_quiet = FALSE;
    ag_headers = (BOOL)args.HEADERS;
    if (args.VERBOSE) {
        ag_verbose = TRUE;
    } else if (args.QUIET) {
        ag_quiet = TRUE;
    }

    err = ag_download(&args);
    FreeArgs(rdargs);

    if (err != 0) {
        ag_msgfh = (BPTR)ErrorOutput();
        if (ag_msgfh == 0) {
            ag_msgfh = Output();
        }
        ag_log_fail("AGet", err);
        return (err > 0 && err < 256) ? err : 20;
    }
    return 0;
}
