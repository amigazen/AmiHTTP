/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * AGet.c - wget-style HTTP/HTTPS client for AmigaOS (amihttp.library).
 *
 * ReadArgs template (must match ag_usage_msg):
 *   URL,TO/K,USERAGENT/K,HEADER/K,HEAD/S,NOREDIR/S,ASYNC/S,
 *   VERBOSE/S,QUIET/S,TEST/S,COOKIEFILE/K
 *
 * Output routing (AmigaDOS):
 *   - Response body  -> stdout, or TO/K file when given
 *   - Status/errors  -> stderr (ErrorOutput), never mixed into body stream
 *
 * Modes (QUIET and VERBOSE are mutually exclusive; TEST implies VERBOSE):
 *   Default  - one-line HTTP status on stderr; TLS cert summary for https;
 *              body to stdout or TO/K
 *   QUIET/S  - body (or TO file) only; stderr used for errors only
 *   VERBOSE/S- step-by-step amihttp API trace on stderr
 *   TEST/S   - VERBOSE plus Tier0/URL/cookie/Tier3 API smoke tests, then fetch
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

#include <libraries/amihttp.h>
#include <proto/amihttp.h>
#include <proto/alib.h>


static const char version_tag[] = "\0$VER: AGet 1.0 (22.6.26)";
static const char stack_cookie[] = "$STACK: 4096";

#define AGET_TEMPLATE \
    "URL," \
    "TO/K," \
    "USERAGENT/K," \
    "HEADER/K," \
    "HEAD/S," \
    "NOREDIR/S," \
    "ASYNC/S," \
    "VERBOSE/S," \
    "QUIET/S," \
    "TEST/S," \
    "COOKIEFILE/K"

struct AGetArgs
{
    STRPTR  URL;
    STRPTR  TO;
    STRPTR  USERAGENT;
    STRPTR *HEADER;
    LONG    HEAD;
    LONG    NOREDIR;
    LONG    ASYNC;
    LONG    VERBOSE;
    LONG    QUIET;
    LONG    TEST;
    STRPTR  COOKIEFILE;
};

static ULONG  ag_step;
static LONG   ag_errno_slot;
static BPTR   ag_msgfh;
static BPTR   ag_bodyfh;
static BOOL   ag_verbose;
static BOOL   ag_quiet;
static BOOL   ag_test_mode;

#define AG_EMPTY_STR    ((STRPTR)"")

static VOID ag_printf(STRPTR fmt, ...);

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

    if (ag_quiet && !ag_verbose) {
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

    ag_step_log("Tier0: HttpError baseline");
    ag_log_errno("initial");

    ag_step_log("Tier0: SetHttpError round-trip");
    prev = SetHttpError(ERROR_HTTP_PROTOCOL);
    ag_log_long("SetHttpError(PROTOCOL) prev", prev);
    code = HttpError();
    ag_log_long("HttpError after set", code);
    prev = SetHttpError(0);
    ag_log_long("SetHttpError(0) prev", prev);

    ag_step_log("Tier0: HttpGetErrorString samples");
    ag_log_str("HttpGetErrorString(0)", HttpGetErrorString(0));
    ag_log_str("HttpGetErrorString(8713)",
        HttpGetErrorString(ERROR_HTTP_INVALID_HANDLE));

    ag_step_log("Tier0: HttpFault formatting");
    flen = HttpFault(ERROR_HTTP_DNS_FAILED, (STRPTR)"lookup",
        (STRPTR)fbuf, (LONG)sizeof(fbuf));
    ag_printf("AGet:     HttpFault -> len=%ld \"%s\"\n", flen, fbuf);
    ag_log_errno("after HttpFault");
}

static VOID
ag_test_url_utils(STRPTR url)
{
    struct ParsedUrl *pu;
    STRPTR rebuilt;
    STRPTR enc;
    STRPTR dec;
    STRPTR penc;
    STRPTR part;
    struct List pairs;
    struct HttpQueryPair qp1;
    struct HttpQueryPair qp2;
    STRPTR qstr;

    ag_step_log("URL: ParseHttpUrl");
    pu = ParseHttpUrl(url);
    ag_log_ptr("ParseHttpUrl", "pu", pu);
    ag_log_errno("after ParseHttpUrl");
    ag_log_parsed_url(pu);

    if (pu != NULL) {
        ag_step_log("URL: BuildHttpUrl round-trip");
        rebuilt = BuildHttpUrl(pu);
        ag_log_str("BuildHttpUrl", rebuilt);
        if (rebuilt != NULL) {
            ag_free_str(rebuilt);
        }

        ag_step_log("URL: URI part helpers");
        part = HttpUriSchemePart(url);
        ag_log_str("HttpUriSchemePart", part);
        ag_free_str(part);
        part = HttpUriHostPart(url);
        ag_log_str("HttpUriHostPart", part);
        ag_free_str(part);
        part = HttpUriAuthorityPart(url);
        ag_log_str("HttpUriAuthorityPart", part);
        ag_free_str(part);
        part = HttpUriPathPart(url);
        ag_log_str("HttpUriPathPart", part);
        ag_free_str(part);
        part = HttpUriFilePart(url);
        ag_log_str("HttpUriFilePart", part);
        ag_free_str(part);
        part = HttpUriParentPart(url);
        ag_log_str("HttpUriParentPart", part);
        ag_free_str(part);
        part = HttpUriQueryPart(url);
        ag_log_str("HttpUriQueryPart", part);
        ag_free_str(part);

        ag_step_log("URL: encode/decode helpers");
        enc = HttpUrlEncode((STRPTR)"hello world&foo=bar");
        ag_log_str("HttpUrlEncode", enc);
        if (enc != NULL) {
            dec = HttpUrlDecode(enc);
            ag_log_str("HttpUrlDecode", dec);
            ag_free_str(dec);
            ag_free_str(enc);
        }
        penc = HttpPathEncode((STRPTR)"/a path/file.html");
        ag_log_str("HttpPathEncode", penc);
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
        ag_free_str(qstr);

        ag_step_log("URL: DisposeHttpUrl");
        DisposeHttpUrl(pu);
        ag_log_errno("after DisposeHttpUrl");
    }
}

static struct HttpCookieJar *
ag_setup_cookie_jar(struct HttpSession *session, STRPTR url, STRPTR cookiefile)
{
    struct HttpCookieJar *jar;
    STRPTR cstr;
    LONG rv;

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
    } else if (ag_test_mode) {
        ag_step_log("Cookie: SetHttpCookie");
        rv = SetHttpCookie(jar,
            (STRPTR)"test=value; Domain=.example.com; Path=/");
        ag_log_bool("SetHttpCookie", rv);

        ag_step_log("Cookie: GetHttpCookieString");
        cstr = GetHttpCookieString(jar, url);
        ag_log_str("GetHttpCookieString", cstr);

        ag_step_log("Cookie: SaveHttpCookieJar");
        rv = SaveHttpCookieJar(jar, (STRPTR)"T:aget_cookies.txt");
        ag_log_bool("SaveHttpCookieJar", rv);

        ag_step_log("Cookie: LoadHttpCookieJar");
        rv = LoadHttpCookieJar(jar, (STRPTR)"T:aget_cookies.txt");
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

static VOID
ag_test_tier3_stubs(struct HttpSession *session)
{
    struct HttpConnection *conn;
    LONG rv;
    BOOL alive;
    UBYTE buf[64];

    ag_step_log("Tier3: OpenHttpConnection (stub)");
    conn = OpenHttpConnection(session, (STRPTR)"example.com", 80, FALSE);
    ag_log_ptr("OpenHttpConnection", "conn", conn);
    ag_log_errno("after OpenHttpConnection");
    if (conn == NULL) {
        return;
    }

    alive = HttpConnectionIsAlive(conn);
    ag_log_bool("HttpConnectionIsAlive", alive ? 1 : 0);

    rv = HttpConnectionWrite(conn, (APTR)"test", 4);
    ag_log_long("HttpConnectionWrite", rv);
    ag_log_errno("after HttpConnectionWrite");

    rv = HttpConnectionRead(conn, (APTR)buf, (ULONG)sizeof(buf));
    ag_log_long("HttpConnectionRead", rv);

    ResetHttpConnection(conn);
    CloseHttpConnection(conn);
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

static LONG
ag_read_body(struct HttpTransaction *txn, LONG expect_cl, LONG *out_total)
{
    UBYTE buf[8192];
    LONG n;
    LONG body_total;
    LONG chunk;

    body_total = 0;
    chunk = 0;
    ag_step_log("Tier2: HttpTransactionReadBody loop");

    for (;;) {
        chunk++;
        if (ag_verbose || ag_test_mode) {
            ag_printf("AGet:     ReadBody chunk %ld buf=%ld txn=%lx\n",
                chunk, (LONG)sizeof(buf), (ULONG)txn);
            ag_flush_msg();
        }

        n = HttpTransactionReadBody(txn, (APTR)buf, (ULONG)sizeof(buf));
        if (ag_verbose || ag_test_mode) {
            ag_printf("AGet:     HttpTransactionReadBody -> %ld\n", n);
            ag_printf("AGet:     HttpTransactionGetBytesReceived -> %ld\n",
                (LONG)HttpTransactionGetBytesReceived(txn));
            ag_log_errno("after ReadBody");
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
    if (ag_quiet && !ag_verbose) {
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

    if (ag_quiet && !ag_verbose) {
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
    STRPTR hdr;
    STRPTR colon;
    LONG err;
    LONG status;
    LONG body_total;
    LONG clen;
    LONG rv;
    LONG wait_iter;
    LONG i;
    BOOL performed;
    BPTR outfh;
    BOOL close_out;

    session = NULL;
    txn = NULL;
    cookie_jar = NULL;
    outfh = 0;
    close_out = FALSE;
    err = 0;
    body_total = 0;
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

    if (ag_verbose || ag_test_mode) {
        ag_printf("AGet: url=\"%s\" to=%s ua=\"%s\"\n",
            args->URL,
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

    if (ag_test_mode) {
        ag_test_tier0();
        ag_test_url_utils(args->URL);
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
        HTSA_KEEPALIVE,        (ULONG)TRUE,
        HTSA_CONNECT_TIMEOUT,  (ULONG)60,
        HTSA_READ_TIMEOUT,     (ULONG)120,
        HTSA_ACCEPT_ENCODING,  (ULONG)"gzip, deflate",
        TAG_DONE);
    if (!rv) {
        ag_log_fail("SetHttpSessionAttrs", HttpError());
        err = HttpError();
        goto dl_cleanup;
    }

    cookie_jar = ag_setup_cookie_jar(session, args->URL, args->COOKIEFILE);
    if (ag_test_mode) {
        ag_test_tier3_stubs(session);
    }

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
        HTTA_URL,        (ULONG)args->URL,
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
    } else if (ag_test_mode) {
        HttpTransactionAddHeader(txn,
            (STRPTR)"X-AGet-Test", (STRPTR)"1");
    }

    if (ag_verbose || ag_test_mode) {
        ag_printf("AGet: --- Request ---\n");
        ag_printf("AGet: %s %s HTTP/1.1\n", method, args->URL);
        ag_printf("AGet: User-Agent: %s\n", user_agent);
        ag_flush_msg();
    }

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

    if (!performed) {
        err = ERROR_HTTP_PROTOCOL;
        goto dl_cleanup;
    }

    status = HttpTransactionGetStatusCode(txn);
    clen = HttpTransactionGetContentLength(txn);
    ag_log_peer_cert(txn, args->URL);

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
        err = 0;
        goto dl_cleanup;
    }

    err = ag_read_body(txn, clen, &body_total);
    if (err != 0) {
        ag_log_fail("ReadBody", err);
        goto dl_cleanup;
    }

    if (ag_verbose || ag_test_mode) {
        ag_log_txn_getters(txn, "post-body getters");
        ag_printf("AGet: --- End (%ld bytes", body_total);
        if (clen >= 0) {
            ag_printf(", Content-Length=%ld", clen);
        }
        ag_printf(") ---\n");
        ag_flush_msg();
    } else if (!ag_quiet) {
        ag_printf("AGet: received %ld bytes", body_total);
        if (args->TO != NULL && args->TO[0] != '\0') {
            ag_printf(" -> %s", args->TO);
        }
        ag_printf("\n");
        ag_flush_msg();
    }

dl_cleanup:
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
    if (close_out && outfh != 0) {
        Close(outfh);
    }
    if (HttpBase != NULL) {
        CloseLibrary((struct Library *)HttpBase);
        HttpBase = NULL;
    }
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
        "  URL,TO/K,USERAGENT/K,HEADER/K,HEAD/S,NOREDIR/S,ASYNC/S,"
        "VERBOSE/S,QUIET/S,TEST/S,COOKIEFILE/K\n"
        "\n"
        "Required:\n"
        "  URL              http:// or https:// URL to fetch\n"
        "\n"
        "Output destination:\n"
        "  TO/K             write decoded body to this file (default: stdout)\n"
        "\n"
        "Request options:\n"
        "  USERAGENT/K      User-Agent request header (default: AGet/1.0)\n"
        "  HEADER/K         extra header, repeatable; use \"Name: value\" form\n"
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
        "  VERBOSE/S        stderr: full amihttp API step trace\n"
        "  TEST/S           VERBOSE + Tier0/URL/cookie/Tier3 API smoke tests\n"
        "\n"
        "Examples:\n"
        "  AGet URL=https://www.amigazen.com\n"
        "  AGet URL=http://example.com TO=RAM:page.html QUIET\n"
        "  AGet URL=https://host/ HEAD VERBOSE\n"
        "  AGet URL=https://host/ TEST\n";

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
    ag_test_mode = FALSE;
    ag_errno_slot = 0;

    memset(&args, 0, sizeof(args));
    rdargs = ReadArgs((STRPTR)AGET_TEMPLATE, (LONG *)&args, NULL);
    if (rdargs == NULL) {
        ag_usage();
        return 20;
    }

    if (args.URL == NULL || args.URL[0] == '\0') {
        ag_usage();
        FreeArgs(rdargs);
        return 20;
    }

    ag_verbose = FALSE;
    ag_quiet = FALSE;
    if (args.TEST) {
        ag_test_mode = TRUE;
        ag_verbose = TRUE;
    } else if (args.VERBOSE) {
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
    if (ag_verbose || ag_test_mode) {
        ag_printf("AGet: OK\n");
    }
    return 0;
}
