/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * HttpStream.c - HTTP/HTTPS live stream client (amihttp.library Tier 2).
 *
 * Fetches a URL and copies the response entity body to stdout or TO/K as
 * chunks arrive (HttpTransactionPerform + HttpTransactionReadBody loop).
 * Intended for ICEcast/Shoutcast radio, HLS segment URLs, and other
 * long-lived or chunked HTTP responses where the caller pipes stdout to a
 * player or file recorder.
 *
 * ReadArgs template (must match hs_usage_msg):
 *   URL,TO/K,USERAGENT/K,ACCEPT/K,HEADER/K/M,CAFILE/K,INSECURE/S,
 *   DURATION/K,STATS/K,QUIET/S,VERBOSE/S,ASYNC/S,GZIP/S
 *
 * Output routing:
 *   - Response body  -> stdout or TO/K (binary-safe; no trailing newline)
 *   - Status/stats   -> stderr (ErrorOutput), never mixed into body stream
 *
 * Defaults tuned for live media:
 *   - Accept-Encoding disabled (no gzip buffering on infinite streams)
 *   - Keep-alive off (one long response per connection)
 *   - Read timeout 3600 s (override with session attrs if needed)
 *   - SIGBREAKF_CTRL_C abort via HTBT_BREAKMASK
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <devices/timer.h>
#include <dos/dos.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <proto/dos.h>
#include <proto/exec.h>

#include <libraries/amihttp.h>
#include <proto/amihttp.h>

static const char version_tag[] = "\0$VER: HttpStream 1.0 (28.6.2026)";
static const char stack_cookie[] = "$STACK: 16384";

#define HS_TEMPLATE \
    "URL," \
    "TO/K," \
    "USERAGENT/K," \
    "ACCEPT/K," \
    "HEADER/K/M," \
    "CAFILE/K," \
    "INSECURE/S," \
    "DURATION/K," \
    "STATS/K," \
    "QUIET/S," \
    "VERBOSE/S," \
    "ASYNC/S," \
    "GZIP/S"

#define HS_DEFAULT_CA_NAME   "cacert.pem"
#define HS_READ_BUF          8192
#define HS_DEFAULT_UA        "HttpStream/1.0"
#define HS_DEFAULT_ACCEPT    "*/*"
#define HS_DEFAULT_READ_TO   3600UL
#define HS_DEFAULT_STATS     5UL

struct HttpStreamArgs
{
    STRPTR  URL;
    STRPTR  TO;
    STRPTR  USERAGENT;
    STRPTR  ACCEPT;
    STRPTR *HEADER;
    STRPTR  CAFILE;
    LONG    INSECURE;
    STRPTR  DURATION;
    STRPTR  STATS;
    LONG    QUIET;
    LONG    VERBOSE;
    LONG    ASYNC;
    LONG    GZIP;
};

static BPTR   hs_msgfh;
static BPTR   hs_bodyfh;
static BOOL   hs_verbose;
static BOOL   hs_quiet;

static VOID hs_printf(STRPTR fmt, ...);
static VOID hs_flush_msg(void);
static VOID hs_flush_body(void);
static LONG hs_open_output(struct HttpStreamArgs *args, BPTR *outfh,
    BOOL *close_out);
static BOOL hs_path_exists(STRPTR path);
static VOID hs_ca_build_path(STRPTR spec, char *buf, ULONG buflen);
static LONG hs_tls_configure(struct HttpStreamArgs *args, char *ca_buf,
    ULONG ca_buflen, ULONG *out_verify);
static LONG hs_write_all(BPTR fh, APTR data, LONG len);
static ULONG hs_parse_ulong(STRPTR s, ULONG defval);
static ULONG hs_wall_secs(struct DateStamp *start);
static VOID hs_log_fail(STRPTR label, LONG code);
static VOID hs_log_status(struct HttpTransaction *txn);
static VOID hs_log_stats(ULONG bytes, ULONG elapsed, STRPTR prefix);
static LONG hs_stream_body(struct HttpTransaction *txn, ULONG max_secs,
    ULONG stats_secs, ULONG *out_bytes);
static LONG hs_run(struct HttpStreamArgs *args);
static VOID hs_usage(void);

static VOID
hs_printf(STRPTR fmt, ...)
{
    char buf[1024];
    va_list ap;
    LONG n;

    va_start(ap, fmt);
    vsprintf(buf, (const char *)fmt, ap);
    va_end(ap);
    n = (LONG)strlen(buf);
    if (n > 0 && hs_msgfh != 0) {
        Write(hs_msgfh, buf, n);
    }
}

static VOID
hs_flush_msg(void)
{
    if (hs_msgfh != 0) {
        Flush(hs_msgfh);
    }
}

static VOID
hs_flush_body(void)
{
    if (hs_bodyfh != 0) {
        Flush(hs_bodyfh);
    }
}

static LONG
hs_open_output(struct HttpStreamArgs *args, BPTR *outfh, BOOL *close_out)
{
    hs_msgfh = (BPTR)ErrorOutput();
    if (hs_msgfh == 0) {
        hs_msgfh = Output();
    }
    *outfh = 0;
    *close_out = FALSE;
    if (args->TO != NULL && args->TO[0] != '\0') {
        *outfh = Open(args->TO, MODE_NEWFILE);
        if (*outfh == 0) {
            hs_printf("HttpStream: cannot create output file \"%s\"\n",
                args->TO);
            hs_bodyfh = 0;
            return ERROR_HTTP_WRITE_FAILED;
        }
        *close_out = TRUE;
        hs_bodyfh = *outfh;
    } else {
        hs_bodyfh = Output();
    }
    return 0;
}

static BOOL
hs_path_exists(STRPTR path)
{
    BPTR lock;

    if (path == NULL || path[0] == '\0') {
        return FALSE;
    }
    lock = Lock(path, ACCESS_READ);
    if (lock == (BPTR)0) {
        return FALSE;
    }
    UnLock(lock);
    return TRUE;
}

static VOID
hs_ca_build_path(STRPTR spec, char *buf, ULONG buflen)
{
    BPTR prog;
    char dir[512];
    ULONG n;
    ULONG dlen;
    BOOL need_sep;

    if (buf == NULL || buflen == 0) {
        return;
    }
    buf[0] = '\0';
    if (spec == NULL || spec[0] == '\0') {
        spec = (STRPTR)HS_DEFAULT_CA_NAME;
    }
    if (strchr((const char *)spec, ':') != NULL) {
        n = 0;
        while (spec[n] != '\0' && n + 1 < buflen) {
            buf[n] = (char)spec[n];
            n++;
        }
        buf[n] = '\0';
        return;
    }
    prog = GetProgramDir();
    if (prog != (BPTR)0) {
        if (NameFromLock(prog, dir, (LONG)sizeof(dir))) {
            dlen = (ULONG)strlen(dir);
            need_sep = TRUE;
            if (dlen > 0 && (dir[dlen - 1] == ':' || dir[dlen - 1] == '/')) {
                need_sep = FALSE;
            }
            n = 0;
            while (n < dlen && n + 1 < buflen) {
                buf[n] = dir[n];
                n++;
            }
            if (need_sep && n + 1 < buflen) {
                buf[n++] = '/';
            }
            dlen = 0;
            while (spec[dlen] != '\0' && n + 1 < buflen) {
                buf[n++] = (char)spec[dlen++];
            }
            buf[n] = '\0';
            UnLock(prog);
            return;
        }
        UnLock(prog);
    }
    n = 0;
    while (spec[n] != '\0' && n + 1 < buflen) {
        buf[n] = (char)spec[n];
        n++;
    }
    buf[n] = '\0';
}

static LONG
hs_tls_configure(struct HttpStreamArgs *args, char *ca_buf, ULONG ca_buflen,
    ULONG *out_verify)
{
    STRPTR spec;

    if (out_verify == NULL || ca_buf == NULL || ca_buflen == 0) {
        return ERROR_HTTP_INVALID_HANDLE;
    }
    ca_buf[0] = '\0';
    if (args != NULL && args->INSECURE) {
        *out_verify = HTSSL_VERIFY_NONE;
        return 0;
    }
    if (args != NULL && args->CAFILE != NULL && args->CAFILE[0] != '\0') {
        spec = args->CAFILE;
    } else {
        spec = (STRPTR)HS_DEFAULT_CA_NAME;
    }
    hs_ca_build_path(spec, ca_buf, ca_buflen);
    if (!hs_path_exists((STRPTR)ca_buf)) {
        hs_printf("HttpStream: CA bundle not found: \"%s\"\n", ca_buf);
        hs_printf("HttpStream: copy cacert.pem beside HttpStream, "
            "CAFILE=<path>, or INSECURE/S\n");
        hs_flush_msg();
        return ERROR_HTTP_SSL_VERIFY;
    }
    *out_verify = HTSSL_VERIFY_PEER;
    return 0;
}

static LONG
hs_write_all(BPTR fh, APTR data, LONG len)
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

static ULONG
hs_parse_ulong(STRPTR s, ULONG defval)
{
    ULONG val;
    ULONG n;

    if (s == NULL || s[0] == '\0') {
        return defval;
    }
    val = 0;
    n = 0;
    while (s[n] >= '0' && s[n] <= '9') {
        val = val * 10UL + (ULONG)(s[n] - '0');
        n++;
    }
    if (n == 0) {
        return defval;
    }
    return val;
}

/*
 * Elapsed whole seconds since start DateStamp (50 Hz ds_Tick).
 */
static ULONG
hs_wall_secs(struct DateStamp *start)
{
    struct DateStamp now;
    LONG days;
    LONG mins;
    ULONG secs;

    if (start == NULL) {
        return 0;
    }
    DateStamp(&now);
    days = now.ds_Days - start->ds_Days;
    mins = now.ds_Minute - start->ds_Minute;
    if (mins < 0) {
        mins += 1440;
        days--;
    }
    secs = (ULONG)days * 86400UL + (ULONG)mins * 60UL;
    if (now.ds_Tick >= start->ds_Tick) {
        secs += (ULONG)(now.ds_Tick - start->ds_Tick) / 50UL;
    } else if (secs > 0) {
        secs -= 1UL;
        secs += (ULONG)(50 + now.ds_Tick - start->ds_Tick) / 50UL;
    }
    return secs;
}

static VOID
hs_log_fail(STRPTR label, LONG code)
{
    char buf[128];

    HttpFault(code, label, (STRPTR)buf, (LONG)sizeof(buf));
    hs_printf("HttpStream: %s (HttpError=%ld)\n", buf, code);
    hs_flush_msg();
}

static VOID
hs_log_status(struct HttpTransaction *txn)
{
    LONG status;
    STRPTR ctype;
    STRPTR clen_hdr;
    LONG clen;

    if (txn == NULL || hs_quiet) {
        return;
    }
    status = HttpTransactionGetStatusCode(txn);
    ctype = HttpTransactionRespHeader(txn, (STRPTR)"Content-Type");
    clen = HttpTransactionGetContentLength(txn);
    clen_hdr = HttpTransactionRespHeader(txn, (STRPTR)"Transfer-Encoding");
    hs_printf("HttpStream: HTTP %ld", status);
    if (ctype != NULL && ctype[0] != '\0') {
        hs_printf(" %s", ctype);
    }
    if (clen >= 0) {
        hs_printf(" len=%ld", clen);
    } else if (clen_hdr != NULL) {
        hs_printf(" %s", clen_hdr);
    } else {
        hs_printf(" (live)");
    }
    hs_printf("\n");
    hs_flush_msg();
}

static VOID
hs_log_stats(ULONG bytes, ULONG elapsed, STRPTR prefix)
{
    ULONG kbps;
    ULONG kbytes;

    if (hs_quiet || elapsed == 0) {
        return;
    }
    kbytes = bytes / 1024UL;
    kbps = (bytes * 8UL) / elapsed / 1024UL;
    if (prefix != NULL) {
        hs_printf("HttpStream: %s ", prefix);
    } else {
        hs_printf("HttpStream: ");
    }
    hs_printf("%lu KiB in %lu s (~%lu kbit/s)\n",
        (unsigned long)kbytes, (unsigned long)elapsed, (unsigned long)kbps);
    hs_flush_msg();
}

/*
 * ReadBody loop: write each chunk to hs_bodyfh and Flush immediately so
 * downstream pipes and players receive data with minimal latency.
 */
static LONG
hs_stream_body(struct HttpTransaction *txn, ULONG max_secs,
    ULONG stats_secs, ULONG *out_bytes)
{
    UBYTE buf[HS_READ_BUF];
    struct DateStamp t0;
    struct DateStamp t_stats;
    LONG n;
    ULONG total;
    ULONG elapsed;
    ULONG since_stats;

    total = 0;
    t0.ds_Days = 0;
    t0.ds_Minute = 0;
    t0.ds_Tick = 0;
    t_stats = t0;
    DateStamp(&t0);
    t_stats = t0;

    for (;;) {
        elapsed = hs_wall_secs(&t0);
        if (max_secs > 0 && elapsed >= max_secs) {
            if (!hs_quiet) {
                hs_printf("HttpStream: duration limit %lu s reached\n",
                    (unsigned long)max_secs);
                hs_flush_msg();
            }
            break;
        }

        n = HttpTransactionReadBody(txn, (APTR)buf, (ULONG)sizeof(buf));
        if (n == 0) {
            if (HttpError() != 0) {
                return HttpError();
            }
            if (HttpTransactionGetLastError(txn) != 0) {
                return HttpTransactionGetLastError(txn);
            }
            break;
        }
        if (n < 0 || n > (LONG)sizeof(buf)) {
            return ERROR_HTTP_READ_FAILED;
        }
        if (hs_write_all(hs_bodyfh, (APTR)buf, n) != 0) {
            return ERROR_HTTP_WRITE_FAILED;
        }
        hs_flush_body();
        total += (ULONG)n;

        if (stats_secs > 0 && !hs_quiet) {
            since_stats = hs_wall_secs(&t_stats);
            if (since_stats >= stats_secs) {
                hs_log_stats(total, hs_wall_secs(&t0), (STRPTR)"stream");
                DateStamp(&t_stats);
            }
        }
    }

    if (out_bytes != NULL) {
        *out_bytes = total;
    }
    return 0;
}

static LONG
hs_run(struct HttpStreamArgs *args)
{
    struct HttpSession *session;
    struct HttpTransaction *txn;
    char ca_path[512];
    STRPTR user_agent;
    STRPTR accept;
    STRPTR hdr;
    STRPTR colon;
    ULONG ssl_verify;
    ULONG max_secs;
    ULONG stats_secs;
    ULONG notify_sig;
    ULONG body_bytes;
    ULONG stream_secs;
    BPTR outfh;
    BOOL close_out;
    LONG rv;
    LONG status;
    LONG err;
    LONG i;
    struct DateStamp stream_start;
    struct HttpTiming timing;

    session = NULL;
    txn = NULL;
    notify_sig = (ULONG)-1;
    outfh = 0;
    close_out = FALSE;
    body_bytes = 0;
    ssl_verify = HTSSL_VERIFY_PEER;
    ca_path[0] = '\0';
    max_secs = hs_parse_ulong(args->DURATION, 0);
    stats_secs = hs_parse_ulong(args->STATS, HS_DEFAULT_STATS);

    if (args->URL == NULL || args->URL[0] == '\0') {
        return ERROR_HTTP_INVALID_URL;
    }

    err = hs_open_output(args, &outfh, &close_out);
    if (err != 0) {
        return err;
    }

    HttpBase = OpenLibrary(AMIHTTPNAME, AMIHTTPVERSION);
    if (HttpBase == NULL) {
        hs_printf("HttpStream: amihttp.library not found\n");
        hs_flush_msg();
        err = 20;
        goto hs_cleanup;
    }

    HttpBaseTags(
        HTBT_BREAKMASK, (ULONG)SIGBREAKF_CTRL_C,
        TAG_DONE);

    err = hs_tls_configure(args, ca_path, (ULONG)sizeof(ca_path), &ssl_verify);
    if (err != 0) {
        goto hs_cleanup;
    }

    session = NewHttpSession();
    if (session == NULL) {
        hs_log_fail("NewHttpSession", HttpError());
        err = HttpError();
        goto hs_cleanup;
    }

    user_agent = HS_DEFAULT_UA;
    if (args->USERAGENT != NULL && args->USERAGENT[0] != '\0') {
        user_agent = args->USERAGENT;
    }
    accept = HS_DEFAULT_ACCEPT;
    if (args->ACCEPT != NULL && args->ACCEPT[0] != '\0') {
        accept = args->ACCEPT;
    }

    rv = SetHttpSessionAttrs(
        session,
        HTSA_USERAGENT,        (ULONG)user_agent,
        HTSA_FOLLOW_REDIRECTS, (ULONG)TRUE,
        HTSA_MAX_REDIRECTS,    (ULONG)5,
        HTSA_KEEPALIVE,        (ULONG)FALSE,
        HTSA_CONNECT_TIMEOUT,  (ULONG)30,
        HTSA_READ_TIMEOUT,     (ULONG)HS_DEFAULT_READ_TO,
        HTSA_ACCEPT_ENCODING,  (ULONG)(args->GZIP ? (ULONG)"gzip" : (ULONG)""),
        TAG_DONE);
    if (ssl_verify != HTSSL_VERIFY_NONE && ca_path[0] != '\0') {
        SetHttpSessionAttrs(session,
            HTSA_SSL_VERIFY,     (ULONG)HTSSL_VERIFY_PEER,
            HTSA_CA_BUNDLE_PATH, (ULONG)ca_path,
            TAG_DONE);
    } else if (ssl_verify == HTSSL_VERIFY_NONE) {
        SetHttpSessionAttrs(session,
            HTSA_SSL_VERIFY, (ULONG)HTSSL_VERIFY_NONE,
            TAG_DONE);
    }
    if (!rv) {
        hs_log_fail("SetHttpSessionAttrs", HttpError());
        err = HttpError();
        goto hs_cleanup;
    }

    txn = NewHttpTransaction(session);
    if (txn == NULL) {
        hs_log_fail("NewHttpTransaction", HttpError());
        err = HttpError();
        goto hs_cleanup;
    }

    rv = SetHttpTransactionAttrs(
        txn,
        HTTA_URL,       (ULONG)args->URL,
        HTTA_METHOD,    (ULONG)"GET",
        HTTA_USERAGENT, (ULONG)user_agent,
        HTTA_NO_CACHE,  (ULONG)TRUE,
        TAG_DONE);
    if (!rv) {
        hs_log_fail("SetHttpTransactionAttrs", HttpError());
        err = HttpError();
        goto hs_cleanup;
    }

    if (accept != NULL && accept[0] != '\0') {
        HttpTransactionAddHeader(txn, (STRPTR)"Accept", accept);
    }

    if (args->HEADER != NULL) {
        for (i = 0; args->HEADER[i] != NULL; i++) {
            hdr = args->HEADER[i];
            colon = strchr((const char *)hdr, ':');
            if (colon == NULL) {
                hs_printf("HttpStream: bad header (missing ':'): %s\n", hdr);
                err = ERROR_HTTP_PROTOCOL;
                goto hs_cleanup;
            }
            *colon = '\0';
            rv = HttpTransactionAddHeader(txn, hdr, colon + 1);
            *colon = ':';
            if (!rv) {
                hs_log_fail("HttpTransactionAddHeader", HttpError());
                err = HttpError();
                goto hs_cleanup;
            }
        }
    }

    if (args->ASYNC) {
        notify_sig = AllocSignal(-1L);
        if (notify_sig == (ULONG)-1) {
            hs_printf("HttpStream: AllocSignal failed\n");
            err = 20;
            goto hs_cleanup;
        }
        SetHttpTransactionAttrs(
            txn,
            HTTA_NOTIFY_TASK,   (ULONG)FindTask(NULL),
            HTTA_NOTIFY_SIGNAL, notify_sig,
            TAG_DONE);
    }

    if (hs_verbose) {
        hs_printf("HttpStream: GET %s\n", args->URL);
        hs_printf("HttpStream: Accept: %s\n", accept);
        hs_flush_msg();
    }

    if (args->ASYNC) {
        rv = HttpTransactionPerformAsync(txn);
        if (!rv) {
            hs_log_fail("HttpTransactionPerformAsync", HttpError());
            err = HttpError();
            goto hs_cleanup;
        }
        while (!HttpTransactionIsComplete(txn)) {
            (void)WaitHttpTransaction(txn, 2);
            if (HttpError() == ERROR_HTTP_ABORTED) {
                err = ERROR_HTTP_ABORTED;
                goto hs_cleanup;
            }
        }
    } else {
        rv = HttpTransactionPerform(txn);
        if (!rv) {
            hs_log_fail("HttpTransactionPerform", HttpError());
            err = HttpError();
            goto hs_cleanup;
        }
    }

    status = HttpTransactionGetStatusCode(txn);
    if (status < 200 || status >= 300) {
        hs_log_status(txn);
        hs_log_fail("HTTP status", ERROR_HTTP_PROTOCOL);
        err = ERROR_HTTP_PROTOCOL;
        goto hs_cleanup;
    }

    hs_log_status(txn);

    if (hs_verbose) {
        memset(&timing, 0, sizeof(timing));
        if (HttpTransactionGetTiming(txn, &timing)) {
            hs_printf("HttpStream: connect=%lu ms ttfb=%lu ms\n",
                (unsigned long)timing.ht_ConnectMs,
                (unsigned long)timing.ht_TtfbMs);
            hs_flush_msg();
        }
    }

    stream_start.ds_Days = 0;
    stream_start.ds_Minute = 0;
    stream_start.ds_Tick = 0;
    DateStamp(&stream_start);
    err = hs_stream_body(txn, max_secs, stats_secs, &body_bytes);
    stream_secs = hs_wall_secs(&stream_start);
    if (err != 0) {
        if (err == ERROR_HTTP_ABORTED) {
            if (!hs_quiet) {
                hs_printf("HttpStream: aborted after %lu bytes\n",
                    (unsigned long)body_bytes);
                hs_flush_msg();
            }
        } else {
            hs_log_fail("ReadBody", err);
        }
        goto hs_cleanup;
    }

    if (!hs_quiet) {
        if (stream_secs == 0) {
            stream_secs = 1;
        }
        hs_log_stats(body_bytes, stream_secs, (STRPTR)"done");
        hs_printf("HttpStream: received %lu bytes", (unsigned long)body_bytes);
        if (args->TO != NULL && args->TO[0] != '\0') {
            hs_printf(" -> %s", args->TO);
        }
        hs_printf("\n");
        hs_flush_msg();
    }

hs_cleanup:
    if (notify_sig != (ULONG)-1) {
        FreeSignal(notify_sig);
    }
    if (txn != NULL) {
        DisposeHttpTransaction(txn);
    }
    if (session != NULL) {
        DisposeHttpSession(session);
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
hs_usage(void)
{
    BPTR fh;
    static const char hs_usage_msg[] =
        "HttpStream - HTTP/HTTPS live stream client (amihttp.library)\n"
        "\n"
        "Usage:\n"
        "  HttpStream URL=<url> [options]\n"
        "\n"
        "ReadArgs template:\n"
        "  URL,TO/K,USERAGENT/K,ACCEPT/K,HEADER/K/M,CAFILE/K,INSECURE/S,"
        "DURATION/K,STATS/K,QUIET/S,VERBOSE/S,ASYNC/S,GZIP/S\n"
        "\n"
        "Required:\n"
        "  URL              http:// or https:// stream URL\n"
        "\n"
        "Output:\n"
        "  TO/K             write body to file (default: stdout, binary-safe)\n"
        "\n"
        "Request:\n"
        "  USERAGENT/K      User-Agent header (default: HttpStream/1.0)\n"
        "  ACCEPT/K         Accept header (default: */*)\n"
        "  HEADER/K/M       extra \"Name: value\" headers (repeatable)\n"
        "  GZIP/S           allow gzip Content-Encoding (off by default)\n"
        "\n"
        "TLS:\n"
        "  (default)        VERIFY_PEER with PROGDIR:cacert.pem\n"
        "  CAFILE/K         PEM CA bundle path\n"
        "  INSECURE/S       skip certificate verification\n"
        "\n"
        "Streaming:\n"
        "  DURATION/K       stop after N seconds (0 = until EOF, default)\n"
        "  STATS/K          stderr progress interval seconds (default: 5, 0=off)\n"
        "  ASYNC/S          HttpTransactionPerformAsync + wait\n"
        "\n"
        "Messages:\n"
        "  QUIET/S          stderr errors only; stdout/file is pure media bytes\n"
        "  VERBOSE/S        API trace and timing on stderr\n"
        "\n"
        "Examples:\n"
        "  HttpStream URL=http://ice.example:8000/stream QUIET\n"
        "  HttpStream URL=https://host/live.m3u8 TO=RAM:live.m3u8\n"
        "  HttpStream URL=https://host/seg.ts ACCEPT=video/mp2t DURATION=60\n"
        "  HttpStream URL=http://host/stream | Play16\n";

    fh = Output();
    Write(fh, (APTR)hs_usage_msg, (ULONG)(sizeof(hs_usage_msg) - 1));
}

int
main(int argc, char **argv)
{
    struct RDArgs *rdargs;
    struct HttpStreamArgs args;
    LONG err;

    (void)argc;
    (void)argv;

    hs_verbose = FALSE;
    hs_quiet = FALSE;

    memset(&args, 0, sizeof(args));
    rdargs = ReadArgs((STRPTR)HS_TEMPLATE, (LONG *)&args, NULL);
    if (rdargs == NULL) {
        hs_usage();
        return 20;
    }

    if (args.URL == NULL || args.URL[0] == '\0') {
        hs_usage();
        FreeArgs(rdargs);
        return 20;
    }

    if (args.VERBOSE) {
        hs_verbose = TRUE;
    } else if (args.QUIET) {
        hs_quiet = TRUE;
    }

    err = hs_run(&args);
    FreeArgs(rdargs);

    if (err != 0) {
        return (err > 0 && err < 256) ? err : 20;
    }
    return 0;
}
