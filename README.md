# amihttp.library

This is **AmiHTTP**, an AmigaOS HTTP/HTTPS client stack shared library for Amiga.  
It provides a modern, tiered C API for any application that needs to fetch or submit 
web resources — browsers, download tools, REST clients, WebDAV handlers, and background 
updaters — without embedding a full web browser stack.

## [amigazen project](http://www.amigazen.com)

*A web, suddenly*

*Forty years meditation*

*Minds awaken, free*

**amigazen project** is using modern software development tools and methods to update and rerelease classic Amiga open source software. Projects include a new AWeb, a new Amiga Python 2, and the ToolKit project - a universal SDK for Amiga.

Key to the amigazen project approach is ensuring every project can be built with the same common set of development tools and configurations, so the ToolKit project was created to provide a standard configuration for Amiga development. All *amigazen project* releases will be guaranteed to build against the ToolKit standard so that anyone can download and begin contributing straightaway without having to tailor the toolchain for their own setup.

AmiHTTP is an original work of amigazen project. This software is redistributed on terms described in the documentation, particularly the file LICENSE.md

The amigazen project philosophy philosophy is based on openness:

*Open* to anyone and everyone	- *Open* source and free for all	- *Open* your mind and create!

PRs for all projects are gratefully received at [GitHub](https://github.com/amigazen/). While the focus now is on classic 68k software, it is intended that all amigazen project releases can be ported to other Amiga-like systems including AROS and MorphOS where feasible.

## About amihttp.library

amihttp.library is a **standalone HTTP client** for the Amiga platform.  It
fully wraps `bsdsocket.library` and TLS (`amisslmaster.library` / AmiSSL, or
the compansion 'AmiTLS' library).  Callers hold only opaque handles; sockets, SSL
contexts, connection pools, and wire buffers are never exposed.

Bootstrap is deliberately minimal: `OpenLibrary("amihttp.library", 0L)`
is sufficient.  `bsdsocket.library` opens on first HTTP use;
`amisslmaster.library` and per-task AmiSSL initialisation run on first HTTPS
use.  No separate init or shutdown library call is required.

## Why a separate HTTP stack?

On most platforms, HTTP is a **system or framework service**: macOS has
`URLSession`, Android has OkHttp, Java has Apache HttpClient.  Developers do
not reimplement TCP, TLS, redirects, and chunked encoding inside every
application.

Classic Amiga never had an equivalent.  Each program that talked to the web
tended to:

- Use **bsdsocket** and **AmiSSL** directly (duplicating effort and increasing risk of defects), and also;
- embed HTTP inside a **monolithic browser** (AWeb, IBrowse, Voyager), making reuse by other tools awkward or impossible.

amihttp.library exists to close that gap **in the Amiga way**: a shared library

### Rationale in brief

| Goal | How amihttp addresses it |
|------|--------------------------|
| **Reuse** | One implementation of HTTP/1.1, pooling, gzip, and TLS for browsers, CLI tools, handlers, and daemons |
| **Separation of concerns** | Transport and wire protocol in the library; UI, disk cache, and cookie consent in the application |
| **Stability** | Public SFD and versioned LVOs; internal pool/SSL refactors do not break callers |
| **Testability** | `AGet` and unit-style examples exercise the API without launching a browser |
| **Standards alignment** | Tiered API modelled on industry practice (session → transaction → optional stream connection) |

## API tiers

Public LVOs follow Amiga object-library conventions: type names in constructors
(`NewHttpSession`), `Set*Attrs` for TagItem configuration, and type-qualified
operation names (`HttpTransactionPerform`) to avoid flat-namespace clashes.

| Tier | Objects | Use case |
|------|---------|----------|
| 0 | `HttpBase`, `HttpBaseTagList` | Per-process defaults (timeouts, pool limits, break mask, CA bundle) |
| 1 | `HttpSession`, `HttpCookieJar` | Persistent client settings (User-Agent, proxy, redirects, optional jar) |
| 2 | `HttpTransaction` | **Primary API** — wget, browser fetch, AJAX, REST, conditional GET |
| 3 | `HttpConnection` | WebDAV, streaming PUT, incremental wire I/O, custom protocols |


### Typical Tier 2 flow

```c
HttpBase = OpenLibrary(AMIHTTPNAME, AMIHTTPVERSION);
session = NewHttpSession();
SetHttpSessionAttrs(session,
    HTSA_USERAGENT,        (ULONG)"MyApp/1.0",
    HTSA_FOLLOW_REDIRECTS, (ULONG)TRUE,
    TAG_DONE);
txn = NewHttpTransaction(session);
SetHttpTransactionAttrs(txn,
    HTTA_URL,    (ULONG)"https://www.example.com/",
    HTTA_METHOD, (ULONG)"GET",
    TAG_DONE);
if (HttpTransactionPerform(txn)) {
    LONG n;
    UBYTE buf[8192];
    while ((n = HttpTransactionReadBody(txn, buf, sizeof(buf))) > 0) {
        /* process buf[0..n-1] */
    }
}
DisposeHttpTransaction(txn);
DisposeHttpSession(session);
CloseLibrary(HttpBase);
```

`HttpTransactionPerform` sends the request and parses response headers.
`HttpTransactionReadBody` streams the entity body in caller-supplied buffers;
the library never requires the full response in RAM.  Loop until `ReadBody`
returns 0.

For async completion, set `HTTA_NOTIFY_TASK` and `HTTA_NOTIFY_SIGNAL`, call
`HttpTransactionPerformAsync`, then `WaitHttpTransaction` or `Wait()` on the
notify signal.  See `SDK/Examples/async_demo.c`.

## HTTP and TLS features

amihttp.library implements HTTP/1.1 client behaviour suitable for the modern
web as seen from classic Amiga constraints.

### Protocol support

| Feature | Support | Notes |
|---------|---------|-------|
| HTTP/1.1 requests | ✅ Full | GET, HEAD, POST, PUT, DELETE, PROPFIND, custom methods via `HTTA_METHOD` |
| HTTPS (TLS) | ✅ Full | AmiSSL (OpenSSL) or AmiTLS (BearSSL) build flavours |
| Keep-alive / connection pool | ✅ Full | Per-session pool keyed by host, port, SSL, task serial |
| Redirects (301–308) | ✅ Partial | 301/302/303 → GET; 307/308 method preservation planned |
| Chunked `Transfer-Encoding` | ✅ Full | Decoded transparently in `HttpTransactionReadBody` |
| `Content-Length` clamping | ✅ Full | Body reads never exceed declared length |
| gzip / deflate bodies | ✅ Full | Via **z.library** when `Content-Encoding` negotiated |
| Brotli (`br`) | ❌ | Not yet decoded |
| HTTP proxy | ❌ | Tags stored; CONNECT tunnel not wired |
| HTTP/2 | ❌ | Reserved (`HTBT_HTTP2_ENABLED`, v2) |
| Digest / NTLM auth | ❌ | Basic auth retry only (v1) |
| Range requests | ✅ Tags | `HTTA_RANGE_START` / `HTTA_RANGE_END` |
| Conditional GET | ✅ Tags | `HTTA_IF_NONE_MATCH`, `HTTA_IF_MODIFIED_SINCE` |
| Multipart POST | ✅ Partial | `HTTA_FORM_MULTIPART`, `HTTA_REQUEST_BODY` |

### TLS and certificates

| Feature | Support | Notes |
|---------|---------|-------|
| SNI | ✅ Full | Hostname sent during handshake |
| Peer certificate fields | ✅ Full | `HttpTransactionGetPeerCert()` after HTTPS Perform |
| CA bundle path | ✅ Full | `HTBT_CA_BUNDLE_PATH` (required for AmiTLS) |
| Verify policy | ✅ Tags | `HTSSL_VERIFY_NONE`, `HTSSL_VERIFY_PEER`, `HTSSL_VERIFY_PEER_STRICT` |
| Custom cert hook | ✅ Partial | `HTHK_CERT_VERIFY` slot; integration varies by consumer |

### Client infrastructure

| Feature | Support | Notes |
|---------|---------|-------|
| Cookie jar (in-memory) | ✅ Partial | `Set-Cookie` ingest; load/save to disk not yet implemented |
| URL parse / encode | ✅ Full | `ParseHttpUrl`, `HttpUrlEncode`, `HttpJoinUri`, path helpers |
| Hooks (`CallHookPkt`) | ✅ Partial | `HEADERS_DONE`, `BODY_CHUNK`, `COMPLETE`, `ERROR` wired |
| Async worker + Exec signal | ✅ Full | `PerformAsync` + `HTTA_NOTIFY_*` |
| Ctrl-C during blocking I/O | ✅ Full | `HTBT_BREAKMASK` polled during Perform / ReadBody |
| Timing metrics | ✅ Partial | `HttpTransactionGetTiming` structure; fields populated incrementally |
| Error model | ✅ Full | `HttpError()` / `GetLastError()` vs `GetStatusCode()` intentionally separate |

### Tier 3 (`HttpConnection`)

| LVO | Support | Notes |
|-----|---------|-------|
| `OpenHttpConnection` / `CloseHttpConnection` | ✅ Full | Pooled TCP/TLS handle |
| `HttpConnectionRead` / `Write` | ✅ Full | Raw wire I/O |
| `HttpConnectionReadResponseHeaders` | ✅ Full | Parsed `HttpHeader` list |
| `HttpConnectionRespHeader` / `RespHeaders` | ✅ Full | Query parsed headers |
| `HttpConnectionSendRequest` | ❌ | Stub (`8700`) |
| `HttpConnectionReadBodyChunk` | ❌ | Stub — use Tier 2 `ReadBody` for now |
| `HttpConnectionWriteBodyChunk` | ❌ | Stub |

## Build (AmiSSL configuration)

SAS/C + smake from `Source/lib_source/`:

```
cd Source/lib_source
smake
``` 

## Build (AmiTLS configuration)

SAS/C + smake from `Source/lib_source/`:

```
cd Source/lib_source
smake -f smakefile.amitls
```

## Prequisites/Dependencies

Building AmiHTTP requires:
- SAS/C C Compiler
- NDK 3.2 with system headers found in include: path
- Roadshow SDK with header files found in netinclude: path
- AmiSSL with header files in sslinclude: path
- AmiTLS with header files in include: path
- ZLib z.library with header files in include: path


Two differing TLS backends are supported via alternate smakefiles:

- **AmiSSL** (default, wraps OpenSSL) — `smakefile`
- **AmiTLS** (alternative, wraps BearSSL) — `smakefile.amitls`

Install headers to your SDK:Include_h directory with the `headers` target in the smakefile, or copy
from `SDK/Include_H/`.

Example clients e.g. AGet build from `SDK/Examples/`:

```
cd SDK/Examples
smake
```

## Contact

- At GitHub https://github.com/amigazen/amihttp/
- on the web at http://www.amigazen.com/ (Amiga browser compatible)
- or email aweb@amigazen.com

## Acknowledgements

*Amiga* is a trademark of **Amiga Inc**.

