/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_url.c - URL parse and encoding utilities
 *
 * String formatting uses utility.library SNPrintf/Strncpy/Strncat (RawDoFmt
 * rules: %s %ld %lu only — not full POSIX printf).  Scheme prefix tests use
 * Strnicmp (case-insensitive; RFC 3986).  utility has Strnicmp, not Strncmp.
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <ctype.h>

#include <proto/utility.h>

#include <libraries/amihttp.h>

#include "private/ht_internal.h"

static STRPTR
ht_strchr(STRPTR s, char c)
{
    ULONG i;

    if (s == NULL) {
        return NULL;
    }
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] == (UBYTE)c) {
            return s + i;
        }
    }
    return NULL;
}

static STRPTR
ht_strrchr(STRPTR s, char c)
{
    STRPTR last;
    ULONG i;

    if (s == NULL) {
        return NULL;
    }
    last = NULL;
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] == (UBYTE)c) {
            last = s + i;
        }
    }
    return last;
}

static BOOL
ht_prefix_icmp(STRPTR s, CONST_STRPTR prefix, LONG plen)
{
    if (s == NULL || prefix == NULL || plen <= 0) {
        return FALSE;
    }
    if (Strnicmp(s, prefix, plen) != 0) {
        return FALSE;
    }
    return TRUE;
}

static ULONG
ht_parse_ulong(STRPTR s, STRPTR *end_out)
{
    ULONG val;
    ULONG i;

    val = 0;
    if (s == NULL) {
        if (end_out != NULL) {
            *end_out = s;
        }
        return 0;
    }
    for (i = 0; s[i] >= '0' && s[i] <= '9'; i++) {
        val = val * 10UL + (ULONG)(s[i] - '0');
    }
    if (end_out != NULL) {
        *end_out = s + i;
    }
    return val;
}

static BOOL
ht_url_default_port(struct ParsedUrl *url, ULONG port)
{
    if (url == NULL) {
        return FALSE;
    }
    if (url->pu_IsSecure && port == 443) {
        return TRUE;
    }
    if (!url->pu_IsSecure && port == 80) {
        return TRUE;
    }
    return FALSE;
}

static STRPTR
ht_url_build_from_parsed(struct ParsedUrl *url)
{
    STRPTR out;
    ULONG len;
    STRPTR scheme;
    ULONG port;

    if (url == NULL || url->pu_Host == NULL) {
        return NULL;
    }
    scheme = url->pu_Scheme;
    if (scheme == NULL) {
        scheme = url->pu_IsSecure ? (STRPTR)"https" : (STRPTR)"http";
    }
    port = url->pu_Port;
    len = ht_strlen(scheme) + ht_strlen(url->pu_Host) + 32;
    if (url->pu_Path) {
        len += ht_strlen(url->pu_Path);
    }
    if (url->pu_Query) {
        len += ht_strlen(url->pu_Query) + 1;
    }
    out = (STRPTR)ht_alloc(len, MEMF_CLEAR);
    if (out == NULL) {
        return NULL;
    }
    if (port != 0 && !ht_url_default_port(url, port)) {
        SNPrintf(out, len, (CONST_STRPTR)"%s://%s:%lu", scheme, url->pu_Host, port);
    } else {
        SNPrintf(out, len, (CONST_STRPTR)"%s://%s", scheme, url->pu_Host);
    }
    if (url->pu_Path != NULL) {
        Strncat(out, url->pu_Path, len);
    } else {
        Strncat(out, (CONST_STRPTR)"/", len);
    }
    if (url->pu_Query != NULL && url->pu_Query[0] != '\0') {
        Strncat(out, (CONST_STRPTR)"?", len);
        Strncat(out, url->pu_Query, len);
    }
    return out;
}

static void
ht_url_clear(struct ParsedUrl *pu)
{
    if (pu == NULL) {
        return;
    }
    if (pu->pu_Scheme) {
        ht_free(pu->pu_Scheme);
    }
    if (pu->pu_Host) {
        ht_free(pu->pu_Host);
    }
    if (pu->pu_Path) {
        ht_free(pu->pu_Path);
    }
    if (pu->pu_Query) {
        ht_free(pu->pu_Query);
    }
    if (pu->pu_User) {
        ht_free(pu->pu_User);
    }
    if (pu->pu_Password) {
        ht_free(pu->pu_Password);
    }
    pu->pu_Scheme = NULL;
    pu->pu_Host = NULL;
    pu->pu_Path = NULL;
    pu->pu_Query = NULL;
    pu->pu_User = NULL;
    pu->pu_Password = NULL;
    pu->pu_Port = 0;
    pu->pu_IsSecure = FALSE;
}

VOID
ht_url_free_fields(struct ParsedUrl *pu)
{
    ht_url_clear(pu);
}

static STRPTR
ht_copy_segment(STRPTR start, STRPTR end)
{
    LONG n;

    if (start == NULL) {
        return NULL;
    }
    if (end == NULL) {
        return ht_strdup(start);
    }
    n = (LONG)(end - start);
    if (n < 0) {
        return NULL;
    }
    return ht_strndup(start, n);
}

LONG
ht_url_parse(STRPTR url, struct ParsedUrl *out)
{
    STRPTR u;
    STRPTR p;
    STRPTR q;
    STRPTR r;
    STRPTR slash;
    STRPTR at;
    STRPTR colon;
    ULONG default_port;

    if (url == NULL || out == NULL) {
        return ERROR_HTTP_INVALID_URL;
    }
    out->pu_Scheme = NULL;
    out->pu_Host = NULL;
    out->pu_Path = NULL;
    out->pu_Query = NULL;
    out->pu_User = NULL;
    out->pu_Password = NULL;
    out->pu_Port = 0;
    out->pu_IsSecure = FALSE;
    ht_url_clear(out);

    u = url;
    if (ht_prefix_icmp(u, (CONST_STRPTR)"http://", 7)) {
        out->pu_Scheme = ht_strdup((STRPTR)"http");
        out->pu_IsSecure = FALSE;
        default_port = 80;
        u += 7;
    } else if (ht_prefix_icmp(u, (CONST_STRPTR)"https://", 8)) {
        out->pu_Scheme = ht_strdup((STRPTR)"https");
        out->pu_IsSecure = TRUE;
        default_port = 443;
        u += 8;
    } else {
        return ERROR_HTTP_INVALID_URL;
    }

    p = u;
    at = NULL;
    slash = ht_strchr(u, '/');
    q = ht_strchr(u, '@');
    if (q != NULL && (slash == NULL || q < slash)) {
        at = q;
        p = q + 1;
        colon = ht_strchr(u, ':');
        if (colon != NULL && colon < at) {
            out->pu_User = ht_copy_segment(u, colon);
            out->pu_Password = ht_copy_segment(colon + 1, at);
        } else {
            out->pu_User = ht_copy_segment(u, at);
        }
    }

    colon = ht_strchr(p, ':');
    slash = ht_strchr(p, '/');
    if (colon != NULL && (slash == NULL || colon < slash)) {
        out->pu_Host = ht_copy_segment(p, colon);
        out->pu_Port = ht_parse_ulong(colon + 1, NULL);
        if (slash != NULL) {
            out->pu_Path = ht_strdup(slash);
            r = ht_strchr(slash, '?');
            if (r != NULL) {
                ht_free(out->pu_Path);
                out->pu_Path = ht_copy_segment(slash, r);
                out->pu_Query = ht_strdup(r + 1);
            }
        } else {
            out->pu_Path = ht_strdup((STRPTR)"/");
        }
    } else {
        if (slash != NULL) {
            out->pu_Host = ht_copy_segment(p, slash);
            out->pu_Path = ht_strdup(slash);
            r = ht_strchr(slash, '?');
            if (r != NULL) {
                ht_free(out->pu_Path);
                out->pu_Path = ht_copy_segment(slash, r);
                out->pu_Query = ht_strdup(r + 1);
            }
        } else {
            out->pu_Host = ht_strdup(p);
            out->pu_Path = ht_strdup((STRPTR)"/");
        }
        out->pu_Port = default_port;
    }

    if (out->pu_Host == NULL || out->pu_Path == NULL) {
        ht_url_clear(out);
        return ERROR_HTTP_INVALID_URL;
    }
    return 0;
}

STRPTR
ht_url_encode(STRPTR str)
{
    STRPTR out;
    ULONG outlen;
    ULONG i;
    ULONG o;
    static const char hex[] = "0123456789ABCDEF";

    if (str == NULL) {
        return NULL;
    }
    outlen = 1;
    for (i = 0; str[i] != '\0'; i++) {
        if (isalnum((unsigned char)str[i]) || str[i] == '-' || str[i] == '_' ||
            str[i] == '.' || str[i] == '~') {
            outlen++;
        } else {
            outlen += 3;
        }
    }
    out = (STRPTR)ht_alloc(outlen, MEMF_CLEAR);
    if (out == NULL) {
        return NULL;
    }
    o = 0;
    for (i = 0; str[i] != '\0'; i++) {
        if (isalnum((unsigned char)str[i]) || str[i] == '-' || str[i] == '_' ||
            str[i] == '.' || str[i] == '~') {
            out[o++] = str[i];
        } else {
            out[o++] = '%';
            out[o++] = hex[(str[i] >> 4) & 0x0F];
            out[o++] = hex[str[i] & 0x0F];
        }
    }
    out[o] = '\0';
    return out;
}

STRPTR
ht_url_decode(STRPTR str)
{
    STRPTR out;
    ULONG i;
    ULONG o;
    int hi;
    int lo;

    if (str == NULL) {
        return NULL;
    }
    out = ht_strdup(str);
    if (out == NULL) {
        return NULL;
    }
    o = 0;
    for (i = 0; str[i] != '\0'; i++) {
        if (str[i] == '%' && str[i + 1] != '\0' && str[i + 2] != '\0') {
            hi = str[i + 1];
            lo = str[i + 2];
            if (hi >= '0' && hi <= '9') {
                hi -= '0';
            } else if (hi >= 'A' && hi <= 'F') {
                hi = hi - 'A' + 10;
            } else if (hi >= 'a' && hi <= 'f') {
                hi = hi - 'a' + 10;
            } else {
                out[o++] = str[i];
                continue;
            }
            if (lo >= '0' && lo <= '9') {
                lo -= '0';
            } else if (lo >= 'A' && lo <= 'F') {
                lo = lo - 'A' + 10;
            } else if (lo >= 'a' && lo <= 'f') {
                lo = lo - 'a' + 10;
            } else {
                out[o++] = str[i];
                continue;
            }
            out[o++] = (UBYTE)((hi << 4) | lo);
            i += 2;
        } else if (str[i] == '+') {
            out[o++] = ' ';
        } else {
            out[o++] = str[i];
        }
    }
    out[o] = '\0';
    return out;
}

STRPTR
ht_path_encode(STRPTR path)
{
    return ht_url_encode(path);
}

STRPTR
ht_build_query_string(struct List *pairs)
{
    struct HttpQueryPair *qp;
    STRPTR result;
    ULONG len;
    STRPTR enc;

    if (pairs == NULL) {
        return NULL;
    }
    len = 1;
    for (qp = (struct HttpQueryPair *)pairs->lh_Head;
         qp != NULL && qp->hqp_Node.ln_Succ != NULL;
         qp = (struct HttpQueryPair *)qp->hqp_Node.ln_Succ) {
        enc = ht_url_encode(qp->hqp_Name);
        if (enc) {
            len += ht_strlen(enc) + 1;
            ht_free(enc);
        }
        enc = ht_url_encode(qp->hqp_Value);
        if (enc) {
            len += ht_strlen(enc);
            ht_free(enc);
        }
        len++;
    }
    result = (STRPTR)ht_alloc(len, MEMF_CLEAR);
    if (result == NULL) {
        return NULL;
    }
    result[0] = '\0';
    for (qp = (struct HttpQueryPair *)pairs->lh_Head;
         qp != NULL && qp->hqp_Node.ln_Succ != NULL;
         qp = (struct HttpQueryPair *)qp->hqp_Node.ln_Succ) {
        if (result[0] != '\0') {
            Strncat(result, (CONST_STRPTR)"&", len);
        }
        enc = ht_url_encode(qp->hqp_Name);
        if (enc) {
            Strncat(result, enc, len);
            ht_free(enc);
        }
        Strncat(result, (CONST_STRPTR)"=", len);
        enc = ht_url_encode(qp->hqp_Value);
        if (enc) {
            Strncat(result, enc, len);
            ht_free(enc);
        }
    }
    return result;
}

VOID
ht_peer_cert_free_fields(struct HttpSslPeerCert *cert)
{
    if (cert == NULL) {
        return;
    }
    if (cert->hpc_Subject) {
        ht_free(cert->hpc_Subject);
    }
    if (cert->hpc_Issuer) {
        ht_free(cert->hpc_Issuer);
    }
    if (cert->hpc_CommonName) {
        ht_free(cert->hpc_CommonName);
    }
    if (cert->hpc_NotBefore) {
        ht_free(cert->hpc_NotBefore);
    }
    if (cert->hpc_NotAfter) {
        ht_free(cert->hpc_NotAfter);
    }
    if (cert->hpc_Serial) {
        ht_free(cert->hpc_Serial);
    }
    cert->hpc_Subject = NULL;
    cert->hpc_Issuer = NULL;
    cert->hpc_CommonName = NULL;
    cert->hpc_NotBefore = NULL;
    cert->hpc_NotAfter = NULL;
    cert->hpc_Serial = NULL;
    cert->hpc_VerifyResult = 0;
}

static STRPTR
ht_uri_part_from_parsed(struct ParsedUrl *pu, ULONG part)
{
    STRPTR path;
    STRPTR slash;
    STRPTR q;
    char portbuf[16];
    ULONG buflen;

    if (pu == NULL) {
        return NULL;
    }
    switch (part) {
    case 0:
        return pu->pu_Scheme ? ht_strdup(pu->pu_Scheme) : NULL;
    case 1:
        return pu->pu_Host ? ht_strdup(pu->pu_Host) : NULL;
    case 2:
        if (pu->pu_Port == 0) {
            return NULL;
        }
        SNPrintf((STRPTR)portbuf, (ULONG)sizeof(portbuf),
            (CONST_STRPTR)"%lu", pu->pu_Port);
        return ht_strdup((STRPTR)portbuf);
    case 3:
        return pu->pu_Path ? ht_strdup(pu->pu_Path) : ht_strdup((STRPTR)"/");
    case 4:
        if (pu->pu_Path == NULL || pu->pu_Path[0] == '\0') {
            return ht_strdup((STRPTR)"");
        }
        slash = ht_strrchr(pu->pu_Path, '/');
        if (slash == NULL || slash[1] == '\0') {
            return ht_strdup((STRPTR)"");
        }
        return ht_strdup(slash + 1);
    case 5:
        return pu->pu_Query ? ht_strdup(pu->pu_Query) : ht_strdup((STRPTR)"");
    case 6:
        if (pu->pu_Path == NULL || pu->pu_Path[0] == '\0') {
            return ht_strdup((STRPTR)"/");
        }
        path = ht_strdup(pu->pu_Path);
        if (path == NULL) {
            return NULL;
        }
        slash = ht_strrchr(path, '/');
        if (slash != NULL && slash != path) {
            slash[1] = '\0';
        } else if (slash == path) {
            path[1] = '\0';
        }
        return path;
    case 7:
        q = NULL;
        if (pu->pu_User != NULL && pu->pu_User[0] != '\0') {
            buflen = ht_strlen(pu->pu_User) + 1;
            if (pu->pu_Password != NULL) {
                buflen += ht_strlen(pu->pu_Password) + 1;
            }
            buflen += pu->pu_Host ? ht_strlen(pu->pu_Host) : 0;
            buflen += 24;
            q = (STRPTR)ht_alloc(buflen, MEMF_CLEAR);
            if (q == NULL) {
                return NULL;
            }
            if (pu->pu_Password != NULL) {
                SNPrintf(q, buflen, (CONST_STRPTR)"%s:%s@",
                    pu->pu_User, pu->pu_Password);
            } else {
                SNPrintf(q, buflen, (CONST_STRPTR)"%s@", pu->pu_User);
            }
            if (pu->pu_Host != NULL) {
                Strncat(q, pu->pu_Host, buflen);
            }
            if (pu->pu_Port != 0 && !ht_url_default_port(pu, pu->pu_Port)) {
                SNPrintf((STRPTR)portbuf, (ULONG)sizeof(portbuf),
                    (CONST_STRPTR)":%lu", pu->pu_Port);
                Strncat(q, (STRPTR)portbuf, buflen);
            }
            return q;
        }
        if (pu->pu_Host == NULL) {
            return NULL;
        }
        if (pu->pu_Port != 0 && !ht_url_default_port(pu, pu->pu_Port)) {
            SNPrintf((STRPTR)portbuf, (ULONG)sizeof(portbuf),
                (CONST_STRPTR)"%lu", pu->pu_Port);
            buflen = ht_strlen(pu->pu_Host) + ht_strlen((STRPTR)portbuf) + 2;
            q = (STRPTR)ht_alloc(buflen, MEMF_CLEAR);
            if (q == NULL) {
                return NULL;
            }
            SNPrintf(q, buflen, (CONST_STRPTR)"%s:%s",
                pu->pu_Host, (STRPTR)portbuf);
            return q;
        }
        return ht_strdup(pu->pu_Host);
    default:
        return NULL;
    }
}

static STRPTR
ht_uri_part(STRPTR url, ULONG part)
{
    struct ParsedUrl pu;
    STRPTR out;
    LONG rc;

    if (url == NULL) {
        return NULL;
    }
    rc = ht_url_parse(url, &pu);
    if (rc != 0) {
        return NULL;
    }
    out = ht_uri_part_from_parsed(&pu, part);
    ht_url_free_fields(&pu);
    return out;
}

STRPTR
ht_uri_scheme_part(STRPTR url)
{
    return ht_uri_part(url, 0);
}

STRPTR
ht_uri_host_part(STRPTR url)
{
    return ht_uri_part(url, 1);
}

STRPTR
ht_uri_path_part(STRPTR url)
{
    return ht_uri_part(url, 3);
}

STRPTR
ht_uri_file_part(STRPTR url)
{
    return ht_uri_part(url, 4);
}

STRPTR
ht_uri_query_part(STRPTR url)
{
    return ht_uri_part(url, 5);
}

STRPTR
ht_uri_parent_part(STRPTR url)
{
    return ht_uri_part(url, 6);
}

STRPTR
ht_uri_authority_part(STRPTR url)
{
    return ht_uri_part(url, 7);
}

STRPTR
ht_join_uri(STRPTR base_url, STRPTR relative_url)
{
    struct ParsedUrl base;
    struct ParsedUrl rel;
    STRPTR out;
    STRPTR path;
    STRPTR slash;
    ULONG len;
    LONG rc;

    if (relative_url == NULL) {
        return NULL;
    }
    if (ht_prefix_icmp(relative_url, (CONST_STRPTR)"http://", 7) ||
        ht_prefix_icmp(relative_url, (CONST_STRPTR)"https://", 8)) {
        return ht_strdup(relative_url);
    }
    if (base_url == NULL) {
        return ht_strdup(relative_url);
    }
    rc = ht_url_parse(base_url, &base);
    if (rc != 0) {
        return ht_strdup(relative_url);
    }
    if (relative_url[0] == '/') {
        STRPTR built;
        STRPTR joined;

        built = ht_url_build_from_parsed(&base);
        if (built == NULL) {
            ht_url_free_fields(&base);
            return NULL;
        }
        len = ht_strlen(built) + ht_strlen(relative_url) + 1;
        joined = (STRPTR)ht_alloc(len, MEMF_CLEAR);
        if (joined == NULL) {
            ht_free(built);
            ht_url_free_fields(&base);
            return NULL;
        }
        Strncpy(joined, built, len);
        Strncat(joined, relative_url, len);
        ht_free(built);
        ht_url_free_fields(&base);
        return joined;
    }
    rc = ht_url_parse(relative_url, &rel);
    if (rc == 0) {
        ht_url_free_fields(&rel);
    }
    path = base.pu_Path ? ht_strdup(base.pu_Path) : ht_strdup((STRPTR)"/");
    if (path == NULL) {
        ht_url_free_fields(&base);
        return NULL;
    }
    slash = ht_strrchr(path, '/');
    if (slash != NULL) {
        slash[1] = '\0';
    } else {
        path[0] = '/';
        path[1] = '\0';
    }
    len = ht_strlen(path) + ht_strlen(relative_url) + 1;
    out = (STRPTR)ht_alloc(len, MEMF_CLEAR);
    if (out == NULL) {
        ht_free(path);
        ht_url_free_fields(&base);
        return NULL;
    }
    Strncpy(out, path, len);
    Strncat(out, relative_url, len);
    ht_free(path);
    base.pu_Path = out;
    out = ht_url_build_from_parsed(&base);
    ht_url_free_fields(&base);
    return out;
}
