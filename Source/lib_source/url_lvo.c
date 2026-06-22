/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * url_lvo.c - URL utility LVO wrappers
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <stdio.h>
#include <string.h>

#include <libraries/amihttp.h>

#include "compiler.h"
#include "amihttp_funcs.h"
#include "private/ht_internal.h"

struct ParsedUrl *
__ASM__ __SAVE_DS__ ParseHttpUrl(
    __REG__(a0, STRPTR url))
{
    struct ParsedUrl *pu;
    LONG rc;

    pu = (struct ParsedUrl *)ht_alloc(sizeof(struct ParsedUrl), MEMF_CLEAR);
    if (pu == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
    }
    rc = ht_url_parse(url, pu);
    if (rc != 0) {
        ht_free(pu);
        ht_set_error(rc);
        return NULL;
    }
    ht_set_error(0);
    return pu;
}

VOID
__ASM__ __SAVE_DS__ DisposeHttpUrl(
    __REG__(a0, struct ParsedUrl *url))
{
    if (url == NULL) {
        return;
    }
    ht_url_free_fields(url);
    ht_free(url);
}

STRPTR
__ASM__ __SAVE_DS__ BuildHttpUrl(
    __REG__(a0, struct ParsedUrl *url))
{
    STRPTR out;
    ULONG len;
    STRPTR scheme;
    ULONG port;

    if (url == NULL || url->pu_Host == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
        return NULL;
    }
    scheme = url->pu_Scheme;
    if (scheme == NULL) {
        scheme = url->pu_IsSecure ? (STRPTR)"https" : (STRPTR)"http";
    }
    port = url->pu_Port;
    len = (ULONG)strlen((char *)scheme) + (ULONG)strlen((char *)url->pu_Host) + 32;
    if (url->pu_Path) {
        len += (ULONG)strlen((char *)url->pu_Path);
    }
    if (url->pu_Query) {
        len += (ULONG)strlen((char *)url->pu_Query) + 1;
    }
    out = (STRPTR)ht_alloc(len, MEMF_CLEAR);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
    }
    if (port != 0 &&
        !((url->pu_IsSecure && port == 443) || (!url->pu_IsSecure && port == 80))) {
        sprintf((char *)out, "%s://%s:%lu", scheme, url->pu_Host, port);
    } else {
        sprintf((char *)out, "%s://%s", scheme, url->pu_Host);
    }
    if (url->pu_Path != NULL) {
        strcat((char *)out, (char *)url->pu_Path);
    } else {
        strcat((char *)out, "/");
    }
    if (url->pu_Query != NULL && url->pu_Query[0] != '\0') {
        strcat((char *)out, "?");
        strcat((char *)out, (char *)url->pu_Query);
    }
    ht_set_error(0);
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUrlEncode(
    __REG__(a0, STRPTR str))
{
    STRPTR out;

    out = ht_url_encode(str);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUrlDecode(
    __REG__(a0, STRPTR str))
{
    STRPTR out;

    out = ht_url_decode(str);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpPathEncode(
    __REG__(a0, STRPTR path))
{
    STRPTR out;

    out = ht_path_encode(path);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpBuildQueryString(
    __REG__(a0, struct List *pairs))
{
    STRPTR out;

    out = ht_build_query_string(pairs);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUriSchemePart(
    __REG__(a0, STRPTR url))
{
    STRPTR out;

    out = ht_uri_scheme_part(url);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUriHostPart(
    __REG__(a0, STRPTR url))
{
    STRPTR out;

    out = ht_uri_host_part(url);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUriPathPart(
    __REG__(a0, STRPTR url))
{
    STRPTR out;

    out = ht_uri_path_part(url);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUriFilePart(
    __REG__(a0, STRPTR url))
{
    STRPTR out;

    out = ht_uri_file_part(url);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUriQueryPart(
    __REG__(a0, STRPTR url))
{
    STRPTR out;

    out = ht_uri_query_part(url);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUriParentPart(
    __REG__(a0, STRPTR url))
{
    STRPTR out;

    out = ht_uri_parent_part(url);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpUriAuthorityPart(
    __REG__(a0, STRPTR url))
{
    STRPTR out;

    out = ht_uri_authority_part(url);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
    } else {
        ht_set_error(0);
    }
    return out;
}

STRPTR
__ASM__ __SAVE_DS__ HttpJoinUri(
    __REG__(a0, STRPTR base_url),
    __REG__(a1, STRPTR relative_url))
{
    STRPTR base;
    STRPTR rel;
    STRPTR out;

    base = base_url;
    rel = relative_url;
    out = ht_join_uri(base, rel);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
    } else {
        ht_set_error(0);
    }
    return out;
}
