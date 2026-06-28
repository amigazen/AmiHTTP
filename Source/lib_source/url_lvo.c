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

#include <proto/utility.h>

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

    if (url == NULL || url->pu_Host == NULL) {
        ht_set_error(ERROR_HTTP_INVALID_URL);
        return NULL;
    }
    out = ht_url_build_from_parsed(url);
    if (out == NULL) {
        ht_set_error(ERROR_HTTP_OUT_OF_MEMORY);
        return NULL;
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
