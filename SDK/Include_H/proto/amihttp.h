/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amihttp.h - proto/pragma dispatcher for amihttp.library callers
 */

#ifndef PROTO_AMIHTTP_H
#define PROTO_AMIHTTP_H

/****************************************************************************/

#ifdef _NO_INLINE

#include <clib/amihttp_protos.h>

#else

/****************************************************************************/

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef EXEC_LISTS_H
#include <exec/lists.h>
#endif
#ifndef UTILITY_TAGITEM_H
#include <utility/tagitem.h>
#endif
#ifndef LIBRARIES_AMIHTTP_H
#include <libraries/amihttp.h>
#endif

#ifndef CLIB_AMIHTTP_PROTOS_H
#include <clib/amihttp_protos.h>
#endif

/****************************************************************************/

#ifndef __NOLIBBASE__

#ifndef EXEC_LIBRARIES_H
#include <exec/libraries.h>
#endif /* EXEC_LIBRARIES_H */

extern struct Library * HttpBase;

#endif /* __NOLIBBASE__ */

/****************************************************************************/

#if defined(LATTICE) || defined(__SASC) || defined(_DCC)

#ifndef PRAGMAS_AMIHTTP_H
#include <pragmas/amihttp_pragmas.h>
#endif /* PRAGMAS_AMIHTTP_H */

/****************************************************************************/

#elif defined(__GNUC__)

#include <clib/amihttp_protos.h>

/****************************************************************************/

#else

#include <clib/amihttp_protos.h>

/****************************************************************************/

#endif /* compiler */

/****************************************************************************/

#endif /* _NO_INLINE */

/****************************************************************************/
/* Variadic tag wrappers (mirror SocketBaseTags / SetWindowAttrs pattern)   */
/****************************************************************************/

#ifndef HT_VARARGS_DEFINED
#define HT_VARARGS_DEFINED 1

static LONG HttpBaseTags(Tag tag1, ...)
{
    return HttpBaseTagList((struct TagItem *)&tag1);
}

static LONG SetHttpSessionAttrs(struct HttpSession *session, Tag tag1, ...)
{
    return SetHttpSessionAttrsA(session, (struct TagItem *)&tag1);
}

static LONG SetHttpTransactionAttrs(struct HttpTransaction *txn, Tag tag1, ...)
{
    return SetHttpTransactionAttrsA(txn, (struct TagItem *)&tag1);
}

#endif /* HT_VARARGS_DEFINED */

#endif /* PROTO_AMIHTTP_H */
