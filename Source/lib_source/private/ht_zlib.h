/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_zlib.h - z.library inflate helpers for Content-Encoding decode
 *
 * Include after <amihttp/amihttpbase.h> and private/ht_internal.h.
 */

#ifndef AMIHTTP_PRIVATE_HT_ZLIB_H
#define AMIHTTP_PRIVATE_HT_ZLIB_H

#ifndef AMIHTTP_PRIVATE_HT_INTERNAL_H
#error "include private/ht_internal.h before private/ht_zlib.h"
#endif

#ifndef AMIHTTP_AMIHTTPBASE_H
#include <amihttp/amihttpbase.h>
#endif

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

BOOL ht_zlib_ensure(struct AmiHttpBase *base);
LONG ht_zlib_inflate_begin(struct HttpTransaction *txn, LONG windowBits);
VOID ht_zlib_inflate_end(struct HttpTransaction *txn);

#endif /* AMIHTTP_PRIVATE_HT_ZLIB_H */
