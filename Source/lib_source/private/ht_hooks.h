/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ht_hooks.h - Hook dispatch helpers (private)
 */

#ifndef AMIHTTP_PRIVATE_HT_HOOKS_H
#define AMIHTTP_PRIVATE_HT_HOOKS_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef LIBRARIES_AMIHTTP_H
#include <libraries/amihttp.h>
#endif

struct AmiHttpBase;

BOOL ht_check_break(struct AmiHttpBase *base);
BOOL ht_check_txn_abort(struct HttpTransaction *txn);

VOID ht_hook_headers_done(struct HttpTransaction *txn);
VOID ht_hook_body_chunk(struct HttpTransaction *txn, APTR data, ULONG len);
VOID ht_hook_complete(struct HttpTransaction *txn);
VOID ht_hook_error(struct HttpTransaction *txn, LONG code);

#endif /* AMIHTTP_PRIVATE_HT_HOOKS_H */
