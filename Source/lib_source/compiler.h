/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * compiler.h - cross-compiler attributes for amihttp.library
 */

#ifndef AMIHTTP_COMPILER_H
#define AMIHTTP_COMPILER_H

#include <exec/types.h>
#include <clib/compiler-specific.h>
#include <proto/exec.h>
#include <proto/alib.h>
#include <proto/dos.h>

#ifndef HT_INITTABLE_DEFINED
#define HT_INITTABLE_DEFINED 1
struct InitTable
{
    ULONG it_LibSize;
    APTR *it_FuncTable;
    APTR  it_DataTable;
    APTR  it_InitFunc;
};
#endif

struct MyDataInit
{
    ULONG md_Init[19];
};

#endif /* AMIHTTP_COMPILER_H */
