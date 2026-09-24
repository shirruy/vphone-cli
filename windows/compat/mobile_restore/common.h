#pragma once

/*
 * Phase 1 Windows compatibility surface for the isolated upstream FTAB module.
 * Upstream ftab.c only needs logger() and LL_ERROR from MobileRestoreCore's
 * much larger common.h dependency graph. Keeping this shim narrow proves the
 * module can compile without pretending the whole restore stack is portable.
 */

#include <stdarg.h>
#include <stdio.h>

enum {
    LL_ERROR = 0,
    LL_WARNING = 1,
    LL_INFO = 2,
    LL_DEBUG = 3
};

static inline void logger(int level, const char *format, ...)
{
    (void)level;
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}
