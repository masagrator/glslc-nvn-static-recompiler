/*
 * guest_printf.c -- the printf family, using musl's own vfprintf.
 *
 * WHY THIS REPLACED A HAND-WRITTEN MARSHALLER
 *
 * The mirror image of guest_scanf.c, and the change HANDOVER.md sec.27 named
 * as the obvious next one.  The port used to walk the format string itself and
 * render each directive with a single-argument call to the HOST's snprintf.
 * Three things were wrong with that:
 *
 *   * it re-derived printf's grammar.  `%n$` positional arguments were not
 *     recognised at all, nor `%S`/`%C` (wide string and wide character), nor
 *     `%m`; and the rules for which directives take a `*` argument were the
 *     port's reading of them rather than the ones in the code the guest calls.
 *   * the answer was glibc's, not musl's.  The guest is a musl binary -- it
 *     imports __nnmusl_init_dso -- so musl's vfprintf IS the behaviour being
 *     emulated, and the two libraries make different choices where the
 *     standard permits: `%a` digit selection is the clearest case.
 *   * `%Lf` COULD NOT WORK.  A guest long double is binary128 in a q register;
 *     the marshaller took the low eight bytes and handed them to the host as a
 *     `double`, so the value printed was unrelated to the value passed.  The
 *     argument cursor grew va_ld_bits() for this (guest_va_int.h).
 *
 * So musl's vfprintf is vendored under runtime/musl/, verbatim except for the
 * edits listed at the top of each file.  What the port supplies is only what
 * musl expects from its environment:
 *
 *   * a stream to write to (gout.h/.c) -- a growable buffer in the port's
 *     per-thread scratch, because a malloc per printf moves the guest's heap
 *     and the compiler hashes some of its tables by pointer;
 *   * an argument cursor that reads the guest register file or a guest
 *     va_list instead of a host va_list (gvaarg.h) -- pop_arg and the two `*`
 *     sites in printf_core;
 *   * the guest's long double, binary128 rather than the host's x87 80-bit
 *     (gld.h), and musl's own ld128 arithmetic for it (gf128.c);
 *   * musl's UTF-8 encoder for `%S`/`%C` (gmb.c) -- musl's C locale is UTF-8
 *     and the guest's wchar_t is 32 bits, neither of which is true of the
 *     host's wctomb;
 *   * musl's strerror table for `%m` (gstrerror.c).
 *
 * WHAT THE THUNKS STILL DO.  Rendering goes to memory first and the thunk then
 * hands the bytes to the host's fwrite, or copies them into the guest's
 * buffer.  That is deliberate: the guest's `stdout` is a HOST FILE, and the
 * host's stdio must stay in charge of buffering and ordering it.  It is also
 * what makes snprintf's "length it WOULD have written" return value fall out
 * without a second pass.
 */

#include "guest_va_int.h"
#include "musl/gvaarg.h"
#include "musl/gout.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* --------------------------------------------------- the vendored formatter */
#include "musl/gf128.c"
#include "musl/gmb.c"
#include "musl/gstrerror.c"
#include "musl/gout.c"
#include "musl/vfprintf.c"

/* ---------------------------------------------------------------- the entry */

/*
 * Render `fmt` with arguments taken from `v`.  Returns a pointer into the
 * per-thread scratch buffer -- NOT a malloc'd string.  Callers must not free
 * it, and must be done with it before the next formatting call on this thread.
 * Every caller in guest_va.c copies the bytes out immediately.
 *
 * `*out_len` is the number of bytes RENDERED, which is also what printf
 * returns; a caller with a fixed-size destination (snprintf) truncates the
 * copy and returns this untruncated length, as C requires.  On an error musl
 * reports -1 and the buffer is meaningless, so NULL comes back and the thunks
 * turn that into the failure return of whichever function they implement.
 */
char *guest_format(va_ctx *v, const char *fmt, size_t *out_len, int *ret) {
    GOFILE o;
    gout_init(&o);
    if (ret) *ret = -1;
    if (out_len) *out_len = 0;
    if (!o.buf) return NULL;
    /*
     * musl's vfprintf takes `const char *restrict fmt` and dereferences it
     * without a null check, exactly as C requires of its caller.  The port has
     * one caller that cannot promise that -- a guest that passes a null format
     * -- and the previous formatter substituted "(null)" for it.  Keeping that
     * is a deliberate divergence from musl, and the only one: musl would
     * segfault, which tells whoever is debugging the port nothing about which
     * guest call was at fault.
     */
    if (!fmt) fmt = "(null)";
    int n = guest_vfprintf(&o, fmt, v);
    if (ret) *ret = n;
    if (n < 0) return NULL;
    if (out_len) *out_len = o.len;
    return o.buf;
}
