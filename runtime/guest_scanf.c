/*
 * guest_scanf.c -- the scanf family, using musl's own vfscanf.
 *
 * WHY THIS REPLACED A HAND-WRITTEN MARSHALLER
 *
 * The port used to walk the format string itself and hand each directive to
 * the HOST's sscanf, one at a time, with a `%n` appended so it could tell how
 * much had been consumed.  That made the port's answer glibc's answer, and it
 * meant the port had to re-derive scanf's grammar -- which is where it went
 * wrong: `%[` scansets were not recognised at all, so a format like
 *
 *     sscanf(name, "%[^[.][%3u]%s", base, &index, tail)
 *
 * was read as three directives when it is three CONVERSIONS with a scanset in
 * the middle, and the arguments came out shifted (HANDOVER.md sec.26).  That
 * one was found and patched, but the general problem stands: a re-derived
 * grammar is a source of bugs that the real one does not have, and the corner
 * cases where glibc and musl legitimately differ were still there.
 *
 * The guest is musl -- it imports __nnmusl_init_dso -- so musl's vfscanf IS
 * the behaviour being emulated.  It is vendored under runtime/musl/, verbatim
 * except for the edits listed at the top of each file.  What the port supplies
 * is only what musl expects from its environment:
 *
 *   * a string pseudo-FILE (musl's own concept, gshgetc.h/.c);
 *   * an argument cursor that reads the guest register file instead of a host
 *     va_list (gvaarg.h) -- three call sites in vfscanf.c;
 *   * the guest's long double, binary128 rather than the host's x87 80-bit
 *     (gld.h), which is what makes %La/%Le/%Lf exact rather than close.
 *
 * WIDE CHARACTERS.  musl's %ls/%lc decode with mbrtowc, and musl's C locale is
 * always UTF-8.  The host's C locale is not, so mbrtowc is the one place where
 * calling the host would still give a different answer -- and on Windows there
 * is a second, larger problem: the host's wchar_t is 16 bits where the guest's
 * is 32, so `k*sizeof(wchar_t)` would allocate half of what the guest reads
 * back.  musl's own conversions (runtime/musl/gmb.c) answer both, on an
 * explicit uint32_t, and vfscanf.c is retyped to that.
 */

/* Before ANY header: glibc only declares the _Float128 type, its constants and
 * its math functions when this is set at the first inclusion of <float.h>, and
 * the guest's long double is binary128 (runtime/musl/gld.h). */
#define __STDC_WANT_IEC_60559_TYPES_EXT__ 1

#include "guest_va_int.h"
#include "musl/gvaarg.h"
#include "musl/gshgetc.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* --------------------------------------------------------------- mbrtowc */
/*
 * musl in the C locale decodes UTF-8 and nothing else.  glibc's C locale does
 * not decode UTF-8 at all, so a guest %ls would disagree byte for byte, and on
 * Windows the host's wchar_t is 16 bits where the guest's is 32.
 *
 * This used to be musl's rule written out by hand, one byte at a time, right
 * here.  It is musl's actual code now (runtime/musl/gmb.c), because the printf
 * side and the wide-character thunks need the same conversions and three
 * copies of one rule is how they drift apart.  The macros below hand musl's
 * scanner the same interface it was written against; only the state type
 * changes, from musl's two-word mbstate_t to the single unsigned its own code
 * casts that to.
 */
#include "musl/gmb.c"

#define mbstate_t               unsigned
#define mbrtowc(pw, ps, n, st)  gmb_mbrtowc((pw), (ps), (n), (st))
#define mbsinit(st)             (*(st) == 0)

/* --------------------------------------------------- the vendored scanner */
/* gf128.c first: floatscan.c calls musl's own ld128 copysign/fmod/scalbn/fabs
 * through it.  Those used to be glibc's copysignf128/fmodf128/scalbnf128,
 * which do not exist on MinGW -- and `fabsl` was left as the HOST's, so that
 * one comparison rounded its argument to x87 precision. */
#include "musl/gf128.c"
#include "musl/gshgetc.c"
#include "musl/intscan.c"
#include "musl/floatscan.c"
#include "musl/vfscanf.c"

/* ------------------------------------------------------------- the thunks */

static void gsf_fromstring(GFILE *f, const char *s) {
    /* musl's vsscanf builds the same object: buffer pointers into the string,
     * rend at its terminator.  Nothing is copied, and nothing is written back
     * -- see gshgetc.c for why the one line of musl that would have written
     * into the string is not reachable here. */
    unsigned char *p = (unsigned char *)(uintptr_t)s;
    f->buf = f->rpos = p;
    f->rend = p + (s ? strlen(s) : 0);
    f->shend = f->rend;
    f->shlim = 0;
    f->shcnt = 0;
}

/*
 * musl's strtold(), for the one host that has no long-double strtod at all.
 *
 * This is musl's src/stdlib/strtod.c -- `strtox(s, p, 2)` -- with its FILE
 * replaced by the string pseudo-FILE the rest of this file uses.  It exists
 * because MSVCRT's `long double` IS `double`, so guest_strtold_l() has nothing
 * on that platform to convert with; glibc's strtof128_l covers the Linux side
 * and is what the corpus was verified against, so this is not used there.
 * The result is written as raw bytes for the same reason guest_strtold_l takes
 * an out-pointer: it goes straight into the guest's q0 slot.
 */
void guest_strtold_musl(void *out, const char *s, char **p) {
    GFILE f;
    gsf_fromstring(&f, s);
    shlim(&f, 0);
    gld_t y = __floatscan(&f, 2, 1);
    off_t cnt = shcnt(&f);
    if (p) *p = cnt ? (char *)s + cnt : (char *)s;
    memcpy(out, &y, 16);
}

int guest_scan_string(const char *input, const char *fmt, va_ctx *v) {
    GFILE f;
    if (!input || !fmt) return EOF;
    gsf_fromstring(&f, input);
    return guest_vfscanf(&f, fmt, v);
}
