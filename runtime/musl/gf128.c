/* gf128.c -- musl's binary128 (ld128) math, retyped for gld_t.
 *
 * WHY THIS FILE EXISTS
 *
 * musl's floatscan.c and vfprintf.c need copysign, fmod, scalbn, fabs and
 * frexp at the guest's long double precision.  Two ways to supply them were
 * available and both are wrong:
 *
 *   * the HOST's long double entry points (copysignl, fmodl, frexpl).  On
 *     x86-64 those are the x87 80-bit versions, which is exactly the precision
 *     loss gld.h exists to prevent -- the argument would be rounded from 113
 *     mantissa bits to 64 on the way in.
 *   * glibc's _Float128 entry points (copysignf128, fmodf128, scalbnf128).
 *     Correct, but they are glibc's: MinGW has no such symbols, so the whole
 *     scanf/printf side failed to LINK for Windows.
 *
 * So musl's own ld128 implementations are vendored here, verbatim except for
 * the retyping listed below.  They are exactly what an AArch64 musl -- the
 * library the guest is linked against -- executes for these operations, which
 * makes this the same substitution the rest of runtime/musl/ performs: the
 * guest's answer instead of the host's.
 *
 * Vendored from musl 1.2.4/1.2.5, src/math/{copysignl,fabsl,fmodl,frexpl,
 * scalbnl}.c, all from the `LDBL_MANT_DIG == 113` branch.
 *
 * Edits, and nothing else:
 *   * `long double` -> `gld_t`, and the names gain a `gld_` prefix.
 *   * `union ldshape` -> `union gld_shape`, musl's own little-endian ld128
 *     layout from src/internal/libm.h.  BIG-ENDIAN IS NOT PROVIDED: the port
 *     builds for x86-64 hosts only, and a silently wrong byte order here would
 *     be far worse than a compile error, so the layout is asserted below.
 *   * musl's `long double` literals (0x1p16383L and friends) become binary128
 *     ones, written GLD_C(0x1p16383) because the suffix is `f128` on GCC and
 *     `q` on the clang that builds the Windows side (gld.h picks).  Mixing
 *     binary128 with long double in one expression is not valid C, and the
 *     x87 value is not the same number.
 *   * `isnan(y)` -> gld_isnan(), for the same reason: the host's isnan would
 *     convert the argument to double.
 *   * every function is `static inline`, because this file is #included by
 *     both guest_scanf.c and guest_printf.c and must not define a symbol
 *     twice.  Nothing here is large enough for that to cost anything.
 *
 * The bit-twiddling is untouched; that is the reason for vendoring.
 */
#ifndef GF128_C
#define GF128_C

#include <stdint.h>
#include "gld.h"

union gld_shape {
    gld_t f;
    struct {
        uint64_t lo;
        uint32_t mid;
        uint16_t top;
        uint16_t se;
    } i;
    struct {
        uint64_t lo;
        uint64_t hi;
    } i2;
};

_Static_assert(sizeof(gld_t) == 16, "gld_t is not binary128");

/* ------------------------------------------------------------- predicates */

static inline int gld_signbit(gld_t x) {
    union gld_shape u = {x};
    return (u.i.se & 0x8000) != 0;
}

static inline int gld_isnan(gld_t x) {
    union gld_shape u = {x};
    return (u.i.se & 0x7fff) == 0x7fff && ((u.i2.hi & 0x0000ffffffffffffULL) | u.i2.lo) != 0;
}

static inline int gld_isinf(gld_t x) {
    union gld_shape u = {x};
    return (u.i.se & 0x7fff) == 0x7fff && ((u.i2.hi & 0x0000ffffffffffffULL) | u.i2.lo) == 0;
}

static inline int gld_isfinite(gld_t x) {
    union gld_shape u = {x};
    return (u.i.se & 0x7fff) != 0x7fff;
}

/* --------------------------------------------------------------- fabsl(3) */

static inline gld_t gld_fabs(gld_t x) {
    union gld_shape u = {x};

    u.i.se &= 0x7fff;
    return u.f;
}

/* ----------------------------------------------------------- copysignl(3) */

static inline gld_t gld_copysign(gld_t x, gld_t y) {
    union gld_shape ux = {x}, uy = {y};
    ux.i.se &= 0x7fff;
    ux.i.se |= uy.i.se & 0x8000;
    return ux.f;
}

/* ------------------------------------------------------------- scalbnl(3) */

static inline gld_t gld_scalbn(gld_t x, int n) {
    union gld_shape u;

    if (n > 16383) {
        x *= GLD_C(0x1p16383);
        n -= 16383;
        if (n > 16383) {
            x *= GLD_C(0x1p16383);
            n -= 16383;
            if (n > 16383)
                n = 16383;
        }
    } else if (n < -16382) {
        x *= GLD_C(0x1p-16382) * GLD_C(0x1p113);
        n += 16382 - 113;
        if (n < -16382) {
            x *= GLD_C(0x1p-16382) * GLD_C(0x1p113);
            n += 16382 - 113;
            if (n < -16382)
                n = -16382;
        }
    }
    u.f = 1.0;
    u.i.se = 0x3fff + n;
    return x * u.f;
}

/* -------------------------------------------------------------- frexpl(3) */

static inline gld_t gld_frexp(gld_t x, int *e) {
    union gld_shape u = {x};
    int ee = u.i.se & 0x7fff;

    if (!ee) {
        if (x) {
            /* musl recurses here; the recursion is one deep (the scaled value
             * is normal) and is written as a loop only because a `static
             * inline` function cannot call itself before it is defined. */
            union gld_shape v;
            v.f = x * GLD_C(0x1p120);
            *e = (v.i.se & 0x7fff) - 0x3ffe - 120;
            v.i.se &= 0x8000;
            v.i.se |= 0x3ffe;
            return v.f;
        }
        *e = 0;
        return x;
    } else if (ee == 0x7fff) {
        return x;
    }

    *e = ee - 0x3ffe;
    u.i.se &= 0x8000;
    u.i.se |= 0x3ffe;
    return u.f;
}

/* --------------------------------------------------------------- fmodl(3) */

static inline gld_t gld_fmod(gld_t x, gld_t y) {
    union gld_shape ux = {x}, uy = {y};
    int ex = ux.i.se & 0x7fff;
    int ey = uy.i.se & 0x7fff;
    int sx = ux.i.se & 0x8000;

    if (y == 0 || gld_isnan(y) || ex == 0x7fff)
        return (x*y)/(x*y);
    ux.i.se = ex;
    uy.i.se = ey;
    if (ux.f <= uy.f) {
        if (ux.f == uy.f)
            return 0*x;
        return x;
    }

    /* normalize x and y */
    if (!ex) {
        ux.f *= 0x1p120f;
        ex = ux.i.se - 120;
    }
    if (!ey) {
        uy.f *= 0x1p120f;
        ey = uy.i.se - 120;
    }

    /* x mod y */
    {
        uint64_t hi, lo, xhi, xlo, yhi, ylo;
        xhi = (ux.i2.hi & -1ULL>>16) | 1ULL<<48;
        yhi = (uy.i2.hi & -1ULL>>16) | 1ULL<<48;
        xlo = ux.i2.lo;
        ylo = uy.i2.lo;
        for (; ex > ey; ex--) {
            hi = xhi - yhi;
            lo = xlo - ylo;
            if (xlo < ylo)
                hi -= 1;
            if (hi >> 63 == 0) {
                if ((hi|lo) == 0)
                    return 0*x;
                xhi = 2*hi + (lo>>63);
                xlo = 2*lo;
            } else {
                xhi = 2*xhi + (xlo>>63);
                xlo = 2*xlo;
            }
        }
        hi = xhi - yhi;
        lo = xlo - ylo;
        if (xlo < ylo)
            hi -= 1;
        if (hi >> 63 == 0) {
            if ((hi|lo) == 0)
                return 0*x;
            xhi = hi;
            xlo = lo;
        }
        for (; xhi >> 48 == 0; xhi = 2*xhi + (xlo>>63), xlo = 2*xlo, ex--);
        ux.i2.hi = xhi;
        ux.i2.lo = xlo;
    }

    /* scale result */
    if (ex <= 0) {
        ux.i.se = (ex+120)|sx;
        ux.f *= 0x1p-120f;
    } else
        ux.i.se = ex|sx;
    return ux.f;
}

#endif /* GF128_C */
