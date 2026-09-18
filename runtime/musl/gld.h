/* gld.h -- the guest's `long double`.
 *
 * AArch64's long double is IEEE binary128; x86-64's is the x87 80-bit format.
 * Compiling musl's floatscan.c against the HOST's long double would silently
 * select musl's `LDBL_MANT_DIG == 64` branch and round every long-double
 * conversion to 64 mantissa bits where the guest keeps 113.
 *
 * So the type becomes _Float128 -- which every GCC that targets x86-64 has,
 * with the arithmetic built in -- and the LDBL_* macros are redefined to the
 * binary128 values BEFORE floatscan.c and vfprintf.c test them, which makes
 * those files compile their own binary128 configuration: the one an AArch64
 * musl is built with.
 *
 * THE CONSTANTS COME FROM THE COMPILER, NOT FROM THE C LIBRARY.  They used to
 * be glibc's FLT128_MAX/FLT128_MIN, which exist only when glibc's <float.h>
 * sees __STDC_WANT_IEC_60559_TYPES_EXT__; MinGW's C library has no such
 * spelling, so the whole scanf/printf side failed to compile for Windows on
 * the first header.  GCC predefines __FLT128_MAX__ and friends unconditionally
 * on every host that has the type, and they are the SAME values -- glibc's
 * FLT128_MAX is defined as __FLT128_MAX__.
 *
 * THE ARITHMETIC HELPERS ARE musl's OWN, NOT THE HOST'S.  floatscan.c and
 * vfprintf.c need copysign/fmod/scalbn/fabs/frexp at binary128.  glibc spells
 * those copysignf128/fmodf128/... in libm and MinGW does not have them at all,
 * so the ld128 versions from musl's own math/ are vendored below (see gf128.c).
 * That removes the -lm dependency for this code AND makes the answer musl's,
 * which is the point of vendoring in the first place.
 */
#ifndef GLD_H
#define GLD_H

#include <float.h>
#include <stdint.h>

/* THE TYPE HAS TWO SPELLINGS, AND ONE COMPILER HAS ONLY THE SECOND.  GCC
 * gives every x86-64 target `_Float128`, the `f128` literal suffix and the
 * __FLT128_* constants.  clang targeting x86_64-w64-mingw32 gives NONE of
 * those three -- `_Float128` is "unknown type name" there -- but does give the
 * older `__float128`, the `q` suffix, and the same arithmetic.  It is the same
 * binary128 either way; only the names differ, so the names are what is
 * selected here.  (clang is how Windows is built at all: src/data_ro.c needs
 * C23 `#embed`, which clang has had since 19 and mingw-w64's gcc only from 15.)
 *
 * __FLT128_MAX__ is the signal rather than __clang__, because it is exactly
 * the thing being asked about, and clang on Linux does define it.
 */
#if defined(__FLT128_MAX__)

typedef _Float128 gld_t;
#define GLD_C(x)        x##f128         /* a binary128 literal */
#define GLD_MAX         __FLT128_MAX__
#define GLD_MIN         __FLT128_MIN__
#define GLD_EPSILON     __FLT128_EPSILON__

#else

typedef __float128 gld_t;
#define GLD_C(x)        x##q
/* Written out because the compiler does not offer them.  These are the exact
 * binary128 values, checked bit for bit against GCC's __FLT128_MAX__ /
 * __FLT128_MIN__ / __FLT128_EPSILON__: 7ffeffffffffffffffffffffffffffff,
 * 00010000000000000000000000000000, 3f8f0000000000000000000000000000. */
#define GLD_MAX         0x1.ffffffffffffffffffffffffffffp+16383q
#define GLD_MIN         0x1p-16382q
#define GLD_EPSILON     0x1p-112q

#endif

#undef  LDBL_MANT_DIG
#define LDBL_MANT_DIG   113
#undef  LDBL_MAX_EXP
#define LDBL_MAX_EXP    16384
#undef  LDBL_MIN_EXP
#define LDBL_MIN_EXP    (-16381)
#undef  LDBL_MAX
#define LDBL_MAX        GLD_MAX
#undef  LDBL_MIN
#define LDBL_MIN        GLD_MIN
/* LDBL_EPSILON was NOT redefined before, and floatscan.c reads it at the one
 * place it decides whether a value is large enough to need the denormal/
 * overflow correction (`fabsl(y) >= 2/LDBL_EPSILON`).  With the host's x87
 * epsilon that threshold is 2^64 where binary128's is 2^113, so the correction
 * was applied over a range of values it should not have been.  Same class of
 * defect as compiling the wrong LDBL_MANT_DIG branch, one macro further on. */
#undef  LDBL_EPSILON
#define LDBL_EPSILON    GLD_EPSILON

#endif
