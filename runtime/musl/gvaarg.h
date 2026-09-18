/* gvaarg.h -- the guest's argument cursor, in the shape musl's vfscanf.c wants.
 *
 * musl reads its arguments through `va_arg(ap, void *)` in three places.  The
 * guest's arguments are not in a host va_list at all -- they are in the guest
 * register file and on the guest stack (AAPCS64) -- so those three sites take
 * this cursor instead.  Nothing else in vfscanf.c changes, which is the whole
 * point: the scanning logic stays musl's.
 *
 * A scanf argument list is all pointers, so only the general-purpose half of
 * the cursor is ever used and the floating-point half never advances.
 */
#ifndef GVAARG_H
#define GVAARG_H

#include "../guest_va_int.h"   /* one level up: this file lives in runtime/musl/ */
#include "gld.h"               /* gld_t, for the long double accessor below */

typedef va_ctx  g_va_ctx;
typedef va_ctx *g_va_list;

/* musl's `va_copy(ap2, ap)` -- take the cursor's CURRENT position, which is
 * what makes `%1$s` mean the first argument after the ones already consumed,
 * exactly as musl defines it. */
#define g_va_copy(dst, src)   ((dst) = *(src))
#define g_va_arg_ptr(c)       ((void *)(uintptr_t)va_gp(&(c)))

/*
 * The printf side needs the other argument classes too -- vfscanf takes only
 * pointers, vfprintf's pop_arg() takes eleven integer widths, a double and a
 * long double -- so the cursor grew the rest of the accessors.
 *
 * Each one is `pointer to cursor` rather than `cursor` because pop_arg is
 * handed a `g_va_list` (a va_ctx *) and must advance the caller's cursor;
 * g_va_arg_ptr above takes a cursor BY VALUE because its one caller, arg_n(),
 * works on a private copy.
 *
 * The narrow signed forms mask and sign-extend explicitly.  A guest argument
 * always arrives as a full 64-bit register, and for a bare `%d` the high half
 * is whatever the caller happened to leave there -- taking the register as-is
 * is what made a 32-bit -1 print as 4294967295 (see the old `arg_bits` walk in
 * guest_va.c, now gone).  The width in the DIRECTIVE is the only thing that
 * says where the sign bit is, which is precisely the question musl's state
 * machine answers with its INT/UINT/SHORT/CHAR/... argument types.
 */
#define g_va_arg_i64(p)       ((uint64_t)va_gp(p))
#define g_va_arg_i32(p)       ((int32_t)(uint32_t)va_gp(p))
#define g_va_arg_u32(p)       ((uint32_t)va_gp(p))
#define g_va_arg_i16(p)       ((int16_t)(uint16_t)va_gp(p))
#define g_va_arg_u16(p)       ((uint16_t)va_gp(p))
#define g_va_arg_i8(p)        ((int8_t)(uint8_t)va_gp(p))
#define g_va_arg_u8(p)        ((uint8_t)va_gp(p))
#define g_va_arg_dbl(p)       (va_fp(p))

/* The guest's long double: 16 bytes out of a v register (or a 16-byte-aligned
 * overflow slot), reinterpreted as binary128.  See va_ld_bits(). */
static inline gld_t g_va_arg_ld(va_ctx *v) {
    gld_t r;
    va_ld_bits(v, &r);
    return r;
}

#endif
