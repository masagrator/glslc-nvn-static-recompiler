/* guest_va_int.h -- variadic argument fetching, shared by guest_va.c (the
 * printf family) and guest_scanf.c (the musl-derived scanf family).
 *
 * This was inside guest_va.c until the scanf family stopped being a hand-
 * written directive walker and became musl's own vfscanf: two files now need
 * the AAPCS64 placement rules, and two copies of them is exactly the kind of
 * thing that drifts.
 */
#ifndef GUEST_VA_INT_H
#define GUEST_VA_INT_H

#include "guest_decls.h"
#include <string.h>

#ifndef GUEST_OFF_Q0
#error "guest_config.h must define GUEST_OFF_Q0"
#endif

/*
 * The v* forms receive an AArch64 va_list, whose layout AAPCS64 fixes as
 *   { void *__stack; void *__gr_top; void *__vr_top; int __gr_offs; int __vr_offs; }
 * with the offsets counting UP to zero from the top of each save area.
 */
typedef struct {
    uint64_t stack, gr_top, vr_top;
    int32_t  gr_offs, vr_offs;
} guest_va_list;

/* ------------------------------------------------------------ arg fetching */
/* `static inline` rather than plain `static`: guest_scanf.c uses va_init and
 * va_gp but never va_fp -- a scanf argument list is all pointers -- and a
 * plain unused `static` function is a warning in a file that includes this. */

typedef struct {
    cpu_t   *cpu;
    unsigned gp;        /* next general register index  */
    unsigned fp;        /* next vector register index   */
    uint64_t stack;     /* overflow area (guest SP at the call) */
    /* Non-NULL for the v* forms (vprintf, vsscanf): the arguments are not in
     * a register window at all but in a guest va_list, an AAPCS64 five-field
     * structure with its own saved areas.  Reading it HERE, rather than
     * copying its contents into a scratch register file first, is what lets a
     * lazy consumer -- musl's vfscanf, which decides argument by argument what
     * it needs -- work on a va_list without anyone having to count the
     * arguments in advance from the format string. */
    guest_va_list *vl;
} va_ctx;

static inline void va_init(va_ctx *v, cpu_t *cpu, unsigned first_gp) {
    v->cpu = cpu;
    v->gp = first_gp;
    v->fp = 0;
    v->stack = *(uint64_t *)(cpu->g + GUEST_OFF_SP);
    v->vl = NULL;
}

/* The same cursor, backed by a guest va_list.  `vl` points at the CALLER's
 * copy, which is what C requires: a function that consumes from a va_list
 * leaves it advanced for its caller. */
static inline void va_init_valist(va_ctx *v, guest_va_list *vl) {
    v->cpu = NULL;
    v->gp = 0;
    v->fp = 0;
    v->stack = 0;
    v->vl = vl;
}

static inline uint64_t va_gp(va_ctx *v) {
    if (v->vl) {
        uint64_t r;
        if (v->vl->gr_offs < 0) {
            memcpy(&r, (const void *)(uintptr_t)(v->vl->gr_top + v->vl->gr_offs), 8);
            v->vl->gr_offs += 8;
        } else {
            memcpy(&r, (const void *)(uintptr_t)v->vl->stack, 8);
            v->vl->stack += 8;
        }
        return r;
    }
    if (v->gp < 8) {
        uint64_t r;
        memcpy(&r, v->cpu->g + GUEST_OFF_X0 + 8 * v->gp, 8);
        v->gp++;
        return r;
    }
    uint64_t r;
    memcpy(&r, (const void *)(uintptr_t)v->stack, 8);
    v->stack += 8;
    return r;
}

static inline double va_fp(va_ctx *v) {
    uint64_t bits;
    if (v->vl) {
        if (v->vl->vr_offs < 0) {
            memcpy(&bits, (const void *)(uintptr_t)(v->vl->vr_top + v->vl->vr_offs), 8);
            v->vl->vr_offs += 16;
        } else {
            memcpy(&bits, (const void *)(uintptr_t)v->vl->stack, 8);
            v->vl->stack += 8;
        }
        return f64_of(bits);
    }
    if (v->fp < 8) {
        memcpy(&bits, v->cpu->g + GUEST_OFF_Q0 + 16 * v->fp, 8);
        v->fp++;
    } else {
        memcpy(&bits, (const void *)(uintptr_t)v->stack, 8);
        v->stack += 8;
    }
    return f64_of(bits);
}

/*
 * A 128-BIT floating argument -- the guest's `long double`.
 *
 * This is what `%Lf` passes, and it is the one argument class the port could
 * not read: va_fp() takes the low EIGHT bytes of the q register, so a
 * binary128 value arrived with its top half missing and printed as a
 * completely different number.  (The old formatter then handed those 8 bytes
 * to the host's snprintf as a `double`, so the directive was wrong twice.)
 *
 * AAPCS64 places a 128-bit floating argument in a whole v register, or, once
 * those are used up, in a 16-byte, 16-BYTE-ALIGNED slot of the overflow area.
 * The alignment is the part that is easy to miss: the general-purpose path
 * advances the stack pointer in 8-byte steps, so a long double after an odd
 * number of stacked words does not begin where the cursor is.
 *
 * The value is delivered as raw bytes rather than as a type, because this
 * header is included by translation units that do not (and should not) pull in
 * the _Float128 machinery; the caller reinterprets the 16 bytes as gld_t.
 */
static inline void va_ld_bits(va_ctx *v, void *out16) {
    if (v->vl) {
        if (v->vl->vr_offs < 0) {
            memcpy(out16, (const void *)(uintptr_t)(v->vl->vr_top + v->vl->vr_offs), 16);
            v->vl->vr_offs += 16;
        } else {
            v->vl->stack = (v->vl->stack + 15) & ~(uint64_t)15;
            memcpy(out16, (const void *)(uintptr_t)v->vl->stack, 16);
            v->vl->stack += 16;
        }
        return;
    }
    if (v->fp < 8) {
        memcpy(out16, v->cpu->g + GUEST_OFF_Q0 + 16 * v->fp, 16);
        v->fp++;
        return;
    }
    v->stack = (v->stack + 15) & ~(uint64_t)15;
    memcpy(out16, (const void *)(uintptr_t)v->stack, 16);
    v->stack += 16;
}


#endif
