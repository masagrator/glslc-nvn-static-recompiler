/*
 * guest_rt.h -- runtime support for elf2c-generated C.
 *
 * The generated code models the guest exactly the way libVEX does: a flat
 * guest-state byte array addressed by VEX register offsets, plus temporaries
 * that become ordinary C locals.  Nothing here is specific to one binary;
 * only GUEST_STATE_SIZE and the section arrays are generated.
 *
 * Pointer model: the RW and RO images are real C arrays.  Every pointer that
 * the loader would have relocated is rewritten at startup to the host address
 * of the corresponding array slot (the linker resolves these; see data_rw.c),
 * so guest pointers ARE host pointers and memory access needs no translation.
 */

#ifndef GUEST_RT_H
#define GUEST_RT_H

/*
 * _GNU_SOURCE before the first include, because a call to an imported libc
 * function is pasted INLINE into the translated function that makes it (see
 * marshal_call), so every one of the tree's ~40,000 files needs the
 * prototype.  The exception-enabled build reaches the locale-aware and
 * multibyte families -- isdigit_l, strtod_l, newlocale, mbsnrtowcs -- which
 * the C library only declares under this macro, and the Makefile keeps
 * -Werror=implicit-function-declaration on precisely so a missing prototype
 * is a build error rather than a truncated 64-bit pointer.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <setjmp.h>
#include <strings.h>   /* strcasecmp */
#include <errno.h>     /* __errno_location */
#include <time.h>      /* clock, strftime_l */
#include <wchar.h>     /* wcslen, mbrtowc and the rest of the wide family */
#include <locale.h>    /* newlocale, uselocale, the *_l functions */
#include <pthread.h>   /* pthread_mutex_lock, pthread_cond_wait */
#ifdef _WIN32
  #ifndef __errno_location
    #define __errno_location() _errno()
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ types */

typedef struct { uint64_t w[2]; } U128;
typedef struct { uint64_t w[4]; } U256;

/* Guest state layout is generated per binary (state size, SP offset, ...).
 * Every translation unit must agree on it, so it lives in its own header
 * rather than in a -D on one compiler invocation. */
#include "guest_config.h"

#ifndef GUEST_STATE_SIZE
#error "guest_config.h must define GUEST_STATE_SIZE"
#endif


typedef struct guest_cpu {
    uint8_t g[GUEST_STATE_SIZE] __attribute__((aligned(16)));
} cpu_t;

/*
 * Every translated function takes an entry selector.  Zero means "start at the
 * beginning"; any other value is the ORIGINAL guest address of a block inside
 * the function, used when a computed branch lands mid-function.  Re-entering
 * an existing function this way avoids duplicating its whole tail into a
 * separate translation for every indirect target.
 */
typedef void (*guest_fn)(cpu_t *, uint64_t entry);

/* --------------------------------------------------------- guest registers */

#define GST_I8(o)    (*(uint8_t  *)(cpu->g + (o)))
#define GST_I16(o)   (*(uint16_t *)(cpu->g + (o)))
#define GST_I32(o)   (*(uint32_t *)(cpu->g + (o)))
#define GST_I64(o)   (*(uint64_t *)(cpu->g + (o)))

static inline U128 gst_get_v128(cpu_t *cpu, unsigned off) {
    U128 r; memcpy(&r, cpu->g + off, 16); return r;
}
static inline void gst_put_v128(cpu_t *cpu, unsigned off, U128 v) {
    memcpy(cpu->g + off, &v, 16);
}
static inline U256 gst_get_v256(cpu_t *cpu, unsigned off) {
    U256 r; memcpy(&r, cpu->g + off, 32); return r;
}
static inline void gst_put_v256(cpu_t *cpu, unsigned off, U256 v) {
    memcpy(cpu->g + off, &v, 32);
}

/* ------------------------------------------------------------------ memory */
/* memcpy-based so that unaligned guest accesses stay defined behaviour. */

#define DEF_LD(name, ty)                                                      \
    static inline ty name(uint64_t a) {                                       \
        ty v; memcpy(&v, (const void *)(uintptr_t)a, sizeof(ty)); return v;   \
    }
#define DEF_ST(name, ty)                                                      \
    static inline void name(uint64_t a, ty v) {                               \
        memcpy((void *)(uintptr_t)a, &v, sizeof(ty));                         \
    }

DEF_LD(ld_i8,  uint8_t)
DEF_LD(ld_i16, uint16_t)
DEF_LD(ld_i32, uint32_t)
DEF_LD(ld_i64, uint64_t)
DEF_LD(ld_v128, U128)
DEF_LD(ld_v256, U256)

DEF_ST(st_i8,  uint8_t)
DEF_ST(st_i16, uint16_t)
DEF_ST(st_i32, uint32_t)
DEF_ST(st_i64, uint64_t)
DEF_ST(st_v128, U128)
DEF_ST(st_v256, U256)

#undef DEF_LD
#undef DEF_ST

/* -------------------------------------------------------- FP bit-container */
/* VEX F32/F64 temporaries are carried as their bit patterns; these convert
 * only at the point of an actual floating-point operation. */

static inline float    f32_of(uint32_t b) { float f;  memcpy(&f, &b, 4); return f; }
static inline uint32_t f32_to(float f)    { uint32_t b; memcpy(&b, &f, 4); return b; }
static inline double   f64_of(uint64_t b) { double d; memcpy(&d, &b, 8); return d; }
static inline uint64_t f64_to(double d)   { uint64_t b; memcpy(&b, &d, 8); return b; }

/* AArch64's default NaN is POSITIVE quiet (0x7ff8000000000000 / 0x7fc00000).
 * x86 produces the NEGATIVE "real indefinite" for the same invalid operations,
 * so `0.0/0.0` and `sqrt(-1)` differ in the sign bit between the guest and the
 * host.  A NaN that merely PROPAGATES from an operand keeps its sign and
 * payload on both machines and must be left alone; only a MANUFACTURED one --
 * no operand was a NaN -- has to be replaced.  Found by vecref.py.
 */
#define GUEST_DEFAULT_NAN64 UINT64_C(0x7ff8000000000000)
#define GUEST_DEFAULT_NAN32 UINT32_C(0x7fc00000)
static inline int f64_isnan(uint64_t b) {
    return (b & UINT64_C(0x7fffffffffffffff)) > UINT64_C(0x7ff0000000000000);
}
static inline int f32_isnan(uint32_t b) {
    return (b & UINT32_C(0x7fffffff)) > UINT32_C(0x7f800000);
}
static inline uint64_t guest_fcanon64_2(uint64_t r, uint64_t a, uint64_t b) {
    return (f64_isnan(r) && !f64_isnan(a) && !f64_isnan(b)) ? GUEST_DEFAULT_NAN64 : r;
}
static inline uint64_t guest_fcanon64_1(uint64_t r, uint64_t a) {
    return (f64_isnan(r) && !f64_isnan(a)) ? GUEST_DEFAULT_NAN64 : r;
}
static inline uint32_t guest_fcanon32_2(uint32_t r, uint32_t a, uint32_t b) {
    return (f32_isnan(r) && !f32_isnan(a) && !f32_isnan(b)) ? GUEST_DEFAULT_NAN32 : r;
}
static inline uint32_t guest_fcanon32_1(uint32_t r, uint32_t a) {
    return (f32_isnan(r) && !f32_isnan(a)) ? GUEST_DEFAULT_NAN32 : r;
}

/* ---- fused multiply-add -------------------------------------------------
 *
 * AArch64's FMADD/FMSUB/FNMADD/FNMSUB and the vector FMLA/FMLS round ONCE,
 * after the multiply and the add together.  libVEX lifts them as a separate
 * MulF and AddF, which rounds twice; irtoc.py puts the pair back together and
 * calls these (see gen.py's fp_is_fused_mac for how the two are told apart).
 *
 * `fma` is the C99 name for exactly this operation and it is correctly rounded
 * on every target this builds for -- x86-64 with -mavx2 has the FMA
 * instructions, which is what the tree is compiled with.
 *
 * The canonicalisation is the same rule as everywhere else: a NaN this
 * operation MANUFACTURED becomes AArch64's positive default NaN, while one
 * that merely propagates from an operand is left alone.
 */
static inline uint32_t guest_fma32(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t r = f32_to(fmaf(f32_of(a), f32_of(b), f32_of(c)));
    return (f32_isnan(r) && !f32_isnan(a) && !f32_isnan(b) && !f32_isnan(c))
           ? GUEST_DEFAULT_NAN32 : r;
}

static inline uint64_t guest_fma64(uint64_t a, uint64_t b, uint64_t c) {
    uint64_t r = f64_to(fma(f64_of(a), f64_of(b), f64_of(c)));
    return (f64_isnan(r) && !f64_isnan(a) && !f64_isnan(b) && !f64_isnan(c))
           ? GUEST_DEFAULT_NAN64 : r;
}

/* FMAX/FMIN vs FMAXNM/FMINNM.
 *
 * VEX lifts all four to the SAME Iop (Max32Fx4 / Min64Fx2 / ...), so the IR
 * alone cannot tell them apart; gen.py looks at the guest instruction and picks
 * the helper.  The four differ only in NaN and signed-zero handling, and the
 * plain `x > y ? x : y` that used to stand here got BOTH wrong: it returns the
 * second operand whenever either is a NaN, and returns -0.0 for max(+0,-0).
 *
 *   FMAX   : if either operand is a NaN, propagate it (a signalling one first,
 *            quieted); max(+0,-0) is +0.
 *   FMAXNM : a quiet NaN is IGNORED when the other operand is a number;
 *            otherwise as FMAX.  (Signalling NaNs still propagate.)
 *   FMIN / FMINNM: the same, mirrored, with min(+0,-0) = -0.
 */
static inline int f32_issnan(uint32_t b) {
    return f32_isnan(b) && !(b & UINT32_C(0x00400000));
}
static inline int f64_issnan(uint64_t b) {
    return f64_isnan(b) && !(b & UINT64_C(0x0008000000000000));
}
static inline uint32_t f32_quiet(uint32_t b) { return b | UINT32_C(0x00400000); }
static inline uint64_t f64_quiet(uint64_t b) { return b | UINT64_C(0x0008000000000000); }

/* FPProcessNaNs: a signalling NaN wins over a quiet one, and `a` over `b`. */
static inline uint32_t f32_pick_nan(uint32_t a, uint32_t b) {
    if (f32_issnan(a)) return f32_quiet(a);
    if (f32_issnan(b)) return f32_quiet(b);
    if (f32_isnan(a))  return a;
    return b;
}
static inline uint64_t f64_pick_nan(uint64_t a, uint64_t b) {
    if (f64_issnan(a)) return f64_quiet(a);
    if (f64_issnan(b)) return f64_quiet(b);
    if (f64_isnan(a))  return a;
    return b;
}

#define GUEST_DEF_MINMAX(W, UT, OFF)                                          \
static inline UT guest_fmax##W(UT a, UT b) {                                  \
    if (f##W##_isnan(a) || f##W##_isnan(b)) return f##W##_pick_nan(a, b);      \
    if (((a | b) & OFF) == 0) return (UT)(a & b);   /* both zero: +0 wins */   \
    return f##W##_of(a) > f##W##_of(b) ? a : b;                               \
}                                                                             \
static inline UT guest_fmin##W(UT a, UT b) {                                  \
    if (f##W##_isnan(a) || f##W##_isnan(b)) return f##W##_pick_nan(a, b);      \
    if (((a | b) & OFF) == 0) return (UT)(a | b);   /* both zero: -0 wins */   \
    return f##W##_of(a) < f##W##_of(b) ? a : b;                               \
}                                                                             \
static inline UT guest_fmaxnm##W(UT a, UT b) {                                \
    if (f##W##_isnan(a) && !f##W##_issnan(a) && !f##W##_isnan(b)) return b;    \
    if (f##W##_isnan(b) && !f##W##_issnan(b) && !f##W##_isnan(a)) return a;    \
    return guest_fmax##W(a, b);                                               \
}                                                                             \
static inline UT guest_fminnm##W(UT a, UT b) {                                \
    if (f##W##_isnan(a) && !f##W##_issnan(a) && !f##W##_isnan(b)) return b;    \
    if (f##W##_isnan(b) && !f##W##_issnan(b) && !f##W##_isnan(a)) return a;    \
    return guest_fmin##W(a, b);                                               \
}

/* OFF masks off the sign bit, so `(a|b) & OFF == 0` means "both are zero". */
GUEST_DEF_MINMAX(32, uint32_t, UINT32_C(0x7fffffff))
GUEST_DEF_MINMAX(64, uint64_t, UINT64_C(0x7fffffffffffffff))
#undef GUEST_DEF_MINMAX

/* ------------------------------------------------- AArch64 condition codes */
/*
 * These live in guest_rt.c rather than being inline here.  They are called
 * from thousands of translation units, so as static inline they were copied
 * into every object -- which bloated the binary and, worse, made any change
 * to a flag rule rebuild the entire tree.  Out of line, a fix costs one
 * object.  Build with -flto if the call overhead ever shows up in a profile.
 */

#define ARM64G_CC_OP_COPY    0
#define ARM64G_CC_OP_ADD32   1
#define ARM64G_CC_OP_ADD64   2
#define ARM64G_CC_OP_SUB32   3
#define ARM64G_CC_OP_SUB64   4
#define ARM64G_CC_OP_ADC32   5
#define ARM64G_CC_OP_ADC64   6
#define ARM64G_CC_OP_SBC32   7
#define ARM64G_CC_OP_SBC64   8
#define ARM64G_CC_OP_LOGIC32 9
#define ARM64G_CC_OP_LOGIC64 10
#define ARM64G_CC_SHIFT_N 31
#define ARM64G_CC_SHIFT_Z 30
#define ARM64G_CC_SHIFT_C 29
#define ARM64G_CC_SHIFT_V 28
#define ARM64CondEQ 0
#define ARM64CondNE 1
#define ARM64CondCS 2
#define ARM64CondCC 3
#define ARM64CondMI 4
#define ARM64CondPL 5
#define ARM64CondVS 6
#define ARM64CondVC 7
#define ARM64CondHI 8
#define ARM64CondLS 9
#define ARM64CondGE 10
#define ARM64CondLT 11
#define ARM64CondGT 12
#define ARM64CondLE 13
#define ARM64CondAL 14
#define ARM64CondNV 15
#define IRRM_NEAREST 0
#define IRRM_NEGINF  1
#define IRRM_POSINF  2
#define IRRM_ZERO    3
#define IRCMP_UN 0x45
#define IRCMP_LT 0x01
#define IRCMP_GT 0x00
#define IRCMP_EQ 0x40

void arm64g_trunc32(uint64_t op, uint64_t *d1, uint64_t *d2, uint64_t *d3);
int arm64g_is32(uint64_t op);
uint64_t arm64g_res(uint64_t op, uint64_t v);
uint64_t arm64g_calculate_flag_n(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3);
uint64_t arm64g_calculate_flag_z(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3);
uint64_t arm64g_calculate_flag_c(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3);
uint64_t arm64g_calculate_flag_v(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3);
uint64_t arm64g_calculate_flags_nzcv(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3);
uint64_t arm64g_calculate_condition(uint64_t cond_n_op, uint64_t d1,
                                    uint64_t d2, uint64_t d3);
double guest_round_mode(double x, uint64_t rm);
uint32_t guest_cmpf64(uint64_t a, uint64_t b);
uint32_t guest_cmpf32(uint32_t a, uint32_t b);
uint64_t guest_absf64(uint64_t a);
uint64_t guest_i32s_to_f64(uint32_t v);
uint32_t guest_f64_to_i32u(uint64_t rm, uint64_t a);
uint64_t guest_f64_to_i64s(uint64_t rm, uint64_t a);
uint64_t guest_f64_to_i64u(uint64_t rm, uint64_t a);
uint32_t guest_f32_to_i32s(uint64_t rm, uint32_t a);
uint32_t guest_f32_to_i32u(uint64_t rm, uint32_t a);
uint64_t guest_f32_to_i64s(uint64_t rm, uint32_t a);
uint64_t guest_f32_to_i64u(uint64_t rm, uint32_t a);
uint64_t guest_roundf64toint(uint64_t rm, uint64_t a);
uint32_t guest_roundf32toint(uint64_t rm, uint32_t a);
uint64_t guest_sqrtf64(uint64_t rm, uint64_t a);
uint32_t guest_sqrtf32(uint64_t rm, uint32_t a);
U128 guest_mullu64(uint64_t a, uint64_t b);
U128 guest_mulls64(uint64_t a, uint64_t b);
U128 guest_cnt8x16(U128 a);
U128 guest_slicev128(U128 hi, U128 lo, uint64_t n);
U128 guest_reverse32sin64_x2(U128 a);
U128 guest_catoddlanes32x4(U128 a, U128 b);
U128 guest_catevenlanes32x4(U128 a, U128 b);
uint64_t guest_narrowun64to32x2(U128 a);
uint64_t guest_narrowun32to16x4(U128 a);
uint64_t guest_narrowun16to8x8(U128 a);

uint32_t guest_absf32(uint32_t a);
uint64_t guest_f32_to_f64(uint32_t a);
uint32_t guest_f64_to_f32(uint64_t rm, uint64_t a);
uint32_t guest_f64_to_i32s(uint64_t rm, uint64_t a);
void guest_fini(cpu_t *cpu);
uint32_t guest_i32s_to_f32(uint64_t rm, uint32_t v);
uint32_t guest_i32u_to_f32(uint64_t rm, uint32_t v);
uint64_t guest_i32u_to_f64(uint32_t v);
uint32_t guest_i64s_to_f32(uint64_t rm, uint64_t v);
uint64_t guest_i64s_to_f64(uint64_t rm, uint64_t v);
uint32_t guest_i64u_to_f32(uint64_t rm, uint64_t v);
uint64_t guest_i64u_to_f64(uint64_t rm, uint64_t v);
void guest_init(cpu_t *cpu);
/* Runs the binary's .init_array constructors, in loader order.  The body is
 * generated (entries.c) because only the generator knows the list; guest_init()
 * calls it once, on the first entry into the guest. */
void guest_run_ctors(cpu_t *cpu);
/* Fills in imported data objects that cannot be initialised statically
 * (guest_cxx.c); called from guest_init() before the constructors. */
void guest_data_imports_init(void);
cpu_t *guest_current_cpu(void);
/* Declared here as well as in the generated guest_decls.h: guest_host.c needs
 * it for the qsort trampoline and includes only this header. */
void guest_dispatch(cpu_t *cpu, uint64_t p);
void guest_missing_import(const char *name);
uint32_t guest_negf32(uint32_t a);
uint64_t guest_negf64(uint64_t a);
void guest_unsupported_import(cpu_t *cpu, const char *name);

U128 guest_perm8x16(U128 data, U128 ctrl);
U128 guest_shlv128(U128 a, uint8_t n);
U128 guest_shrv128(U128 a, uint8_t n);

/* ------------------------------------------------------------ misc helpers */

static inline uint64_t guest_clz64(uint64_t x) { return x ? (uint64_t)__builtin_clzll(x) : 64; }
static inline uint32_t guest_clz32(uint32_t x) { return x ? (uint32_t)__builtin_clz(x)   : 32; }
static inline uint64_t guest_ctz64(uint64_t x) { return x ? (uint64_t)__builtin_ctzll(x) : 64; }
static inline uint32_t guest_ctz32(uint32_t x) { return x ? (uint32_t)__builtin_ctz(x)   : 32; }

/* setjmp support.  The slot is reserved here but setjmp() itself is executed
 * by the generated code, inline, so the jmp_buf names the translated
 * function's own frame rather than a thunk that has already returned. */
typedef struct guest_jb guest_jb;
guest_jb *guest_setjmp_slot(cpu_t *cpu, uint64_t key);
jmp_buf  *guest_jb_env(guest_jb *jb);
void      guest_longjmp(cpu_t *cpu, uint64_t key, uint64_t val);
void      guest_jb_reset(void);

/* ------------------------------------------------- C++ exception support */
/*
 * Only a function whose .eh_frame FDE names a language-specific data area can
 * be re-entered at a landing pad, so only those push a frame.  guest_eh.c has
 * the whole design; the shape is here because the GENERATED wrapper declares
 * one of these as a local.
 *
 * `save` holds the registers an unwinder restores -- x19..x28, x29, sp and
 * d8..d15 -- snapshotted at the CALL rather than at function entry, because
 * those are the values the ABI promises the landing pad will see.  The layout
 * is decided by the generated guest_eh_snapshot()/guest_eh_unsnapshot() pair,
 * which are the only things that ever look inside it.
 */
#define GUEST_EH_SAVE_WORDS 20

typedef struct guest_eh_frame {
    struct guest_eh_frame *prev;
    jmp_buf  jb;
    uint64_t ra;        /* guest return address of the call in progress */
    uint64_t lp;        /* landing pad to resume at; set just before longjmp */
    uint64_t save[GUEST_EH_SAVE_WORDS];
    int      have_save;
} guest_eh_frame;

void guest_eh_push(cpu_t *cpu, guest_eh_frame *f);
void guest_eh_pop(guest_eh_frame *f);
void guest_eh_mark(cpu_t *cpu, uint64_t ra);
guest_eh_frame *guest_eh_top(void);
void guest_eh_set_top(guest_eh_frame *f);
void guest_eh_fatal(const char *what, uint64_t detail);

/* Supplied by the generated tree; weak no-op defaults live in guest_eh.c so
 * that harnesses linking only the runtime still link. */
uint64_t guest_eh_region_lsda(uint64_t pc);
uint64_t guest_eh_region_start(uint64_t pc);
void    *guest_eh_host_of(uint64_t guest_addr);
void     guest_eh_snapshot(cpu_t *cpu, uint64_t *out);
void     guest_eh_unsnapshot(cpu_t *cpu, const uint64_t *in);
void     guest_eh_set_handler_args(cpu_t *cpu, uint64_t x0, uint64_t x1);

/* The Itanium ABI entry points, as this port implements them.  gen.py routes
 * the guest's imports here through IMPORT_ALIAS, the same way it routes
 * operator new, so no host C++ runtime is needed and nothing depends on how a
 * particular libstdc++ spells a mangled name. */
uint64_t guest_cxa_allocate_exception(uint64_t size);
void     guest_cxa_free_exception(uint64_t obj);
void     guest_cxa_throw(cpu_t *cpu, uint64_t obj, uint64_t tinfo, uint64_t dtor);
void     guest_unwind_resume(cpu_t *cpu, uint64_t obj);
uint64_t guest_cxa_begin_catch(uint64_t obj);
void     guest_cxa_end_catch(cpu_t *cpu);
void     guest_cxa_rethrow(cpu_t *cpu);
uint64_t guest_cxa_uncaught_exceptions(void);
void     guest_std_terminate(void);
void     guest_gxx_personality(cpu_t *cpu);
uint64_t guest_cxa_guard_acquire(uint64_t guard);
void     guest_cxa_guard_release(uint64_t guard);
void     guest_cxa_guard_abort(uint64_t guard);

/* A guest branch reached an address the translator could not resolve. */
void guest_unresolved(cpu_t *cpu, uint64_t target, const char *where);
/* A guest instruction VEX could not decode (udf and friends). */
void guest_nodecode(cpu_t *cpu, uint64_t pc);

/* Guest stack: each entry point runs on its own stack region. */
#ifndef GUEST_STACK_SIZE
#define GUEST_STACK_SIZE (8u << 20)
#endif

/* Per-thread scratch memory for the port's OWN bookkeeping.  It comes from
 * mmap, deliberately not from the allocator the guest uses: see the comment
 * on guest_scratch() in guest_rt.c for what sharing one cost. */
char  *guest_scratch(unsigned slot, size_t need);
size_t guest_scratch_cap(unsigned slot);

void *guest_stack_alloc(void);
void  guest_stack_free(void *);

#ifdef __cplusplus
}
#endif
#endif /* GUEST_RT_H */
