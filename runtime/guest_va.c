/*
 * guest_va.c -- variadic marshalling and setjmp/longjmp for translated code.
 *
 * WHY THIS FILE EXISTS
 *
 * A thunk cannot simply forward a guest printf to the host printf: the guest's
 * arguments sit in the guest register file and on the guest stack, and there
 * is no portable way to synthesise a va_list from them.  So an ARGUMENT CURSOR
 * (guest_va_int.h) reads them where they are, and musl's own vfprintf --
 * vendored under runtime/musl/, driven from guest_printf.c -- pulls from that
 * cursor instead of from a va_list.
 *
 * This file used to contain a formatter of its own, which walked the format
 * string and rendered each directive with a single-argument snprintf on the
 * host.  guest_printf.c records why that had to go.
 *
 * ARGUMENT PLACEMENT (AAPCS64)
 *
 * Variadic arguments follow the same rules as named ones on standard AArch64:
 * integers and pointers consume x0..x7 in order, floating-point values consume
 * v0..v7 in order, and anything left over goes on the stack at the call site.
 * Floats are promoted to double by the caller, as C requires.
 */

#include "guest_decls.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef GUEST_OFF_Q0
#error "guest_config.h must define GUEST_OFF_Q0"
#endif

#include "guest_va_int.h"

/* ------------------------------------------------------------- formatting */
/*
 * The formatter itself is musl's -- see guest_printf.c for why -- and lives in
 * its own translation unit.  What is left in this file is the thunks that say
 * where the format string and the arguments are, which is the same division
 * the scanf side has had since HANDOVER.md sec.27.
 *
 * What USED to be here: a 250-line walk of the format string that copied each
 * directive out, normalised its length modifier, worked out from `arg_bits`
 * how wide the guest's argument really was, and rendered it with a single-
 * argument snprintf on the host.  All of it is gone -- grammar, sign
 * extension, the oversized-directive fallback buffer and its scratch slot --
 * because musl's printf_core does the same job by construction and does the
 * parts the re-derived version got wrong (`%n$`, `%S`, `%C`, `%m`, `%Lf`) as
 * well.
 */
char *guest_format(va_ctx *v, const char *fmt, size_t *out_len, int *ret);

/* ------------------------------------------------------------ the thunks */

#define X(i) (*(uint64_t *)(cpu->g + GUEST_OFF_X0 + 8 * (i)))

static void set_ret(cpu_t *cpu, uint64_t v) {
    memcpy(cpu->g + GUEST_OFF_X0, &v, 8);
}

/*
 * A guest printf returns an int: the number of bytes it would have written, or
 * -1 on error.  musl's vfprintf reports EOVERFLOW/EINVAL failures that way and
 * the old marshaller had no way to express them -- it returned the length it
 * had managed so far -- so the count and the status are now carried
 * separately, and the negative one is sign-extended into x0 the way the guest
 * reads it.
 */
static void set_ret_int(cpu_t *cpu, int r) {
    set_ret(cpu, (uint64_t)(int64_t)r);
}

void plt_printf(cpu_t *cpu, uint64_t entry) { (void)entry;
    va_ctx v; va_init(&v, cpu, 1);
    size_t n = 0; int r = -1;
    char *s = guest_format(&v, (const char *)(uintptr_t)X(0), &n, &r);
    if (s) fwrite(s, 1, n, stdout);
    set_ret_int(cpu, r);
}

void plt_fprintf(cpu_t *cpu, uint64_t entry) { (void)entry;
    va_ctx v; va_init(&v, cpu, 2);
    size_t n = 0; int r = -1;
    char *s = guest_format(&v, (const char *)(uintptr_t)X(1), &n, &r);
    FILE *f = (FILE *)(uintptr_t)X(0);
    if (s && f) fwrite(s, 1, n, f);
    set_ret_int(cpu, r);
}

void plt_sprintf(cpu_t *cpu, uint64_t entry) { (void)entry;
    va_ctx v; va_init(&v, cpu, 2);
    size_t n = 0; int r = -1;
    char *s = guest_format(&v, (const char *)(uintptr_t)X(1), &n, &r);
    char *dst = (char *)(uintptr_t)X(0);
    if (s && dst) { memcpy(dst, s, n); dst[n] = '\0'; }
    set_ret_int(cpu, r);
}

void plt_snprintf(cpu_t *cpu, uint64_t entry) { (void)entry;
    va_ctx v; va_init(&v, cpu, 3);
    size_t n = 0; int r = -1;
    char *s = guest_format(&v, (const char *)(uintptr_t)X(2), &n, &r);
    char *dst = (char *)(uintptr_t)X(0);
    uint64_t cap = X(1);
    if (s && dst && cap) {
        size_t copy = n < cap - 1 ? n : cap - 1;
        memcpy(dst, s, copy);
        dst[copy] = '\0';
    }
    /* snprintf returns the length it WOULD have written. */
    set_ret_int(cpu, r);
}

/* guest_va_list moved to guest_va_int.h: the scanf side reads one too. */

/*
 * The v* forms.
 *
 * These used to materialise the guest's va_list into a scratch register file
 * before formatting: walk the format string to classify every argument, pull
 * that many values out of the va_list in the right classes, write them into a
 * fake cpu_t's x0..x7 / q0..q7 and a spill array, and then run the formatter
 * over that.  It needed a SECOND copy of printf's grammar to do the
 * classification -- the same grammar whose gaps this change exists to remove
 * -- and it silently truncated at eight arguments of each class plus 64 spill
 * slots.
 *
 * None of that is necessary.  The cursor already knows how to read a guest
 * va_list (guest_va_int.h grew that when the scanf side started doing it), so
 * the formatter pulls each argument when it decides it needs one, exactly as
 * musl's vfprintf does from a host va_list.
 *
 * The va_list is copied and NOT written back, which is musl's `va_copy(ap2,
 * ap)`: vfprintf leaves its caller's va_list unchanged.  (vsscanf is the
 * opposite -- it consumes in place -- and plt_vsscanf below does write back.)
 */
static char *format_from_valist(uint64_t ap, const char *fmt, size_t *len, int *ret) {
    guest_va_list vl;
    if (ret) *ret = -1;
    if (len) *len = 0;
    if (!ap) return NULL;
    memcpy(&vl, (const void *)(uintptr_t)ap, sizeof vl);
    va_ctx v;
    va_init_valist(&v, &vl);
    return guest_format(&v, fmt, len, ret);
}

void plt_vfprintf(cpu_t *cpu, uint64_t entry) { (void)entry;
    size_t n = 0; int r = -1;
    char *s = format_from_valist(X(2), (const char *)(uintptr_t)X(1), &n, &r);
    FILE *f = (FILE *)(uintptr_t)X(0);
    if (s && f) fwrite(s, 1, n, f);
    set_ret_int(cpu, r);
}

void plt_vsprintf(cpu_t *cpu, uint64_t entry) { (void)entry;
    size_t n = 0; int r = -1;
    char *s = format_from_valist(X(2), (const char *)(uintptr_t)X(1), &n, &r);
    char *dst = (char *)(uintptr_t)X(0);
    if (s && dst) { memcpy(dst, s, n); dst[n] = '\0'; }
    set_ret_int(cpu, r);
}

void plt_vsnprintf(cpu_t *cpu, uint64_t entry) { (void)entry;
    size_t n = 0; int r = -1;
    char *s = format_from_valist(X(3), (const char *)(uintptr_t)X(2), &n, &r);
    char *dst = (char *)(uintptr_t)X(0);
    uint64_t cap = X(1);
    if (s && dst && cap) {
        size_t copy = n < cap - 1 ? n : cap - 1;
        memcpy(dst, s, copy);
        dst[copy] = '\0';
    }
    set_ret_int(cpu, r);
}

/* ----------------------------------------------------------------- sscanf */
/*
 * The scanner itself is musl's -- see guest_scanf.c for why -- and lives in
 * its own translation unit.  What is left here is the three thunks that say
 * where the input, the format and the arguments are.
 */
int guest_scan_string(const char *input, const char *fmt, va_ctx *v);

void plt_sscanf(cpu_t *cpu, uint64_t entry) { (void)entry;
    const char *input = (const char *)(uintptr_t)X(0);
    const char *fmt = (const char *)(uintptr_t)X(1);
    va_ctx v; va_init(&v, cpu, 2);
    set_ret(cpu, (uint64_t)(int64_t)guest_scan_string(input, fmt, &v));
}

/*
 * vsscanf and vasprintf.  Both take a guest va_list, which is a five-field
 * AAPCS64 structure rather than a register window, so the arguments are
 * materialised into a scratch register file first and the ordinary walker is
 * reused -- the same trick format_from_valist() uses for the printf family,
 * and for the same reason: there is one formatter and one scanner, not two.
 *
 * A scanf argument list is all pointers, so only the general-purpose half of
 * the va_list is ever read and the classification walk the printf side needs
 * is unnecessary here.
 */
void plt_vsscanf(cpu_t *cpu, uint64_t entry) { (void)entry;
    const char *input = (const char *)(uintptr_t)X(0);
    const char *fmt = (const char *)(uintptr_t)X(1);
    uint64_t ap = X(2);
    if (!input || !fmt || !ap) { set_ret(cpu, (uint64_t)-1); return; }

    /* The guest's va_list is consumed IN PLACE, which is what C requires of
     * vsscanf: the caller's va_list is left advanced past what was read.
     *
     * This used to walk the format string first to count the conversions that
     * take an argument, copy that many pointers into a scratch register file,
     * and run the scanner over that.  The counting walk was a second copy of
     * scanf's grammar -- the same grammar whose gaps this change exists to
     * remove -- and it is gone: musl's vfscanf pulls each argument when it
     * decides it needs one. */
    guest_va_list vl;
    memcpy(&vl, (const void *)(uintptr_t)ap, sizeof vl);
    va_ctx v;
    va_init_valist(&v, &vl);
    int r = guest_scan_string(input, fmt, &v);
    memcpy((void *)(uintptr_t)ap, &vl, sizeof vl);
    set_ret(cpu, (uint64_t)(int64_t)r);
}

void plt_vasprintf(cpu_t *cpu, uint64_t entry) { (void)entry;
    size_t n = 0; int r = -1;
    char **out = (char **)(uintptr_t)X(0);
    char *s = format_from_valist(X(2), (const char *)(uintptr_t)X(1), &n, &r);
    if (!s || r < 0) {
        if (out) *out = NULL;
        set_ret(cpu, (uint64_t)(int64_t)-1);
        return;
    }
    /*
     * THIS one really does come from the guest's allocator, and must: the
     * guest frees it with free(), and the reference's vasprintf allocates it
     * the same way, so the two sides make the same request at the same point.
     * (`s` is scratch and is not freed -- see guest_format.)
     */
    char *dup = (char *)malloc(n + 1);
    if (!dup) {
        if (out) *out = NULL;
        set_ret(cpu, (uint64_t)(int64_t)-1);
        return;
    }
    memcpy(dup, s, n);
    dup[n] = '\0';
    if (out) *out = dup; else free(dup);
    set_ret(cpu, (uint64_t)n);
}

/* ------------------------------------------------------- setjmp / longjmp */
/*
 * setjmp cannot be called from inside a thunk: the jmp_buf would name the
 * thunk's frame, which is gone by the time longjmp runs.  So the generated
 * code calls guest_setjmp_slot() to reserve a slot and performs the actual
 * setjmp() inline, in the translated function's own frame (see gen.py).
 * Here we only keep the slot table and implement the jump.
 */

#define GUEST_JB_MAX 32

struct guest_jb {
    uint64_t key;               /* guest jmp_buf address */
    jmp_buf  host;
    uint8_t  state[GUEST_STATE_SIZE];
    /* A guest longjmp jumps past the frames between here and there, so it
     * also jumps past their guest_eh_pop()s.  Recording the exception-frame
     * stack alongside the register file is what lets guest_longjmp() put it
     * back, instead of leaving the unwinder walking frames whose host storage
     * has gone. */
    struct guest_eh_frame *eh_top;
    int      used;
};

static _Thread_local struct guest_jb g_jbs[GUEST_JB_MAX];

guest_jb *guest_setjmp_slot(cpu_t *cpu, uint64_t key) {
    int free_slot = -1;
    for (int i = 0; i < GUEST_JB_MAX; i++) {
        if (g_jbs[i].used && g_jbs[i].key == key) { free_slot = i; break; }
        if (!g_jbs[i].used && free_slot < 0) free_slot = i;
    }
    if (free_slot < 0) {
        fprintf(stderr, "guest: out of setjmp slots\n");
        abort();
    }
    g_jbs[free_slot].used = 1;
    g_jbs[free_slot].key = key;
    g_jbs[free_slot].eh_top = guest_eh_top();
    memcpy(g_jbs[free_slot].state, cpu->g, GUEST_STATE_SIZE);
    return &g_jbs[free_slot];
}

/* Release every slot.  Nothing marks a slot free when its frame returns, so
 * the table only ever grew: ten compiles in a row exhausted 32 slots and
 * aborted with "out of setjmp slots".  A guest jmp_buf cannot outlive the
 * guest invocation that created it, so guest_fini() drops them all when the
 * outermost call returns. */
void guest_jb_reset(void) {
    for (int i = 0; i < GUEST_JB_MAX; i++) g_jbs[i].used = 0;
}

/* The generated code performs setjmp() itself, in its own frame. */
jmp_buf *guest_jb_env(guest_jb *jb) { return &jb->host; }

void guest_longjmp(cpu_t *cpu, uint64_t key, uint64_t val) {
    for (int i = 0; i < GUEST_JB_MAX; i++) {
        if (g_jbs[i].used && g_jbs[i].key == key) {
            /* Restore the guest register file as it was at the setjmp, then
             * unwind the host stack to the frame that captured it. */
            memcpy(cpu->g, g_jbs[i].state, GUEST_STATE_SIZE);
            guest_eh_set_top(g_jbs[i].eh_top);
            longjmp(g_jbs[i].host, (int)(val ? val : 1));
        }
    }
    fprintf(stderr, "guest: longjmp to an unknown jmp_buf %#llx\n",
            (unsigned long long)key);
    abort();
}

void plt_longjmp(cpu_t *cpu, uint64_t entry) { (void)entry;
    guest_longjmp(cpu, X(0), X(1));
}
