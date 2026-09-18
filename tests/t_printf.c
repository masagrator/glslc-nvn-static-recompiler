/*
 * t_printf.c -- differential test for the vendored printf family.
 *
 * WHAT IT TESTS, AND AGAINST WHAT
 *
 * Two different questions, and they need two different oracles:
 *
 *  1. IS THE ARGUMENT MARSHALLING RIGHT?  The guest's arguments are read out
 *     of a synthetic AAPCS64 register file here, exactly as a thunk would read
 *     a real one, and the result is compared with the HOST's snprintf given
 *     the same values.  For every directive where musl and glibc are required
 *     to agree -- integers of every width and sign, strings, characters,
 *     pointers, %f/%e/%g of doubles, flags, widths, precisions, `*` forms --
 *     any difference is the port's bug, not a library difference.  This is the
 *     part that used to be wrong (a 32-bit -1 printing as 4294967295, the
 *     stack overflow area, a `*` width taken from the wrong class), so it is
 *     the part worth hammering.
 *
 *  2. DOES IT DO THE THINGS THE OLD MARSHALLER COULD NOT?  `%n$` positional
 *     arguments, `%S`/`%C` wide output, `%m`, and above all `%Lf`/`%La` of a
 *     binary128 -- which cannot be checked against the host at all, because
 *     the host's long double is the x87 80-bit format.  Those are checked
 *     against expected text, with the binary128 values built from their exact
 *     bit patterns so the expectation does not depend on the host either.
 *
 * Build (from the generated tree):
 *   cc -Iinclude -std=c11 -O1 tests/t_printf.c runtime/guest_printf.c -o t_printf
 * The scratch allocator is stubbed at the bottom rather than dragging in
 * guest_rt.c, which needs the generated image to link.
 */

#include "guest_decls.h"
#include "guest_va_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

char *guest_format(va_ctx *v, const char *fmt, size_t *out_len, int *ret);

static int failures, checks;

/* ---------------------------------------------------- the synthetic caller */
/*
 * A register file laid out the way a variadic call leaves one: integers in
 * x0.. in order, floating-point values in q0.., anything past the eighth of
 * each class in the overflow area that SP points at.  arg_gp/arg_fp/arg_ld
 * place one argument each and fall back to the overflow area exactly as
 * AAPCS64 says, INCLUDING the 16-byte alignment a long double gets there --
 * which is the rule the port had no code for at all before va_ld_bits().
 */
typedef struct {
    cpu_t    cpu;
    uint64_t stack[64];
    unsigned gp, fp, sp;
} caller;

static void caller_init(caller *c, unsigned first_gp) {
    memset(c, 0, sizeof *c);
    c->gp = first_gp;
    c->fp = 0;
    c->sp = 0;
    uint64_t s = (uint64_t)(uintptr_t)c->stack;
    memcpy(c->cpu.g + GUEST_OFF_SP, &s, 8);
}

static void arg_gp(caller *c, uint64_t v) {
    if (c->gp < 8) memcpy(c->cpu.g + GUEST_OFF_X0 + 8 * c->gp++, &v, 8);
    else c->stack[c->sp++] = v;
}

static void arg_fp(caller *c, double d) {
    uint64_t bits;
    memcpy(&bits, &d, 8);
    if (c->fp < 8) memcpy(c->cpu.g + GUEST_OFF_Q0 + 16 * c->fp++, &bits, 8);
    else c->stack[c->sp++] = bits;
}

static void arg_ld(caller *c, const void *bits16) {
    if (c->fp < 8) memcpy(c->cpu.g + GUEST_OFF_Q0 + 16 * c->fp++, bits16, 16);
    else {
        if (c->sp & 1) c->sp++;          /* 16-byte aligned in the overflow area */
        memcpy(&c->stack[c->sp], bits16, 16);
        c->sp += 2;
    }
}

static const char *run(caller *c, const char *fmt, unsigned first_gp, int *ret) {
    va_ctx v;
    va_init(&v, &c->cpu, first_gp);
    size_t n = 0;
    char *s = guest_format(&v, fmt, &n, ret);
    return s ? s : "<null>";
}

static void check(const char *what, const char *got, const char *want) {
    checks++;
    if (strcmp(got, want) != 0) {
        failures++;
        printf("FAIL %-28s got \"%s\" want \"%s\"\n", what, got, want);
    }
}

/* ------------------------------------------- 1. agreement with the host */

#define HOST(buf, ...) (snprintf((buf), sizeof (buf), __VA_ARGS__), (buf))

static void t_integers(void) {
    static const struct { const char *fmt; int64_t val; } cases[] = {
        { "%d",      -1 },        { "%d",  2147483647 },   { "%d", -2147483648LL },
        { "%i",      -42 },       { "%u",  4294967295u },  { "%u", 0 },
        { "%x",      0xdeadbeef }, { "%X", 0xdeadbeef },   { "%o", 0755 },
        { "%hd",     -1 },        { "%hu", 65535 },        { "%hhd", -1 },
        { "%hhu",    255 },       { "%ld", -1 },           { "%lu", 12345678901234LL },
        { "%lld",    -9007199254740993LL },                { "%zu", 4096 },
        { "%jd",     -1 },        { "%td", -8 },
        { "%08d",    -42 },       { "%-8d|", 42 },         { "%+d", 42 },
        { "% d",     42 },        { "%#x", 255 },          { "%#o", 8 },
        { "%.5d",    42 },        { "%10.5d", -42 },       { "%-10.5d|", 42 },
        { "%.0d",    0 },         { "%#.3x", 1 },
    };
    char hb[256];
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        caller c; caller_init(&c, 1);
        arg_gp(&c, (uint64_t)cases[i].val);
        int r;
        const char *got = run(&c, cases[i].fmt, 1, &r);
        /* The host is handed the SAME 64-bit value the guest register holds,
         * with the same directive, so any disagreement is the port's. */
        const char *want;
        const char *f = cases[i].fmt;
        /*
         * The host directive is not always the guest's.  The guest is LP64, so
         * its `%ld` is 64-bit; a Windows host is LLP64, where `long` is 32
         * bits and the same directive would print half the value -- the ORACLE
         * would be wrong, not the port.  So `l` becomes `ll` for the host call
         * when the host's long is narrower than the guest's.  (`%zu`, `%jd`
         * and `%td` need no such fixup: size_t, intmax_t and ptrdiff_t are
         * 64-bit on every host this builds for.)
         */
        char hf[32];
        if (sizeof(long) < 8 && strchr(f, 'l') && !strstr(f, "ll")) {
            char *o = hf;
            for (const char *q = f; *q && o < hf + sizeof hf - 2; q++) {
                *o++ = *q;
                if (*q == 'l') *o++ = 'l';
            }
            *o = '\0';
            f = hf;
        }
        if (strstr(f, "hh") || strstr(f, "h") || (!strstr(f, "l") && !strstr(f, "z")
            && !strstr(f, "j") && !strstr(f, "t")))
            want = HOST(hb, f, (int)cases[i].val);
        else
            want = HOST(hb, f, cases[i].val);
        check(cases[i].fmt, got, want);
    }
}

static void t_floats(void) {
    static const double vals[] = {
        0.0, -0.0, 1.0, -1.0, 0.5, 1e-300, 1e300, 3.14159265358979,
        2.2250738585072014e-308, 1.0/3.0, 1e16, 123456789.125,
    };
    static const char *fmts[] = {
        "%f", "%F", "%e", "%E", "%g", "%G", "%.0f", "%.17g", "%12.4f",
        "%-12.4f|", "%+.3e", "%#.0f", "%.20f",
    };
    char hb[512];
    for (size_t i = 0; i < sizeof vals / sizeof *vals; i++)
        for (size_t j = 0; j < sizeof fmts / sizeof *fmts; j++) {
            caller c; caller_init(&c, 1);
            arg_fp(&c, vals[i]);
            int r;
            const char *got = run(&c, fmts[j], 1, &r);
            check(fmts[j], got, HOST(hb, fmts[j], vals[i]));
        }
    /* Infinities and NaN, which have their own path in fmt_fp. */
    static const double special[] = { 1.0/0.0, -1.0/0.0 };
    for (size_t i = 0; i < 2; i++) {
        caller c; caller_init(&c, 1);
        arg_fp(&c, special[i]);
        int r;
        check("%f inf", run(&c, "%f", 1, &r), HOST(hb, "%f", special[i]));
    }
}

static void t_strings(void) {
    char hb[256];
    struct { const char *fmt; const char *s; } cases[] = {
        { "%s", "hello" }, { "%10s|", "hi" }, { "%-10s|", "hi" },
        { "%.2s", "hello" }, { "%.0s|", "hello" }, { "%s", "" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        caller c; caller_init(&c, 1);
        arg_gp(&c, (uint64_t)(uintptr_t)cases[i].s);
        int r;
        check(cases[i].fmt, run(&c, cases[i].fmt, 1, &r),
              HOST(hb, cases[i].fmt, cases[i].s));
    }
    /* A null %s: musl prints "(null)" and so does glibc. */
    caller c; caller_init(&c, 1);
    arg_gp(&c, 0);
    int r;
    check("%s null", run(&c, "%s", 1, &r), "(null)");
}

static void t_char_and_pointer(void) {
    char hb[64];
    caller c; caller_init(&c, 1);
    arg_gp(&c, 'A');
    int r;
    check("%c", run(&c, "%c", 1, &r), HOST(hb, "%c", 'A'));

    /*
     * %p is NOT compared with the host, because musl and glibc genuinely
     * differ -- and musl's answer here is an accident worth knowing about.
     * musl sets `p = MAX(p, 2*sizeof(void*))` with p == -1, and MAX compares
     * an int against a size_t, so -1 converts to SIZE_MAX and WINS: the
     * minimum field width never applies.  So musl prints the shortest hex
     * form, "0x7f1234567890", where glibc pads to the pointer width, and a
     * null pointer comes out as a bare "0" (the ALT_FORM prefix is suppressed
     * for a zero value).  Reproducing that exactly is the entire point of
     * vendoring rather than re-deriving.
     */
    caller_init(&c, 1);
    arg_gp(&c, 0);
    check("%p null", run(&c, "%p", 1, &r), "0");

    caller_init(&c, 1);
    arg_gp(&c, 0x7f1234567890ULL);
    check("%p", run(&c, "%p", 1, &r), "0x7f1234567890");
}

static void t_mixed_and_overflow(void) {
    /*
     * Nine integers and nine doubles: the ninth of each class is the first
     * that AAPCS64 puts in the overflow area, so this is the case the cursor's
     * stack path exists for.  The host is given the same values through its
     * own varargs.
     */
    char hb[512];
    const char *fmt = "%d %d %d %d %d %d %d %d %d "
                      "%.1f %.1f %.1f %.1f %.1f %.1f %.1f %.1f %.1f";
    caller c; caller_init(&c, 1);
    for (int i = 0; i < 9; i++) arg_gp(&c, (uint64_t)(int64_t)(i - 4));
    for (int i = 0; i < 9; i++) arg_fp(&c, i + 0.5);
    int r;
    snprintf(hb, sizeof hb, fmt, -4, -3, -2, -1, 0, 1, 2, 3, 4,
             0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5);
    check("overflow area", run(&c, fmt, 1, &r), hb);
}

static void t_star(void) {
    char hb[128];
    caller c; caller_init(&c, 1);
    arg_gp(&c, 8);
    arg_gp(&c, 3);
    arg_fp(&c, 3.14159);
    int r;
    check("%*.*f", run(&c, "%*.*f", 1, &r), HOST(hb, "%*.*f", 8, 3, 3.14159));

    /* A negative `*` width means left adjustment, and it takes the argument
     * from the INTEGER class -- the old marshaller's `star_width` path is the
     * one that got this wrong when it followed a float. */
    caller_init(&c, 1);
    arg_gp(&c, (uint64_t)(int64_t)-8);
    arg_fp(&c, 1.5);
    check("%*f neg", run(&c, "%*.1f|", 1, &r), HOST(hb, "%*.1f|", -8, 1.5));
}

static void t_percent_n(void) {
    caller c; caller_init(&c, 1);
    int n = -1;
    arg_gp(&c, (uint64_t)(uintptr_t)"abcd");
    arg_gp(&c, (uint64_t)(uintptr_t)&n);
    int r;
    check("%n text", run(&c, "%s%n", 1, &r), "abcd");
    checks++;
    if (n != 4) { failures++; printf("FAIL %%n got %d want 4\n", n); }
}

/* ------------------------- 2. what the old marshaller could not do at all */

/* A binary128 built from its exact bits, so the expectation does not depend on
 * the host's long double existing or being any particular format. */
static void ld_bits(unsigned char out[16], uint64_t hi, uint64_t lo) {
    memcpy(out, &lo, 8);
    memcpy(out + 8, &hi, 8);
}

static void t_long_double(void) {
    unsigned char b[16];
    caller c;
    int r;

    /* 1.0 : sign 0, exponent 0x3fff, mantissa 0 */
    ld_bits(b, 0x3fff000000000000ULL, 0);
    caller_init(&c, 1); arg_ld(&c, b);
    check("%Lf 1.0", run(&c, "%Lf", 1, &r), "1.000000");

    /* -2.5 : exponent 0x4000, mantissa 0x4000... */
    ld_bits(b, 0xc000400000000000ULL, 0);
    caller_init(&c, 1); arg_ld(&c, b);
    check("%Lf -2.5", run(&c, "%.2Lf", 1, &r), "-2.50");

    /*
     * The decisive one: a value whose top half alone is meaningless.  The low
     * 64 bits are all ones, which is what the old code passed to the host as a
     * `double` -- a NaN.  Correct output needs all 16 bytes.
     *
     * 0x3fff_ffffffffffff_ffffffffffffffff is the largest long double below 2:
     * 2 - 2^-112 = 1.9999999999999999999999999999999998074070...  Printed at 40
     * decimals it shows every one of the 113 bits; a `double` cannot represent
     * this value at all (it rounds to exactly 2), so a port that reads only
     * half the register cannot produce this line by accident.
     */
    ld_bits(b, 0x3fffffffffffffffULL, 0xffffffffffffffffULL);
    caller_init(&c, 1); arg_ld(&c, b);
    check("%.40Lf near 2", run(&c, "%.40Lf", 1, &r),
          "1.9999999999999999999999999999999998074070");

    /* %La prints the exact hex form, which is where 113 bits show plainly. */
    ld_bits(b, 0x3fff000000000000ULL, 0);
    caller_init(&c, 1); arg_ld(&c, b);
    check("%La 1.0", run(&c, "%La", 1, &r), "0x1p+0");

    ld_bits(b, 0x4000921fb54442d1ULL, 0x8469898cc51701b8ULL);   /* pi */
    caller_init(&c, 1); arg_ld(&c, b);
    check("%La pi", run(&c, "%La", 1, &r), "0x1.921fb54442d18469898cc51701b8p+1");

    /* Infinity and NaN take fmt_fp's early path. */
    ld_bits(b, 0x7fff000000000000ULL, 0);
    caller_init(&c, 1); arg_ld(&c, b);
    check("%Lf inf", run(&c, "%Lf", 1, &r), "inf");

    /* Past the eighth vector register: the overflow slot, 16-byte aligned. */
    caller_init(&c, 1);
    for (int i = 0; i < 8; i++) arg_fp(&c, 1.0);
    ld_bits(b, 0x3fff000000000000ULL, 0);
    arg_ld(&c, b);
    check("%Lf stacked", run(&c, "%.0f%.0f%.0f%.0f%.0f%.0f%.0f%.0f %Lf", 1, &r),
          "11111111 1.000000");
}

static void t_positional(void) {
    caller c; caller_init(&c, 1);
    arg_gp(&c, (uint64_t)(uintptr_t)"one");
    arg_gp(&c, (uint64_t)(uintptr_t)"two");
    int r;
    check("%n$", run(&c, "%2$s %1$s", 1, &r), "two one");
}

static void t_wide(void) {
    /* %S is a wide string, encoded to UTF-8 by musl's rules regardless of the
     * host's locale.  U+00E9, U+4E2D, U+1F600 exercise the 2-, 3- and 4-byte
     * forms. */
    static const uint32_t ws[] = { 0x41, 0xe9, 0x4e2d, 0x1f600, 0 };
    caller c; caller_init(&c, 1);
    arg_gp(&c, (uint64_t)(uintptr_t)ws);
    int r;
    check("%S", run(&c, "%S", 1, &r), "A\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80");

    caller_init(&c, 1);
    arg_gp(&c, 0x4e2d);
    check("%C", run(&c, "%C", 1, &r), "\xe4\xb8\xad");
}

static void t_errno_m(void) {
    caller c; caller_init(&c, 1);
    errno = 2;      /* ENOENT on musl and on Linux */
    int r;
    check("%m", run(&c, "%m", 1, &r), "No such file or directory");

    caller_init(&c, 1);
    errno = 25;     /* musl: "Not a tty"; glibc: "Inappropriate ioctl..." */
    check("%m musl wording", run(&c, "%m", 1, &r), "Not a tty");
}

static void t_return_value(void) {
    caller c; caller_init(&c, 1);
    arg_gp(&c, (uint64_t)(uintptr_t)"abcde");
    int r = 0;
    run(&c, "[%s]", 1, &r);
    checks++;
    if (r != 7) { failures++; printf("FAIL return got %d want 7\n", r); }

    /* An unknown conversion is EINVAL and -1, which the old marshaller had no
     * way to report -- it printed the directive literally. */
    caller_init(&c, 1);
    r = 0;
    run(&c, "%q", 1, &r);
    checks++;
    if (r != -1) { failures++; printf("FAIL bad directive got %d want -1\n", r); }
}

int main(void) {
    t_integers();
    t_floats();
    t_strings();
    t_char_and_pointer();
    t_mixed_and_overflow();
    t_star();
    t_percent_n();
    t_long_double();
    t_positional();
    t_wide();
    t_errno_m();
    t_return_value();
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}

/* ------------------------------------------------------------- the stub */
/*
 * guest_scratch() lives in guest_rt.c, which cannot be linked without the
 * generated image.  The contract is all this test needs: a per-slot buffer
 * that grows and keeps its contents.
 */
static char  *slot[4];
static size_t slot_cap[4];

char *guest_scratch(unsigned s, size_t need) {
    if (s >= 4) return NULL;
    if (need && need <= slot_cap[s]) return slot[s];
    size_t cap = slot_cap[s] ? slot_cap[s] : 4096;
    while (cap < need) cap *= 2;
    char *p = (char *)realloc(slot[s], cap);
    if (!p) return NULL;
    slot[s] = p;
    slot_cap[s] = cap;
    return p;
}

size_t guest_scratch_cap(unsigned s) { return s < 4 ? slot_cap[s] : 0; }
