/*
 * t_scanf.c -- regression test for the scanf side.
 *
 * The scanner itself did not change in this batch, but three things under it
 * did, and each of them can only be checked by running it:
 *
 *   * floatscan.c's long-double path now uses musl's own ld128 fmod/copysign/
 *     scalbn/fabs (gf128.c) instead of glibc's _Float128 entry points, and
 *     LDBL_EPSILON is binary128's rather than the host's x87 value -- which is
 *     a behaviour fix, not just a portability one.
 *   * `%ls`/`%lc` are retyped to the guest's 32-bit wchar_t and decode with
 *     musl's own UTF-8 code.
 *   * all of it now compiles for Windows, where none of the glibc spellings
 *     exist.
 *
 * The oracle is the host's sscanf where the two libraries must agree, and
 * written-out expectations where they need not (the scanset that HANDOVER.md
 * sec.26 was about, and the long double, which the host cannot represent).
 *
 * Build (from the generated tree):
 *   cc -Iinclude -Iruntime -std=c11 -O1 tests/t_scanf.c runtime/guest_scanf.c -o t_scanf
 */

#include "guest_decls.h"
#include "guest_va_int.h"

#include <stdio.h>
#include <string.h>

int guest_scan_string(const char *input, const char *fmt, va_ctx *v);
void guest_strtold_musl(void *out, const char *s, char **p);

static int failures, checks;

static void ok(const char *what, int cond) {
    checks++;
    if (!cond) { failures++; printf("FAIL %s\n", what); }
}

/* The same synthetic AAPCS64 caller as t_printf.c: scanf arguments are all
 * pointers, so only the general-purpose half is ever used. */
typedef struct { cpu_t cpu; uint64_t stack[32]; unsigned gp; } caller;

static void caller_init(caller *c) {
    memset(c, 0, sizeof *c);
    c->gp = 0;
    uint64_t s = (uint64_t)(uintptr_t)c->stack;
    memcpy(c->cpu.g + GUEST_OFF_SP, &s, 8);
}

static void arg(caller *c, void *p) {
    uint64_t v = (uint64_t)(uintptr_t)p;
    if (c->gp < 8) memcpy(c->cpu.g + GUEST_OFF_X0 + 8 * c->gp++, &v, 8);
    else c->stack[c->gp++ - 8] = v;
}

static int scan(caller *c, const char *in, const char *fmt) {
    va_ctx v;
    va_init(&v, &c->cpu, 0);
    return guest_scan_string(in, fmt, &v);
}

static void t_basics(void) {
    caller c; caller_init(&c);
    int a = 0, b = 0;
    char s[32] = {0};
    arg(&c, &a); arg(&c, &b); arg(&c, s);
    ok("three conversions", scan(&c, "12 -34 hello", "%d %d %s") == 3);
    ok("int a", a == 12);
    ok("int b", b == -34);
    ok("string", strcmp(s, "hello") == 0);

    /* A suppressed conversion takes NO argument -- the defect the vendoring
     * fixed, and the one most likely to be reintroduced by a "helpful" edit. */
    caller_init(&c);
    a = 0;
    arg(&c, &a);
    ok("%*d takes no argument", scan(&c, "1 2", "%*d %d") == 1);
    ok("%*d value", a == 2);

    /* End of input before the first conversion is EOF, not 0. */
    caller_init(&c);
    arg(&c, &a);
    ok("EOF at end of input", scan(&c, "", "%d") == EOF);
}

static void t_scanset(void) {
    /*
     * HANDOVER.md sec.26's own example: the uniform-name split.  The port's
     * hand-written marshaller read this as the wrong number of directives and
     * every uniform came out with the wrong array size.
     */
    caller c; caller_init(&c);
    char base[64] = {0}, tail[64] = {0};
    unsigned idx = 0;
    arg(&c, base); arg(&c, &idx); arg(&c, tail);
    int n = scan(&c, "block.field[12].x", "%[^[.][%3u]%s");
    ok("scanset conversions", n == 1);
    ok("scanset base", strcmp(base, "block") == 0);

    caller_init(&c);
    memset(base, 0, sizeof base); memset(tail, 0, sizeof tail); idx = 0;
    arg(&c, base); arg(&c, &idx); arg(&c, tail);
    n = scan(&c, "arr[7].y", "%[^[.][%3u]%s");
    ok("scanset with index", n == 3);
    ok("scanset base 2", strcmp(base, "arr") == 0);
    ok("scanset index", idx == 7);
    ok("scanset tail", strcmp(tail, ".y") == 0);

    /* A ']' immediately after the '[' is a member, not the terminator. */
    caller_init(&c);
    memset(base, 0, sizeof base);
    arg(&c, base);
    ok("scanset leading ]", scan(&c, "]]]x", "%[]]") == 1);
    ok("scanset leading ] value", strcmp(base, "]]]") == 0);
}

static void t_floats(void) {
    caller c; caller_init(&c);
    double d = 0;
    float f = 0;
    arg(&c, &d); arg(&c, &f);
    ok("double and float", scan(&c, "3.25 -1.5e3", "%lf %f") == 2);
    ok("double value", d == 3.25);
    ok("float value", f == -1500.0f);

    /* Hex float, and the host must agree. */
    caller_init(&c);
    d = 0;
    arg(&c, &d);
    double hd = 0;
    sscanf("0x1.8p3", "%lf", &hd);
    scan(&c, "0x1.8p3", "%lf");
    ok("hex float", d == hd);
}

static void t_long_double(void) {
    /*
     * The binary128 path.  The result is 16 bytes the host cannot print, so it
     * is compared bit for bit against the value musl's own strtold produces
     * for the same text -- and against a bit pattern written out by hand, so
     * that "both agree" cannot mean "both are wrong the same way".
     */
    unsigned char got[16], via_strtold[16];
    caller c; caller_init(&c);
    arg(&c, got);
    ok("%Lf conversions", scan(&c, "1.0", "%Lf") == 1);
    guest_strtold_musl(via_strtold, "1.0", 0);
    ok("%Lf agrees with strtold", memcmp(got, via_strtold, 16) == 0);

    unsigned char one[16] = {0};
    one[15] = 0x3f; one[14] = 0xff;          /* 1.0 == 0x3fff<112 zero bits> */
    ok("%Lf is exactly 1.0", memcmp(got, one, 16) == 0);

    /* A value that needs more than 64 mantissa bits: 1 + 2^-100.  On the x87
     * long double this rounds to 1.0, so a port that went through the host's
     * type would produce the `one` pattern above. */
    caller_init(&c);
    memset(got, 0, sizeof got);
    arg(&c, got);
    scan(&c, "1.00000000000000000000000000000078886090522101180541", "%Lf");
    ok("%Lf keeps 113 bits", memcmp(got, one, 16) != 0);
    guest_strtold_musl(via_strtold,
                       "1.00000000000000000000000000000078886090522101180541", 0);
    ok("%Lf agrees with strtold (2)", memcmp(got, via_strtold, 16) == 0);
}

static void t_wide(void) {
    /* %ls decodes UTF-8 into the GUEST's 32-bit wchar_t. */
    caller c; caller_init(&c);
    uint32_t ws[8] = {0};
    arg(&c, ws);
    ok("%ls conversions", scan(&c, "A\xc3\xa9\xe4\xb8\xad", "%ls") == 1);
    ok("%ls value", ws[0] == 0x41 && ws[1] == 0xe9 && ws[2] == 0x4e2d && ws[3] == 0);
}

int main(void) {
    t_basics();
    t_scanset();
    t_floats();
    t_long_double();
    t_wide();
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}

/* guest_scanf.c reaches no scratch allocator, so unlike t_printf.c this needs
 * no stub -- the scanner reads a string the caller already owns. */
