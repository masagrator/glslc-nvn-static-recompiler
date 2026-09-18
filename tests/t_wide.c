/*
 * t_wide.c -- test for the wide-character and multibyte wrappers.
 *
 * WHAT IT TESTS, AND AGAINST WHAT
 *
 * The wrappers exist for two reasons (guest_wide.c), and each needs its own
 * oracle:
 *
 *  1. THE GUEST'S wchar_t IS 32 BITS.  Every conversion below writes into an
 *     explicitly-typed uint32_t array and the test checks the CODE POINTS, not
 *     just the return value -- which is what would catch a host writing UTF-16
 *     code units into it.  The same test therefore passes on Linux, where the
 *     old direct calls also happened to be right, and fails on Windows for the
 *     old code, which is the whole point.
 *
 *  2. musl's C LOCALE IS UTF-8 AND THE HOST'S IS NOT.  The multi-byte cases
 *     are checked against the UTF-8 encoding written out by hand, because
 *     glibc in the C locale would reject them and MSVCRT would use its code
 *     page.  The ASCII cases are checked against the host as well, since there
 *     the two are required to agree -- that is the claim that lets this change
 *     land without re-running the corpus.
 *
 * Build (from the generated tree):
 *   cc -Iinclude -std=c11 -O1 tests/t_wide.c runtime/guest_wide.c -o t_wide
 */

#include "guest_decls.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

static int failures, checks;

static void ok(const char *what, int cond) {
    checks++;
    if (!cond) { failures++; printf("FAIL %s\n", what); }
}

static void eq_u64(const char *what, uint64_t got, uint64_t want) {
    checks++;
    if (got != want) {
        failures++;
        printf("FAIL %-24s got %llu want %llu\n", what,
               (unsigned long long)got, (unsigned long long)want);
    }
}

/* U+0041 'A', U+00E9 'e-acute', U+4E2D, U+1F600 -- one of each UTF-8 length. */
static const char  U8[]  = "A\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80";
static const uint32_t U32[] = { 0x41, 0xe9, 0x4e2d, 0x1f600 };

static void t_mbrtowc(void) {
    unsigned st = 0;
    uint32_t wc = 0;
    const char *p = U8;
    static const size_t lens[] = { 1, 2, 3, 4 };
    for (int i = 0; i < 4; i++) {
        uint64_t l = guest_mbrtowc(&wc, p, 4, &st);
        eq_u64("mbrtowc length", l, lens[i]);
        eq_u64("mbrtowc value", wc, U32[i]);
        p += l;
    }
    /* One byte at a time: the incomplete-sequence return, which is what the
     * scanf path relies on. */
    st = 0;
    eq_u64("mbrtowc partial", guest_mbrtowc(&wc, "\xe4", 1, &st), (uint64_t)-2);
    eq_u64("mbrtowc partial 2", guest_mbrtowc(&wc, "\xb8", 1, &st), (uint64_t)-2);
    eq_u64("mbrtowc complete", guest_mbrtowc(&wc, "\xad", 1, &st), 1);
    eq_u64("mbrtowc assembled", wc, 0x4e2d);

    /* An invalid byte is EILSEQ.  0xc0 is an overlong lead, which musl rejects
     * outright rather than decoding. */
    st = 0;
    eq_u64("mbrtowc EILSEQ", guest_mbrtowc(&wc, "\xc0\x80", 2, &st), (uint64_t)-1);
    ok("mbrtowc sets EILSEQ", errno == EILSEQ);
}

static void t_wcrtomb(void) {
    char buf[8];
    static const size_t lens[] = { 1, 2, 3, 4 };
    const char *exp = U8;
    for (int i = 0; i < 4; i++) {
        memset(buf, 0, sizeof buf);
        uint64_t l = guest_wcrtomb(buf, U32[i], 0);
        eq_u64("wcrtomb length", l, lens[i]);
        ok("wcrtomb bytes", memcmp(buf, exp, l) == 0);
        exp += l;
    }
    /* A surrogate is not a character: musl refuses to encode it. */
    eq_u64("wcrtomb surrogate", guest_wcrtomb(buf, 0xd800, 0), (uint64_t)-1);
}

static void t_strings(void) {
    uint32_t ws[8];
    const char *src = U8;
    unsigned st = 0;
    uint64_t n = guest_mbsrtowcs(ws, &src, 8, &st);
    eq_u64("mbsrtowcs count", n, 4);
    ok("mbsrtowcs values", memcmp(ws, U32, sizeof U32) == 0);
    ok("mbsrtowcs terminates", ws[4] == 0);
    ok("mbsrtowcs consumed", src == NULL);

    /* mbsnrtowcs bounds the INPUT as well, and must stop on a character
     * boundary -- the partial character at the end is rolled back. */
    src = U8;
    st = 0;
    n = guest_mbsnrtowcs(ws, &src, 4, 8, &st);   /* 4 bytes = A, e-acute, half */
    eq_u64("mbsnrtowcs count", n, 2);
    ok("mbsnrtowcs stops mid-char", src == U8 + 3);

    /* Back to bytes. */
    char out[32];
    const uint32_t *wp = U32;
    memset(out, 0, sizeof out);
    n = guest_wcsnrtombs(out, &wp, 4, sizeof out, 0);
    eq_u64("wcsnrtombs count", n, strlen(U8));
    ok("wcsnrtombs bytes", memcmp(out, U8, strlen(U8)) == 0);
}

static void t_walkers(void) {
    static const uint32_t s[] = { 'a', 'b', 'c', 0 };
    eq_u64("wcslen", guest_wcslen(s), 3);
    eq_u64("wcslen empty", guest_wcslen((const uint32_t[]){0}), 0);
    ok("wmemchr found", guest_wmemchr(s, 'b', 4) == (void *)(s + 1));
    ok("wmemchr missing", guest_wmemchr(s, 'z', 4) == NULL);
    /* The count bounds the search even when the character is present later. */
    ok("wmemchr bounded", guest_wmemchr(s, 'c', 2) == NULL);
}

static void t_ascii_matches_host(void) {
    /*
     * For ASCII the host and musl are required to agree, and this is the check
     * that says so -- it is the reason routing these through musl cannot have
     * changed any corpus result.
     */
    for (unsigned c = 0; c < 0x80; c++) {
        char b1[8] = {0};
        char host[8] = {0};
        uint64_t l1 = guest_wcrtomb(b1, c, 0);
        int l2 = wctomb(host, (wchar_t)c);
        if (l1 != (uint64_t)l2 || memcmp(b1, host, l1) != 0) {
            failures++;
            printf("FAIL ascii wcrtomb differs at %u\n", c);
        }
        checks++;

        uint32_t wc = 0;
        char in[2] = { (char)c, 0 };
        if (c) {
            uint64_t r = guest_mbrtowc(&wc, in, 1, &(unsigned){0});
            if (r != 1 || wc != c) {
                failures++;
                printf("FAIL ascii mbrtowc differs at %u\n", c);
            }
            checks++;
        }
    }
}

static void t_streams(void) {
    /* The wide stream functions encode to UTF-8 on a byte stream.  A temporary
     * file is the simplest way to see what actually reached it. */
    FILE *f = tmpfile();
    if (!f) { printf("SKIP streams (no tmpfile)\n"); return; }
    for (int i = 0; i < 4; i++) guest_fputwc(U32[i], f);
    rewind(f);
    char buf[32] = {0};
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    eq_u64("fputwc bytes", n, strlen(U8));
    ok("fputwc encoding", memcmp(buf, U8, n) == 0);

    rewind(f);
    for (int i = 0; i < 4; i++)
        eq_u64("getwc", (uint64_t)guest_getwc(f), U32[i]);
    /* The GUEST's WEOF, 0xFFFFFFFF -- not the host's, which is 0xFFFF on
     * Windows because its wint_t is 16 bits.  A guest reading that back would
     * see an ordinary character, so the wrappers return the guest's value and
     * this is where that is pinned down. */
    eq_u64("getwc at EOF", (uint64_t)(uint32_t)guest_getwc(f), 0xFFFFFFFFu);

    /* Push one back and read it again.  ASCII always works: C guarantees one
     * byte of pushback. */
    rewind(f);
    guest_getwc(f);
    ok("ungetwc ascii", guest_ungetwc('x', f) == 'x');
    eq_u64("ungetwc ascii read", (uint64_t)guest_getwc(f), 'x');

    /*
     * A MULTI-BYTE pushback needs more room than C promises, and the answer is
     * the host's: glibc accepts it, MSVCRT refuses the second byte.  Both are
     * conforming, so the test accepts either -- but it insists that a REFUSAL
     * LEAVES THE STREAM WHERE IT WAS, which is the part the port is
     * responsible for (guest_ungetwc reads back whatever it managed to push).
     */
    rewind(f);
    int64_t c0 = guest_getwc(f);
    int64_t c1 = guest_getwc(f);
    int64_t u  = guest_ungetwc(c1, f);
    if (u == c1) {
        eq_u64("ungetwc wide re-read", (uint64_t)guest_getwc(f), (uint64_t)c1);
    } else {
        checks++;
        if (guest_getwc(f) != (int64_t)U32[2]) {
            failures++;
            printf("FAIL ungetwc refusal moved the stream\n");
        }
    }
    (void)c0;
    fclose(f);
}

int main(void) {
    t_mbrtowc();
    t_wcrtomb();
    t_strings();
    t_walkers();
    t_ascii_matches_host();
    t_streams();
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
