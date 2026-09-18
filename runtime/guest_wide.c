/*
 * guest_wide.c -- the wide-character and multibyte imports.
 *
 * WHY THESE ARE WRAPPED RATHER THAN CALLED DIRECTLY
 *
 * Every function here used to be a direct call from the generated thunk to the
 * host's C library.  That worked on Linux by coincidence and did not work on
 * Windows at all, for two separate reasons:
 *
 * 1. wchar_t IS NOT THE SAME TYPE.  The guest's is a 32-bit unsigned int, and
 *    the guest passes POINTERS INTO ITS OWN MEMORY for these functions to fill
 *    in.  x86-64 Linux agrees with AArch64 Linux, so glibc's mbsnrtowcs
 *    happened to write 32-bit characters where the guest expected them.  On
 *    Windows wchar_t is 16 bits: the host would write UTF-16 code units into
 *    an array the guest reads as UTF-32, and nothing would report an error.
 *    Two of these functions (wcslen, wmemchr) do not even convert anything --
 *    they just walk an array whose element size the host would get wrong.
 *
 * 2. HALF OF THEM DO NOT EXIST ON MinGW.  mbsnrtowcs and wcsnrtombs are POSIX,
 *    not ISO C, and the Windows C library has neither.  That is the error the
 *    Windows build actually stopped on.
 *
 * So the conversions are musl's own (runtime/musl/gmb.c), written against an
 * explicit uint32_t.  That also closes a fidelity gap nobody had to think
 * about while the port only ran on Linux: musl's C locale is UTF-8 and glibc's
 * is not, so for any byte above 0x7f the host's answer was already the wrong
 * one.  For ASCII -- which is every shader source in the corpus -- the two
 * agree byte for byte, so this changes nothing that was ever measured.
 *
 * WHAT IS NOT HERE.  __ctype_get_mb_cur_max, which lives in guest_host.c
 * because it is a locale question rather than a conversion.  It returns musl's
 * 4 rather than the host's 1 -- held back for one batch because, unlike the
 * conversions here, it differs for EVERY call, and then measured: the guest
 * never calls it at all (HANDOVER.md sec.30.5).
 */

#include "guest_decls.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "musl/gmb.c"

/* --------------------------------------------------------- the conversions */

uint64_t guest_mbrtowc(void *wc, const void *src, uint64_t n, void *st) {
    return (uint64_t)gmb_mbrtowc((gwchar_t *)wc, (const char *)src, (size_t)n,
                                 (unsigned *)st);
}

uint64_t guest_mbrlen(const void *s, uint64_t n, void *st) {
    return (uint64_t)gmb_mbrlen((const char *)s, (size_t)n, (unsigned *)st);
}

int64_t guest_mbtowc(void *wc, const void *src, uint64_t n) {
    return gmb_mbtowc((gwchar_t *)wc, (const char *)src, (size_t)n);
}

uint64_t guest_mbsrtowcs(void *ws, void *src, uint64_t wn, void *st) {
    return (uint64_t)gmb_mbsrtowcs((gwchar_t *)ws, (const char **)src, (size_t)wn,
                                   (unsigned *)st);
}

uint64_t guest_mbsnrtowcs(void *ws, void *src, uint64_t n, uint64_t wn, void *st) {
    return (uint64_t)gmb_mbsnrtowcs((gwchar_t *)ws, (const char **)src, (size_t)n,
                                    (size_t)wn, (unsigned *)st);
}

uint64_t guest_wcrtomb(void *s, uint64_t wc, void *st) {
    return (uint64_t)gmb_wcrtomb((char *)s, (gwchar_t)wc, (unsigned *)st);
}

uint64_t guest_wcsnrtombs(void *dst, void *wcs, uint64_t wn, uint64_t n, void *st) {
    return (uint64_t)gmb_wcsnrtombs((char *)dst, (const gwchar_t **)wcs, (size_t)wn,
                                    (size_t)n, (unsigned *)st);
}

uint64_t guest_wcsrtombs(void *dst, void *wcs, uint64_t n, void *st) {
    return (uint64_t)gmb_wcsrtombs((char *)dst, (const gwchar_t **)wcs, (size_t)n,
                                   (unsigned *)st);
}

/* ------------------------------------------------- the array walkers */
/*
 * No conversion in these two -- only the element size, which is the whole
 * reason they cannot be the host's on Windows.
 */

uint64_t guest_wcslen(const void *s) {
    const gwchar_t *p = (const gwchar_t *)s;
    const gwchar_t *q = p;
    while (*q) q++;
    return (uint64_t)(q - p);
}

void *guest_wmemchr(const void *s, uint64_t c, uint64_t n) {
    const gwchar_t *p = (const gwchar_t *)s;
    gwchar_t want = (gwchar_t)c;
    for (uint64_t i = 0; i < n; i++)
        if (p[i] == want) return (void *)(uintptr_t)(p + i);
    return NULL;
}

/* ------------------------------------------------------- the wide streams */
/*
 * The FILE is a HOST FILE -- the guest's stdin/stdout/stderr are the host's,
 * see the DATA_IMPORTS table in gen.py -- so the byte I/O below is the host's
 * and only the ENCODING is musl's.  Calling the host's fputwc instead would
 * encode with the host's locale, which on glibc in the C locale means
 * refusing every character above 0x7f, and on Windows means MSVCRT's current
 * code page.
 *
 * These do not touch the stream's orientation (fwide): the guest's stdio is
 * not the host's stdio object, so there is no guest-visible orientation to
 * maintain, and setting the HOST stream to wide would break the byte writes
 * that printf/fwrite perform on the same FILE.
 */

/*
 * WEOF IS NOT THE HOST'S.  The guest's wint_t is a 32-bit unsigned int, so its
 * WEOF is 0xFFFFFFFF; on Windows the host's wint_t is 16 bits and WEOF is
 * 0xFFFF, which the guest would read as a perfectly ordinary character.  These
 * three functions therefore return and compare the GUEST's value.  (`-1` as an
 * int64_t sign-extends, so the low 32 bits the guest reads are 0xFFFFFFFF.)
 */
#define GUEST_WEOF      ((int64_t)-1)
#define IS_GUEST_WEOF(c) ((uint32_t)(c) == 0xFFFFFFFFu)

int64_t guest_fputwc(int64_t c, void *f) {
    char mb[4];
    FILE *fp = (FILE *)f;
    if (!fp) return GUEST_WEOF;
    size_t l = gmb_wcrtomb(mb, (gwchar_t)c, 0);
    if (l == (size_t)-1) return GUEST_WEOF;
    if (fwrite(mb, 1, l, fp) != l) return GUEST_WEOF;
    return (int64_t)(uint32_t)c;
}

int64_t guest_getwc(void *f) {
    FILE *fp = (FILE *)f;
    unsigned st = 0;
    gwchar_t wc = 0;
    int first = 1;
    if (!fp) return GUEST_WEOF;
    /*
     * musl's fgetwc, byte at a time (its buffer fast path is not available
     * here and produces the same characters).  A partial sequence at end of
     * input, or an invalid byte after a valid prefix, is an error and the
     * offending byte goes back -- exactly as musl does it, because a caller
     * that then reads bytes must see the same stream position.
     */
    for (;;) {
        int c = fgetc(fp);
        if (c < 0) return GUEST_WEOF;
        unsigned char b = (unsigned char)c;
        size_t l = gmb_mbrtowc(&wc, (const char *)&b, 1, &st);
        if (l == (size_t)-1) {
            if (!first) ungetc(b, fp);
            return GUEST_WEOF;
        }
        if (l != (size_t)-2) return (int64_t)wc;
        first = 0;
    }
}

int64_t guest_ungetwc(int64_t c, void *f) {
    char mb[4];
    FILE *fp = (FILE *)f;
    if (!fp || IS_GUEST_WEOF(c)) return GUEST_WEOF;
    size_t l = gmb_wcrtomb(mb, (gwchar_t)c, 0);
    if (l == (size_t)-1) return GUEST_WEOF;
    /*
     * C guarantees ONE byte of pushback, not four.  musl can always push a
     * whole character because it owns the buffer and checks the room first;
     * here the host's ungetc is the only way to ask, and glibc happens to
     * accept several while MSVCRT refuses the second.
     *
     * The bytes go back in reverse order so the next read returns them in the
     * original one -- and if the host refuses part way, THE ONES ALREADY
     * PUSHED ARE READ BACK OFF, so the stream is left exactly where it was.
     * Returning a failure while having half-pushed a character would leave the
     * caller's next read returning the tail of a character it never got, which
     * is a far worse failure than the one being reported.
     */
    for (size_t i = l; i-- > 0; ) {
        if (ungetc((unsigned char)mb[i], fp) != EOF) continue;
        for (size_t j = i + 1; j < l; j++) (void)fgetc(fp);
        return GUEST_WEOF;
    }
    return (int64_t)(uint32_t)c;
}
