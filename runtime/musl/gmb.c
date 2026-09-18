/* gmb.c -- musl's multibyte conversions, on the GUEST's wchar_t.
 *
 * WHY THIS FILE EXISTS -- TWO REASONS, AND EITHER ONE ALONE WOULD BE ENOUGH
 *
 * 1. THE ANSWER MUST BE musl's.  The guest is a musl binary, and musl's C
 *    locale is UTF-8 -- always, unconditionally, with no way to select
 *    anything else.  glibc's C locale is not: bytes 0x80..0xff are not part of
 *    its character set at all, so the host's mbrtowc reports EILSEQ exactly
 *    where the guest's returns a character.  Calling the host's conversion
 *    functions therefore gives the wrong answer for every non-ASCII byte, and
 *    the whole point of runtime/musl/ is not to do that.  (guest_scanf.c
 *    already reached this conclusion for the one function IT needed; this file
 *    is the same decision for the whole family, taken from musl's source
 *    rather than restated.)
 *
 * 2. THE GUEST'S wchar_t IS 32 BITS.  On AArch64 Linux wchar_t is a 32-bit
 *    unsigned int, and the guest hands these functions POINTERS INTO ITS OWN
 *    MEMORY to fill in.  x86-64 Linux agrees, so calling the host's
 *    mbsnrtowcs happened to write the right thing there -- but on Windows
 *    wchar_t is 16 bits, and the host's version would have written UTF-16 code
 *    units into an array the guest reads as 32-bit characters.  Every
 *    character after the first would be wrong, and nothing would report an
 *    error.  The conversions are written here against an explicit uint32_t, so
 *    the host's idea of wchar_t never enters into it.
 *
 * Vendored from musl 1.2.4/1.2.5, src/multibyte/{internal.c,internal.h,
 * mbrtowc.c,mbtowc.c,mbrlen.c,mbsrtowcs.c,mbsnrtowcs.c,wcrtomb.c,wctomb.c,
 * wcsnrtombs.c,wcsrtombs.c}.
 *
 * Edits, and nothing else:
 *   * `wchar_t` -> `gwchar_t` (uint32_t), and the names gain a `gmb_` prefix.
 *   * `mbstate_t *` -> `unsigned *`.  musl's mbstate_t is two unsigned words
 *     of which only the first is used, and musl's own code casts the pointer
 *     to `unsigned *` before touching it; taking the guest's pointer as that
 *     directly is what musl does, minus the cast.
 *   * MB_CUR_MAX is 4, spelled as a constant.  In musl it reads the current
 *     locale, and the answer is 4 unless the locale is one of the byte-based
 *     legacy ones, which the guest cannot select -- it never calls setlocale
 *     with anything but "C", and guest_newlocale() returns NULL for every
 *     newlocale the guest makes.  musl's `MB_CUR_MAX==1` branches are kept
 *     verbatim rather than deleted so that this stays diffable against musl,
 *     and they are simply unreachable.
 *   * mbsrtowcs's aligned-word fast path is dropped.  It reads four bytes at a
 *     time through a may_alias uint32_t, which is a strict-aliasing and an
 *     alignment question the port does not need to answer for a path that only
 *     makes it faster; the byte loop it short-circuits is musl's own and
 *     produces the same characters.
 *   * every function is `static inline`, because this file is #included by
 *     more than one translation unit (guest_printf.c wants wctomb, guest_wide.c
 *     wants all of them) and must not define a symbol twice.
 */
#ifndef GMB_C
#define GMB_C

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* The guest's wchar_t.  Unsigned, 32-bit, on every AArch64 Linux ABI. */
typedef uint32_t gwchar_t;

#define GMB_CUR_MAX 4
#define GMB_LEN_MAX 4

/* ------------------------------------------- musl src/multibyte/internal.h */

/* Upper 6 state bits are a negative integer offset to bound-check next byte */
/*    equivalent to: ( (b-0x80) | (b+offset) ) & ~0x3f      */
#define GMB_OOB(c,b) (((((b)>>3)-0x10)|(((b)>>3)+((int32_t)(c)>>26))) & ~7)

/* Interval [a,b). Either a must be 80 or b must be c0, lower 3 bits clear. */
#define GMB_R(a,b) ((uint32_t)((a==0x80 ? 0x40u-b : 0u-a) << 23))

#define GMB_SA 0xc2u
#define GMB_SB 0xf4u

/* Arbitrary encoding for representing code units instead of characters. */
#define GMB_CODEUNIT(c) (0xdfff & (signed char)(c))
#define GMB_IS_CODEUNIT(c) ((unsigned)(c)-0xdf80 < 0x80)

/* ------------------------------------------- musl src/multibyte/internal.c */

#define GMB_C_(x) ( x<2 ? -1 : ( GMB_R(0x80,0xc0) | x ) )
#define GMB_D_(x) GMB_C_((x+16))
#define GMB_E_(x) ( ( x==0 ? GMB_R(0xa0,0xc0) : \
                      x==0xd ? GMB_R(0x80,0xa0) : \
                      GMB_R(0x80,0xc0) ) \
                  | ( GMB_R(0x80,0xc0) >> 6 ) \
                  | x )
#define GMB_F_(x) ( ( x>=5 ? 0 : \
                      x==0 ? GMB_R(0x90,0xc0) : \
                      x==4 ? GMB_R(0x80,0x90) : \
                      GMB_R(0x80,0xc0) ) \
                  | ( GMB_R(0x80,0xc0) >> 6 ) \
                  | ( GMB_R(0x80,0xc0) >> 12 ) \
                  | x )

static const uint32_t gmb_bittab[] = {
	                    GMB_C_(0x2),GMB_C_(0x3),GMB_C_(0x4),GMB_C_(0x5),GMB_C_(0x6),GMB_C_(0x7),
	GMB_C_(0x8),GMB_C_(0x9),GMB_C_(0xa),GMB_C_(0xb),GMB_C_(0xc),GMB_C_(0xd),GMB_C_(0xe),GMB_C_(0xf),
	GMB_D_(0x0),GMB_D_(0x1),GMB_D_(0x2),GMB_D_(0x3),GMB_D_(0x4),GMB_D_(0x5),GMB_D_(0x6),GMB_D_(0x7),
	GMB_D_(0x8),GMB_D_(0x9),GMB_D_(0xa),GMB_D_(0xb),GMB_D_(0xc),GMB_D_(0xd),GMB_D_(0xe),GMB_D_(0xf),
	GMB_E_(0x0),GMB_E_(0x1),GMB_E_(0x2),GMB_E_(0x3),GMB_E_(0x4),GMB_E_(0x5),GMB_E_(0x6),GMB_E_(0x7),
	GMB_E_(0x8),GMB_E_(0x9),GMB_E_(0xa),GMB_E_(0xb),GMB_E_(0xc),GMB_E_(0xd),GMB_E_(0xe),GMB_E_(0xf),
	GMB_F_(0x0),GMB_F_(0x1),GMB_F_(0x2),GMB_F_(0x3),GMB_F_(0x4)
};

/* -------------------------------------------------------------- wcrtomb(3) */

static inline size_t gmb_wcrtomb(char *restrict s, gwchar_t wc, unsigned *restrict st) {
	(void)st;   /* musl ignores the state here too: UTF-8 output is stateless */
	if (!s) return 1;
	if ((unsigned)wc < 0x80) {
		*s = wc;
		return 1;
	} else if (GMB_CUR_MAX == 1) {
		if (!GMB_IS_CODEUNIT(wc)) {
			errno = EILSEQ;
			return -1;
		}
		*s = wc;
		return 1;
	} else if ((unsigned)wc < 0x800) {
		*s++ = 0xc0 | (wc>>6);
		*s = 0x80 | (wc&0x3f);
		return 2;
	} else if ((unsigned)wc < 0xd800 || (unsigned)wc-0xe000 < 0x2000) {
		*s++ = 0xe0 | (wc>>12);
		*s++ = 0x80 | ((wc>>6)&0x3f);
		*s = 0x80 | (wc&0x3f);
		return 3;
	} else if ((unsigned)wc-0x10000 < 0x100000) {
		*s++ = 0xf0 | (wc>>18);
		*s++ = 0x80 | ((wc>>12)&0x3f);
		*s++ = 0x80 | ((wc>>6)&0x3f);
		*s = 0x80 | (wc&0x3f);
		return 4;
	}
	errno = EILSEQ;
	return -1;
}

/* --------------------------------------------------------------- wctomb(3) */

static inline int gmb_wctomb(char *s, gwchar_t wc) {
	if (!s) return 0;
	return gmb_wcrtomb(s, wc, 0);
}

/* -------------------------------------------------------------- mbrtowc(3) */

static inline size_t gmb_mbrtowc(gwchar_t *restrict wc, const char *restrict src,
                                 size_t n, unsigned *restrict st) {
	static unsigned internal_state;
	unsigned c;
	const unsigned char *s = (const void *)src;
	const unsigned N = n;
	gwchar_t dummy;

	if (!st) st = &internal_state;
	c = *st;

	if (!s) {
		if (c) goto ilseq;
		return 0;
	} else if (!wc) wc = &dummy;

	if (!n) return -2;
	if (!c) {
		if (*s < 0x80) return !!(*wc = *s);
		if (GMB_CUR_MAX==1) return (*wc = GMB_CODEUNIT(*s)), 1;
		if (*s-GMB_SA > GMB_SB-GMB_SA) goto ilseq;
		c = gmb_bittab[*s++-GMB_SA]; n--;
	}

	if (n) {
		if (GMB_OOB(c,*s)) goto ilseq;
loop:
		c = c<<6 | *s++-0x80; n--;
		if (!(c&(1U<<31))) {
			*st = 0;
			*wc = c;
			return N-n;
		}
		if (n) {
			if (*s-0x80u >= 0x40) goto ilseq;
			goto loop;
		}
	}

	*st = c;
	return -2;
ilseq:
	*st = 0;
	errno = EILSEQ;
	return -1;
}

/* --------------------------------------------------------------- mbrlen(3) */

static inline size_t gmb_mbrlen(const char *restrict s, size_t n, unsigned *restrict st) {
	static unsigned internal;
	return gmb_mbrtowc(0, s, n, st ? st : &internal);
}

/* --------------------------------------------------------------- mbtowc(3) */

static inline int gmb_mbtowc(gwchar_t *restrict wc, const char *restrict src, size_t n) {
	unsigned c;
	const unsigned char *s = (const void *)src;
	gwchar_t dummy;

	if (!s) return 0;
	if (!n) goto ilseq;
	if (!wc) wc = &dummy;

	if (*s < 0x80) return !!(*wc = *s);
	if (GMB_CUR_MAX==1) return (*wc = GMB_CODEUNIT(*s)), 1;
	if (*s-GMB_SA > GMB_SB-GMB_SA) goto ilseq;
	c = gmb_bittab[*s++-GMB_SA];

	/* Avoid excessive checks against n: If shifting the state n-1
	 * times does not clear the high bit, then the value of n is
	 * insufficient to read a character */
	if (n<4 && ((c<<(6*n-6)) & (1U<<31))) goto ilseq;

	if (GMB_OOB(c,*s)) goto ilseq;
	c = c<<6 | *s++-0x80;
	if (!(c&(1U<<31))) {
		*wc = c;
		return 2;
	}

	if (*s-0x80u >= 0x40) goto ilseq;
	c = c<<6 | *s++-0x80;
	if (!(c&(1U<<31))) {
		*wc = c;
		return 3;
	}

	if (*s-0x80u >= 0x40) goto ilseq;
	*wc = c<<6 | *s++-0x80;
	return 4;

ilseq:
	errno = EILSEQ;
	return -1;
}

/* ------------------------------------------------------------ mbsrtowcs(3) */

static inline size_t gmb_mbsrtowcs(gwchar_t *restrict ws, const char **restrict src,
                                   size_t wn, unsigned *restrict st) {
	const unsigned char *s = (const void *)*src;
	size_t wn0 = wn;
	unsigned c = 0;

	if (st && (c = *st)) {
		if (ws) {
			*st = 0;
			goto resume;
		} else {
			goto resume0;
		}
	}

	if (GMB_CUR_MAX==1) {
		if (!ws) return strlen((const char *)s);
		for (;;) {
			if (!wn) {
				*src = (const void *)s;
				return wn0;
			}
			if (!*s) break;
			c = *s++;
			*ws++ = GMB_CODEUNIT(c);
			wn--;
		}
		*ws = 0;
		*src = 0;
		return wn0-wn;
	}

	if (!ws) for (;;) {
		if (*s-1u < 0x7f) {
			s++;
			wn--;
			continue;
		}
		if (*s-GMB_SA > GMB_SB-GMB_SA) break;
		c = gmb_bittab[*s++-GMB_SA];
resume0:
		if (GMB_OOB(c,*s)) { s--; break; }
		s++;
		if (c&(1U<<25)) {
			if (*s-0x80u >= 0x40) { s-=2; break; }
			s++;
			if (c&(1U<<19)) {
				if (*s-0x80u >= 0x40) { s-=3; break; }
				s++;
			}
		}
		wn--;
		c = 0;
	} else for (;;) {
		if (!wn) {
			*src = (const void *)s;
			return wn0;
		}
		if (*s-1u < 0x7f) {
			*ws++ = *s++;
			wn--;
			continue;
		}
		if (*s-GMB_SA > GMB_SB-GMB_SA) break;
		c = gmb_bittab[*s++-GMB_SA];
resume:
		if (GMB_OOB(c,*s)) { s--; break; }
		c = (c<<6) | *s++-0x80;
		if (c&(1U<<31)) {
			if (*s-0x80u >= 0x40) { s-=2; break; }
			c = (c<<6) | *s++-0x80;
			if (c&(1U<<31)) {
				if (*s-0x80u >= 0x40) { s-=3; break; }
				c = (c<<6) | *s++-0x80;
			}
		}
		*ws++ = c;
		wn--;
		c = 0;
	}

	if (!c && !*s) {
		if (ws) {
			*ws = 0;
			*src = 0;
		}
		return wn0-wn;
	}
	errno = EILSEQ;
	if (ws) *src = (const void *)s;
	return -1;
}

/* ----------------------------------------------------------- mbsnrtowcs(3) */

static inline size_t gmb_mbsnrtowcs(gwchar_t *restrict wcs, const char **restrict src,
                                    size_t n, size_t wn, unsigned *restrict st) {
	size_t l, cnt=0, n2;
	gwchar_t *ws, wbuf[256];
	const char *s = *src;
	const char *tmp_s;

	if (!wcs) ws = wbuf, wn = sizeof wbuf / sizeof *wbuf;
	else ws = wcs;

	/* making sure output buffer size is at most n/4 will ensure
	 * that mbsrtowcs never reads more than n input bytes. thus
	 * we can use mbsrtowcs as long as it's practical.. */

	while ( s && wn && ( (n2=n/4)>=wn || n2>32 ) ) {
		if (n2>=wn) n2=wn;
		tmp_s = s;
		l = gmb_mbsrtowcs(ws, &s, n2, st);
		if (!(l+1)) {
			cnt = l;
			wn = 0;
			break;
		}
		if (ws != wbuf) {
			ws += l;
			wn -= l;
		}
		n = s ? n - (s - tmp_s) : 0;
		cnt += l;
	}
	if (s) while (wn && n) {
		l = gmb_mbrtowc(ws, s, n, st);
		if (l+2<=2) {
			if (!(l+1)) {
				cnt = l;
				break;
			}
			if (!l) {
				s = 0;
				break;
			}
			/* have to roll back partial character */
			*st = 0;
			break;
		}
		s += l; n -= l;
		/* safe - this loop runs fewer than sizeof(wbuf)/8 times */
		ws++; wn--;
		cnt++;
	}
	if (wcs) *src = s;
	return cnt;
}

/* ----------------------------------------------------------- wcsnrtombs(3) */

static inline size_t gmb_wcsnrtombs(char *restrict dst, const gwchar_t **restrict wcs,
                                    size_t wn, size_t n, unsigned *restrict st) {
	(void)st;   /* as in musl: UTF-8 output carries no shift state */
	const gwchar_t *ws = *wcs;
	size_t cnt = 0;
	if (!dst) n=0;
	while (ws && wn) {
		char tmp[GMB_LEN_MAX];
		size_t l = gmb_wcrtomb(n<GMB_LEN_MAX ? tmp : dst, *ws, 0);
		if (l==-1) {
			cnt = -1;
			break;
		}
		if (dst) {
			if (n<GMB_LEN_MAX) {
				if (l>n) break;
				memcpy(dst, tmp, l);
			}
			dst += l;
			n -= l;
		}
		if (!*ws) {
			ws = 0;
			break;
		}
		ws++;
		wn--;
		cnt += l;
	}
	if (dst) *wcs = ws;
	return cnt;
}

/* ------------------------------------------------------------ wcsrtombs(3) */

static inline size_t gmb_wcsrtombs(char *restrict s, const gwchar_t **restrict ws,
                                   size_t n, unsigned *restrict st) {
	(void)st;   /* as in musl: UTF-8 output carries no shift state */
	const gwchar_t *ws2;
	char buf[4];
	size_t N = n, l;
	if (!s) {
		for (n=0, ws2=*ws; *ws2; ws2++) {
			if (*ws2 >= 0x80u) {
				l = gmb_wcrtomb(buf, *ws2, 0);
				if (!(l+1)) return -1;
				n += l;
			} else n++;
		}
		return n;
	}
	while (n>=4) {
		if (**ws-1u >= 0x7fu) {
			if (!**ws) {
				*s = 0;
				*ws = 0;
				return N-n;
			}
			l = gmb_wcrtomb(s, **ws, 0);
			if (!(l+1)) return -1;
			s += l;
			n -= l;
		} else {
			*s++ = **ws;
			n--;
		}
		(*ws)++;
	}
	while (n) {
		if (**ws-1u >= 0x7fu) {
			if (!**ws) {
				*s = 0;
				*ws = 0;
				return N-n;
			}
			l = gmb_wcrtomb(buf, **ws, 0);
			if (!(l+1)) return -1;
			if (l>n) return N-n;
			gmb_wcrtomb(s, **ws, 0);
			s += l;
			n -= l;
		} else {
			*s++ = **ws;
			n--;
		}
		(*ws)++;
	}
	return N;
}

#endif /* GMB_C */
