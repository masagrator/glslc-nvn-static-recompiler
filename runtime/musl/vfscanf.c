/* Vendored from musl 1.2.5, stdio/vfscanf.c.
 *
 * WHY VERBATIM.  The guest is a musl binary (it imports __nnmusl_init_dso), so
 * musl's conversion code IS the guest's own behaviour, down to the corner
 * cases where implementations legitimately differ.  The port used to walk the
 * format string itself and hand each directive to the HOST's sscanf/snprintf,
 * which meant the port's answer was glibc's answer; that is how the `%[`
 * scanset went unparsed (HANDOVER.md sec.26).  Vendoring removes the whole
 * class of difference rather than the one instance of it.
 *
 * Changes from upstream are listed at the top of each file and nowhere else:
 * the rule is that a reader can diff this against musl and see every edit.
 */
/* Edits:
 *   * the three argument-list sites (arg_n, the `%%n$` case and the ordinary
 *     case) take the guest's argument cursor instead of a host va_list.  They
 *     are the only places musl reads an argument, so nothing else has to know.
 *   * `long double` -> `gld_t` (binary128, the guest's long double).
 *   * GFILE -> GFILE, and the FLOCK/__toread prologue is dropped: the stream is
 *     a string the caller just built, so it is readable and unshared.
 *   * vfscanf -> guest_vfscanf, and the weak alias is dropped.
 * The scanning logic, the scanset parser and the return-value rules are
 * untouched -- they are the reason for vendoring.
 *   * every `FILE` is the string pseudo-FILE of gshgetc.h (`GFILE`).
 *   * `wchar_t` -> `gwchar_t` (uint32_t) for `%ls`/`%lc`.  The guest's wchar_t
 *     is 32 bits; the HOST's is 16 on Windows, and musl's `k*sizeof(wchar_t)`
 *     would then allocate half the space the guest reads back, and store
 *     UTF-16 code units where the guest expects UTF-32.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <wchar.h>
#include <wctype.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>

#include "gshgetc.h"
#include "gintscan.h"
#include "gfloatscan.h"

#define SIZE_hh -2
#define SIZE_h  -1
#define SIZE_def 0
#define SIZE_l   1
#define SIZE_L   2
#define SIZE_ll  3

static void store_int(void *dest, int size, unsigned long long i)
{
	if (!dest) return;
	switch (size) {
	case SIZE_hh:
		*(char *)dest = i;
		break;
	case SIZE_h:
		*(short *)dest = i;
		break;
	case SIZE_def:
		*(int *)dest = i;
		break;
	case SIZE_l:
		*(long *)dest = i;
		break;
	case SIZE_ll:
		*(long long *)dest = i;
		break;
	}
}

static void *arg_n(g_va_list ap, unsigned int n)
{
	void *p;
	unsigned int i;
	g_va_ctx ap2;
	g_va_copy(ap2, ap);
	for (i=n; i>1; i--) g_va_arg_ptr(ap2);
	p = g_va_arg_ptr(ap2);
	return p;
}

int guest_vfscanf(GFILE *restrict f, const char *restrict fmt, g_va_list ap)
{
	int width;
	int size;
	int alloc = 0;
	int base;
	const unsigned char *p;
	int c, t;
	char *s;
	gwchar_t *wcs;
	mbstate_t st;
	void *dest=NULL;
	int invert;
	int matches=0;
	unsigned long long x;
	gld_t y;
	off_t pos = 0;
	unsigned char scanset[257];
	size_t i, k;
	gwchar_t wc;

	/* No lock and no __toread: this stream is a string set up by the caller
	 * (guest_sscanf), so it is already readable and private to this call. */

	for (p=(const unsigned char *)fmt; *p; p++) {

		alloc = 0;

		if (isspace(*p)) {
			while (isspace(p[1])) p++;
			shlim(f, 0);
			while (isspace(shgetc(f)));
			shunget(f);
			pos += shcnt(f);
			continue;
		}
		if (*p != '%' || p[1] == '%') {
			shlim(f, 0);
			if (*p == '%') {
				p++;
				while (isspace((c=shgetc(f))));
			} else {
				c = shgetc(f);
			}
			if (c!=*p) {
				shunget(f);
				if (c<0) goto input_fail;
				goto match_fail;
			}
			pos += shcnt(f);
			continue;
		}

		p++;
		if (*p=='*') {
			dest = 0; p++;
		} else if (isdigit(*p) && p[1]=='$') {
					dest = arg_n(ap, *p-'0'); p+=2;
		} else {
			dest = g_va_arg_ptr(*ap);
		}

		for (width=0; isdigit(*p); p++) {
			width = 10*width + *p - '0';
		}

		if (*p=='m') {
			wcs = 0;
			s = 0;
			alloc = !!dest;
			p++;
		} else {
			alloc = 0;
		}

		size = SIZE_def;
		switch (*p++) {
		case 'h':
			if (*p == 'h') p++, size = SIZE_hh;
			else size = SIZE_h;
			break;
		case 'l':
			if (*p == 'l') p++, size = SIZE_ll;
			else size = SIZE_l;
			break;
		case 'j':
			size = SIZE_ll;
			break;
		case 'z':
		case 't':
			size = SIZE_l;
			break;
		case 'L':
			size = SIZE_L;
			break;
		case 'd': case 'i': case 'o': case 'u': case 'x':
		case 'a': case 'e': case 'f': case 'g':
		case 'A': case 'E': case 'F': case 'G': case 'X':
		case 's': case 'c': case '[':
		case 'S': case 'C':
		case 'p': case 'n':
			p--;
			break;
		default:
			goto fmt_fail;
		}

		t = *p;

		/* C or S */
		if ((t&0x2f) == 3) {
			t |= 32;
			size = SIZE_l;
		}

		switch (t) {
		case 'c':
			if (width < 1) width = 1;
		case '[':
			break;
		case 'n':
			store_int(dest, size, pos);
			/* do not increment match count, etc! */
			continue;
		default:
			shlim(f, 0);
			while (isspace(shgetc(f)));
			shunget(f);
			pos += shcnt(f);
		}

		shlim(f, width);
		if (shgetc(f) < 0) goto input_fail;
		shunget(f);

		switch (t) {
		case 's':
		case 'c':
		case '[':
			if (t == 'c' || t == 's') {
				memset(scanset, -1, sizeof scanset);
				scanset[0] = 0;
				if (t == 's') {
					scanset[1+'\t'] = 0;
					scanset[1+'\n'] = 0;
					scanset[1+'\v'] = 0;
					scanset[1+'\f'] = 0;
					scanset[1+'\r'] = 0;
					scanset[1+' '] = 0;
				}
			} else {
				if (*++p == '^') p++, invert = 1;
				else invert = 0;
				memset(scanset, invert, sizeof scanset);
				scanset[0] = 0;
				if (*p == '-') p++, scanset[1+'-'] = 1-invert;
				else if (*p == ']') p++, scanset[1+']'] = 1-invert;
				for (; *p != ']'; p++) {
					if (!*p) goto fmt_fail;
					if (*p=='-' && p[1] && p[1] != ']')
						for (c=p++[-1]; c<*p; c++)
							scanset[1+c] = 1-invert;
					scanset[1+*p] = 1-invert;
				}
			}
			wcs = 0;
			s = 0;
			i = 0;
			k = t=='c' ? width+1U : 31;
			if (size == SIZE_l) {
				if (alloc) {
					wcs = malloc(k*sizeof(gwchar_t));
					if (!wcs) goto alloc_fail;
				} else {
					wcs = dest;
				}
				st = (mbstate_t){0};
				while (scanset[(c=shgetc(f))+1]) {
					switch (mbrtowc(&wc, &(char){c}, 1, &st)) {
					case -1:
						goto input_fail;
					case -2:
						continue;
					}
					if (wcs) wcs[i++] = wc;
					if (alloc && i==k) {
						k+=k+1;
						gwchar_t *tmp = realloc(wcs, k*sizeof(gwchar_t));
						if (!tmp) goto alloc_fail;
						wcs = tmp;
					}
				}
				if (!mbsinit(&st)) goto input_fail;
			} else if (alloc) {
				s = malloc(k);
				if (!s) goto alloc_fail;
				while (scanset[(c=shgetc(f))+1]) {
					s[i++] = c;
					if (i==k) {
						k+=k+1;
						char *tmp = realloc(s, k);
						if (!tmp) goto alloc_fail;
						s = tmp;
					}
				}
			} else if ((s = dest)) {
				while (scanset[(c=shgetc(f))+1])
					s[i++] = c;
			} else {
				while (scanset[(c=shgetc(f))+1]);
			}
			shunget(f);
			if (!shcnt(f)) goto match_fail;
			if (t == 'c' && shcnt(f) != width) goto match_fail;
			if (alloc) {
				if (size == SIZE_l) *(gwchar_t **)dest = wcs;
				else *(char **)dest = s;
			}
			if (t != 'c') {
				if (wcs) wcs[i] = 0;
				if (s) s[i] = 0;
			}
			break;
		case 'p':
		case 'X':
		case 'x':
			base = 16;
			goto int_common;
		case 'o':
			base = 8;
			goto int_common;
		case 'd':
		case 'u':
			base = 10;
			goto int_common;
		case 'i':
			base = 0;
		int_common:
			x = __intscan(f, base, 0, ULLONG_MAX);
			if (!shcnt(f)) goto match_fail;
			if (t=='p' && dest) *(void **)dest = (void *)(uintptr_t)x;
			else store_int(dest, size, x);
			break;
		case 'a': case 'A':
		case 'e': case 'E':
		case 'f': case 'F':
		case 'g': case 'G':
			y = __floatscan(f, size, 0);
			if (!shcnt(f)) goto match_fail;
			if (dest) switch (size) {
			case SIZE_def:
				*(float *)dest = y;
				break;
			case SIZE_l:
				*(double *)dest = y;
				break;
			case SIZE_L:
				/* The guest's long double is binary128; the host's is x87
				 * 80-bit.  gld_t IS binary128, so this stores the 16 bytes
				 * the guest expects, at the guest's precision. */
				*(gld_t *)dest = y;
				break;
			}
			break;
		}

		pos += shcnt(f);
		if (dest) matches++;
	}
	if (0) {
fmt_fail:
alloc_fail:
input_fail:
		if (!matches) matches--;
match_fail:
		if (alloc) {
			free(s);
			free(wcs);
		}
	}
	return matches;
}

