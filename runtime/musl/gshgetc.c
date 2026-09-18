/* gshgetc.c -- musl's src/internal/shgetc.c, reduced to the string case.
 *
 * musl's __shgetc calls __uflow() to refill the buffer.  A string pseudo-FILE
 * has nothing to refill from, so __uflow is the constant EOF; everything else
 * here is musl's code and musl's comment, unchanged, including the shcnt
 * bookkeeping the shcnt() macro depends on.
 *
 * The `if (f->rpos <= f->buf) f->rpos[-1] = c;` line at the end of musl's
 * __shgetc is DELIBERATELY absent: it exists to push a refilled byte back into
 * the unget area of a real FILE, and it is only reachable on the path where
 * __uflow succeeded.  Here __uflow never succeeds, so the line is dead -- and
 * keeping it would write one byte in front of the guest's string.
 */
#include "gshgetc.h"

/* The shcnt field stores the number of bytes read so far, offset by
 * the value of buf-rpos at the last function call (__shlim or __shgetc),
 * so that between calls the inline shcnt macro can add rpos-buf to get
 * the actual count. */

void __shlim(GFILE *f, off_t lim)
{
	f->shlim = lim;
	f->shcnt = f->buf - f->rpos;
	/* If lim is nonzero, rend must be a valid pointer. */
	if (lim && f->rend - f->rpos > lim)
		f->shend = f->rpos + lim;
	else
		f->shend = f->rend;
}

int __shgetc(GFILE *f)
{
	off_t cnt = shcnt(f);
	/* __uflow() on a string pseudo-FILE is EOF: there is no more input than
	 * the string, and rend already marks its end. */
	f->shcnt = f->buf - f->rpos + cnt;
	f->shend = f->rpos;
	f->shlim = -1;
	return EOF;
}
