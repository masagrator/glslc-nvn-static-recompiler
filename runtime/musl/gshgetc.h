/* gshgetc.h -- the port's replacement for musl's stdio_impl.h + shgetc.h.
 *
 * musl's scanning helpers work over a "pseudo FILE" whose buffer pointers
 * point into a string.  That is the only mode the port needs -- every guest
 * call that reaches here is an sscanf/vsscanf -- so the whole FILE machinery
 * (locking, __toread, __uflow, buffer refill) collapses to a struct of five
 * pointers and an EOF at the end of the string.
 *
 * The macros below are musl's, unchanged, so vfscanf.c/intscan.c/floatscan.c
 * see exactly the interface they were written against.
 */
#ifndef GSHGETC_H
#define GSHGETC_H

#include <stdio.h>
#include <sys/types.h>

typedef struct GFILE {
    unsigned char *buf;     /* start of the string                        */
    unsigned char *rpos;    /* next byte to read                          */
    unsigned char *rend;    /* one past the last readable byte            */
    unsigned char *shend;   /* read limit for the current directive       */
    off_t shlim;            /* field width, 0 for none, -1 after EOF      */
    off_t shcnt;            /* bytes consumed, offset by buf-rpos         */
} GFILE;

void __shlim(GFILE *, off_t);
int  __shgetc(GFILE *);

/* Verbatim from musl's shgetc.h. */
#define shcnt(f) ((f)->shcnt + ((f)->rpos - (f)->buf))
#define shlim(f, lim) __shlim((f), (lim))
#define shgetc(f) (((f)->rpos != (f)->shend) ? *(f)->rpos++ : __shgetc(f))
#define shunget(f) ((f)->shlim>=0 ? (void)(f)->rpos-- : (void)0)

#endif
