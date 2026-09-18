/* gout.c -- the growable scratch buffer behind GOFILE.  See gout.h. */
#ifndef GOUT_C
#define GOUT_C

#include <string.h>

#include "gout.h"
/* guest_rt.h, not ../guest_rt.h: the generated tree puts it in include/ and
 * the Makefile passes -Iinclude, while the package keeps it next to the other
 * runtime sources.  The angle-bracket-free spelling finds it in both. */
#include "guest_rt.h"

/* Slot 0 of the per-thread scratch, and 256 bytes to start with, doubling --
 * the same slot and the same growth the previous formatter used, so the
 * port's scratch footprint is unchanged by the switch to musl's vfprintf.
 * (Slot 1, which the old code used for a single oversized directive rendered
 * through the host's snprintf, has no successor: musl's formatter never needs
 * a second buffer, so that allocation is simply gone.) */
#define GOUT_SLOT 0

void gout_init(GOFILE *o) {
    o->buf = guest_scratch(GOUT_SLOT, 256);
    o->cap = o->buf ? guest_scratch_cap(GOUT_SLOT) : 0;
    o->len = 0;
    o->err = o->buf ? 0 : 1;
    if (o->buf) o->buf[0] = '\0';
}

void gout_write(GOFILE *o, const char *s, size_t n) {
    if (o->err || !n) return;
    if (o->len + n + 1 > o->cap) {
        size_t want = o->cap ? o->cap : 256;
        while (o->len + n + 1 > want) want *= 2;
        o->buf = guest_scratch(GOUT_SLOT, want);
        if (!o->buf) { o->cap = 0; o->err = 1; return; }
        o->cap = guest_scratch_cap(GOUT_SLOT);
    }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    /* NUL-terminated at every step: the thunks hand `buf` straight to the
     * guest for sprintf, and a caller that looks at it before reading `len`
     * must not run off the end. */
    o->buf[o->len] = '\0';
}

#endif /* GOUT_C */
