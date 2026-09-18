/* gout.h -- the port's replacement for the FILE that musl's vfprintf writes to.
 *
 * The mirror image of gshgetc.h.  musl's vfprintf pushes bytes at a FILE
 * through exactly two operations -- `__fwritex(s, l, f)` and a check of the
 * stream's error flag -- and the port has no use for the rest of the stdio
 * machinery (locking, the write callback, buffer flipping, the unbuffered-
 * stream fixup in musl's own vfprintf wrapper), because every guest call that
 * reaches here renders into memory first:
 *
 *   * printf/fprintf hand the finished bytes to the HOST's fwrite, so that the
 *     host's stdio owns the ordering and the buffering of the real stream;
 *   * sprintf/snprintf copy them into the guest's buffer;
 *   * vasprintf copies them into a block from the GUEST's allocator, which it
 *     must (see plt_vasprintf).
 *
 * So the stream is a growable byte buffer, and it lives in the port's
 * per-thread SCRATCH rather than on the heap.  That is not a micro-
 * optimisation: a malloc per printf moves the guest's heap one block further
 * along than the reference's, and the compiler hashes some of its tables by
 * pointer.  guest_scratch() in guest_rt.c has the full account.
 */
#ifndef GOUT_H
#define GOUT_H

#include <stddef.h>

typedef struct GOFILE {
    char  *buf;     /* scratch, owned by guest_scratch(); never freed here */
    size_t len;     /* bytes written so far                               */
    size_t cap;     /* capacity of buf                                    */
    int    err;     /* set when the buffer could not be grown             */
} GOFILE;

void gout_init(GOFILE *o);
void gout_write(GOFILE *o, const char *s, size_t n);

/* The two operations musl's vfprintf performs on its stream, under the names
 * it uses for them. */
#define gferror(f)          ((f)->err)
#define g__fwritex(s, l, f) gout_write((f), (const char *)(s), (l))

#endif
