/*
 * guest_host.c -- host implementations for the non-libc imports.
 *
 * Scope note.  The binary imports three kinds of symbol:
 *
 *   1. C library functions        -- called directly by the generated thunks.
 *   2. glslc_Alloc/Free/Realloc/GetAllocator
 *                                 -- NOT defined here.  The project already
 *                                    implements these (they route through the
 *                                    GLSLCallocateFunction callbacks that
 *                                    glslcSetAllocator installs), and those
 *                                    definitions are the ones to link.  They
 *                                    are `static` in glslcCompile.c, so make
 *                                    them non-static, or build with
 *                                    -DGUEST_PROVIDE_GLSLC_ALLOC to use the
 *                                    equivalent fallbacks at the bottom of
 *                                    this file.
 *   3. NvOs* platform primitives  -- wrapped here.
 *
 * The mutex wrappers deliberately mirror the ones already in glslcCompile.c,
 * including NvOsMutexCreate returning void rather than an error code.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE     /* newlocale, LC_ALL_MASK, strtold_l, strtof128_l */
#endif

#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <pthread.h>
#include <wctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>       /* strftime, struct tm -- guest_strftime_l */

/* ------------------------------------------------------------ NvOs mutexes */

/* A FIXED size rather than sizeof(pthread_mutex_t), which is 40 bytes on
 * x86-64 and 48 on AArch64.  The port and the QEMU reference build this same
 * file for different hosts, and a different request size here shifts every
 * allocation the GUEST makes afterwards -- which matters because the compiler
 * hashes some of its tables by pointer.  64 is comfortably above every
 * platform's pthread_mutex_t and is checked below. */
#define GUEST_MUTEX_SLOT 64

void NvOsMutexCreate(void **out) {
    _Static_assert(sizeof(pthread_mutex_t) <= GUEST_MUTEX_SLOT,
                   "GUEST_MUTEX_SLOT too small for this platform");
    pthread_mutex_t *m = malloc(GUEST_MUTEX_SLOT);
    if (!m) { *out = NULL; return; }
    pthread_mutex_init(m, NULL);
    *out = m;
}

void NvOsMutexDestroy(void *m) {
    if (!m) return;
    pthread_mutex_destroy((pthread_mutex_t *)m);
    free(m);
}

void NvOsMutexLock(void *m)   { if (m) pthread_mutex_lock((pthread_mutex_t *)m); }
void NvOsMutexUnlock(void *m) { if (m) pthread_mutex_unlock((pthread_mutex_t *)m); }

/* --------------------------------------------------------------- NvOs file */
/*
 * glslcCompile.c only ever declared this family, so there is no existing
 * implementation to reuse.  These follow the NvOs convention: zero is success,
 * non-zero is an error, and results come back through out-parameters.
 */

#define NVOS_OK              0
#define NVOS_ERR_FILE        0x00030002u

/* NvOsFopenFlags */
#define NVOS_OPEN_READ    0x1u
#define NVOS_OPEN_WRITE   0x2u
#define NVOS_OPEN_CREATE  0x4u

/* NvOsSeekEnum */
#define NVOS_SEEK_SET 0u
#define NVOS_SEEK_CUR 1u
#define NVOS_SEEK_END 2u

int64_t NvOsFopen(const char *path, uint64_t flags, void **out) {
    const char *mode;
    if (!path || !out) return NVOS_ERR_FILE;
    if (flags & NVOS_OPEN_CREATE)      mode = (flags & NVOS_OPEN_READ) ? "w+b" : "wb";
    else if (flags & NVOS_OPEN_WRITE)  mode = (flags & NVOS_OPEN_READ) ? "r+b" : "wb";
    else                               mode = "rb";
    FILE *f = fopen(path, mode);
    *out = f;
    return f ? NVOS_OK : NVOS_ERR_FILE;
}

void NvOsFclose(void *file) {
    if (file) fclose((FILE *)file);
}

int64_t NvOsFread(void *file, void *buf, uint64_t size, uint64_t *read) {
    if (!file || !buf) return NVOS_ERR_FILE;
    size_t n = fread(buf, 1, (size_t)size, (FILE *)file);
    if (read) *read = n;
    /* A short read is only an error if nothing at all came back. */
    if (n == 0 && size != 0) return NVOS_ERR_FILE;
    return NVOS_OK;
}

int64_t NvOsFwrite(void *file, const void *buf, uint64_t size) {
    if (!file || !buf) return NVOS_ERR_FILE;
    size_t n = fwrite(buf, 1, (size_t)size, (FILE *)file);
    return n == (size_t)size ? NVOS_OK : NVOS_ERR_FILE;
}

int64_t NvOsFseek(void *file, int64_t offset, uint64_t whence) {
    int w;
    if (!file) return NVOS_ERR_FILE;
    switch (whence) {
    case NVOS_SEEK_SET: w = SEEK_SET; break;
    case NVOS_SEEK_CUR: w = SEEK_CUR; break;
    case NVOS_SEEK_END: w = SEEK_END; break;
    default: return NVOS_ERR_FILE;
    }
    return fseek((FILE *)file, (long)offset, w) == 0 ? NVOS_OK : NVOS_ERR_FILE;
}

int64_t NvOsFtell(void *file, uint64_t *pos) {
    if (!file || !pos) return NVOS_ERR_FILE;
    long p = ftell((FILE *)file);
    if (p < 0) return NVOS_ERR_FILE;
    *pos = (uint64_t)p;
    return NVOS_OK;
}

/* ------------------------------------------------- glslc allocator surface */
/*
 * glslc_GetAllocator is NOT one of the functions glslcCompile.c defines -- it
 * is listed there only as a GOT slot ("supplied by the loader; unread here").
 * It has to be real, though: glslcSetAllocator calls it and then stores four
 * default callback pointers through the returned pointer
 *
 *     stp x8, x10, [x0]        ; [0] = default alloc, [8]  = default free
 *     stp x11, x9, [x0, #0x10] ; [16]= default realloc,[24] = default ...
 *
 * so returning NULL faults immediately.  A static table of four pointers is
 * all the binary needs; it fills the entries in itself.
 */
static void *g_glslc_allocator[4];

void *glslc_GetAllocator(void) {
    return g_glslc_allocator;
}

/* ------------------------------------------------- optional glslc fallbacks */
/*
 * Only for building the generated unit on its own.  When linking against the
 * project's own glslcCompile.c these must NOT be defined here.
 */
#ifdef GUEST_PROVIDE_GLSLC_ALLOC

/* GUEST_POISON also fills freshly allocated guest heap, for the same reason
 * it fills the guest stack (see guest_stack_alloc): a value read from a slot
 * nothing wrote is otherwise indistinguishable from a real one.  Off by
 * default -- with the variable unset these are plain malloc/free/realloc. */
static int guest_poison_byte(void) {
    static int cached = -2;          /* -2 = not looked up yet, -1 = disabled */
    if (cached == -2) {
        const char *p = getenv("GUEST_POISON");
        cached = (p && *p) ? (int)(strtol(p, NULL, 0) & 0xFF) : -1;
    }
    return cached;
}

/*
 * ONE ALLOCATOR PAIR, CHOSEN BY PLATFORM.
 *
 * glslc_Free must be able to release anything the other three returned, and
 * that is what decides the spelling here:
 *
 *   * POSIX/C11: aligned_alloc's result is free()-able by definition, so the
 *     ordinary malloc/realloc/free are the pair and glslc_AllocAlign joins it.
 *   * Windows: MinGW's C library has NO aligned_alloc -- it is C11, and MSVCRT
 *     predates it -- and _aligned_malloc's result must be released with
 *     _aligned_free and resized with _aligned_realloc.  Mixing those with
 *     malloc/free is undefined, and glslc_Free cannot know which of the two
 *     made the block it is given.  So on Windows ALL FOUR go through the
 *     _aligned_* family, with a 16-byte default alignment for the calls that
 *     do not ask for one; that is the only combination where every pairing is
 *     legal.
 *
 * (16 is not arbitrary: it is what malloc guarantees on x86-64 and AArch64
 * alike, so the Windows fallback hands out blocks that are aligned at least as
 * strictly as the Linux one -- the guest cannot tell the two apart.)
 */
#if defined(_WIN32)
#define GUEST_ALLOC_ALIGN 16
#endif

/* GLSLC_ALLOC_LOG=<path>: one line per allocation, sizes only.
 *
 * guest_host.c is compiled for BOTH sides of a differential run -- the port
 * links it, and qemu-ref.sh cross-compiles it against the original AArch64
 * library -- so the two logs come from the same source.  Only SIZES and call
 * ORDER are recorded, never a pointer: pointers differ between the two address
 * spaces for reasons that are not defects, while the sequence of requested
 * sizes is a pure function of what the compiler decided to do.  That is the
 * technique HANDOVER credits with locating the sec.26 divergence in one step
 * (the sequences agreed for 1,596 calls, then parted) after several sessions
 * of tracing single values backwards had not converged. */
static FILE *glslc_alloc_log(void) {
    static FILE *f = NULL;
    static int tried = 0;
    if (!tried) {
        const char *e = getenv("GLSLC_ALLOC_LOG");
        tried = 1;
        if (e && *e) { f = fopen(e, "w"); if (f) setvbuf(f, NULL, _IOLBF, 0); }
    }
    return f;
}

void *glslc_Alloc(size_t size) {
    { FILE *l = glslc_alloc_log(); if (l) fprintf(l, "A %llu\n", (unsigned long long)size); }
#if defined(_WIN32)
    void *p = _aligned_malloc(size ? size : 1, GUEST_ALLOC_ALIGN);
#else
    void *p = malloc(size);
#endif
    int b = guest_poison_byte();
    if (p && b >= 0) memset(p, b, size);
    return p;
}

void glslc_Free(void *ptr) {
    { FILE *l = glslc_alloc_log(); if (l) fprintf(l, "F\n"); }
    if (!ptr) return;
#if defined(_WIN32)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

void *glslc_Realloc(void *ptr, size_t newSz) {
    { FILE *l = glslc_alloc_log(); if (l) fprintf(l, "R %llu\n", (unsigned long long)newSz); }
#if defined(_WIN32)
    return _aligned_realloc(ptr, newSz, GUEST_ALLOC_ALIGN);
#else
    return realloc(ptr, newSz);
#endif
}

/*
 * glslc_AllocAlign is new in the 17.24 library.  The real one forwards the
 * alignment to the GLSLCallocateFunction the caller installed -- that callback
 * has taken (size, alignment, userPtr) since the first version, so the
 * alignment has always been part of the contract and only the internal entry
 * point is new.
 */
void *glslc_AllocAlign(size_t size, size_t align) {
    if (align < sizeof(void *)) align = sizeof(void *);
    /* Both allocators require a power-of-two alignment; aligned_alloc also
     * requires a size that is a multiple of it, and rounding up is allowed and
     * is what every real implementation does. */
    if (align & (align - 1)) {
        size_t p2 = sizeof(void *);
        while (p2 < align) p2 <<= 1;
        align = p2;
    }
    size_t rounded = (size + align - 1) & ~(align - 1);
    if (!rounded) rounded = align;
#if defined(_WIN32)
    void *p = _aligned_malloc(rounded, align);
#else
    void *p = aligned_alloc(align, rounded);
#endif
    int b = guest_poison_byte();
    if (p && b >= 0) memset(p, b, rounded);
    return p;
}

#endif

/* ---- C++ allocation operators -------------------------------------------
 *
 * The guest imports `operator new`/`operator delete` by their Itanium ABI
 * names.  Those names encode the size_t type, so the AArch64/LP64 binary's
 * `_Znwm` is `_Znwy` on a MinGW-w64 host (size_t is unsigned long long there)
 * and `_Znwj` where it is 32-bit -- importing the mangled name directly does
 * not link on Windows.  gen.py routes every spelling to these two shims
 * instead, so there is one name on every platform and libstdc++ is not needed
 * to link at all.
 *
 * The guest allocates and frees entirely through this pair, so they only have
 * to agree with each other.  Real `operator new` throws std::bad_alloc on
 * failure; an exception thrown by the host into translated AArch64 code has
 * nowhere to go, so this aborts with a message instead.
 */
void *guest_operator_new(unsigned long long size) {
    /* `new T` with sizeof(T) == 0 is not possible in C++, but operator new(0)
     * is, and it must return a distinct non-null pointer -- malloc(0) is
     * allowed to return NULL. */
    void *p = malloc(size ? (size_t)size : 1);
    if (!p) {
        fprintf(stderr, "guest: operator new(%llu) failed\n", size);
        abort();
    }
    return p;
}

void guest_operator_delete(void *p) { free(p); }



/* ------------------------------------------------- added for subsdk0.elf */

/*
 * NvOsFcloseEx(file, flags) replaces NvOsFclose in the newer SDK.  The second
 * argument selects between closing and closing-and-deleting; nothing in the
 * shader compiler passes anything but 0, and a port that has no NvOs
 * filesystem to delete from cannot honour the other value, so the close is
 * what is implemented and a non-zero flag is reported rather than ignored.
 */
void guest_NvOsFcloseEx(void *file, uint64_t flags) {
    if (flags)
        fprintf(stderr, "guest: NvOsFcloseEx(%p, %llu): only flags=0 is modelled\n",
                file, (unsigned long long)flags);
    if (file) fclose((FILE *)file);
}

/*
 * newlocale() -- passed straight through, ARGUMENTS AND ALL.
 *
 * The first version of this wrapper "helpfully" replaced the guest's category
 * mask with LC_ALL_MASK, on the reasoning that musl (which the guest was
 * linked against) numbers the categories differently from the host, and that
 * the compiler only ever asks for the C locale anyway so the name is what
 * carries the meaning.
 *
 * That reasoning is about what the call MEANS.  What matters is what it
 * RETURNS, and widening the mask changed that: with a musl mask the host's
 * newlocale rejects the request and returns NULL, and the library has a path
 * for exactly that -- libc++'s "is this locale single-byte" check at
 * 0x11301c0 returns 1 immediately when the locale_t it holds is null, instead
 * of consulting __ctype_get_mb_cur_max().  Making the call SUCCEED sent the
 * port down the other branch, and that was the first divergence from the
 * reference in a 6.8-million-block trace: everything downstream -- an extra
 * entry in a type table, a hash table sized 1024 instead of 512, two dwords
 * of every uniform record in the reflection section -- followed from it.
 *
 * The reference reaches the host's newlocale with the guest's own mask and
 * gets NULL.  So does this.  A wrapper survives only to say so, and because
 * the port must not depend on how a particular platform spells locale_t.
 */
void *guest_newlocale(int64_t mask, const char *name, void *base) {
#if !defined(_WIN32)
    return (void *)newlocale((int)mask, name, (locale_t)base);
#else
    /*
     * Windows has no newlocale, and this must not be routed to MSVCRT's
     * _create_locale: that would SUCCEED, and succeeding is the bug.  The
     * paragraph above is the whole argument -- the reference gets NULL back
     * because the host rejects the guest's musl category mask, and the library
     * has a path that depends on it.  Returning NULL directly is the same
     * answer by construction rather than by accident, and it is what the Linux
     * side produces for every mask the guest actually passes.
     *
     * (If a mask the host WOULD accept ever reached here on Linux, the two
     * platforms would diverge.  It cannot: the guest's LC_*_MASK constants are
     * musl's, and musl's LC_ALL_MASK is 0x7fffffff, outside anything glibc
     * accepts.  The arguments are named rather than ignored so that a reader
     * comparing this with the Linux branch can see they are the same call.)
     */
    (void)mask; (void)name; (void)base;
    return NULL;
#endif
}

/*
 * strtold() returns a long double, and that type does not have one format:
 * AArch64's is IEEE binary128, x86-64's is the x87 80-bit extended format.
 * Returning the host's would put the wrong bits in q0.
 *
 * The result is therefore written into the guest's q0 slot explicitly, in
 * binary128, which is what __float128 is on every host this builds for.  Where
 * the host C library has strtof128_l the conversion is exact; where it does
 * not, the value goes through the host's long double first and the comment
 * below says what that costs.
 */
/* musl's own binary128 strtold, in guest_scanf.c (it owns __floatscan). */
void guest_strtold_musl(void *out, const char *s, char **p);

void guest_strtold_l(void *out, const char *s, void **end, void *loc) {
#if defined(__GLIBC__) && defined(__x86_64__)
    _Float128 v = strtof128_l(s, (char **)end, (locale_t)loc);
    memcpy(out, &v, 16);
#elif !defined(_WIN32)
    /* Falls back to the host's long double: the value is correct to at least
     * 64 bits of significand, and binary128 has 113, so the low bits of a
     * literal that needs more than 64 are lost.  No shader source contains
     * such a literal -- GLSL has no long double -- and this path exists only
     * because the C library's scanf family can reach it. */
    long double t = strtold_l(s, (char **)end, (locale_t)loc);
    _Float128 v = (_Float128)t;
    memcpy(out, &v, 16);
#else
    /* Windows: no strtold_l, and MSVCRT's `long double` is a double, which
     * would lose 53 bits rather than 49.  The port has musl's own binary128
     * scanner, so this goes through THAT -- the same __floatscan the guest's
     * own strtold calls, at the guest's own precision, which makes the Windows
     * answer the exactly-correct one rather than the least bad one.
     *
     * (The Linux path is left on glibc's strtof128_l because that is what the
     * corpus was verified with; the two agree, but "agree" is a claim to test
     * before it is a reason to change verified code.  HANDOVER.md sec.30.) */
    (void)loc;
    guest_strtold_musl(out, s, (char **)end);
#endif
}

/*
 * strerror_r has two incompatible definitions.  musl -- which the guest was
 * linked against -- provides the POSIX/XSI one: it fills the caller's buffer
 * and returns an int.  glibc's default under _GNU_SOURCE is a different
 * function that returns a char * which need not point into the buffer at all.
 * Calling the host's directly would put a pointer where the guest expects a
 * status, so the XSI behaviour is produced explicitly.
 */
int guest_strerror_r(int64_t err, char *buf, uint64_t len) {
    if (!buf || !len) return 22 /* EINVAL */;
#if defined(__GLIBC__)
    const char *msg = strerror_r((int)err, buf, (size_t)len);
    if (msg != buf) {
        size_t n = strlen(msg);
        if (n >= (size_t)len) {
            memcpy(buf, msg, (size_t)len - 1);
            buf[len - 1] = '\0';
            return 34 /* ERANGE */;
        }
        memcpy(buf, msg, n + 1);
    }
    return 0;
#elif !defined(_WIN32)
    return strerror_r((int)err, buf, (size_t)len);
#else
    /*
     * Windows has neither strerror_r spelling.  strerror_s is MSVCRT's, and it
     * is the XSI shape (fills the buffer, returns an int) -- but it returns
     * STRUNCATE (80) where XSI returns ERANGE (34), and the guest compares
     * against musl's ERANGE.  The truncation case is translated; everything
     * else it returns is already an errno value.
     */
    errno_t rc = strerror_s(buf, (size_t)len, (int)err);
    return rc == 80 /* STRUNCATE */ ? 34 /* ERANGE */ : (int)rc;
#endif
}

/*
 * The locale-aware ctype predicates are macros in glibc that index the locale
 * object's tables directly, so they cannot be handed a `void *`.  The guest's
 * locale_t is whatever guest_newlocale() returned -- a host locale_t -- so the
 * cast is safe; doing it here keeps it in one place instead of in every
 * translated call site.
 */
#if !defined(_WIN32)
int guest_isdigit_l(int64_t c, void *loc)  { return isdigit_l((int)c, (locale_t)loc); }
int guest_isxdigit_l(int64_t c, void *loc) { return isxdigit_l((int)c, (locale_t)loc); }
int guest_islower_l(int64_t c, void *loc)  { return islower_l((int)c, (locale_t)loc); }
int guest_isupper_l(int64_t c, void *loc)  { return isupper_l((int)c, (locale_t)loc); }
int guest_iswlower_l(int64_t c, void *loc) { return iswlower_l((wint_t)c, (locale_t)loc); }
#else
/*
 * Windows has no POSIX locale_t at all -- MSVCRT's is `_locale_t`, made by
 * _create_locale, and the *_l functions are spelled _isdigit_l and friends.
 * Rather than map one onto the other, these answer for the ONE locale the
 * guest can be holding.
 *
 * That is not an assumption, it is what guest_newlocale() below produces: it
 * hands the host's newlocale the guest's own musl category mask, the host
 * rejects it, and the guest gets NULL -- every time, on every platform (see
 * the long comment there; making that call succeed was the first divergence
 * of a 6.8-million-block trace).  A null locale_t means "the current locale",
 * and the current locale is C, because the guest never calls setlocale with
 * anything else.  So the C-locale answer is the correct answer, and it is the
 * same answer glibc gives on the Linux side for the same input.
 *
 * The predicates are written out rather than delegated to the host's
 * isdigit()/islower(), whose behaviour above 0x7f depends on the process code
 * page.  ASCII is the whole of the C locale, so this is exact.
 */
int guest_isdigit_l(int64_t c, void *loc)  { (void)loc; return c >= '0' && c <= '9'; }
int guest_isxdigit_l(int64_t c, void *loc) { (void)loc;
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
int guest_islower_l(int64_t c, void *loc)  { (void)loc; return c >= 'a' && c <= 'z'; }
int guest_isupper_l(int64_t c, void *loc)  { (void)loc; return c >= 'A' && c <= 'Z'; }
/* iswlower is the wide form, and the C locale's lowercase set is still just
 * a-z: a wide character outside ASCII is not lowercase in it. */
int guest_iswlower_l(int64_t c, void *loc) { (void)loc; return c >= 'a' && c <= 'z'; }
#endif

/* ------------------------------------------------ the rest of the locale API */
/*
 * uselocale/freelocale/strftime_l/strtod_l/strtof_l are POSIX 2008.  glibc has
 * them; MSVCRT has none of them, which is where the Windows build stopped.
 * They are wrapped here on BOTH platforms -- one name, one set of semantics --
 * rather than being made conditional at each call site in the generated code.
 *
 * On glibc every one of them is a pass-through, so the Linux behaviour that
 * the corpus was verified against is unchanged, byte for byte.
 */

#if !defined(_WIN32)

void *guest_uselocale(void *loc)   { return (void *)uselocale((locale_t)loc); }
void  guest_freelocale(void *loc)  { if (loc) freelocale((locale_t)loc); }

uint64_t guest_strftime_l(void *s, uint64_t max, const char *fmt, void *tm, void *loc) {
    return (uint64_t)strftime_l((char *)s, (size_t)max, fmt, (const struct tm *)tm,
                                (locale_t)loc);
}

double guest_strtod_l(const char *s, void **end, void *loc) {
    return strtod_l(s, (char **)end, (locale_t)loc);
}

float guest_strtof_l(const char *s, void **end, void *loc) {
    return strtof_l(s, (char **)end, (locale_t)loc);
}

#else

/*
 * uselocale() on a host that has no thread locales.
 *
 * The POSIX contract is entirely about the value: it installs `loc` as the
 * thread's locale and returns what was installed before, uselocale(NULL)
 * queries without changing anything, and LC_GLOBAL_LOCALE -- (locale_t)-1,
 * the same constant in musl and in glibc -- means "go back to the process
 * locale".  Since the only locale object that exists in this port is the null
 * one (see guest_newlocale), storing the value and handing back the previous
 * one IS the behaviour; there is nothing else for it to select.
 *
 * The initial value is LC_GLOBAL_LOCALE, which is what a thread that has never
 * called uselocale has.
 */
#define GUEST_LC_GLOBAL_LOCALE ((void *)(intptr_t)-1)

static _Thread_local void *g_thread_locale = GUEST_LC_GLOBAL_LOCALE;

void *guest_uselocale(void *loc) {
    void *prev = g_thread_locale;
    if (loc) g_thread_locale = loc;
    return prev;
}

/* Nothing was allocated -- guest_newlocale returns NULL -- so there is nothing
 * to release.  Freeing whatever pointer arrives would be worse than doing
 * nothing: it is not a block this port owns. */
void guest_freelocale(void *loc) { (void)loc; }

/*
 * The C locale's strftime, strtod and strtof.  On Windows the process locale
 * is "C" unless something calls setlocale, and nothing in the port or the
 * guest does, so the plain functions ARE the _l ones for this locale.  The
 * locale argument is therefore unused from here on -- it can only be the null
 * locale (guest_newlocale) or the global one (uselocale above), which name the
 * same C locale -- and it is named only to keep the signature the generated
 * thunk calls with.
 */
uint64_t guest_strftime_l(void *s, uint64_t max, const char *fmt, void *tm, void *loc) {
    (void)loc;
    return (uint64_t)strftime((char *)s, (size_t)max, fmt, (const struct tm *)tm);
}

double guest_strtod_l(const char *s, void **end, void *loc) {
    (void)loc;
    return strtod(s, (char **)end);
}

float guest_strtof_l(const char *s, void **end, void *loc) {
    (void)loc;
    return strtof(s, (char **)end);
}

#endif

/*
 * __ctype_get_mb_cur_max: 4, which is musl's answer and not the host's.
 *
 * musl's C locale is UTF-8 -- unconditionally, with no way to select anything
 * else -- so its __ctype_get_mb_cur_max returns 4.  A C-locale glibc or MSVCRT
 * returns 1.  The guest is musl, so 4 is the value the library being emulated
 * would have seen, and the host's was simply the wrong number.
 *
 * This was held back for one batch on the grounds that it differs for EVERY
 * call, where the rest of the conversion changes differ only above 0x7f.  What
 * closed it (HANDOVER.md sec.30.5):
 *
 *   * the call is NEVER MADE.  Instrumented and counted: zero calls across the
 *     200 largest shaders on both option sets, and zero for a source with
 *     non-ASCII bytes in it.  Both call sites sit behind a null check on the
 *     locale_t, and guest_newlocale() returns NULL by construction (see the
 *     long comment there), so libc++ takes its early return instead -- which
 *     is the same branch sec.26 traced through the whole divergence hunt.
 *   * the 200 largest shaders were re-scored against the operator's hash lists
 *     with this value in place: 200/200 on both option sets.
 *
 * And it is the better code as well as the truer answer.  A constant is a
 * two-instruction leaf; MB_CUR_MAX on glibc is a CALL into the C library that
 * reaches into the current locale, per invocation:
 *
 *     return 4;              ->  endbr64 / mov $0x4,%eax / ret        (10 bytes)
 *     return MB_CUR_MAX;     ->  endbr64 / sub / call / add / ret     (18 + callee)
 *
 * and under `-flto=auto` (sec.3.3b) the constant propagates into the two
 * translated call sites, where the host call could not.
 */
uint64_t guest_ctype_get_mb_cur_max(void) {
    return 4;
}


/* nninitStartup -- the Nintendo SDK start-up hook.  EMPTY BODY, RETURNS
 * NOTHING, deliberately.
 *
 * Imported by glslc.elf 17.10 (NVN 1.9) and by nothing else in the set; the
 * later binaries dropped it.  In a real NSO the SDK calls this before main so
 * the application can size its heap, pick an allocator and register memory
 * regions with the Horizon kernel -- none of which exists here.  This port
 * supplies the heap itself: allocation goes through glslc_Alloc/glslc_Realloc/
 * glslc_Free, which route to the caller-supplied GLSLCallocateFunction
 * callbacks (or malloc when the caller sets none), and that is already in
 * place before any guest code runs.  So there is nothing for a start-up hook
 * to set up, and anything it did set up would be state the port does not read.
 *
 * The empty body is the whole point rather than a placeholder: this is not a
 * stub standing in for behaviour still to be written.  It is a no-op because
 * the behaviour is genuinely absent from the port's model, which is why it
 * does NOT go through guest_unimplemented() the way an unsupported import
 * would.
 *
 * `void`, with no `return` statement, is likewise deliberate.  What the image
 * actually contains was checked rather than assumed:
 *
 *   * the only reference to the import is a ONE-INSTRUCTION TAIL-CALL THUNK
 *     at 0x1b0 -- `b nninitStartup@plt` -- sitting in the same run of
 *     crt-style thunks as __nnDetailNintendoSdkRuntimeObjectFileRefer (0x1b4);
 *   * nothing in the image reaches that thunk.  Zero `bl`/`b` to 0x1b0 across
 *     the whole disassembly, no symbol at that address, and no relocation
 *     anywhere in the file whose target is 0x1b0 -- so it is not in a vtable
 *     or a function-pointer table either.
 *
 * So there is no call site whose expectations a return value could fail to
 * meet: no caller reads w0, because there is no caller.  Declaring it `void`
 * means the port never fabricates a status code that the original would not
 * have produced; a tail-call thunk propagates its callee's w0, so inventing
 * one here is the only way this could be made to differ from doing nothing.
 */
void nninitStartup(void) {
}
