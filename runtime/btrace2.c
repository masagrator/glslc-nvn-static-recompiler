/* btrace2.c -- ordered hard-target block trace for the port side.
   Copy into out/src/ and run btpatch.py; see REFERENCE-DIFFING.md section 8. */
/* struct sigaction is POSIX, not ISO C, and the tree builds with -std=c11,
 * which hides it.  Same trap guest_rt.c hit when its fault handler was added. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#define BT_CAP (64u << 20)                 /* 64 M entries = 256 MB */
static uint32_t bt_buf[BT_CAP];
uint32_t *g_bp2 = bt_buf;
uint32_t *g_bp2_end = bt_buf + BT_CAP;

static void bt_write(void) {
    static volatile int done;
    if (done) return;                      /* a second signal must not re-enter */
    done = 1;
    const char *p = getenv("BTRACE_OUT");
    if (!p) p = "/tmp/port.u32";
    FILE *f = fopen(p, "wb");
    if (!f) return;
    fwrite(bt_buf, 4, (size_t)(g_bp2 - bt_buf), f);
    fclose(f);
    fprintf(stderr, "btrace: %zu entries -> %s%s\n",
            (size_t)(g_bp2 - bt_buf), p,
            g_bp2 == g_bp2_end ? "  *** BUFFER FULL, TRUNCATED ***" : "");
}

__attribute__((destructor)) static void bt_flush(void) { bt_write(); }

/* A CRASHING port is exactly when the trace is worth having, and a destructor
 * does not run for one: guest_rt.c's fault handler ends in _exit(), which by
 * definition skips atexit/destructor handlers.  Before this, tracing a port
 * that faulted produced an empty file -- the one case the whole mechanism
 * exists to diagnose.
 *
 * So the trace installs its own handler, in a CONSTRUCTOR, which runs before
 * any guest code and therefore before guest_install_handler().  That ordering
 * is what makes it win: guest_rt.c installs its reporting handler only if the
 * process has not already set one, so this one stays and the buffer is written
 * out.  The guest register dump is given up in exchange, which is the right
 * trade here -- the ordered block trace says WHERE the two sides part, and the
 * registers can be had from a second run without BTRACE_OUT set. */
static void bt_signal(int sig) {
    bt_write();
    _exit(128 + sig);
}

__attribute__((constructor)) static void bt_install(void) {
    if (!getenv("BTRACE_OUT")) return;     /* not tracing: leave signals alone */
    struct sigaction sa;
    sa.sa_handler = bt_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}
