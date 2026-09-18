/*
 * cctest.c -- dump the runtime's flag/condition results for a list of cases.
 *
 * Reads "op dep1 dep2 dep3 cond" lines on stdin and prints
 * "n z c v cond_result" for each.  A separate reference implementation checks
 * the output; the point is that the two are written independently, so an
 * agreement is evidence rather than a restatement of the same assumption.
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "guest_rt.h"

int main(void) {
    uint64_t op, d1, d2, d3, cond;
    while (scanf("%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
                 &op, &d1, &d2, &d3, &cond) == 5) {
        uint64_t n = arm64g_calculate_flag_n(op, d1, d2, d3);
        uint64_t z = arm64g_calculate_flag_z(op, d1, d2, d3);
        uint64_t c = arm64g_calculate_flag_c(op, d1, d2, d3);
        uint64_t v = arm64g_calculate_flag_v(op, d1, d2, d3);
        uint64_t r = arm64g_calculate_condition((cond << 4) | op, d1, d2, d3);
        printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
               n, z, c, v, r);
    }
    return 0;
}

/* The runtime references these; the flag helpers under test do not. */
/* Stands in for the generated image.  guest_relocate() used to be stubbed here
 * too; it no longer exists, since relocation is now done by the linker. */
uint64_t g_rw[1];
/* g_ro joined it when guest_init() started reading the read-only image; without
 * it the build line in HANDOVER.md section 6 fails to link. */
const uint8_t g_ro[1];

/* guest_fini() reclaims the setjmp side table, which lives in guest_va.c.
 * This harness links only guest_rt.c and never runs guest code, so a stub is
 * enough -- pulling in guest_va.c would drag in the whole varargs layer. */
void guest_jb_reset(void) {}
