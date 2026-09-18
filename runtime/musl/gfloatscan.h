/* Verbatim interface from musl's src/internal/floatscan.h, retyped for GFILE
 * and for the guest's long double (binary128) rather than the host's. */
#ifndef GFLOATSCAN_H
#define GFLOATSCAN_H
#include "gshgetc.h"
#include "gld.h"
gld_t __floatscan(GFILE *, int, int);
#endif
