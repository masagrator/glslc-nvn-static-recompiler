/* Verbatim interface from musl's src/internal/intscan.h, retyped for GFILE. */
#ifndef GINTSCAN_H
#define GINTSCAN_H
#include "gshgetc.h"
unsigned long long __intscan(GFILE *, unsigned, int, unsigned long long);
#endif
