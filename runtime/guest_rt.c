/*
 * guest_rt.c -- runtime support, shared by every generated translation unit.
 */

/* sigaction and friends are POSIX, hidden by -std=c11's strict namespace. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "guest_rt.h"

#if !defined(_WIN32)
#include <sys/mman.h>
#endif

/* ---- condition codes, FP and vector helpers (see header for why) ---- */
void arm64g_trunc32(uint64_t op, uint64_t *d1, uint64_t *d2, uint64_t *d3) {
    switch (op) {
    case ARM64G_CC_OP_ADD32:
    case ARM64G_CC_OP_SUB32:
        *d1 = (uint32_t)*d1; *d2 = (uint32_t)*d2; break;
    case ARM64G_CC_OP_ADC32:
    case ARM64G_CC_OP_SBC32:
        *d1 = (uint32_t)*d1; *d2 = (uint32_t)*d2; *d3 = (uint32_t)*d3; break;
    case ARM64G_CC_OP_LOGIC32:
        *d1 = (uint32_t)*d1; break;
    default: break;
    }
}

int arm64g_is32(uint64_t op) {
    return op == ARM64G_CC_OP_ADD32 || op == ARM64G_CC_OP_SUB32
        || op == ARM64G_CC_OP_ADC32 || op == ARM64G_CC_OP_SBC32
        || op == ARM64G_CC_OP_LOGIC32;
}

uint64_t arm64g_res(uint64_t op, uint64_t v) {
    return arm64g_is32(op) ? (uint64_t)(uint32_t)v : v;
}

uint64_t arm64g_calculate_flag_n(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3) {
    arm64g_trunc32(op, &d1, &d2, &d3);
    switch (op) {
    case ARM64G_CC_OP_COPY:    return (d1 >> ARM64G_CC_SHIFT_N) & 1;
    case ARM64G_CC_OP_ADD32:   return (uint32_t)(d1 + d2) >> 31;
    case ARM64G_CC_OP_ADD64:   return (d1 + d2) >> 63;
    case ARM64G_CC_OP_SUB32:   return (uint32_t)(d1 - d2) >> 31;
    case ARM64G_CC_OP_SUB64:   return (d1 - d2) >> 63;
    case ARM64G_CC_OP_ADC32:   return (uint32_t)(d1 + d2 + d3) >> 31;
    case ARM64G_CC_OP_ADC64:   return (d1 + d2 + d3) >> 63;
    case ARM64G_CC_OP_SBC32:   return (uint32_t)(d1 - d2 - (d3 ^ 1)) >> 31;
    case ARM64G_CC_OP_SBC64:   return (d1 - d2 - (d3 ^ 1)) >> 63;
    case ARM64G_CC_OP_LOGIC32: return (uint32_t)d1 >> 31;
    case ARM64G_CC_OP_LOGIC64: return d1 >> 63;
    default: abort();
    }
}

uint64_t arm64g_calculate_flag_z(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3) {
    arm64g_trunc32(op, &d1, &d2, &d3);
    switch (op) {
    case ARM64G_CC_OP_COPY:    return (d1 >> ARM64G_CC_SHIFT_Z) & 1;
    case ARM64G_CC_OP_ADD32:
    case ARM64G_CC_OP_ADD64:   return arm64g_res(op, d1 + d2) == 0;
    case ARM64G_CC_OP_SUB32:
    case ARM64G_CC_OP_SUB64:   return arm64g_res(op, d1 - d2) == 0;
    case ARM64G_CC_OP_ADC32:
    case ARM64G_CC_OP_ADC64:   return arm64g_res(op, d1 + d2 + d3) == 0;
    case ARM64G_CC_OP_SBC32:
    case ARM64G_CC_OP_SBC64:   return arm64g_res(op, d1 - d2 - (d3 ^ 1)) == 0;
    case ARM64G_CC_OP_LOGIC32:
    case ARM64G_CC_OP_LOGIC64: return arm64g_res(op, d1) == 0;
    default: abort();
    }
}

uint64_t arm64g_calculate_flag_c(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3) {
    arm64g_trunc32(op, &d1, &d2, &d3);
    uint64_t res;
    switch (op) {
    case ARM64G_CC_OP_COPY:    return (d1 >> ARM64G_CC_SHIFT_C) & 1;
    case ARM64G_CC_OP_ADD32:
        /* carry out of bit 31, which a 64-bit sum would hide */
        return (uint32_t)(d1 + d2) < (uint32_t)d1;
    case ARM64G_CC_OP_ADD64:   return (d1 + d2) < d1;
    case ARM64G_CC_OP_SUB32:
    case ARM64G_CC_OP_SUB64:   return d1 >= d2;
    case ARM64G_CC_OP_ADC32:
        res = (uint32_t)(d1 + d2 + d3);
        return d3 ? (res <= (uint32_t)d1) : (res < (uint32_t)d1);
    case ARM64G_CC_OP_ADC64:
        res = d1 + d2 + d3;
        return d3 ? (res <= d1) : (res < d1);
    case ARM64G_CC_OP_SBC32:
    case ARM64G_CC_OP_SBC64:
        return d3 ? (d1 >= d2) : (d1 > d2);
    case ARM64G_CC_OP_LOGIC32:
    case ARM64G_CC_OP_LOGIC64: return 0;   /* C is zero after a logic op */
    default: abort();
    }
}

uint64_t arm64g_calculate_flag_v(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3) {
    arm64g_trunc32(op, &d1, &d2, &d3);
    uint64_t res, v;
    switch (op) {
    case ARM64G_CC_OP_COPY:    return (d1 >> ARM64G_CC_SHIFT_V) & 1;
    case ARM64G_CC_OP_ADD32:
        res = (uint32_t)(d1 + d2);
        v = (res ^ d1) & (res ^ d2);
        return (uint32_t)v >> 31;
    case ARM64G_CC_OP_ADD64:
        res = d1 + d2;
        v = (res ^ d1) & (res ^ d2);
        return v >> 63;
    case ARM64G_CC_OP_SUB32:
        res = (uint32_t)(d1 - d2);
        v = (d1 ^ d2) & (d1 ^ res);
        return (uint32_t)v >> 31;
    case ARM64G_CC_OP_SUB64:
        res = d1 - d2;
        v = (d1 ^ d2) & (d1 ^ res);
        return v >> 63;
    case ARM64G_CC_OP_ADC32:
        res = (uint32_t)(d1 + d2 + d3);
        v = (res ^ d1) & (res ^ d2);
        return (uint32_t)v >> 31;
    case ARM64G_CC_OP_ADC64:
        res = d1 + d2 + d3;
        v = (res ^ d1) & (res ^ d2);
        return v >> 63;
    case ARM64G_CC_OP_SBC32:
        res = (uint32_t)(d1 - d2 - (d3 ^ 1));
        v = (d1 ^ d2) & (d1 ^ res);
        return (uint32_t)v >> 31;
    case ARM64G_CC_OP_SBC64:
        res = d1 - d2 - (d3 ^ 1);
        v = (d1 ^ d2) & (d1 ^ res);
        return v >> 63;
    case ARM64G_CC_OP_LOGIC32:
    case ARM64G_CC_OP_LOGIC64: return 0;
    default: abort();
    }
}

uint64_t arm64g_calculate_flags_nzcv(uint64_t op, uint64_t d1, uint64_t d2, uint64_t d3) {
    return (arm64g_calculate_flag_n(op, d1, d2, d3) << ARM64G_CC_SHIFT_N)
         | (arm64g_calculate_flag_z(op, d1, d2, d3) << ARM64G_CC_SHIFT_Z)
         | (arm64g_calculate_flag_c(op, d1, d2, d3) << ARM64G_CC_SHIFT_C)
         | (arm64g_calculate_flag_v(op, d1, d2, d3) << ARM64G_CC_SHIFT_V);
}

uint64_t arm64g_calculate_condition(uint64_t cond_n_op, uint64_t d1,
                                                  uint64_t d2, uint64_t d3) {
    uint64_t cond = cond_n_op >> 4;
    uint64_t op   = cond_n_op & 0xF;
    uint64_t inv  = cond & 1;
    uint64_t nf, zf, cf, vf;

    switch (cond) {
    case ARM64CondAL: case ARM64CondNV:
        return 1;
    case ARM64CondEQ: case ARM64CondNE:
        zf = arm64g_calculate_flag_z(op, d1, d2, d3);
        return inv ^ zf;
    case ARM64CondCS: case ARM64CondCC:
        cf = arm64g_calculate_flag_c(op, d1, d2, d3);
        return inv ^ cf;
    case ARM64CondMI: case ARM64CondPL:
        nf = arm64g_calculate_flag_n(op, d1, d2, d3);
        return inv ^ nf;
    case ARM64CondVS: case ARM64CondVC:
        vf = arm64g_calculate_flag_v(op, d1, d2, d3);
        return inv ^ vf;
    case ARM64CondHI: case ARM64CondLS:
        cf = arm64g_calculate_flag_c(op, d1, d2, d3);
        zf = arm64g_calculate_flag_z(op, d1, d2, d3);
        return inv ^ (1 & (cf & ~zf));
    case ARM64CondGE: case ARM64CondLT:
        nf = arm64g_calculate_flag_n(op, d1, d2, d3);
        vf = arm64g_calculate_flag_v(op, d1, d2, d3);
        return inv ^ (1 & ~(nf ^ vf));
    case ARM64CondGT: case ARM64CondLE:
        nf = arm64g_calculate_flag_n(op, d1, d2, d3);
        vf = arm64g_calculate_flag_v(op, d1, d2, d3);
        zf = arm64g_calculate_flag_z(op, d1, d2, d3);
        return inv ^ (1 & ~(zf | (nf ^ vf)));
    default:
        abort();
    }
}

double guest_round_mode(double x, uint64_t rm) {
    switch (rm & 3) {
    case IRRM_NEGINF: return __builtin_floor(x);
    case IRRM_POSINF: return __builtin_ceil(x);
    case IRRM_ZERO:   return __builtin_trunc(x);
    default:          return __builtin_nearbyint(x);
    }
}

uint32_t guest_cmpf64(uint64_t a, uint64_t b) {
    double x = f64_of(a), y = f64_of(b);
    if (__builtin_isunordered(x, y)) return IRCMP_UN;
    if (x < y) return IRCMP_LT;
    if (x > y) return IRCMP_GT;
    return IRCMP_EQ;
}

uint32_t guest_cmpf32(uint32_t a, uint32_t b) {
    float x = f32_of(a), y = f32_of(b);
    if (__builtin_isunordered(x, y)) return IRCMP_UN;
    if (x < y) return IRCMP_LT;
    if (x > y) return IRCMP_GT;
    return IRCMP_EQ;
}

uint64_t guest_absf64(uint64_t a) { return a & ~(UINT64_C(1) << 63); }
uint64_t guest_negf64(uint64_t a) { return a ^  (UINT64_C(1) << 63); }
uint32_t guest_absf32(uint32_t a) { return a & 0x7FFFFFFFu; }
uint32_t guest_negf32(uint32_t a) { return a ^ 0x80000000u; }

uint64_t guest_f32_to_f64(uint32_t a) { return f64_to((double)f32_of(a)); }
uint32_t guest_f64_to_f32(uint64_t rm, uint64_t a) {
    (void)rm; return f32_to((float)f64_of(a));
}

uint64_t guest_i32s_to_f64(uint32_t v) { return f64_to((double)(int32_t)v); }
uint64_t guest_i32u_to_f64(uint32_t v) { return f64_to((double)(uint32_t)v); }
uint64_t guest_i64s_to_f64(uint64_t rm, uint64_t v) { (void)rm; return f64_to((double)(int64_t)v); }
uint64_t guest_i64u_to_f64(uint64_t rm, uint64_t v) { (void)rm; return f64_to((double)(uint64_t)v); }
uint32_t guest_i32s_to_f32(uint64_t rm, uint32_t v) { (void)rm; return f32_to((float)(int32_t)v); }
uint32_t guest_i32u_to_f32(uint64_t rm, uint32_t v) { (void)rm; return f32_to((float)(uint32_t)v); }
uint32_t guest_i64s_to_f32(uint64_t rm, uint64_t v) { (void)rm; return f32_to((float)(int64_t)v); }
uint32_t guest_i64u_to_f32(uint64_t rm, uint64_t v) { (void)rm; return f32_to((float)(uint64_t)v); }

/* float -> integer, saturating the way AArch64 FCVT does */
uint32_t guest_f64_to_i32s(uint64_t rm, uint64_t a) {
    double x = guest_round_mode(f64_of(a), rm);
    if (__builtin_isnan(x)) return 0;
    if (x >= 2147483647.0) return 0x7FFFFFFFu;
    if (x <= -2147483648.0) return 0x80000000u;
    return (uint32_t)(int32_t)x;
}

uint32_t guest_f64_to_i32u(uint64_t rm, uint64_t a) {
    double x = guest_round_mode(f64_of(a), rm);
    if (__builtin_isnan(x) || x <= 0.0) return 0;
    if (x >= 4294967295.0) return 0xFFFFFFFFu;
    return (uint32_t)x;
}

uint64_t guest_f64_to_i64s(uint64_t rm, uint64_t a) {
    double x = guest_round_mode(f64_of(a), rm);
    if (__builtin_isnan(x)) return 0;
    if (x >= 9223372036854775807.0) return UINT64_C(0x7FFFFFFFFFFFFFFF);
    if (x <= -9223372036854775808.0) return UINT64_C(0x8000000000000000);
    return (uint64_t)(int64_t)x;
}

uint64_t guest_f64_to_i64u(uint64_t rm, uint64_t a) {
    double x = guest_round_mode(f64_of(a), rm);
    if (__builtin_isnan(x) || x <= 0.0) return 0;
    if (x >= 18446744073709551615.0) return UINT64_MAX;
    return (uint64_t)x;
}

uint32_t guest_f32_to_i32s(uint64_t rm, uint32_t a) {
    return guest_f64_to_i32s(rm, f64_to((double)f32_of(a)));
}

uint32_t guest_f32_to_i32u(uint64_t rm, uint32_t a) {
    return guest_f64_to_i32u(rm, f64_to((double)f32_of(a)));
}

uint64_t guest_f32_to_i64s(uint64_t rm, uint32_t a) {
    return guest_f64_to_i64s(rm, f64_to((double)f32_of(a)));
}

uint64_t guest_f32_to_i64u(uint64_t rm, uint32_t a) {
    return guest_f64_to_i64u(rm, f64_to((double)f32_of(a)));
}

uint64_t guest_roundf64toint(uint64_t rm, uint64_t a) {
    return f64_to(guest_round_mode(f64_of(a), rm));
}

uint32_t guest_roundf32toint(uint64_t rm, uint32_t a) {
    return f32_to((float)guest_round_mode((double)f32_of(a), rm));
}

uint64_t guest_sqrtf64(uint64_t rm, uint64_t a) {
    /* sqrt of a negative manufactures a NaN, so it needs the same sign
       correction as the arithmetic ops -- see guest_fcanon64_1. */
    (void)rm; return guest_fcanon64_1(f64_to(__builtin_sqrt(f64_of(a))), a);
}

uint32_t guest_sqrtf32(uint64_t rm, uint32_t a) {
    (void)rm; return guest_fcanon32_1(f32_to(__builtin_sqrtf(f32_of(a))), a);
}

U128 guest_mullu64(uint64_t a, uint64_t b) {
    U128 r;
#ifdef __SIZEOF_INT128__
    unsigned __int128 p = (unsigned __int128)a * b;
    r.w[0] = (uint64_t)p;
    r.w[1] = (uint64_t)(p >> 64);
#else
    uint64_t al = (uint32_t)a, ah = a >> 32, bl = (uint32_t)b, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = (ll >> 32) + (uint32_t)lh + (uint32_t)hl;
    r.w[0] = (uint32_t)ll | (mid << 32);
    r.w[1] = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
#endif
    return r;
}

U128 guest_mulls64(uint64_t a, uint64_t b) {
    U128 r;
#ifdef __SIZEOF_INT128__
    __int128 p = (__int128)(int64_t)a * (int64_t)b;
    r.w[0] = (uint64_t)p;
    r.w[1] = (uint64_t)((unsigned __int128)p >> 64);
#else
    r = guest_mullu64(a, b);
    if ((int64_t)a < 0) r.w[1] -= b;
    if ((int64_t)b < 0) r.w[1] -= a;
#endif
    return r;
}

U128 guest_cnt8x16(U128 a) {
    U128 r;
    uint8_t v[16];
    memcpy(v, &a, 16);
    for (int i = 0; i < 16; i++) v[i] = (uint8_t)__builtin_popcount(v[i]);
    memcpy(&r, v, 16);
    return r;
}

U128 guest_slicev128(U128 hi, U128 lo, uint64_t n) {
    U128 r;
    uint8_t buf[32], out[16];
    memcpy(buf, &lo, 16);
    memcpy(buf + 16, &hi, 16);
    n &= 31;
    for (int i = 0; i < 16; i++) out[i] = buf[(n + i) & 31];
    memcpy(&r, out, 16);
    return r;
}

U128 guest_reverse32sin64_x2(U128 a) {
    U128 r;
    uint32_t v[4], o[4];
    memcpy(v, &a, 16);
    o[0] = v[1]; o[1] = v[0]; o[2] = v[3]; o[3] = v[2];
    memcpy(&r, o, 16);
    return r;
}

U128 guest_catoddlanes32x4(U128 a, U128 b) {
    U128 r;
    uint32_t av[4], bv[4], o[4];
    memcpy(av, &a, 16); memcpy(bv, &b, 16);
    o[0] = bv[1]; o[1] = bv[3]; o[2] = av[1]; o[3] = av[3];
    memcpy(&r, o, 16);
    return r;
}

U128 guest_catevenlanes32x4(U128 a, U128 b) {
    U128 r;
    uint32_t av[4], bv[4], o[4];
    memcpy(av, &a, 16); memcpy(bv, &b, 16);
    o[0] = bv[0]; o[1] = bv[2]; o[2] = av[0]; o[3] = av[2];
    memcpy(&r, o, 16);
    return r;
}

uint64_t guest_narrowun64to32x2(U128 a) {
    return (uint64_t)(uint32_t)a.w[0] | ((uint64_t)(uint32_t)a.w[1] << 32);
}

uint64_t guest_narrowun32to16x4(U128 a) {
    uint32_t v[4]; uint16_t o[4];
    memcpy(v, &a, 16);
    for (int i = 0; i < 4; i++) o[i] = (uint16_t)v[i];
    uint64_t r; memcpy(&r, o, 8); return r;
}

uint64_t guest_narrowun16to8x8(U128 a) {
    uint16_t v[8]; uint8_t o[8];
    memcpy(v, &a, 16);
    for (int i = 0; i < 8; i++) o[i] = (uint8_t)v[i];
    uint64_t r; memcpy(&r, o, 8); return r;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
 
#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <execinfo.h>
#endif
 
/*
 * Translated code is a very deep call graph of same-shaped functions, so a
 * crash is far more useful with a backtrace than without.  Installed once, on
 * first entry, and only if the process has not set its own handler.
 */
/* The faulting address is the single most useful fact about a crash in
 * translated code: it says immediately whether a guest pointer was null, was a
 * raw guest address that should have been translated, or was simply wrong. */
static _Thread_local cpu_t *g_current_cpu = NULL;
 
static void guest_crash_report(int sig, void *fault_addr) {
    /* _exit() skips stdio flushing, which would throw away everything the
     * program printed before the fault -- including which test case it was
     * in.  Flush first. */
    fflush(NULL);
 
#ifdef _WIN32
    void *frames[64];
    int n = (int)CaptureStackBackTrace(0, 64, frames, NULL);
#else
    void *frames[64];
    int n = backtrace(frames, 64);
#endif
 
    fprintf(stderr, "\nguest: fatal signal %d at address %p\n",
            sig, fault_addr);
    if (g_current_cpu) {
        fprintf(stderr, "guest registers:\n");
        for (int i = 0; i < 31; i += 4) {
            fprintf(stderr, "  x%-2d %016llx  x%-2d %016llx  x%-2d %016llx  x%-2d %016llx\n",
                    i,   (unsigned long long)*(uint64_t *)(g_current_cpu->g + GUEST_OFF_X0 + 8*i),
                    i+1, (unsigned long long)*(uint64_t *)(g_current_cpu->g + GUEST_OFF_X0 + 8*(i+1)),
                    i+2, (unsigned long long)*(uint64_t *)(g_current_cpu->g + GUEST_OFF_X0 + 8*(i+2)),
                    i+3, (unsigned long long)*(uint64_t *)(g_current_cpu->g + GUEST_OFF_X0 + 8*(i+3)));
        }
        fprintf(stderr, "  sp  %016llx\n",
                (unsigned long long)*(uint64_t *)(g_current_cpu->g + GUEST_OFF_SP));
    }
 
    fprintf(stderr, "%d frames:\n", n);
#ifdef _WIN32
    {
        /* SymInitialize must run before SymFromAddr can resolve anything.
         * Doing it here (rather than once at startup) keeps this a minimal,
         * self-contained diff; it's cheap enough to not matter since we're
         * about to _exit() anyway. */
        HANDLE process = GetCurrentProcess();
        BOOL syms_ready = SymInitialize(process, NULL, TRUE);
 
        char sym_buf[sizeof(SYMBOL_INFO) + 256 * sizeof(char)];
        SYMBOL_INFO *symbol = (SYMBOL_INFO *)sym_buf;
        symbol->MaxNameLen = 255;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
 
        for (int i = 0; i < n; i++) {
            DWORD64 address = (DWORD64)(uintptr_t)frames[i];
            DWORD64 displacement = 0;
            if (syms_ready && SymFromAddr(process, address, &displacement, symbol)) {
                fprintf(stderr, "  [%2d] %p %s + 0x%llx\n",
                        i, frames[i], symbol->Name,
                        (unsigned long long)displacement);
            } else {
                fprintf(stderr, "  [%2d] %p\n", i, frames[i]);
            }
        }
 
        if (syms_ready) {
            SymCleanup(process);
        }
    }
#else
    backtrace_symbols_fd(frames, n, 2);
#endif
 
    _exit(139);
}
 
#ifdef _WIN32
 
/* Vectored exception handler: Windows' equivalent entry point to a POSIX
 * sigaction handler. Runs on the faulting thread before any SEH unwinding. */
static LONG WINAPI guest_segv_veh(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
 
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_STACK_OVERFLOW) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
 
    /* ExceptionInformation[1] is the faulting address for access violations
     * (ExceptionInformation[0] is 0=read/1=write/8=exec); other exception
     * codes here don't carry an address. */
    void *fault_addr = NULL;
    if (code == EXCEPTION_ACCESS_VIOLATION &&
        ep->ExceptionRecord->NumberParameters >= 2) {
        fault_addr = (void *)ep->ExceptionRecord->ExceptionInformation[1];
    }
 
    guest_crash_report((int)code, fault_addr);
    return EXCEPTION_CONTINUE_SEARCH; /* unreachable: guest_crash_report() calls _exit() */
}
 
#else
 
static void guest_segv(int sig, siginfo_t *info, void *uctx) {
    (void)uctx;
    guest_crash_report(sig, info ? info->si_addr : NULL);
}
 
#endif
 
static void guest_install_handler(void) {
    static int done = 0;
    if (done) return;
    done = 1;
 
#ifdef _WIN32
    /* No SIG_DFL-style "has the process already installed a handler" check
     * exists for VEH; AddVectoredExceptionHandler chains handlers instead of
     * replacing one, so installing unconditionally is the correct analog. */
    AddVectoredExceptionHandler(1 /* call first */, guest_segv_veh);
#else
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = guest_segv;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
    if (sigaction(SIGSEGV, NULL, &old) == 0 && old.sa_handler == SIG_DFL)
        sigaction(SIGSEGV, &sa, NULL);
    if (sigaction(SIGBUS, NULL, &old) == 0 && old.sa_handler == SIG_DFL)
        sigaction(SIGBUS, &sa, NULL);
#endif
}
 


/* The generated unit defines these.
 *
 * g_rw is an array of 8-byte slots (see g_rw_slot in guest_decls.h), not of
 * bytes, and only its ADDRESS is used here, so the element type is declared
 * opaquely rather than duplicating the union.  guest_relocate() is gone: every
 * pointer in the image is now a static initialiser the linker resolves, so
 * there is nothing left to patch at startup.
 */
extern uint64_t g_rw[];
extern const uint8_t g_ro[];

typedef struct guest_stack {
    void   *base;
    size_t  size;
} guest_stack;

/* One stack per entry-point invocation, so nested and concurrent entries do
 * not share a guest stack. */
static _Thread_local guest_stack g_stack = { NULL, 0 };
static _Thread_local int         g_depth = 0;

/* ---- scratch buffers for the port's own bookkeeping ---------------------
 *
 * NOTHING the port does for its own convenience may go through the allocator
 * the GUEST uses.  The variadic marshaller used to malloc a 256-byte buffer
 * for every printf-family call the guest made; the reference's C library
 * renders small results on its stack and allocates nothing.  Each of those
 * allocations shifted every pointer the guest allocated afterwards, and the
 * shader compiler hashes some of its tables BY POINTER (0xf3bd9c), so the two
 * runs ended up walking a hash bucket in a different order and two dwords of
 * the reflection section came out different.  It cost a full trace diff to
 * find; keeping the port's memory and the guest's memory apart is the rule
 * that stops it recurring.
 *
 * These are per-thread, grown on demand, never handed back: the formatter's
 * buffer is transient and reused on every call, so a steady state is reached
 * within the first few calls.  mmap, not malloc, for the reason above.
 */
#define GUEST_SCRATCH_SLOTS 2

static _Thread_local char  *g_scratch[GUEST_SCRATCH_SLOTS];
static _Thread_local size_t g_scratch_cap[GUEST_SCRATCH_SLOTS];

char *guest_scratch(unsigned slot, size_t need) {
    if (slot >= GUEST_SCRATCH_SLOTS) return NULL;
    if (need && need <= g_scratch_cap[slot]) return g_scratch[slot];
    size_t cap = g_scratch_cap[slot] ? g_scratch_cap[slot] : 4096;
    while (cap < need) cap *= 2;
#if defined(_WIN32)
    char *p = (char *)malloc(cap);
    if (!p) return NULL;
    if (g_scratch[slot]) {
        memcpy(p, g_scratch[slot], g_scratch_cap[slot]);
        free(g_scratch[slot]);
    }
#else
    char *p = (char *)mmap(NULL, cap, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (g_scratch[slot]) {
        memcpy(p, g_scratch[slot], g_scratch_cap[slot]);
        munmap(g_scratch[slot], g_scratch_cap[slot]);
    }
#endif
    g_scratch[slot] = p;
    g_scratch_cap[slot] = cap;
    return p;
}

size_t guest_scratch_cap(unsigned slot) {
    return slot < GUEST_SCRATCH_SLOTS ? g_scratch_cap[slot] : 0;
}

void *guest_stack_alloc(void) {
    /*
     * mmap, not malloc, and for a reason that took a while to matter: the
     * guest's own heap and the port's bookkeeping must not share an
     * allocator.  An 8 MB malloc shifts everything the GUEST allocates
     * afterwards, and the compiler hashes some of its tables by pointer, so
     * "the port allocates one thing the reference does not" is enough to make
     * two runs take different paths through a hash bucket.  Keeping the stack
     * out of the heap entirely makes the guest's allocation stream depend on
     * the guest alone, which is what makes it comparable with the reference's.
     *
     * malloc stays as the fallback for hosts without mmap (Windows).
     */
    void *p = NULL;
#if defined(_WIN32)
    p = malloc(GUEST_STACK_SIZE);
#else
    p = mmap(NULL, GUEST_STACK_SIZE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) p = NULL;
#endif
    if (!p) {
        fprintf(stderr, "guest: cannot allocate %u-byte stack\n",
                (unsigned)GUEST_STACK_SIZE);
        abort();
    }
    /* Diagnostic: GUEST_POISON=<byte> fills the guest stack with that byte
     * instead of leaving it as whatever malloc returned.
     *
     * A value the guest reads from a slot it never wrote is otherwise
     * invisible -- it just looks like a plausible number.  Poisoning makes it
     * self-identifying: if a suspect value turns into a run of the poison
     * byte when the poison changes, the slot feeding it was never written.
     * Off by default, so it cannot affect a normal run.
     */
    const char *poison = getenv("GUEST_POISON");
    if (poison && *poison) {
        int b = (int)strtol(poison, NULL, 0);
        memset(p, b & 0xFF, GUEST_STACK_SIZE);
    }
    return p;
}

void guest_stack_free(void *p) {
    if (!p) return;
#if defined(_WIN32)
    free(p);
#else
    munmap(p, GUEST_STACK_SIZE);
#endif
}

/* The guest state of the call in progress on this thread.  A host callback
 * invoked from inside guest code -- qsort's comparator is the only one this
 * binary needs -- has to run on the SAME state and the same guest stack, so it
 * needs to get at it.  See guest_qsort() in guest_host.c. */
cpu_t *guest_current_cpu(void) { return g_current_cpu; }

/* ---- the C++ exception shadow stack ------------------------------------
 *
 * The STACK POINTER lives here rather than in guest_eh.c because guest_rt.c is
 * linked by every harness -- cctest and the QEMU reference build link it
 * ALONE -- and both the qsort trampoline and guest_longjmp() have to be able
 * to save and restore it.  Putting it here keeps those two working without
 * dragging the whole exception implementation into a harness that has no
 * exceptions to handle.  guest_eh.c owns everything that INTERPRETS it.
 */
static guest_eh_frame *g_eh_top;

guest_eh_frame *guest_eh_top(void) { return g_eh_top; }

void guest_eh_set_top(guest_eh_frame *f) { g_eh_top = f; }

/* Set once, the first time the guest is entered; see guest_init(). */
static int g_ctors_done;

/* The real body is generated into entries.c, which only a full port links.
 * Small harnesses (cctest, the QEMU reference build) link guest_rt.c on its
 * own and have no constructors to run, so a weak empty default keeps them
 * linking; the generated definition overrides it wherever it is present. */
#if defined(__GNUC__)
/* Fills in the imported data objects whose value is not a constant
 * expression (stdin/stdout/stderr and the C++ typeinfo vptrs).  Defined in
 * guest_cxx.c; a weak empty default keeps harnesses that link only the runtime
 * linkable, exactly as guest_run_ctors does. */
__attribute__((weak)) void guest_data_imports_init(void) { }

__attribute__((weak)) void guest_run_ctors(cpu_t *cpu) { (void)cpu; }

/* Same reason, for the qsort trampoline's dispatch: a harness never sorts with
 * a guest comparator.  This one aborts rather than returning quietly -- a real
 * port always links the generated definition, so reaching this body means the
 * generated one is missing and silence would hide it. */
__attribute__((weak)) void guest_dispatch(cpu_t *cpu, uint64_t p) {
    (void)cpu;
    fprintf(stderr, "guest: guest_dispatch(%#llx) with no dispatch table linked\n",
            (unsigned long long)p);
    abort();
}
#endif

void guest_init(cpu_t *cpu) {
    guest_install_handler();
    g_current_cpu = cpu;
    memset(cpu->g, 0, GUEST_STATE_SIZE);

    if (g_depth == 0) {
        g_stack.base = guest_stack_alloc();
        g_stack.size = GUEST_STACK_SIZE;
    }
    g_depth++;

    /* Stack grows down; leave a red zone and keep 16-byte alignment. */
    uint64_t top = (uint64_t)(uintptr_t)g_stack.base + g_stack.size - 4096;
    top &= ~(uint64_t)15;
    *(uint64_t *)(cpu->g + GUEST_OFF_SP) = top;

    /* The dynamic loader runs .init_array at dlopen.  Nothing here does, so
     * the constructors run on the first entry into the guest instead -- after
     * the stack exists (they use it) and before any entry point has written
     * its arguments into the guest state, which is why this sits at the END of
     * guest_init() and not in the callers.  They initialise RW globals the
     * library reads much later; leaving them unrun made --opt-level none write
     * zeroes into the debug info where the original library writes real
     * values.  g_ctors_done is set BEFORE the call so that a constructor that
     * itself reaches an entry point cannot recurse into this. */
    if (!g_ctors_done) {
        g_ctors_done = 1;
        guest_data_imports_init();
        guest_run_ctors(cpu);
        /* A constructor leaves its own scratch in the guest state; wipe it so
         * the entry point that triggered this sees exactly what it would have
         * seen had the constructors run at load time. */
        memset(cpu->g, 0, GUEST_STATE_SIZE);
        *(uint64_t *)(cpu->g + GUEST_OFF_SP) = top;
    }
}

void guest_fini(cpu_t *cpu) {
    (void)cpu;
    if (--g_depth == 0) {
        /* The setjmp side table is keyed by guest jmp_buf address and nothing
         * frees a slot when its frame returns, so it has to be reclaimed here
         * -- see guest_jb_reset(). */
        guest_jb_reset();
        /* Same argument, one line up: no exception frame can outlive the
         * outermost guest call, and a frame left behind by a trap or a
         * non-local jump would be walked by the next unwind. */
        g_eh_top = NULL;
        if (g_stack.base) {
            guest_stack_free(g_stack.base);
            g_stack.base = NULL;
            g_stack.size = 0;
        }
    }
}

void guest_unresolved(cpu_t *cpu, uint64_t target, const char *where) {
    (void)cpu;
    fprintf(stderr, "guest: unresolved control transfer to %#llx (%s)\n",
            (unsigned long long)target, where ? where : "?");
    abort();
}

void guest_nodecode(cpu_t *cpu, uint64_t pc) {
    (void)cpu;
    fprintf(stderr, "guest: undecodable instruction at %#llx\n",
            (unsigned long long)pc);
    abort();
}

void guest_missing_import(const char *name) {
    fprintf(stderr, "guest: import %s is not implemented; "
                    "link a real definition to override the weak stub\n", name);
    abort();
}

void guest_unsupported_import(cpu_t *cpu, const char *name) {
    (void)cpu;
    fprintf(stderr, "guest: import %s needs a hand-written marshaller "
                    "(variadic or setjmp-family)\n", name);
    abort();
}

/*
 * TBL/permute: each control byte selects a source byte; anything with the top
 * bit set (index >= 16) yields zero, matching AArch64 TBL semantics.
 */
U128 guest_perm8x16(U128 data, U128 ctrl) {
    U128 r;
    uint8_t d[16], c[16], o[16];
    memcpy(d, &data, 16);
    memcpy(c, &ctrl, 16);
    for (int i = 0; i < 16; i++) {
        uint8_t idx = c[i];
        o[i] = (idx < 16) ? d[idx] : 0;
    }
    memcpy(&r, o, 16);
    return r;
}

/* Whole-register shifts, by a bit count. */
U128 guest_shlv128(U128 a, uint8_t n) {
    U128 r;
    n &= 127;
    if (n == 0) return a;
    if (n < 64) {
        r.w[1] = (a.w[1] << n) | (a.w[0] >> (64 - n));
        r.w[0] = a.w[0] << n;
    } else {
        r.w[1] = a.w[0] << (n - 64);
        r.w[0] = 0;
    }
    return r;
}

U128 guest_shrv128(U128 a, uint8_t n) {
    U128 r;
    n &= 127;
    if (n == 0) return a;
    if (n < 64) {
        r.w[0] = (a.w[0] >> n) | (a.w[1] << (64 - n));
        r.w[1] = a.w[1] >> n;
    } else {
        r.w[0] = a.w[1] >> (n - 64);
        r.w[1] = 0;
    }
    return r;
}

/* ---- qsort with a guest comparator --------------------------------------
 *
 * Here rather than in guest_host.c because that file is also compiled for the
 * QEMU reference build, against the real AArch64 library, where none of the
 * dispatch machinery exists.
 *
 * `qsort` takes a function POINTER, and the guest's is a guest address.
 * Passing it to the host qsort makes the C library call into the middle of
 * nothing -- the observed crash was a jump to 0x71005bcf20, a guest address,
 * from inside glibc's msort_with_tmp.
 *
 * So the host is given a trampoline instead, and the guest address is called
 * through guest_dispatch.  Three things make that safe:
 *
 *   - it runs on the CURRENT guest state and stack, exactly as a real call
 *     from that point would.  A fresh guest_init() would reset SP to the top
 *     of the stack and scribble over the frame qsort was called from;
 *   - the state is saved and restored around each comparison, so a comparator
 *     cannot leak register changes into the caller;
 *   - the "which guest function" slot is saved and restored around the sort,
 *     so a comparator that itself sorts still works.
 */
static _Thread_local uint64_t g_qsort_cmp;

static int guest_qsort_trampoline(const void *a, const void *b) {
    cpu_t *cpu = guest_current_cpu();
    uint8_t saved[GUEST_STATE_SIZE];
    /* A comparator that throws would leave its own exception frames behind on
     * a stack the host qsort is about to unwind past.  Restoring the top is
     * the same repair guest_longjmp() makes, for the same reason. */
    struct guest_eh_frame *eh_outer = guest_eh_top();
    memcpy(saved, cpu->g, sizeof saved);
    *(uint64_t *)(cpu->g + GUEST_OFF_X0)     = (uint64_t)(uintptr_t)a;
    *(uint64_t *)(cpu->g + GUEST_OFF_X0 + 8) = (uint64_t)(uintptr_t)b;
    guest_dispatch(cpu, g_qsort_cmp);
    int r = (int)(int32_t)*(uint64_t *)(cpu->g + GUEST_OFF_X0);
    memcpy(cpu->g, saved, sizeof saved);
    guest_eh_set_top(eh_outer);
    return r;
}

void guest_qsort(void *base, uint64_t n, uint64_t size, uint64_t cmp) {
    /* A null comparator is undefined behaviour in C and the guest never passes
     * one; say so rather than crashing inside the C library. */
    if (!cmp) { fprintf(stderr, "guest: qsort with a null comparator\n"); abort(); }
    uint64_t outer = g_qsort_cmp;
    g_qsort_cmp = cmp;
    qsort(base, (size_t)n, (size_t)size, guest_qsort_trampoline);
    g_qsort_cmp = outer;
}
