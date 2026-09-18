#!/usr/bin/env python3
"""vecref.py -- differential test of the SIMD/FP translation, the vector
counterpart of ccref.py.

ccref.py has tested the condition-code helpers from the start; nothing tested
the vector helpers, which is how `v_interleavelo32x4` shipped with its two
arguments the wrong way round -- making every widening `sxtl` return zero.
This closes that gap.

Method: for each distinct vector instruction FORM that appears in the binary
(vscan.py inventories them), run the REAL instruction on AArch64 under QEMU and
the TRANSLATED instruction -- lifted by pyvex and emitted by irtoc.IRToC, the
same path the generator uses -- on the host, over the same pseudo-random guest
states, and compare the whole register file afterwards.

  usage: vecref.py <glslc.elf> <outdir> [forms.pkl] [n-inputs]

Needs qemu-aarch64 and the aarch64 cross compiler (see REFERENCE-DIFFING.md).
"""
import os, pickle, random, struct, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capstone
import pyvex, archinfo
from irtoc import IRToC, UnsupportedIR

ELF     = sys.argv[1] if len(sys.argv) > 1 else 'glslc.elf'
OUTDIR  = sys.argv[2] if len(sys.argv) > 2 else 'out'
FORMS   = sys.argv[3] if len(sys.argv) > 3 else '/tmp/vforms.pkl'
NINPUT  = int(sys.argv[4]) if len(sys.argv) > 4 else 16
WORK    = tempfile.mkdtemp(prefix='vecref-')

# ---------------------------------------------------------------- state layout
# One test state, identical on both sides:
#     0    .. 511   q0..q31         (32 * 16)
#     512  .. 719   x0..x25         (26 * 8)
#     720  .. 727   nzcv, in bits 31..28
#     728  .. 1239  scratch reached through sp (sp points 256 bytes into it,
#                   so negative displacements and pre-decrements work)
#     1240 .. 1247  sp displacement after the instruction, relative to that
# x26 holds the real stack pointer across the stub and x27/x28 the in/out
# pointers, so all three are off limits to the instruction under test.
NQ, NX = 32, 26
OFF_X, OFF_F, OFF_SCR, OFF_SPD, STATE = 512, 720, 728, 1240, 1248
SP_BIAS = 256
# VEX guest-state offsets (archinfo); the generated tree hard-codes the same.
G_X0, G_Q0, G_CCOP, G_D1, G_D2, G_ND = 16, 320, 280, 288, 296, 304

# x27/x28 carry the in/out pointers through the reference stub, so an example
# that reads or writes them (or sp/pc) cannot be used.
BANNED = {'x26', 'w26', 'x27', 'w27', 'x28', 'w28',
          'x29', 'w29', 'x30', 'w30', 'pc'}

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True

# Set per case before translating; see Ctx.fp_minmax_is_nm.
CUR_IS_NM = [False]

# Likewise for the fused multiply-adds, whose fusion the IR does not record --
# see Ctx.fp_is_fused_mac in gen.py.  The real context reads it back out of the
# encoding; here the mnemonic capstone already produced says it directly.
CUR_IS_FMA = [False]
FMA_MNEMONICS = {'fmadd', 'fmsub', 'fnmadd', 'fnmsub', 'fmla', 'fmls'}


def usable(enc):
    """True if this encoding can be run inside the reference stub."""
    ins = next(md.disasm(enc, 0x1000), None)
    if ins is None:
        return False
    if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL) or \
       ins.group(capstone.CS_GRP_RET) or ins.group(capstone.CS_GRP_INT):
        return False
    # Padding and system instructions cannot be run inside the stub: `udf`
    # traps, and the barrier/system family either faults at EL0 or has no
    # observable effect on the state being compared.
    if ins.mnemonic in ('udf', 'brk', 'hlt', 'svc', 'hvc', 'smc', 'msr', 'mrs',
                        'sys', 'sysl', 'dsb', 'dmb', 'isb', 'eret', 'drps',
                        'wfi', 'wfe', 'sev', 'sevl', 'yield', 'hint',
                        'clrex', 'dc', 'ic', 'at', 'tlbi',
                        'ldxr', 'ldaxr', 'stxr', 'stlxr', 'ldxp', 'stxp',
                        'ldaxp', 'stlxp', 'casp', 'cas'):
        return False
    regs_r, regs_w = ins.regs_access()
    for r in list(regs_r) + list(regs_w):
        if ins.reg_name(r) in BANNED:
            return False
    return True


# ------------------------------------------------------------------ the forms
forms, rep = pickle.load(open(FORMS, 'rb'))
cases = []                       # (name, encoding bytes, disasm text)
skipped = []
for key in sorted(rep, key=lambda k: (k[0], k[1])):
    if key[1] == 'MEM':
        continue                 # needs an address to mean anything
    pick = None
    for addr, mn, ops, enc in rep[key]:
        if usable(enc):
            pick = (addr, mn, ops, enc)
            break
    if pick is None:
        skipped.append((key, 'no example avoids x26/x27/x28/lr'))
        continue
    cases.append(('%s %s' % (pick[1], pick[2]), pick[3], '%s %s' % (pick[1], pick[2])))

# --------------------------------------------------------- the reference stub
def gen_ref_asm(cases):
    L = ['    .text']
    for i, (_n, enc, txt) in enumerate(cases):
        # The body loads x0..x26 with test data, which destroys the
        # callee-saved x19..x26 (and the d8..d15 halves) the C caller relies
        # on -- without this frame the CALLER crashes, not the instruction.
        L += ['    .globl vt_%d' % i, '    .type vt_%d, %%function' % i,
              'vt_%d:' % i,
              '    sub sp, sp, #176',
              '    stp x19, x20, [sp, #0]', '    stp x21, x22, [sp, #16]',
              '    stp x23, x24, [sp, #32]', '    stp x25, x26, [sp, #48]',
              '    stp x27, x28, [sp, #64]', '    stp x29, x30, [sp, #80]',
              '    stp d8, d9, [sp, #96]',   '    stp d10, d11, [sp, #112]',
              '    stp d12, d13, [sp, #128]','    stp d14, d15, [sp, #144]',
              '    mov x27, x0', '    mov x28, x1',
              '    mov x26, sp',            # the real stack, restored below
              '    ldr x9, [x27, #%d]' % OFF_F, '    msr nzcv, x9']
        for q in range(NQ):
            L.append('    ldr q%d, [x27, #%d]' % (q, q * 16))
        for x in range(NX):
            L.append('    ldr x%d, [x27, #%d]' % (x, OFF_X + x * 8))
        # sp addresses the scratch area of the OUTPUT buffer, which main()
        # has already filled with a copy of the input -- so a load reads the
        # test data and a store is captured in the result.
        L.append('    add sp, x28, #%d' % (OFF_SCR + SP_BIAS))
        L.append('    .inst 0x%08x        // %s' % (
            struct.unpack('<I', enc)[0], txt))
        # x0 is freed first so it can carry the sp displacement out.
        L += ['    str x0, [x28, #%d]' % OFF_X,
              '    mov x0, sp', '    sub x0, x0, x28',
              '    sub x0, x0, #%d' % (OFF_SCR + SP_BIAS),
              '    str x0, [x28, #%d]' % OFF_SPD,
              '    mov sp, x26']
        for x in range(1, NX):          # x0 was stored above
            L.append('    str x%d, [x28, #%d]' % (x, OFF_X + x * 8))
        for q in range(NQ):
            L.append('    str q%d, [x28, #%d]' % (q, q * 16))
        L += ['    mrs x0, nzcv', '    str x0, [x28, #%d]' % OFF_F,
              '    ldp x19, x20, [sp, #0]', '    ldp x21, x22, [sp, #16]',
              '    ldp x23, x24, [sp, #32]', '    ldp x25, x26, [sp, #48]',
              '    ldp x27, x28, [sp, #64]', '    ldp x29, x30, [sp, #80]',
              '    ldp d8, d9, [sp, #96]',   '    ldp d10, d11, [sp, #112]',
              '    ldp d12, d13, [sp, #128]','    ldp d14, d15, [sp, #144]',
              '    add sp, sp, #176', '    ret',
              '    .size vt_%d, .-vt_%d' % (i, i), '']
    return '\n'.join(L) + '\n'


REF_MAIN = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define STATE %d
#define NCASE %d
%s
typedef void (*fn_t)(const unsigned char *, unsigned char *);
static const fn_t fns[NCASE] = { %s };
int main(int argc, char **argv){
    FILE *in = fopen(argv[1], "rb"), *out = fopen(argv[2], "wb");
    unsigned char *st = malloc(STATE), *res = malloc(STATE);
    long n = 0;
    while (fread(st, 1, STATE, in) == STATE) {
        for (int c = 0; c < NCASE; ++c) {
            /* The scratch area sp points into lives in `res`, so it starts as
               a copy of the input: loads see the test data, stores are kept. */
            memcpy(res, st, STATE);
            /* A crash inside one of these stubs would otherwise be anonymous:
               record which case is about to run so the driver can name it. */
            if (argc > 3) { FILE *m=fopen(argv[3],"w"); fprintf(m,"%%d\n",c); fclose(m); }
            fns[c](st, res);
            fwrite(res, 1, STATE, out);
        }
        ++n;
    }
    fprintf(stderr, "reference: %%ld states x %%d cases\n", n, NCASE);
    fclose(in); fclose(out); return 0;
}
'''

# -------------------------------------------------------------- the port side
class Ctx(object):
    """The slice of elf2c's context that IRToC needs for register-only code.

    A vector instruction touches no memory and no call targets, so everything
    address-related is a hard error here rather than a silent approximation.
    """
    pc_offset = 272
    def __init__(self):
        self.notes = []
    def const_addr(self, v, ty=None):
        return None
    def const_is_immediate_data(self, insn, v):
        return True
    def disasm(self, addr, length):
        return ''
    def in_rx(self, v):
        return False
    def fp_minmax_is_nm(self, insn_addr):
        # The test lifts one instruction at a time, so the encoding under test
        # is the only one there is; vecref sets it before translating.
        return CUR_IS_NM[0]
    def fp_is_fused_mac(self, insn_addr):
        return CUR_IS_FMA[0]
    def goto_or_call(self, *a, **k):
        raise UnsupportedIR('goto_or_call', 'not expected in a vector test')
    def need_simd(self, *a): pass
    def need_simd_cat(self, *a): pass
    def need_simd_cmp(self, *a): pass
    def need_simd_fp(self, *a): pass
    def need_simd_fma(self, *a): pass
    def need_simd_interleave(self, *a): pass
    def need_simd_minmax(self, *a): pass
    def need_simd_neg(self, *a): pass
    def need_simd_shift(self, *a): pass
    def need_simd_varshift(self, *a): pass


def gen_port_c(cases):
    ctx = Ctx()
    arch = archinfo.ArchAArch64()
    bodies, names, bad = [], [], []
    for i, (_n, enc, txt) in enumerate(cases):
        CUR_IS_NM[0] = txt.split()[0] in ('fmaxnm', 'fminnm')
        CUR_IS_FMA[0] = txt.split()[0] in FMA_MNEMONICS
        irsb = pyvex.lift(enc + b'\xc0\x03\x5f\xd6', 0x71000000, arch, opt_level=0)
        out, tr = [], None
        try:
            tr = IRToC(ctx, irsb, out)
            for s in irsb.statements:
                if type(s).__name__ == 'IMark' and s.addr != 0x71000000:
                    break            # stop before the trailing `ret`
                tr.stmt(s)
        except UnsupportedIR as ex:
            bad.append((txt, str(ex)))
            names.append(None)
            continue
        decls = ''.join('    %s\n' % d.strip() for d in tr.declare_temps())
        bodies.append('static void vt_%d(cpu_t *cpu) {\n%s%s\n}\n'
                      % (i, decls, '\n'.join(out)))
        names.append('vt_%d' % i)
    return bodies, names, bad


PORT_MAIN = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "guest_core.h"
/* guest_rt.c refers to the image arrays and to the dispatch table.  A
   register-only vector test touches neither, so minimal definitions satisfy
   the linker without pulling in the 1.3 GB tree. */
const uint8_t g_ro[1] = {0};
g_rw_slot g_rw[1];
/* guest_fini() reclaims the setjmp side table from guest_va.c, which this
   harness does not link; it never runs guest code, so a stub is enough. */
void guest_jb_reset(void) {}
#define STATE %d
#define NCASE %d
#define OFF_X %d
#define OFF_F %d
#define OFF_SCR %d
#define OFF_SPD %d
#define SP_BIAS %d
%s
typedef void (*fn_t)(cpu_t *);
static const fn_t fns[NCASE] = { %s };
int main(int argc, char **argv){
    FILE *in = fopen(argv[1], "rb"), *out = fopen(argv[2], "wb");
    unsigned char *st = malloc(STATE), *res = malloc(STATE);
    long n = 0;
    while (fread(st, 1, STATE, in) == STATE) {
        for (int c = 0; c < NCASE; ++c) {
            memcpy(res, st, STATE);
            if (fns[c]) {
                cpu_t cpu; memset(&cpu, 0, sizeof(cpu));
                memcpy(cpu.g + %d, st, 32*16);              /* q0..q31 */
                memcpy(cpu.g + %d, st + OFF_X, 26*8);       /* x0..x25 */
                /* sp addresses the scratch area of `res`, as in the stub. */
                *(uint64_t *)(cpu.g + 264) =
                    (uint64_t)(uintptr_t)(res + OFF_SCR + SP_BIAS);
                *(uint64_t *)(cpu.g + %d) = ARM64G_CC_OP_COPY;
                *(uint64_t *)(cpu.g + %d) = *(uint64_t *)(st + OFF_F);
                *(uint64_t *)(cpu.g + %d) = 0;
                *(uint64_t *)(cpu.g + %d) = 0;
                fns[c](&cpu);
                memcpy(res, cpu.g + %d, 32*16);
                memcpy(res + OFF_X, cpu.g + %d, 26*8);
                *(int64_t *)(res + OFF_SPD) =
                    (int64_t)(*(uint64_t *)(cpu.g + 264)
                              - (uint64_t)(uintptr_t)(res + OFF_SCR + SP_BIAS));
                *(uint64_t *)(res + OFF_F) = arm64g_calculate_flags_nzcv(
                    *(uint64_t *)(cpu.g + %d), *(uint64_t *)(cpu.g + %d),
                    *(uint64_t *)(cpu.g + %d), *(uint64_t *)(cpu.g + %d))
                    & UINT64_C(0xf0000000);
            }
            fwrite(res, 1, STATE, out);
        }
        ++n;
    }
    fprintf(stderr, "port: %%ld states x %%d cases\n", n, NCASE);
    fclose(in); fclose(out); return 0;
}
'''


def main():
    print('%d testable forms (%d skipped)' % (len(cases), len(skipped)))
    for k, why in skipped:
        print('   skipped %-10s %-40s %s' % (k[0], k[1], why))

    # --- the shared inputs -------------------------------------------------
    rnd = random.Random(20260906)
    blob = bytearray()
    for k in range(NINPUT):
        st = bytearray(STATE)
        for i in range(0, OFF_X, 8):
            # A mix of small integers, float-shaped words and full-range noise:
            # a pure-random vector never exercises a comparison's equal case.
            pick = rnd.randrange(4)
            v = (0 if pick == 0 else
                 rnd.randrange(0, 8) if pick == 1 else
                 struct.unpack('<Q', struct.pack('<dd' if False else '<d',
                     rnd.uniform(-1e3, 1e3)))[0] if pick == 2 else
                 rnd.getrandbits(64))
            struct.pack_into('<Q', st, i, v)
        for i in range(NX):
            struct.pack_into('<Q', st, OFF_X + i * 8,
                             rnd.getrandbits(64) if rnd.randrange(2) else
                             rnd.randrange(0, 8))
        struct.pack_into('<Q', st, OFF_F, rnd.randrange(16) << 28)
        for i in range(OFF_SCR, OFF_SPD, 8):
            struct.pack_into('<Q', st, i, rnd.getrandbits(64))
        blob += st
    open(os.path.join(WORK, 'in.bin'), 'wb').write(bytes(blob))

    # --- reference ---------------------------------------------------------
    open(os.path.join(WORK, 'ref.S'), 'w').write(gen_ref_asm(cases))
    decls = '\n'.join('void vt_%d(const unsigned char *, unsigned char *);' % i
                      for i in range(len(cases)))
    tbl = ', '.join('vt_%d' % i for i in range(len(cases)))
    open(os.path.join(WORK, 'ref.c'), 'w').write(
        REF_MAIN % (STATE, len(cases), decls, tbl))
    subprocess.check_call(['aarch64-linux-gnu-gcc', '-O1', '-static', '-o',
                           os.path.join(WORK, 'ref'),
                           os.path.join(WORK, 'ref.c'),
                           os.path.join(WORK, 'ref.S')])
    mark = os.path.join(WORK, 'mark')
    try:
        subprocess.check_call(['qemu-aarch64', os.path.join(WORK, 'ref'),
                               os.path.join(WORK, 'in.bin'),
                               os.path.join(WORK, 'ref.out'), mark])
    except subprocess.CalledProcessError:
        c = int(open(mark).read().strip())
        print('reference crashed in case %d: %s' % (c, cases[c][2]))
        raise

    # --- port --------------------------------------------------------------
    bodies, names, bad = gen_port_c(cases)
    for txt, why in bad:
        print('   NOT TRANSLATED  %-40s %s' % (txt, why))
    tbl = ', '.join(n if n else '0' for n in names)
    open(os.path.join(WORK, 'port.c'), 'w').write(
        PORT_MAIN % (STATE, len(cases), OFF_X, OFF_F, OFF_SCR, OFF_SPD, SP_BIAS,
                     '\n'.join(bodies), tbl,
                     G_Q0, G_X0, G_CCOP, G_D1, G_D2, G_ND,
                     G_Q0, G_X0, G_CCOP, G_D1, G_D2, G_ND))
    subprocess.check_call(['gcc', '-I%s/include' % OUTDIR, '-I.', '-O1',
                           '-std=c11', '-mavx2', '-fno-strict-aliasing',
                           '-o', os.path.join(WORK, 'port'),
                           os.path.join(WORK, 'port.c'),
                           '%s/src/helpers.c' % OUTDIR,
                           'runtime/guest_rt.c', '-lm'])
    subprocess.check_call([os.path.join(WORK, 'port'),
                           os.path.join(WORK, 'in.bin'),
                           os.path.join(WORK, 'port.out')])

    # --- compare -----------------------------------------------------------
    R = open(os.path.join(WORK, 'ref.out'), 'rb').read()
    P = open(os.path.join(WORK, 'port.out'), 'rb').read()
    ncase, bad_cases, tested = len(cases), {}, 0
    for k in range(NINPUT):
        for c in range(ncase):
            if names[c] is None:
                continue
            off = (k * ncase + c) * STATE
            if R[off:off + STATE] != P[off:off + STATE]:
                bad_cases.setdefault(cases[c][2], []).append((k, off))
    tested = sum(1 for n in names if n)
    print('\n%d instruction forms executed, %d states each' % (tested, NINPUT))
    if not bad_cases:
        print('MATCH: every form agrees with the hardware semantics')
        return 0
    print('MISMATCH in %d forms:' % len(bad_cases))
    for txt, hits in sorted(bad_cases.items()):
        k, off = hits[0]
        r, p = R[off:off + STATE], P[off:off + STATE]
        diffs = []
        for q in range(NQ):
            if r[q*16:q*16+16] != p[q*16:q*16+16]:
                diffs.append('q%d ref=%s port=%s' % (q, r[q*16:q*16+16].hex(),
                                                     p[q*16:q*16+16].hex()))
        for x in range(NX):
            a, b = OFF_X + x*8, OFF_X + x*8 + 8
            if r[a:b] != p[a:b]:
                diffs.append('x%d ref=%s port=%s' % (x, r[a:b].hex(), p[a:b].hex()))
        if r[OFF_F:OFF_F+8] != p[OFF_F:OFF_F+8]:
            diffs.append('nzcv ref=%s port=%s'
                         % (r[OFF_F:OFF_F+8].hex(), p[OFF_F:OFF_F+8].hex()))
        if r[OFF_SCR:OFF_SPD] != p[OFF_SCR:OFF_SPD]:
            for o in range(OFF_SCR, OFF_SPD, 8):
                if r[o:o+8] != p[o:o+8]:
                    diffs.append('scr%+d ref=%s port=%s'
                                 % (o - OFF_SCR - SP_BIAS, r[o:o+8].hex(), p[o:o+8].hex()))
        if r[OFF_SPD:] != p[OFF_SPD:]:
            diffs.append('sp-delta ref=%s port=%s'
                         % (r[OFF_SPD:].hex(), p[OFF_SPD:].hex()))
        print('  %-44s %d/%d states; first: %s'
              % (txt, len(hits), NINPUT, '; '.join(diffs[:3])))
    return 1


if __name__ == '__main__':
    sys.exit(main())
