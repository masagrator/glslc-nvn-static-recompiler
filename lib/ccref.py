"""
ccref.py -- an independent reference for AArch64 NZCV and condition results.

Written straight from the architecture's definitions (result computed at the
operation's own width, N = sign bit, Z = result zero, C = carry out of the
top bit, V = signed overflow) rather than from the runtime's structure, so a
disagreement points at a real bug instead of a shared assumption.

Used by cctest.sh to cross-check runtime/guest_rt.c.
"""

import random
import subprocess
import sys

COPY, ADD32, ADD64, SUB32, SUB64, ADC32, ADC64, SBC32, SBC64, LOGIC32, LOGIC64 = range(11)

W32 = (1 << 32) - 1
W64 = (1 << 64) - 1

OPS = {
    ADD32: (32, 'add'), ADD64: (64, 'add'),
    SUB32: (32, 'sub'), SUB64: (64, 'sub'),
    ADC32: (32, 'adc'), ADC64: (64, 'adc'),
    SBC32: (32, 'sbc'), SBC64: (64, 'sbc'),
    LOGIC32: (32, 'logic'), LOGIC64: (64, 'logic'),
}


def flags(op, d1, d2, d3):
    """Return (N, Z, C, V) for one CC op."""
    if op == COPY:
        return ((d1 >> 31) & 1, (d1 >> 30) & 1, (d1 >> 29) & 1, (d1 >> 28) & 1)

    width, kind = OPS[op]
    mask = W32 if width == 32 else W64
    sign = 1 << (width - 1)

    a = d1 & mask
    b = d2 & mask
    carry = (d3 & 1) if kind in ('adc', 'sbc') else None

    if kind == 'add':
        full = a + b
    elif kind == 'adc':
        full = a + b + carry
    elif kind == 'sub':
        full = a + ((~b) & mask) + 1
    elif kind == 'sbc':
        full = a + ((~b) & mask) + carry
    else:                       # logic
        full = a

    res = full & mask
    n = 1 if res & sign else 0
    z = 1 if res == 0 else 0
    if kind == 'logic':
        c = 0
        v = 0
    else:
        c = 1 if full > mask else 0
        if kind in ('add', 'adc'):
            v = 1 if ((a ^ res) & (b ^ res) & sign) else 0
        else:
            nb = (~b) & mask
            v = 1 if ((a ^ res) & (nb ^ res) & sign) else 0
    return (n, z, c, v)


def condition(cond, op, d1, d2, d3):
    n, z, c, v = flags(op, d1, d2, d3)
    base = cond >> 1
    inv = cond & 1
    if base == 0:   r = z                       # EQ
    elif base == 1: r = c                       # CS
    elif base == 2: r = n                       # MI
    elif base == 3: r = v                       # VS
    elif base == 4: r = c & (1 - z)             # HI
    elif base == 5: r = 1 if n == v else 0      # GE
    elif base == 6: r = 1 if (z == 0 and n == v) else 0   # GT
    else:           return 1                    # AL / NV
    return r ^ inv


def main():
    binary = sys.argv[1]
    random.seed(11)
    cases = []
    interesting = [0, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff,
                   0x100000000, 0x7fffffffffffffff, 0x8000000000000000,
                   W64, W64 - 1, 0xfffffffc, 4]
    for op in OPS:
        for a in interesting:
            for b in interesting:
                for d3 in (0, 1):
                    for cond in range(14):
                        cases.append((op, a, b, d3, cond))
    for _ in range(20000):
        cases.append((random.choice(list(OPS)),
                      random.getrandbits(64), random.getrandbits(64),
                      random.getrandbits(1), random.randrange(14)))

    stdin = '\n'.join('%d %d %d %d %d' % c for c in cases) + '\n'
    out = subprocess.run([binary], input=stdin, capture_output=True,
                         text=True, check=True).stdout.split('\n')

    bad = 0
    for case, line in zip(cases, out):
        if not line.strip():
            continue
        got = tuple(int(x) for x in line.split())
        op, a, b, d3, cond = case
        want = flags(op, a, b, d3) + (condition(cond, op, a, b, d3),)
        if got != want:
            bad += 1
            if bad <= 10:
                print('MISMATCH op=%d a=%#x b=%#x c=%d cond=%d: got %s want %s'
                      % (op, a, b, d3, cond, got, want))
    print('%d cases, %d mismatches' % (len(cases), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
