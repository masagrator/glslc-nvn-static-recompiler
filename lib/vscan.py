#!/usr/bin/env python3
"""vscan.py -- inventory of the SIMD instruction forms this binary actually uses.

The condition-code helpers have had a differential test (ccref.py) since early
on; the vector helpers never did, which is how a swapped-argument
InterleaveLO/HI survived.  vecref.py tests them -- this script tells it WHAT to
test, by canonicalising every vector instruction in .text into a
(mnemonic, operand shape) form and keeping one real example of each.
"""
import capstone, collections, re, pickle, sys

argv = [a for a in sys.argv[1:] if not a.startswith('--')]
ELF = argv[0] if len(argv) > 0 else 'glslc.elf'
OUT = argv[1] if len(argv) > 1 else '/tmp/vforms.pkl'
OFF, SIZE = 0x2848, 0x601d50          # the single executable LOAD segment

data = open(ELF, 'rb').read()[OFF:OFF + SIZE]
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
VEC = re.compile(r'\b[vqdshb]\d+\b')
# --all also inventories the SCALAR forms.  The vector filter was there because
# the helpers were the suspect; a missing 32->64 sign extension in ordinary
# integer code is just as translatable-wrong, and vecref.py runs any encoding.
ALL = '--all' in sys.argv

forms, rep = collections.Counter(), {}
pos = 0
while pos < SIZE:
    got = False
    for ins in md.disasm(data[pos:], pos):
        got = True
        pos = ins.address + 4
        ops = ins.op_str
        if not ALL and not VEC.search(ops):
            continue
        # A memory operand needs an address to be meaningful, so those forms
        # are inventoried but not testable register-only; keep them separate.
        if re.search(r'\[[wx]?\d', ops) and not re.search(r'\.\w+\[\d+\]', ops):
            key = (ins.mnemonic, 'MEM')
        else:
            shape = re.sub(r'\b([vqdshb])\d+\b', r'\1N', ops)
            shape = re.sub(r'\b([wx])\d+\b', r'\1N', shape)
            shape = re.sub(r'#0x[0-9a-f]+', '#i', shape)
            shape = re.sub(r'#-?\d+(\.\d+)?(e[+-]?\d+)?', '#i', shape)
            key = (ins.mnemonic, shape)
        forms[key] += 1
        # Keep several examples, not one: vecref.py runs the instruction with
        # x27/x28 holding its in/out pointers, so it needs the freedom to pick
        # an example that does not touch them.
        cands = rep.setdefault(key, [])
        if len(cands) < 8:
            cands.append((ins.address, ins.mnemonic, ins.op_str,
                          data[ins.address:ins.address + 4]))
    if not got:
        pos += 4          # udf / literal padding: skip one word and resume

pickle.dump((forms, rep), open(OUT, 'wb'))
nmem = sum(1 for k in forms if k[1] == 'MEM')
print(f'{len(forms)} distinct vector forms, {sum(forms.values())} instructions; '
      f'{nmem} of the forms take a memory operand')
for k, v in forms.most_common():
    if k[1] != 'MEM':
        print('%8d  %-12s %s' % (v, k[0], k[1]))
