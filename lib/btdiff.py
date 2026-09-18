#!/usr/bin/env python3
"""btdiff.py -- positional diff of the two hard-target sequences.

  usage: btdiff.py <ref.u32> <port.u32> [context]

The runs do NOT start together: the reference executes the four .init_array
constructors and lazy PLT binding that the port skips (REFERENCE-DIFFING sec.8.3).
So both sides are aligned on a SYNC ADDRESS -- one that occurs exactly once in
each sequence -- and compared positionally from there, which is exact.
"""
import sys, array, collections

LIMIT = 0x601000   # must match htrace.LIMIT: the PLT and above is not compared

def load(p):
    a = array.array('I')
    with open(p, 'rb') as f:
        a.frombytes(f.read())
    # htrace.py drops >= LIMIT on the reference side; the port emits those
    # blocks (they exist in its tree), so drop them here too or every PLT
    # thunk shows as a bogus divergence.
    return array.array('I', [v for v in a if v < LIMIT])

ref, port = load(sys.argv[1]), load(sys.argv[2])
CTX = int(sys.argv[3]) if len(sys.argv) > 3 else 12
print(f'ref {len(ref)} entries, port {len(port)} entries')

cr, cp = collections.Counter(ref), collections.Counter(port)
once = [a for a in cr if cr[a] == 1 and cp.get(a) == 1]
if not once:
    sys.exit('no address occurs exactly once in both sequences: cannot align')
# The EARLIEST such address in the port gives the longest comparable region.
ri = {a: i for i, a in enumerate(ref)}
pi = {a: i for i, a in enumerate(port)}
sync = min(once, key=lambda a: pi[a])
r0, p0 = ri[sync], pi[sync]
print(f'sync on 0x{sync:x}: ref index {r0}, port index {p0} '
      f'({len(ref)-r0} vs {len(port)-p0} entries after it)')

n = min(len(ref) - r0, len(port) - p0)
for k in range(n):
    if ref[r0 + k] != port[p0 + k]:
        print(f'\nfirst divergence at aligned index {k} '
              f'(ref {r0+k}, port {p0+k})')
        lo = max(0, k - CTX)
        for j in range(lo, min(n, k + CTX + 1)):
            mark = '  ' if ref[r0 + j] == port[p0 + j] else '<<'
            print(f'  {j:>10} ref 0x{ref[r0+j]:08x}   port 0x{port[p0+j]:08x} {mark}')
        break
else:
    print(f'\nno divergence in {n} compared entries '
          f'(tail: ref {len(ref)-r0-n}, port {len(port)-p0-n})')
