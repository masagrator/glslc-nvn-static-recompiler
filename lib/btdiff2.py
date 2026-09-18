#!/usr/bin/env python3
"""btdiff2.py -- diff the two hard-target sequences WITH RESYNCHRONISATION.

btdiff.py stops at the first mismatch.  That is not enough: the guest hashes
some maps BY POINTER (0x809a40 is `(p>>12)^p`, 0x809b20 is `p0-p1`), and the
two runs have different heaps, so their probe sequences legitimately differ.
REFERENCE-DIFFING.md sec.5 already warns that raw pointers are not comparable;
this is that warning showing up inside an otherwise exact comparison.

So: find EVERY divergence region, resynchronise after each, and report them.
A benign one is short and re-syncs immediately; a real one does not.

  usage: btdiff2.py <ref.u32> <port.u32> [max-regions] [window] [confirm]
"""
import os
import sys, array, collections

# Both sides are already restricted to translated addresses -- htrace.py drops
# anything at or above the PLT, and the port only has probes in code it
# translated -- so no second filter is needed here.  It was a hard-coded
# 0x601000, glslc.elf's PLT; on a binary whose text ends at 0x1136900 that
# silently threw away 80% of BOTH sequences and then "resynchronised" on an
# address pair that has nothing to do with each other.  Kept as an override
# for the case where a caller really does want to cut the tail off.
LIMIT = int(os.environ.get('BTDIFF_LIMIT', '0'), 0) or (1 << 32)
SYNC_K = 32               # entries that must match to call it resynchronised

def load(p):
    a = array.array('I')
    with open(p, 'rb') as f:
        a.frombytes(f.read())
    return array.array('I', [v for v in a if v < LIMIT])

ref, port = load(sys.argv[1]), load(sys.argv[2])
MAXREG = int(sys.argv[2 + 1]) if len(sys.argv) > 3 else 40
WINDOW = int(sys.argv[4]) if len(sys.argv) > 4 else 4000
print(f'ref {len(ref)} entries, port {len(port)} entries')

cr, cp = collections.Counter(ref), collections.Counter(port)
once = [a for a in cr if cr[a] == 1 and cp.get(a) == 1]
if not once:
    sys.exit('no address occurs exactly once in both: cannot align')
ri = {a: i for i, a in enumerate(ref)}
pi = {a: i for i, a in enumerate(port)}
sync = min(once, key=lambda a: pi[a])
i, j = ri[sync], pi[sync]
print(f'sync on 0x{sync:x}: ref {i}, port {j}')

def matches(i, j):
    if i + SYNC_K > len(ref) or j + SYNC_K > len(port):
        return False
    return ref[i:i + SYNC_K] == port[j:j + SYNC_K]

regions = 0
while i < len(ref) and j < len(port):
    if ref[i] == port[j]:
        i += 1; j += 1
        continue
    start_i, start_j = i, j
    # Bounded two-dimensional search for the nearest resynchronisation point.
    found = None
    for d in range(1, WINDOW):
        for a, b in ((start_i + d, start_j), (start_i, start_j + d),
                     (start_i + d, start_j + d)):
            if matches(a, b):
                found = (a, b)
                break
        if found:
            break
    regions += 1
    if found:
        ni, nj = found
        print(f'\n#{regions} ref[{start_i}:{ni}] ({ni-start_i}) vs '
              f'port[{start_j}:{nj}] ({nj-start_j})')
        print('   ref  ' + ' '.join('%06x' % v for v in ref[start_i:min(ni, start_i+12)]))
        print('   port ' + ' '.join('%06x' % v for v in port[start_j:min(nj, start_j+12)]))
        i, j = ni, nj
    else:
        print(f'\n#{regions} ref[{start_i}] vs port[{start_j}]: '
              f'NO RESYNC within {WINDOW} -- runs have genuinely parted')
        print('   ref  ' + ' '.join('%06x' % v for v in ref[start_i:start_i+16]))
        print('   port ' + ' '.join('%06x' % v for v in port[start_j:start_j+16]))
        break
    if regions >= MAXREG:
        print(f'\n... stopping after {MAXREG} regions')
        break
print(f'\ntotal regions reported: {regions}; '
      f'ended at ref {i}/{len(ref)}, port {j}/{len(port)}')
