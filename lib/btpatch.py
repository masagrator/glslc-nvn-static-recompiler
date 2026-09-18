#!/usr/bin/env python3
"""btpatch.py -- instrument every HARD-TARGET block of the generated tree, so
the port emits the same ordered sequence htrace.py extracts from the QEMU log.
The hard-target rule itself is imported from htrace.py: one copy, so the two
sequences are guaranteed to be built from the same definition.

  usage: btpatch.py <outdir> <glslc.elf> [base]   add the probes
         btpatch.py <outdir> --revert             remove them again

Idempotent -- a label that already carries a probe is left alone.  Patching a
tree twice silently doubles every count (REFERENCE-DIFFING.md sec.8.4), so the
guard matters.  Prints the list of files it changed to <outdir>/btrace.list,
but rebuild from `grep -rl` rather than that list: a run that changes nothing
because the tree is ALREADY instrumented writes an empty list, and rebuilding
from it compiles nothing while the archive keeps stale objects.
"""
import sys, os, re, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

OUT = sys.argv[1]
FILES = sorted(glob.glob(os.path.join(OUT, 'src', 'fn', '*.c')))
DECL = 'extern uint32_t *g_bp2, *g_bp2_end;   /* btpatch.py */\n'
PROBE_RE = re.compile(r'^    if \(g_bp2 < g_bp2_end\) \*g_bp2\+\+ = ')
LABEL_RE = re.compile(r'^L_([0-9a-f]+): \{$')

if len(sys.argv) > 2 and sys.argv[2] == '--revert':
    n = 0
    for p in FILES:
        src = open(p).read()
        if 'g_bp2' not in src:
            continue
        open(p, 'w').write(''.join(
            l for l in src.splitlines(True)
            if not PROBE_RE.match(l) and l != DECL))
        n += 1
    print('reverted', n, 'files')
    raise SystemExit(0)

import htrace
htrace.load_elf(sys.argv[2])
BASE = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x7100000000

changed, sites = [], 0
for p in FILES:
    lines = open(p).read().splitlines(True)
    out, hit, i = [], False, 0
    while i < len(lines):
        out.append(lines[i])
        m = LABEL_RE.match(lines[i])
        if m:
            va = int(m.group(1), 16) - BASE
            # A probe already sitting on this label means the tree is patched.
            already = (i + 1 < len(lines) and PROBE_RE.match(lines[i + 1]))
            if not already and 0 <= va < (1 << 32) and htrace.is_hard(va):
                out.append('    if (g_bp2 < g_bp2_end) *g_bp2++ = UINT32_C(0x%x);\n' % va)
                hit = True
                sites += 1
        i += 1
    if hit:
        if DECL not in out:
            for j, l in enumerate(out):
                if l.startswith('#include'):
                    out.insert(j + 1, DECL)
                    break
        open(p, 'w').write(''.join(out))
        changed.append(p)

with open(os.path.join(OUT, 'btrace.list'), 'w') as f:
    f.write('\n'.join(changed) + ('\n' if changed else ''))
print(f'{len(changed)} files patched, {sites} probe sites')
