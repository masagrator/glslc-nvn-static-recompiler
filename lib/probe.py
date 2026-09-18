#!/usr/bin/env python3
"""probe.py -- put an fprintf at the head of a generated guest block, and relink.

HANDOVER.md sec.25.8 describes doing this by hand with one `sed`.  This is the
same trick made repeatable, because every divergence hunt needs it and the
hand-written version has to be retyped (and mistyped) each time.

    probe.py OUT LABEL "fmt" x19 x0 ...        # print guest registers
    probe.py OUT LABEL --deref x19:0x20:u32    # print *(u32*)(x19+0x20)

The generated bodies are `static` and built -g0, so a guest BLOCK has no
symbol and gdb cannot break on one.  The way in is a one-line source overlay
LINKED AHEAD OF THE ARCHIVE: the overlay object defines the same function, the
linker takes it and never pulls the archive member, and the archive itself is
never rewritten.  The link costs ~12 s against a 476 MB archive, so this is a
fast edit/run loop.

Register offsets are the VEX guest-state layout baked into the tree:
x<n> is GST_I64(16 + 8*n), sp is GST_I64(264).
"""
import os, re, sys

def reg_off(name):
    if name == 'sp':
        return 264
    m = re.fullmatch(r'x(\d+)', name)
    if not m:
        raise SystemExit('probe.py: not a register: %s' % name)
    n = int(m.group(1))
    if n > 30:
        raise SystemExit('probe.py: x%d out of range' % n)
    return 16 + 8 * n

def find_file(out, label):
    """The generated file that DEFINES this label.

    Every block label appears once as a definition (`L_...: {`) and possibly
    many times as a `goto`, so match the definition form only.
    """
    want = re.compile(r'^\s*%s:\s*\{' % re.escape(label), re.M)
    for root, _dirs, files in os.walk(os.path.join(out, 'src')):
        for f in files:
            if not f.endswith('.c'):
                continue
            p = os.path.join(root, f)
            with open(p, 'r', errors='replace') as fh:
                if want.search(fh.read()):
                    return p
    raise SystemExit('probe.py: no file defines %s' % label)

def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    out, label = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]

    fmt = [label]
    vals = []
    for a in args:
        if ':' in a:
            # reg:offset:type -- a field of the object a register points at
            r, off, ty = a.split(':')
            cty = {'u32': 'unsigned int', 'i32': 'int',
                   'u64': 'unsigned long long', 'p': 'unsigned long long'}[ty]
            spec = {'u32': '%u', 'i32': '%d',
                    'u64': '%llu', 'p': '0x%llx'}[ty]
            fmt.append('%s+%s=%s' % (r, off, spec))
            vals.append('(%s)*(%s*)(uintptr_t)(GST_I64(%d)+%s)'
                        % ('unsigned long long' if ty in ('u64', 'p') else cty,
                           cty, reg_off(r), off))
        else:
            fmt.append('%s=0x%%llx' % a)
            vals.append('(unsigned long long)GST_I64(%d)' % reg_off(a))

    src = find_file(out, label)
    ovdir = os.path.join(out, 'ov')
    os.makedirs(ovdir, exist_ok=True)
    dst = os.path.join(ovdir, os.path.basename(src))

    call = ('fprintf(stderr, "PROBE %s\\n", %s);'
            % (' '.join(fmt), ', '.join(vals)) if vals else
            'fprintf(stderr, "PROBE %s\\n");' % ' '.join(fmt))

    text = open(src, 'r', errors='replace').read()
    pat = re.compile(r'^(\s*%s:\s*\{)' % re.escape(label), re.M)
    new, n = pat.subn(lambda m: m.group(1) + ' ' + call, text, count=1)
    if n != 1:
        raise SystemExit('probe.py: failed to patch %s in %s' % (label, src))
    # stdio is not otherwise included by a generated file.
    new = '#include <stdio.h>\n#include <stdint.h>\n' + new
    open(dst, 'w').write(new)
    print('overlay: %s  (from %s)' % (dst, src))
    return dst

if __name__ == '__main__':
    main()
