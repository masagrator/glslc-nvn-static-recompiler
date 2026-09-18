#!/usr/bin/env python3
"""htrace.py -- build the REFERENCE hard-target sequence from a QEMU exec log.

See REFERENCE-DIFFING.md sec.8.  A block whose PRECEDING instruction is an
unconditional `b`, `br`, `ret` or a trap cannot be entered by falling through,
so QEMU must start a translation block there every time it executes.  Restricted
to those, the reference TB sequence and the port block sequence are the SAME
sequence and a positional diff is exact.

  usage: htrace.py <qemu-exec-log> <binary.elf> <out.u32>

BASE (where ld.so mapped the library) and LIMIT (the first address that is not
translated -- the PLT, and libc and ld.so beyond it) used to be constants for
one binary.  They are derived from the log and the ELF now, because a second
version of the library maps somewhere else and has its PLT somewhere else, and
a wrong constant here does not fail -- it silently produces a sequence of the
wrong addresses.  Override with HTRACE_BASE / HTRACE_LIMIT if a run ever needs
it.
"""
import os, sys, struct, array, re

BASE = None                      # detected from the log; see detect_base()
LIMIT = None                     # taken from the ELF; see elf_limit()

# --- ELF image, so the instruction BEFORE an address can be decoded ---------
# load_elf() is imported by btpatch.py, which needs the SAME hard-target rule
# on the port side; keeping one copy is what makes the two sequences comparable.
segs = []
elf = b''

exec_span = (0, 0)      # (vaddr, memsz) of the executable LOAD segment


def load_elf(path):
    global elf, segs, exec_span
    elf = open(path, 'rb').read()
    segs = []
    e_phoff = struct.unpack_from('<Q', elf, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from('<HH', elf, 0x36)
    for i in range(e_phnum):
        p_type, fl, off, va, _pa, fsz, msz, _al = struct.unpack_from(
            '<IIQQQQQQ', elf, e_phoff + i * e_phentsize)
        if p_type == 1:
            segs.append((va, va + fsz, off))
            if fl & 1:
                exec_span = (va, msz)

def word_at(va):
    for lo, hi, off in segs:
        if lo <= va and va + 4 <= hi:
            return struct.unpack_from('<I', elf, off + va - lo)[0]
    return None

def is_hard(va):
    """True when va cannot be reached by falling through."""
    if va < 4:
        return False
    w = word_at(va - 4)
    if w is None:
        return False
    if w == 0:                       # padding
        return True
    if (w >> 26) == 0b000101:        # b  (unconditional immediate branch)
        return True
    if (w & 0xFFFFFC1F) == 0xD65F0000:   # ret
        return True
    if (w & 0xFFFFFC1F) == 0xD61F0000:   # br
        return True
    if (w >> 24) == 0xD4:            # brk/svc/hlt traps
        return True
    return False

def elf_limit(path):
    """First address that is NOT part of what the port translates.

    That is the PLT: every stub in it belongs to an import, and the generated
    tree replaces those with thunks rather than translating them.  Read from
    the section header when there is one, and otherwise from the end of the
    executable segment, which is a safe over-estimate -- an address above the
    real limit simply never appears in the port's sequence, so it can only
    add entries the diff will report, never hide one.
    """
    data = open(path, 'rb').read()
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3A)
    if e_shoff and e_shnum:
        sh = lambda i: struct.unpack_from('<IIQQQQIIQQ', data,
                                          e_shoff + i * e_shentsize)
        _, _, _, _, str_off, _, _, _, _, _ = sh(e_shstrndx)
        for i in range(e_shnum):
            nameoff, _t, _f, addr, _off, _sz, _l, _i, _a, _e = sh(i)
            end = data.index(b'\0', str_off + nameoff)
            if data[str_off + nameoff:end] == b'.plt' and addr:
                return addr
    hi = 0
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    for i in range(e_phnum):
        p_type, fl, _off, va, _pa, _fsz, msz, _al = struct.unpack_from(
            '<IIQQQQQQ', data, e_phoff + i * e_phentsize)
        if p_type == 1 and (fl & 1):
            hi = max(hi, va + msz)
    return hi


def base_from_pagemap(path, text_size):
    """The library's load address, read out of QEMU's own page map.

    `qemu-aarch64 -d page` prints the memory map every time it changes; the
    library is the r-x range whose size is the executable segment rounded up
    to a page.  This is the EXACT answer, and it is worth capturing the page
    map for: getting the base wrong does not fail, it shifts every address,
    and the diff then reports nonsense at entry zero.
    """
    # The r-x mapping is the EXECUTABLE segment, not the whole image: matching
    # against the image size found nothing and silently fell through to the
    # heuristic, which then picked the executable's own base.
    want = (text_size + 0xFFF) & ~0xFFF
    pat = re.compile(rb'^([0-9a-f]{8,16})-([0-9a-f]{8,16}) ([0-9a-f]{8,16}) r-x')
    best = None
    with open(path, 'rb') as f:
        for line in f:
            m = pat.match(line)
            if not m:
                continue
            lo, _hi, size = (int(g, 16) for g in m.groups())
            if size == want:
                best = lo
    return best


def detect_base(addrs, text_size):
    """Fallback when the log has no page map: score candidate bases.

    The right base is the one under which the most DISTINCT addresses both
    land inside the text and pass the hard-target test -- a shifted base makes
    most addresses point into the middle of an instruction, where the
    preceding word does not decode as a branch.  The first version of this
    took the lowest address in the busiest region instead, which picked the
    EXECUTABLE's base rather than the library's (they are 0x56000 apart under
    QEMU) and produced two sequences with 403 addresses in common out of
    11,000.
    """
    if not addrs:
        return 0
    from collections import Counter
    pages = Counter(a & ~0xFFF for a in addrs)
    cands = [b for b, _ in pages.most_common(512)]
    cands += [min(addrs) & ~0xFFF]
    sample = list(set(addrs))
    if len(sample) > 4000:
        sample = sample[::max(1, len(sample) // 4000)]
    best, best_score = 0, -1
    uniq = sample
    for b in sorted(set(cands)):
        score = 0
        for a in uniq:
            v = a - b
            if 0 <= v < text_size and is_hard(v):
                score += 1
        if score > best_score:
            best, best_score = b, score
    return best


hard, soft = set(), set()
def hard_target(va):
    if va in hard:
        return True
    if va in soft:
        return False
    (hard if is_hard(va) else soft).add(va)
    return va in hard

# --- scan the log ----------------------------------------------------------
def main():
    global BASE, LIMIT
    LOGP, ELFP, OUTP = sys.argv[1], sys.argv[2], sys.argv[3]
    load_elf(ELFP)

    LIMIT = int(os.environ.get('HTRACE_LIMIT', '0'), 0) or elf_limit(ELFP)
    text_size = max(hi for _lo, hi, _o in segs)

    pat = re.compile(rb'/([0-9a-f]{16})/')

    if os.environ.get('HTRACE_BASE'):
        BASE = int(os.environ['HTRACE_BASE'], 0)
    elif base_from_pagemap(LOGP, exec_span[1]) is not None:
        BASE = base_from_pagemap(LOGP, exec_span[1])
    else:
        # One pass to find the base, one to build the sequence.  Reading the
        # log twice costs less than getting the base wrong.
        seen = []
        with open(LOGP, 'rb') as f:
            for line in f:
                m = pat.search(line)
                if m:
                    seen.append(int(m.group(1), 16))
        BASE = detect_base(seen, text_size)
        del seen
    print('base=%#x limit=%#x' % (BASE, LIMIT))

    out = array.array('I')
    n = 0
    with open(LOGP, 'rb') as f:
        for line in f:
            m = pat.search(line)
            if not m:
                continue
            n += 1
            va = int(m.group(1), 16) - BASE
            if va < 0 or va >= LIMIT:
                continue
            if hard_target(va):
                out.append(va)
    with open(OUTP, 'wb') as f:
        out.tofile(f)
    print(f"{n} trace lines, {len(out)} hard-target entries, "
          f"{len(hard)} distinct hard / {len(soft)} distinct soft")

if __name__ == '__main__':
    main()
