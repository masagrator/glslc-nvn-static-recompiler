"""
analyze.py -- function discovery + jump-table resolution, cached to disk.

Uses angr's CFGFast (which already has jump-table resolvers) instead of a
hand-rolled scanner.  All addresses are CLE addresses (the loader's mapped
base), which is the canonical address space for the whole toolchain.

Run once per input binary; every later stage reads the cache.
"""

import json
import logging
import os
import sys
import time

for _n in ('angr', 'cle', 'pyvex', 'claripy', 'ailment'):
    logging.getLogger(_n).setLevel(logging.CRITICAL)

import angr  # noqa: E402

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'lib'))
if lib_path not in sys.path:
    sys.path.append(lib_path)

import cachekey  # noqa: E402
import elfcompat  # noqa: E402


def text_span(mo):
    for s in mo.segments:
        if s.is_executable:
            return s.vaddr, s.vaddr + s.memsize
    raise RuntimeError('no executable segment')


def collect_seeds(mo, lo, hi):
    """Function starts we know about before any scanning.

    Three independent sources:
      * every code pointer stored in the RW image (vtables, dispatch tables) --
        these are exactly the functions the port must implement;
      * every FUNC symbol the binary still exports;
      * every .eh_frame FDE's initial location.  A binary built with C++
        exceptions records one per function, which is recorded evidence rather
        than anything a scanner has to infer, and it covers functions that are
        only ever reached by a computed branch.  A binary without .eh_frame
        (glslc.elf has none) contributes nothing here and is unaffected.

    The relative relocations are matched with elfcompat.is_relative() rather
    than by class name: CLE spells a packed RELR entry GenericRelativeReloc,
    of which R_AARCH64_RELATIVE is a subclass, so a name test sees none of the
    70,917 pointers in a RELR binary and the RW-pointer seed source silently
    goes empty.
    """
    seeds = set()
    ptr_seeds = set()
    for r in mo.relocs:
        if elfcompat.is_relative(r):
            v = r.value
            # AArch64 instructions are 4-byte aligned without exception, so a
            # relocated word with a low bit set is not a code address however
            # much it looks like one by range.  The Itanium C++ ABI's
            # pointer-to-member-function is the one that reaches here: a
            # virtual target is stored as `vtable_offset + 1`.  Seeding CFG
            # recovery with it asks angr to decode at an unaligned address.
            if lo <= v < hi and not (v & 3):
                seeds.add(v)
                ptr_seeds.add(v)
    for s in mo.symbols:
        a = s.rebased_addr
        if s.is_function and a and lo <= a < hi:
            seeds.add(a)
    fde_seeds = elfcompat.fde_function_starts(mo)
    seeds |= fde_seeds
    return seeds, ptr_seeds, fde_seeds


def main():
    binary = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else 'cache'
    # Optional third argument: where to map the image.  CLE's default for a
    # PIE is 0x400000, which puts the whole 10 MB image in the range ordinary
    # integers occupy, so a packed word like 0xb90000 (opcode 185 shifted into
    # the top half) is indistinguishable BY VALUE from an address.  Mapping
    # the image above 4 GB removes the ambiguity: no immediate a compiler
    # emits as data lands there, so "this value names a location in the image"
    # becomes an exact test rather than a heuristic.  The cache records the
    # base it was built at; gen.py must be given the same one.
    base = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
    os.makedirs(outdir, exist_ok=True)

    # A CACHE FROM A DIFFERENT BINARY IS WORSE THAN NO CACHE: every entry in it
    # is keyed by address, so the addresses stay plausible and nothing downstream
    # notices.  This tool owns the cache, so a stale one is discarded and rebuilt
    # rather than reported -- rebuilding it is what was asked for.  Only the
    # three files this tool writes are removed; see cachekey.discard().
    if os.path.exists(os.path.join(outdir, 'meta.json')):
        why, verified = cachekey.check(outdir, binary)
        if why:
            print('cache in %s/ does not match %s:' % (outdir, binary))
            print('  %s' % why)
            gone = cachekey.discard(outdir)
            print('  discarded %s -- rebuilding' % ', '.join(gone), flush=True)
        elif verified:
            print('cache in %s/ matches this binary; rebuilding it anyway '
                  '(that is what this tool does)' % outdir, flush=True)
    
    t0 = time.time()
    elfcompat.apply()
    opts = {'base_addr': base} if base is not None else {}
    # default limit of 5000 is not enough to analyze properly glslc 17.24 package 113
    proj = angr.Project(binary, auto_load_libs=False, main_opts=opts, cache_limits={'functions': 200_000, 'cfg_nodes': 200_000, 'cfg_edges': 200_000})
    mo = proj.loader.main_object
    lo, hi = text_span(mo)
    seeds, ptr_seeds, fde_seeds = collect_seeds(mo, lo, hi)
    print('base=%#x text=[%#x,%#x) seeds=%d (%d from RW pointers, %d from .eh_frame)'
          % (mo.mapped_base, lo, hi, len(seeds), len(ptr_seeds), len(fde_seeds)),
          flush=True)

    # Progress reporting.  CFGFast is silent for ~20 minutes on an 18 MB input,
    # which makes a poll of the log indistinguishable from a hung job; the only
    # way to see where it was, before this, was `py-spy dump`.  angr publishes
    # an incremental-progress callback, so use it rather than inferring
    # liveness from the outside.
    _last = [0.0]

    def _progress(percentage, **kwargs):
        now = time.time()
        # One line per 30 s, not per callback: CFGFast calls this thousands of
        # times and a line each would bury the summary lines that follow.
        if now - _last[0] < 30.0 and percentage < 100.0:
            return
        _last[0] = now
        delta_time = now - t0
        print('  CFGFast %5.1f%%  %.0f:%02.0f min elapsed' % (percentage, delta_time // 60.0, delta_time % 60.0), flush=True)

    cfg = proj.analyses.CFGFast(
        # progress_callback=_progress, < use this if you are outputting log to file, also set show_progressbar to False otherwise you will get a ton of logging
        show_progressbar=True,
        regions=[(lo, hi)],
        normalize=True,
        force_complete_scan=False,
        function_starts=sorted(seeds),
        data_references=False
    )
    delta_time = time.time() - t0
    print('CFGFast done in %.0f:%02.0f min, %d functions'
          % (delta_time // 60.0, delta_time % 60.0, len(cfg.functions)), flush=True)

    funcs = {}
    for f in cfg.functions.values():
        if not (lo <= f.addr < hi):
            continue
        try:
            blocks = sorted(b.addr for b in f.blocks)
            sizes = {b.addr: b.size for b in f.blocks}
        except Exception:
            blocks, sizes = [], {}
        funcs['%#x' % f.addr] = {
            'name': f.name,
            'size': f.size,
            'blocks': ['%#x' % b for b in blocks],
            'block_sizes': {'%#x' % k: v for k, v in sizes.items()},
            'returning': bool(f.returning),
            'is_plt': bool(f.is_plt),
            'has_unresolved_jumps': bool(f.has_unresolved_jumps),
            'has_unresolved_calls': bool(f.has_unresolved_calls),
        }

    ind = {}
    for a, j in cfg.indirect_jumps.items():
        ind['%#x' % a] = {
            'func': '%#x' % j.func_addr,
            'jumpkind': str(j.jumpkind),
            'resolved': ['%#x' % t for t in sorted(j.resolved_targets)],
            'type': str(getattr(j, 'type', None)),
        }

    # The hash is what makes this cache checkable later; the path is kept only
    # because it is useful to a human reading meta.json, and is NOT an identity
    # (the cache shipped with this package records a D:\\ path).
    meta = cachekey.stamp({
        'binary': os.path.abspath(binary),
        'base': mo.mapped_base,
        'text_lo': lo, 'text_hi': hi,
        'seeds': sorted('%#x' % s for s in seeds),
        'ptr_seeds': sorted('%#x' % s for s in ptr_seeds),
        'fde_seeds': sorted('%#x' % s for s in fde_seeds),
    }, binary)

    json.dump(funcs, open(os.path.join(outdir, 'funcs.json'), 'w'))
    json.dump(ind, open(os.path.join(outdir, 'indirect.json'), 'w'))
    json.dump(meta, open(os.path.join(outdir, 'meta.json'), 'w'))

    nres = sum(1 for v in ind.values() if v['resolved'])
    print('indirect jumps: %d resolved, %d unresolved' % (nres, len(ind) - nres))
    delta_time = time.time() - t0
    print('cached in %s/ (%.0f:%02.0f min total)' % (outdir, delta_time // 60.0, delta_time % 60.0))


if __name__ == '__main__':
    main()
