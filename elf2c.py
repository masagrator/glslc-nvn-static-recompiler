"""
elf2c.py -- entry point.

    python3 elf2c.py <binary> -o out/ [--entries name,name] [--closure]

By default it translates the documented entry points plus everything reachable
from them, together with every function whose address is stored in the RW
image (those are the ones reached through vtables at run time).
"""

import argparse
import json
import os
import sys
import time

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'lib'))
if lib_path not in sys.path:
    sys.path.append(lib_path)

from lib.gen import Ctx, emit_function, cname, IGNORED_FUNCS
from lib import elfcompat
from lib import unit
from lib import layout


DEFAULT_ENTRIES = ['glslcInitialize', 'glslcGetDefaultOptions', 'glslcFinalize',
                   'glslcCompile', 'glslcGetVersion', 'glslcSetAllocator']


def find_exports(ctx):
    out = {}
    for s in ctx.mo.symbols:
        if s.is_function and s.rebased_addr and ctx.in_rx(s.rebased_addr):
            if s.name:
                out.setdefault(s.name, s.rebased_addr)
    return out


def rw_pointer_functions(ctx):
    """Functions whose address is stored in the writable image.

    Two rules, both of which this function got wrong until section 28.5:

      * match with elfcompat.is_relative(), NOT on the class NAME.  CLE spells
        a packed RELR entry `GenericRelativeReloc`, of which R_AARCH64_RELATIVE
        is a subclass, so a name test sees NONE of a RELR binary's relocations
        -- and subsdk0.elf keeps all 70,917 of its relative relocations in
        DT_RELR.  `--rw-pointers` therefore contributed nothing at all there.
        Section 24.1 fixed this in four places; this was the fifth and it was
        missed because the flag still "worked" on glslc.elf.
      * a code address is 4-byte aligned.  The Itanium C++ ABI stores a pointer
        to a VIRTUAL member function as `vtable_offset + 1`, which lands in the
        text range and is not code; translating it produced a function whose
        whole body was `guest_nodecode` (section 28.5).
    """
    out = set()
    for r in ctx.mo.relocs:
        if elfcompat.is_relative(r) and ctx.in_rw(r.rebased_addr):
            v = r.value
            if ctx.in_rx(v) and not (v & 3):
                out.add(v)
    return out


def closure(ctx, roots, limit=None):
    """Everything reachable by direct call from `roots`."""
    seen, work = set(), list(roots)
    while work:
        a = work.pop()
        if a in seen:
            continue
        if not ctx.in_rx(a) or a in ctx.plt_by_addr:
            continue
        seen.add(a)
        if limit and len(seen) >= limit:
            break
        blocks = ctx.blocks_of.get(a) or ctx.discover(a)
        for b in blocks:
            irsb = ctx.lift(b, limit=ctx.next_block_start(b, blocks))
            if irsb is None:
                continue
            nxt = irsb.next
            if irsb.jumpkind == 'Ijk_Call' and type(nxt).__name__ == 'Const':
                work.append(nxt.con.value)
            elif type(nxt).__name__ == 'Const':
                d = nxt.con.value
                if d not in blocks:
                    work.append(d)
            for s in irsb.statements:
                if type(s).__name__ == 'Exit' and s.dst.value not in blocks:
                    work.append(s.dst.value)
    return seen


def _dedupe(seq):
    """Distinct items, first occurrence order."""
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def fold_subset_functions(ctx, done, writer):
    """Replace a function whose blocks are all inside a bigger one with a stub.

    The CFG hands out a separate function for an address that is also a block
    of a larger function, so the same code is translated twice.  f_00a003a8 is
    literally a suffix of f_00a003a4: every block it contains, including the
    label L_00a003a8 it starts at, is already in the bigger file.

    Nothing new is needed to exploit that, because every function already
    accepts an entry selector and dispatches on it -- entering f_00a003a4 at
    L_00a003a8 is exactly what `f_00a003a4(cpu, 0xa003a8)` does.  So the
    duplicate body becomes:

        void f_00a003a8(cpu_t *cpu, uint64_t entry) {
            if (entry == 0) entry = UINT64_C(0xa003a8);
            return f_00a003a4(cpu, entry);
        }

    Only entry 0 is rewritten: 0 means "start at my own address", which for the
    host means its address, not this one.  Any other selector is a block
    address that both functions share, so it passes through untouched.

    This does NOT change what runs.  Both files were generated from the same
    blocks by the same emitter, so the host's code at L_00a003a8 is the same
    code the stub replaces -- the guest stack is in cpu, and the only
    difference is one extra host frame.

    Two conditions, both required:
      * the host has more than one block, so it emitted a `_local_dispatch`
        with a case for every block -- a single-block function has no switch
        to enter through;
      * the folded function's blocks are a SUBSET of the host's, so every
        selector it can be given names a case the host actually emitted.

    Hosts are ranked (most blocks first, then lowest address) and a function
    only folds into a strictly better-ranked host, which makes the relation a
    strict order and therefore acyclic.  Chains are collapsed to their root so
    a fold is always a single call.
    """
    block_sets = {}
    for a in done:
        blocks = ctx.blocks_of.get(a)
        if blocks:
            block_sets[a] = frozenset(blocks)

    rank = {a: (-len(bs), a) for a, bs in block_sets.items()}

    # ---- finding the host ---------------------------------------------------
    #
    # The obvious spelling of this is "for every function, for every block it
    # contains, is the function starting at that block a subset of me" -- and
    # it is what this used to do.  It costs one FULL SET COMPARISON per
    # (container, contained) pair, and both factors grow with the binary: by
    # the time a block list has been merged into its owners and every call's
    # return address has been added to its callee (see ctx.merge_into_owner and
    # the fixpoint in emit_all), the tree here has ~16 million block entries
    # spread over ~66,000 functions and the pairs run to the high hundreds of
    # thousands.  Each comparison walks thousands of elements, so the pass sat
    # at over a minute.  Same answer, three changes:
    #
    #  1. `bs & starts` instead of a Python loop with a membership test per
    #     block.  Only a block that is ITSELF a function start can ever be
    #     folded, and those are a small minority of the 16 million; the
    #     intersection finds them in C rather than one interpreted iteration
    #     each.
    #
    #  2. The pairs are inverted into candidates-per-function and sorted by
    #     rank, so the FIRST candidate that passes is the best-ranked one and
    #     the scan stops there.  The old loop had to consider every container
    #     of b to know which one won.
    #
    #  3. Two filters in front of the set comparison, both exact -- they only
    #     ever reject a pair that the comparison would also have rejected:
    #       * address range.  A subset cannot reach outside its superset, so
    #         min/max settle most pairs with two integer compares.
    #       * remembered witnesses.  When b turns out not to be a subset of a,
    #         one block of b that a does not have is kept; b is usually not a
    #         subset of its other containers for the SAME missing block, so the
    #         remaining containers are then rejected by a hash lookup.
    #
    # Measured on the 66,000-function shape above: 70.1s -> 3.1s, with the
    # resulting `host` mapping identical.
    starts = set(block_sets)

    containers = {}
    for a, bs in block_sets.items():
        if len(bs) < 2:
            continue                      # no local dispatch to enter through
        for b in bs & starts:
            if b == a:
                continue
            lst = containers.get(b)
            if lst is None:
                containers[b] = [a]
            else:
                lst.append(a)

    # min()/max() over a frozenset are C loops; the whole table costs one pass.
    lo = {a: min(bs) for a, bs in block_sets.items()}
    hi = {a: max(bs) for a, bs in block_sets.items()}

    host = {}
    rank_of = rank.__getitem__
    for b, cands in containers.items():
        if len(cands) > 1:
            cands.sort(key=rank_of)       # best-ranked host first
        rb = rank[b]
        bsb = block_sets[b]
        lb, hb = lo[b], hi[b]
        witnesses = []                    # blocks of b seen missing from a host
        for a in cands:
            if rank[a] >= rb:
                break                     # only fold into a better-ranked host
            bsa = block_sets[a]
            if lo[a] > lb or hi[a] < hb:
                continue                  # b reaches outside a: not a subset
            for w in witnesses:
                if w not in bsa:
                    break
            else:
                if bsb <= bsa:
                    host[b] = a
                    break
                if len(witnesses) < 8:
                    witnesses.append(min(bsb - bsa))

    # Collapse A -> B -> C to A -> C.  The ranking guarantees this terminates,
    # but the visited set makes that independent of the ranking staying strict.
    def root(x):
        seen = {x}
        while x in host and host[x] not in seen:
            x = host[x]
            seen.add(x)
        return x

    folded = 0
    folded_addrs = ctx.folded_addrs = set()
    for b in sorted(host):
        h = root(b)
        if h == b or h not in done:
            continue
        writer.write(b, [
            '/* %s is entirely contained in %s: every one of its %d blocks is'
            % (cname(b), cname(h), len(block_sets[b])),
            ' * a block of that function, which was emitted with a dispatch'
            ' case for each.',
            ' * Entering the host at this address runs the identical code, so'
            ' the duplicate',
            ' * body is replaced by the call.  See fold_subset_functions() in'
            ' elf2c.py. */',
            'void %s(cpu_t *cpu, uint64_t entry) {' % cname(b),
            '    /* 0 means "my own address"; any other selector is a block'
            ' both share. */',
            '    if (entry == 0) entry = UINT64_C(%#x);' % b,
            '    return %s(cpu, entry);' % cname(h),
            '}',
        ], deps={cname(h)})
        folded += 1
        folded_addrs.add(b)

    if False:   # the note is issued after the prune instead; see below
        ctx.notes.append(('subset functions folded into their container',
                          folded, ''))
    return folded


# ---- parallel emission -------------------------------------------------
#
# `emit_function` is pure with respect to the OUTPUT of every other function --
# two functions never write each other's file -- but it is not pure with
# respect to `ctx`: it records what it referenced, which imports and vector
# helpers it needed, which interior blocks are re-entrable, and so on.  Those
# accumulations are what drives the next round of the fixpoint and what the
# dispatch table and the runtime headers are built from later, so a worker's
# copy of them has to come back.
#
# The pool is fork-based ON PURPOSE.  A worker inherits the finished `ctx` --
# the ELF image, the CFG cache, the jump tables, ~13 MB of parsed JSON -- for
# free, so nothing has to be pickled INTO a worker; only the emitted lines and
# the accumulations come back out.
#
# Every attribute below only ever GROWS, and each function touches its own key,
# so merging is a union (sets), an update (dicts) or an extend past the
# inherited length (lists).  Order does not matter: a block's dispatch selector
# is derived from its ADDRESS, not from the order it was discovered in.
_MERGE_SETS = ('referenced', 'imports_used', 'owned_blocks', 'landing_pads',
               'potential_entries', 'func_set', 'open_branch_funcs',
               'indirect_branch_funcs')
_MERGE_DICTS = ('simd_helpers', 'file_deps', 'entry_blocks', 'forced_entries',
                'blocks_of')
_MERGE_LISTS = ('notes', 'const_log')

_POOL_CTX = None
_SENT = None        # per-worker: what this worker has already reported


class _JournalDict(dict):
    """A dict that remembers which keys were written since the last drain.

    Installed on a WORKER only.  Reporting "keys this worker has that the
    parent does not" is not enough: a worker also MODIFIES existing keys --
    `blocks_of[callee]` gains the return address of every call the function it
    is emitting makes -- and a new-keys-only delta silently drops that.
    Scanning every key after each function to find the changed ones would be
    O(keys) per function, which is the quadratic cost this design already had
    to remove once.  Every write in gen.py is a plain `d[k] = v`, so recording
    the key in __setitem__ costs one set insert and catches all of them.
    """

    def __init__(self, *a, **kw):
        dict.__init__(self, *a, **kw)
        self.touched = set()

    def __setitem__(self, k, v):
        dict.__setitem__(self, k, v)
        self.touched.add(k)

    def setdefault(self, k, d=None):
        if k not in self:
            self.touched.add(k)
        return dict.setdefault(self, k, d)

    def update(self, *a, **kw):
        before = len(self)
        dict.update(self, *a, **kw)
        if len(self) != before or a or kw:
            self.touched.update(dict(*a, **kw).keys())

    def drain(self):
        t, self.touched = self.touched, set()
        return t


def _emit_body(ctx, a):
    """Emit one function; never raises."""
    lines = []
    try:
        emit_function(ctx, a, lines)
    except Exception as ex:                       # noqa: BLE001 -- reported, not raised
        ctx.notes.append(('function failed', a, repr(ex)))
        lines = ['/* %s: translation failed: %r */' % (cname(a), ex),
                 'void %s(cpu_t *cpu, uint64_t e) { (void)e; '
                 'guest_unresolved(cpu, UINT64_C(%#x), "untranslated"); }'
                 % (cname(a), a)]
    return lines


def _emit_one(a):
    """Worker body: emit one function and report ONLY WHAT IS NEW.

    The obvious version of this returned a copy of each accumulator after every
    function.  `ctx.referenced` and `ctx.blocks_of` hold tens of thousands of
    entries, so copying them once per function is O(n) per function and O(n^2)
    over the pass: it made the generator TEN TIMES SLOWER than the serial path
    it was meant to speed up, which py-spy pinned to this line in one dump.

    So each worker remembers what it has already sent and reports the
    difference.  A worker's accumulators only ever grow, and the parent unions
    everything from every worker, so per-worker increments add up to the whole.
    """
    ctx = _POOL_CTX
    sent = _SENT
    lines = _emit_body(ctx, a)

    sets = {}
    for k in _MERGE_SETS:
        cur = getattr(ctx, k)
        seen = sent['sets'][k]
        if len(cur) != seen[0]:
            new = cur - seen[1]
            if new:
                sets[k] = new
                seen[1].update(new)
            seen[0] = len(cur)
    dicts = {}
    for k in _MERGE_DICTS:
        cur = getattr(ctx, k)
        touched = cur.drain()
        if touched:
            dicts[k] = {kk: cur[kk] for kk in touched}
    lists = {}
    for k in _MERGE_LISTS:
        cur = getattr(ctx, k)
        n = sent['lists'][k]
        if len(cur) != n:
            lists[k] = cur[n:]
            sent['lists'][k] = len(cur)

    delta = {'sets': sets, 'dicts': dicts, 'lists': lists,
             'text_data_used': ctx.text_data_used}
    return a, lines, ctx.file_deps.get(a), delta


def _pool_init(ctx=None):
    """Runs once per worker, after fork -- or once per spawned process.

    On a fork() pool `ctx` is not passed: the context is picked up from the
    module global the parent set before forking, so it is inherited by the
    fork and never pickled.  Passing it through `initargs` there would
    serialise the whole thing -- the ELF image, the CFG cache, the jump
    tables -- into every worker for nothing, which is the cost this design
    exists to avoid.

    On platforms with no fork() (Windows), the pool is spawn-based and each
    worker starts empty, so `ctx` IS passed through `initargs` -- this is
    the one and only place it gets shipped across.  `Ctx.__setstate__`
    rebuilds the angr/Capstone handles that don't survive the pickle; see
    the comment there.  Ordinary Pool() semantics unpickle `initargs`
    exactly once per worker, so this still only pays the pickling cost
    once per process, not once per function.

    `sent` starts from what was inherited, not from empty; otherwise each
    worker would report the entire inherited state as new on its first task.
    """
    global _SENT, _POOL_CTX
    if ctx is not None:
        _POOL_CTX = ctx
    ctx = _POOL_CTX
    for k in _MERGE_DICTS:
        setattr(ctx, k, _JournalDict(getattr(ctx, k)))
    _SENT = {
        'sets': {k: [len(getattr(ctx, k)), set(getattr(ctx, k))] for k in _MERGE_SETS},
        'lists': {k: len(getattr(ctx, k)) for k in _MERGE_LISTS},
    }


def _merge(ctx, delta):
    for k, v in delta['sets'].items():
        getattr(ctx, k).update(v)
    for k, v in delta['dicts'].items():
        cur = getattr(ctx, k)
        for kk, vv in v.items():
            old = cur.get(kk)
            if old is None or old == vv:
                cur[kk] = vv
                continue
            # ELEMENT-WISE, not replace.  Two workers can both extend the SAME
            # key: emitting a function adds the return address of every call it
            # makes to the CALLEE's block list, so `blocks_of[callee]` grows in
            # whichever worker happens to emit a caller.  A plain dict.update()
            # keeps one worker's list and drops the other's, and the loss is
            # not visible until the very end -- fold_subset_functions() then
            # sees an incomplete block list, decides a function is NOT a subset
            # of the one that contains it, and emits a standalone body where
            # the serial run emitted a fold.  That was 53 extra files and 22
            # differing ones on the first comparison run.
            if isinstance(old, list):
                cur[kk] = sorted(set(old) | set(vv))
            elif isinstance(old, set):
                cur[kk] = old | vv
            else:
                cur[kk] = vv
    for k, v in delta['lists'].items():
        getattr(ctx, k).extend(v)
    if delta['text_data_used']:
        ctx.text_data_used = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary')
    ap.add_argument('-o', '--outdir', default='out')
    ap.add_argument('--cache', default='cache')
    ap.add_argument('--base', default=None,
                    help='load address for the image; defaults to the base '
                         'recorded in the cache.  Mapping above 4 GB (e.g. '
                         '0x7100000000) makes constant classification exact')
    ap.add_argument('--entries', default=','.join(DEFAULT_ENTRIES))
    ap.add_argument('--closure', action='store_true',
                    help='also translate everything reachable from the entries')
    ap.add_argument('-j', '--jobs', type=int, default=1, metavar='N',
                    help='emit functions on N processes (0 = one per CPU, '
                         'which is the count of the MACHINE and not '
                         "necessarily this process's share -- prefer a number). "
                         'The generated C is byte-identical to the serial '
                         'tree; see HANDOVER.md section 29.')
    ap.add_argument('--rw-pointers', action='store_true',
                    help='also translate every function addressed from the RW image')
    ap.add_argument('--all', action='store_true',
                    help='translate every function the CFG discovered, not just '
                         'what the entry points and RW pointers reach')
    ap.add_argument('--no-comments', action='store_true',
                    help='omit the per-instruction disassembly comments (~21%% smaller)')
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--no-fold-subsets', action='store_true',
                    help='keep the duplicate body of a function that is wholly '
                         'contained in a larger one, instead of forwarding to it')
    args = ap.parse_args()

    print("  Recovering jump table arms....", end="\r")

    t0 = time.time()
    os.makedirs(args.outdir, exist_ok=True)
    ctx = Ctx(args.binary, args.cache,
              int(args.base, 0) if args.base else None)
    ctx.emit_comments = not args.no_comments
    exports = find_exports(ctx)

    wanted = [n.strip() for n in args.entries.split(',') if n.strip()]
    roots = {}
    for n in wanted:
        if n in exports:
            roots[n] = exports[n]
        else:
            print('warning: export %r not found' % n, file=sys.stderr)

    todo = set(roots.values())
    # The .init_array constructors are entry points in their own right: nothing
    # in the image calls them, the loader does, so a closure from the API alone
    # would never reach them.  guest_init() runs them once (see emit_entries).
    todo |= set(ctx.init_array_order)
    # DT_INIT is an entry point in its own right for the same reason the
    # constructors are: nothing in the image calls it, so a closure from the
    # API never reaches it.
    sorted_todo = sorted(todo)
    if getattr(ctx, 'init_func', None) is not None:
        todo.add(ctx.init_func)
    if args.rw_pointers:
        todo |= rw_pointer_functions(ctx)
    if args.all:
        todo |= set(ctx.funcs)
    if args.closure:
        # Expand from EVERY root, including the functions reached only through
        # pointers in the RW image.  Expanding from the entry points alone
        # leaves every vtable target's callees untranslated, which shows up as
        # a pile of stubs that abort the moment a virtual call is made.
        todo |= closure(ctx, sorted_todo, limit=args.limit or None)
    if args.limit:
        todo = set(sorted_todo[:args.limit])

    # Drop CFG "functions" that are really continuation blocks, folding them
    # into the function that encloses them.  Doing this BEFORE trimming matters:
    # a false start would otherwise be treated as a legitimate boundary and cut
    # its owner short at exactly the wrong place.
    # Jump-table arms the CFG could not recover.  These become block starts of
    # their owning function, which is what gives a computed branch a label to
    # land on -- an arm can sit in the middle of an existing block otherwise.
    arms = ctx.resolve_jump_tables()
    if arms:
        ctx.potential_entries |= arms
        # An arm that belongs to no function's block list has nowhere to be a
        # re-entry case, so it is translated on its own.  Entering there skips
        # a prologue, which is exactly what the guest does when it JUMPS to the
        # address; the chain unwinds through the shared epilogue as usual.

        print('  %d jump-table arms recovered from the tables themselves'
              % len(arms), flush=True)

    # Landing pads are registered the same way, and for the same reason: they
    # are addresses control reaches without a branch, so nothing else in the
    # pipeline knows they are code.  The difference is only where the evidence
    # comes from -- .gcc_except_table rather than a jump table (ehframe.py).
    pads = getattr(ctx, 'landing_pads', set())
    if pads:
        ctx.potential_entries |= pads
        arms = (arms | pads) if arms else set(pads)
        print('  %d landing pads recovered from .gcc_except_table'
              % len(pads), flush=True)
    print("  Sweeping missed blocks...", end = "\r")
    missed = ctx.sweep_missed_blocks()
    if missed:
        todo |= missed
        print('  %d block starts the CFG missed, added as entries' % len(missed),
              flush=True)

    print("  Scanning false starts...     ", end = "\r")
    false_starts = ctx.detect_false_starts()
    ctx.false_starts = false_starts     # trimming must not cut at these
    print('  false-start scan: %d of %d CFG functions are continuation blocks'
          % (len(false_starts), len(ctx.funcs)), flush=True)
    if false_starts:
        attached = ctx.reattach_false_starts(false_starts)
        print('  %d false function starts folded into their enclosing function'
              % attached, flush=True)
        todo -= false_starts

    # The function set is complete now (CFG + exports + RW pointers), so
    # over-merged functions can be cut back before anything is emitted.
    ctx.func_set |= set(todo)
    ctx.func_set -= false_starts
    print("  Applying trimming...          ", end = "\r")
    ctx.apply_trimming()

    todo -= ctx.ignored_funcs
    if ctx.ignored_funcs:
        print('skipping start-up stubs: %s'
              % ', '.join(sorted(n for n in IGNORED_FUNCS if n in ctx.defined_syms)),
              flush=True)

    print('translating %d functions' % len(todo), flush=True)

    # Bodies first: emitting them populates the import list, the vector-helper
    # set and the constant-rewrite log that everything else depends on.  Each
    # function is kept separate so it can become its own translation unit.
    # Translating can reveal new call targets -- jump-table destinations in
    # particular are only discovered while emitting the block that dispatches
    # to them.  Keep going until nothing new turns up, so those become real
    # translations rather than trap stubs.
    os.makedirs(args.outdir, exist_ok=True)

    # PASS 1 -- discovery only.  Emitting a function is what reveals the code
    # addresses it materialises, and those are exactly the blocks a computed
    # branch can land on.  A function needs to know about its own re-entrable
    # blocks BEFORE it is written, so the output of this pass is thrown away
    # and only ctx.potential_entries is kept.
    print('pass 1: discovering indirect-branch targets', flush=True)
    scan = set()
    scan_work = sorted(todo)
    while scan_work:
        len_scan_work = len(scan_work)
        for i in range(len_scan_work):
            print("  Done: %d/%d              " % (i, len_scan_work), end="\r")
            a = scan_work[i]
            if a in scan or a in ctx.plt_by_addr or not ctx.in_rx(a):
                continue
            if a in ctx.ignored_funcs:
                continue
            scan.add(a)
            try:
                ctx.scan_function(a)     # discovery only; no C text produced
            except Exception:
                pass
        scan_work = sorted(a for a in ctx.referenced
                           if a not in scan and ctx.in_rx(a)
                           and a not in ctx.plt_by_addr and a not in ctx.ignored_funcs)
    print('  %d functions, %d indirect targets' % (len(scan), len(ctx.potential_entries)),
          flush=True)

    # An address that is an interior block of a known function must NOT become
    # a translation of its own.  The guest reaches it by jumping inside a frame
    # its owner's prologue already pushed; a standalone translation would skip
    # that prologue and then run the shared epilogue, popping a frame nobody
    # pushed and shifting SP.  Hand it to the owner as a re-entry instead.
    # Relocations name code addresses too (vtable slots), and some of those are
    # interior blocks.  They are resolved here, before ownership is computed,
    # so the owning function is emitted WITH an entry case for them -- the
    # relocation pass proper runs after pass 2 and would be too late.
    for r in ctx.mo.relocs:
        # By class, not by class name: a packed RELR entry is a
        # GenericRelativeReloc (elfcompat.is_relative).
        if elfcompat.is_relative(r) and ctx.in_rw(r.rebased_addr):
            if ctx.in_rx(r.value):
                ctx.reloc_addr(r.value)

    # Ownership must come from the CFG's ORIGINAL block lists, not from
    # ctx.blocks_of: the latter has been truncated where functions were
    # over-merged, so an interior block can have been cut away from its owner
    # and would then look like an orphan.
    owner_of = {}
    for fa, info in ctx.funcs.items():
        for b in info.get('blocks', ()):
            ba = int(b, 16) if isinstance(b, str) else b
            if ba != fa:
                owner_of.setdefault(ba, fa)
    for fa, blks in ctx.blocks_of.items():
        for b in blks:
            if b != fa:
                owner_of.setdefault(b, fa)

    # Arms that no function's block list contains: translate them standalone,
    # since there is no owner able to host a re-entry case for them.
    block_owner = {}
    for fa, info in ctx.funcs.items():
        for b in info.get('blocks', ()):
            ba = int(b, 16) if isinstance(b, str) else b
            block_owner.setdefault(ba, fa)
    # ONLY the resolved jump-table arms -- potential_entries also accumulates
    # every code constant seen during discovery, and treating those as orphans
    # asked for half a million standalone translations.
    orphans = {a for a in arms
               if a not in block_owner and a not in ctx.funcs and ctx.in_rx(a)}
    if orphans:
        todo |= orphans
        print('  %d orphan jump-table arms translated standalone' % len(orphans),
              flush=True)

    interior_targets = 0
    # Two sources of interior addresses: constants materialised in code
    # (potential_entries) and addresses that pass 1 ended up treating as
    # functions because something branched to them (scan).  The second kind is
    # what a tail call to a mid-function label produces, and missing it is what
    # left an owner without a case for a block it actually contains.
    for a in sorted(set(ctx.potential_entries) | set(scan)):
        if a in ctx.funcs:
            continue                      # a genuine function start
        owner = owner_of.get(a)
        if owner is not None and owner != a:
            ctx.forced_entries.setdefault(owner, set()).add(a)
            interior_targets += 1
    if interior_targets:
        print('  %d indirect targets handed to their owning function'
              % interior_targets, flush=True)

    todo |= {a for a in ctx.referenced if ctx.in_rx(a)}
    todo -= ctx.ignored_funcs
    todo -= {a for blks in ctx.forced_entries.values() for a in blks}

    owned_by_other = {a for blks in ctx.forced_entries.values() for a in blks}
    ctx.owned_blocks = owned_by_other

    print('pass 2: emitting', flush=True)
    writer = layout.FunctionWriter(args.outdir)
    # How to declare each name a function file might reference.
    writer.decl_for = {}
    for nm in unit.thunk_names(ctx):
        writer.decl_for['plt_%s' % nm] = 'void plt_%s(cpu_t *cpu, uint64_t entry);' % nm

    class _FnDecls(dict):
        """Any f_<hex> name declares itself; no need to enumerate 43,000."""
        def __contains__(self, k):
            return dict.__contains__(self, k) or (
                isinstance(k, str) and k.startswith('f_'))

        def __getitem__(self, k):
            if dict.__contains__(self, k):
                return dict.__getitem__(self, k)
            if isinstance(k, str) and k.startswith('f_'):
                return 'void %s(cpu_t *cpu, uint64_t entry);' % k
            raise KeyError(k)

    fd = _FnDecls()
    fd.update(writer.decl_for)
    writer.decl_for = fd
    done = set()
    work = sorted(todo)
    print("  entrypoints to process:", len(work))
    rounds = 0
    pool = None
    nproc = 1
    if args.jobs != 1:
        import multiprocessing
        nproc = args.jobs if args.jobs > 0 else (os.cpu_count() or 1)
        if nproc > 1:
            global _POOL_CTX
            _POOL_CTX = ctx
            if 'fork' in multiprocessing.get_all_start_methods():
                # fork, not spawn: a spawned worker would start empty and
                # need the whole context shipped to it. Set the global
                # BEFORE forking so the workers inherit it for free.
                pool = multiprocessing.get_context('fork').Pool(
                    nproc, initializer=_pool_init)
            else:
                # No fork() on this platform (Windows). A spawned worker
                # starts empty, so `ctx` has to be shipped to it -- but
                # only ONCE per worker, through initargs, not per task.
                # Ctx.__getstate__/__setstate__ (lib/gen.py) drop the
                # angr/Capstone handles that don't pickle and rebuild them
                # fresh in the worker; that's a plain ELF reload, seconds,
                # not a repeat of the CFG recovery / jump-table resolution
                # that produced everything else in ctx.
                print('  no fork() on this platform; sending the finished '
                      'analysis to %d worker processes (spawn)...' % nproc,
                      flush=True)
                pool = multiprocessing.get_context('spawn').Pool(
                    nproc, initializer=_pool_init, initargs=(ctx,))
            print('  emitting %d functions on %d processes, this can take '
                  'a while...' % (len(work), nproc), flush=True)
        else:
            # `--jobs` was given but resolved to one process (`-j 0` on a
            # single-core box, say), so this is the serial path with the
            # parallel machinery bypassed -- no process count to report.
            print('  emitting %d functions, this can take a while...'
                  % len(work), flush=True)
    while work:
        rounds += 1
        batch = []
        for a in work:
            if a in done or a in ctx.plt_by_addr or not ctx.in_rx(a):
                continue
            if a in ctx.ignored_funcs:
                continue
            if a in owned_by_other:
                continue          # handled as a re-entry of its owner
            done.add(a)
            batch.append(a)
        if pool is None:
            # The serial path does NOT go through _emit_one: there is nobody to
            # report a delta to, and building one per function is what made an
            # earlier version of this quadratic.  This is the original loop.
            for a in batch:
                lines = _emit_body(ctx, a)
                writer.write(a, lines, deps=ctx.file_deps.get(a))
        else:
            # A chunk big enough that the per-task overhead disappears, small
            # enough that the round's tail is not one worker's alone.
            # imap, NOT imap_unordered.  The parent's merge sequence is what
            # fixes the insertion order of `ctx.entry_blocks`, and that order
            # decides which function owns a shared block in the dispatch table.
            # Merging in completion order picked a different owner for 62% of
            # the table.  Ordered results cost a little head-of-line blocking
            # and buy an output identical to the serial one.
            chunk = max(1, min(256, len(batch) // (nproc * 8) or 1))
            for a, lines, deps, delta in pool.imap(_emit_one, batch, chunk):
                _merge(ctx, delta)
                writer.write(a, lines, deps=deps)
        work = sorted(a for a in ctx.referenced
                      if a not in done and ctx.in_rx(a)
                      and a not in ctx.plt_by_addr and a not in ctx.ignored_funcs
                      and a not in owned_by_other)
        if args.limit and len(done) >= args.limit:
            break
    if pool is not None:
        # The workers inherited the ctx as it was at fork; they must not
        # outlive the pass, because everything after this point reads the
        # MERGED ctx and a stale worker would answer from the old one.
        pool.close()
        pool.join()

    print('  reached a fixpoint after %d rounds, %d functions' % (rounds, len(done)),
          flush=True)

    # After the fixpoint, so ctx.blocks_of is final: emit_function can still add
    # blocks to a function (call return addresses, recovered arms), and a subset
    # test against a stale block list would be wrong in both directions.
    print("  Folding functions, this can take a while...", end = "\r")
    if not args.no_fold_subsets:
        folded = fold_subset_functions(ctx, done, writer)
        if folded:
            print('  %d functions folded into the larger function that contains '
                  'them' % folded, flush=True)

    # Relocation is generated before the arrays: it names every code pointer in
    # the RW image, and it can be what first forces a data copy of .text.
    # Relocations may name a code address; only those with a real definition
    # can be taken by address, so the emitted set has to be known first.
    ctx.emitted_funcs = set(done)
    unit.collect_relocations(ctx)

    # Dispatch table.  An address that is an interior block of some function
    # MUST map to that function with an entry selector, not to a standalone
    # translation starting at that block.
    #
    # Both exist: a computed branch target gets translated on its own AND is
    # recorded as a re-entry point of its owner.  Picking the standalone one
    # breaks the stack: the guest reaches that block by jumping WITHIN a frame
    # its prologue already pushed, so a translation that starts there skips the
    # prologue but still runs the shared epilogue, popping a frame that was
    # never pushed.  That shifts SP (0x70 in the case that surfaced), and the
    # caller then restores its callee-saved registers from the wrong slots.
    # Only blocks that emit_function ACTUALLY emitted a case for can be routed
    # to their owner -- a selector naming a case that does not exist would fall
    # through to `default` at run time.
    # A block can be claimed by more than one function -- an interior block of
    # a big function is often also the start of a smaller one the CFG split
    # out.  The first claimant wins, and `ctx.entry_blocks` is in INSERTION
    # order, which is emission order: the winner is the function emitted first,
    # i.e. the lowest address in the round that claims it.
    #
    # That is an order dependence, and it is deliberately KEPT rather than
    # replaced with a ranking, because this table is what the verified corpus
    # results were produced with.  Parallel emission reproduces the order
    # instead of arguing with it -- see section 29.
    emitted = {}
    for fa, inner in ctx.entry_blocks.items():
        for b in inner:
            emitted.setdefault(b, (fa, b))

    table = {}
    orphaned = []
    for a in done:
        if a in emitted:
            table[a] = emitted[a]      # owner + selector wins
        else:
            if a in owner_of and a not in ctx.funcs:
                # Wanted to route this to its owner but the owner has no case
                # for it, so a standalone translation is the only option left.
                # Recorded rather than silently accepted: entering mid-function
                # skips the prologue while still running the shared epilogue.
                orphaned.append(a)
            table[a] = (a, 0)
    for b, owner_entry in emitted.items():
        table.setdefault(b, owner_entry)

    # A row can only name a function that actually has a definition: an owner
    # may itself have been pruned (it can be an interior block of yet another
    # function) or ignored.
    # An owner can itself be an interior block of a third function, so follow
    # the ownership chain before giving up on a row.
    def resolve(fn, seen=None):
        seen = seen or set()
        while fn not in done and fn in owner_of and fn not in seen:
            seen.add(fn)
            fn = owner_of[fn]
        return fn

    rechained = 0
    for a, (fn, sel) in list(table.items()):
        if fn in done:
            continue
        root = resolve(fn)
        if root in done and (sel or a) in ctx.entry_blocks.get(root, ()):
            table[a] = (root, a)
            rechained += 1
    if rechained:
        print('  %d dispatch rows re-chained to an emitted owner' % rechained, flush=True)

    dropped = [a for a, (fn, _) in table.items() if fn not in done]
    for a in dropped:
        del table[a]
    if dropped:
        ctx.notes.append(('dispatch rows dropped, owner not emitted', len(dropped),
                          ','.join('%#x' % a for a in dropped[:10])))
        print('  %d dispatch rows dropped (owner has no definition)' % len(dropped),
              flush=True)

    # Every recovered jump-table arm must be reachable.
    #
    # Arms are attributed to the nearest preceding function start, which is
    # wrong when a table's arms live in a DIFFERENT function than the branch
    # that uses it -- tables that are subsets of larger tables elsewhere do
    # exactly that.  An arm that ends up with no entry anywhere would then be
    # a computed branch into nothing, so it is checked rather than assumed.
    print("  Measuring arm misses...                   ", end = "\r")
    arm_misses = sorted(a for a in arms if a not in table) if arms else []
    if arm_misses:
        ctx.notes.append(('jump-table arms with no dispatch entry',
                          len(arm_misses),
                          ','.join('%#x' % a for a in arm_misses[:20])))
        print('  WARNING: %d recovered arms have no dispatch entry '
              '(possible cross-function table)' % len(arm_misses), flush=True)

    # Every non-zero selector must name a case that exists.
    bad = [(a, fn, e) for a, (fn, e) in table.items()
           if e and e not in ctx.entry_blocks.get(fn, ())]
    if bad:
        ctx.notes.append(('dispatch selectors with no case', len(bad),
                          ','.join('%#x->%#x' % (a, fn) for a, fn, _ in bad[:10])))
        print('  WARNING: %d dispatch entries name a case that was not emitted'
              % len(bad), flush=True)
    if orphaned:
        ctx.notes.append(('interior blocks left standalone', len(orphaned),
                          ','.join('%#x' % a for a in orphaned[:10])))
        print('  %d interior blocks could not be routed to an owner'
              % len(orphaned), flush=True)

    # Commenting this out because it takes a while

    print("  Measuring unresolved targets...         ", end="\r")
    unresolved_targets = [a for a in ctx.potential_entries if a not in table]
    if unresolved_targets:
        ctx.notes.append(('indirect targets with no translation',
                          len(unresolved_targets),
                          ','.join('%#x' % a for a in unresolved_targets[:20])))

    dispatch = []
    print("  Emitting dispatch...         ", end="\r")
    unit.emit_dispatch(ctx, dispatch, table)
    # The exception tables go in the same file as the dispatch table: both are
    # whole-image tables, and both need the image arrays that guest_decls.h
    # declares.
    print("  Emitting eh...               ", end="\r")
    unit.emit_eh(ctx, dispatch)


    helpers = []        # prototypes -> shared header
    helper_defs = []    # bodies -> their own translation unit
    print("  Emitting simd...             ", end="\r")
    unit.emit_simd(ctx, helpers, helper_defs)

    thunks = []
    print("  Emitting thunks...           ", end="\r")
    unit.emit_thunks(ctx, thunks)

    # Referenced but not translated: declaration plus a trap body, so the tree
    # always links no matter how small a slice was requested.
    print("  Measuring missing targets...         ", end="\r")
    referenced = set(ctx.referenced)
    missing = sorted(a for a in referenced
                     if a not in done and ctx.in_rx(a) and a not in ctx.plt_by_addr
                     and a not in owned_by_other      # owned blocks live in their owner
                     and a not in ctx.ignored_funcs)  # already emitted as no-ops

    api_header = []
    entries = []
    print("  Emitting entries...           ", end="\r")
    unit.emit_entries(ctx, entries, exports, header=api_header)
    for a in sorted(ctx.ignored_funcs & set(ctx.referenced)):
        nm = next((n for n, v in ctx.defined_syms.items() if v == a),
                  'init_array constructor' if a in ctx.init_array_funcs else '?')
        entries.append('void %s(cpu_t *cpu, uint64_t e) { (void)cpu; (void)e; }   /* %s: start-up stub */'
                       % (cname(a), nm))
    if missing:
        entries.append('/* referenced but not translated in this run */')
    for a in missing:
        entries.append('void %s(cpu_t *cpu, uint64_t e) { (void)e; guest_unresolved(cpu, UINT64_C(%#x), "not translated"); }'
                       % (cname(a), a))

    decls = []
    decls.append('/* Generated by elf2c from %s -- do not edit. */'
                 % os.path.basename(args.binary))
    decls.append('#ifndef GUEST_DECLS_H')
    decls.append('#define GUEST_DECLS_H')
    decls.append('#include "guest_rt.h"')
    decls.append('')
    decls.append('extern const uint8_t g_ro[];')
    decls.append('')
    decls.append('/* A slot of the writable image: eight bytes that are either')
    decls.append(' * plain data or an address the image relocates.  Writing it as')
    decls.append(' * a union lets data_rw.c give each slot a static initialiser,')
    decls.append(' * so the LINKER resolves every pointer and the old startup')
    decls.append(' * guest_relocate() -- 44,241 stores -- is gone entirely. */')
    decls.append('typedef union g_rw_slot {')
    decls.append('    uint64_t     u;   /* the image\'s eight bytes */')
    decls.append('    const void  *p;   /* a slot the image relocates */')
    decls.append('} g_rw_slot;')
    decls.append('extern g_rw_slot g_rw[];')
    decls.append('')
    decls.append('/* Byte view of the same storage.  Guest pointers are byte')
    decls.append(' * offsets and need not be slot-aligned, and `g_rw + n` would')
    decls.append(' * now scale by 8, so every byte-wise use goes through this. */')
    decls.append('#define G_RW ((uint8_t *)g_rw)')
    if ctx.text_data_used:
        decls.append('extern const uint8_t g_text_data[];')
    decls.append('')
    decls.append('void guest_init(cpu_t *cpu);')
    decls.append('void guest_run_ctors(cpu_t *cpu);   /* .init_array, run once from guest_init */')
    decls.append('void guest_fini(cpu_t *cpu);')
    decls.append('void guest_dispatch(cpu_t *cpu, uint64_t p);')
    decls.append('void guest_dispatch_addr(cpu_t *cpu, uint64_t addr);')

    decls.append('void guest_missing_import(const char *name);')
    decls.append('void guest_unsupported_import(cpu_t *cpu, const char *name);')
    decls.append('')
    decls.append('/* imports called directly by the translated code */')
    for nm in sorted(ctx.imports_used):
        if nm in unit.EXTERN_PROTOS:
            decls.append(unit.EXTERN_PROTOS[nm])
    decls.append('')
    # Thunk declarations likewise move into the files that call them.
    decls.append('')
    # The per-function declarations stay OUT of the header the 43,000 function
    # files include (that cost ~86 GB of parsing).  They are still needed by the
    # few aggregate files -- relocate.c, entries.c, thunks.c -- which reference
    # thousands of functions each, so they go into their own header that only
    # those files include.
    decls.append('')
    aggregate_decls = ['#ifndef GUEST_ALL_H', '#define GUEST_ALL_H',
                       '#include "guest_decls.h"', '']
    for a in sorted(done | set(missing) | (ctx.ignored_funcs & set(ctx.referenced))):
        aggregate_decls.append('void %s(cpu_t *cpu, uint64_t entry);' % cname(a))
    for nm in unit.thunk_names(ctx):
        aggregate_decls.append('void plt_%s(cpu_t *cpu, uint64_t entry);' % nm)
    aggregate_decls.append('#endif')
    decls.extend(unit.data_import_decls(ctx))
    decls.append('/* address mapping + vector helpers */')
    addrmap = []
    print("  Emitting addrmap...                   ", end = "\r")
    unit.emit_addrmap(ctx, addrmap)
    print("  Emitting hostmap...                   ", end = "\r")
    unit.emit_hostmap(ctx, addrmap)
    decls.extend(addrmap)
    decls.extend(helpers)
    decls.append('#endif /* GUEST_DECLS_H */')

    cfg = []
    cfg.append('/* Generated by elf2c -- guest state layout for %s. */'
               % os.path.basename(args.binary))
    cfg.append('#ifndef GUEST_CONFIG_H')
    cfg.append('#define GUEST_CONFIG_H')
    cfg.append('#define GUEST_STATE_SIZE %d' % ((ctx.state_size + 15) & ~15))
    cfg.append('#define GUEST_OFF_SP %d' % ctx.off['sp'])
    cfg.append('#define GUEST_OFF_X0 %d' % ctx.off['x0'])
    cfg.append('#define GUEST_OFF_LR %d' % ctx.off['x30'])
    cfg.append('#define GUEST_OFF_Q0 %d' % ctx.qoff)
    cfg.append('#define GUEST_BASE UINT64_C(%#x)' % ctx.base)
    cfg.append('#endif /* GUEST_CONFIG_H */')

    # One emitter per image, rather than one flat list split apart afterwards
    # by matching on the text of its own declarations.  That split broke the
    # moment g_rw stopped being `uint8_t g_rw[...]`, and it was fragile before
    # -- the prefixes had to be kept in step with the emitter by hand.
    ro_lines, rw_lines, text_lines = [], [], []
    print("  Emitting ro...                   ", end = "\r")
    unit.emit_ro(ctx, ro_lines)
    print("  Emitting rw...                   ", end = "\r")
    unit.emit_rw(ctx, rw_lines)
    print("  Emitting sections...                   ", end = "\r")
    unit.emit_sections(ctx, text_lines)

    stats = layout.write_tree(
        ctx, args.outdir,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'runtime'),
        {'config': cfg, 'decls': decls, 'api': api_header,
         'ro': ro_lines, 'rw': rw_lines, 'text': text_lines,
         'dispatch': dispatch, 'thunks': thunks, 'entries': entries,
         'ro_blob': getattr(ctx, 'ro_blob', None),
         'helpers': helper_defs, 'function_count': len(done),
         'aggregate_decls': aggregate_decls,
         'pruned': writer.prune()})

    # Now that dispatch.c and the aggregate files are on disk, drop the
    # function files nothing can reach.  See FunctionWriter.prune_unreachable:
    # these are orphan jump-table arms whose owner also emits them, and the
    # linker discards every one of them today -- this just stops generating and
    # compiling them in the first place.
    print("  Pruning unreachable functions...                   ", end = "\r")
    unreachable = writer.prune_unreachable(args.outdir)
    # Note the folds that SURVIVED, not the folds attempted.  A fold whose file
    # the prune then deletes changed nothing about the tree, and how many of
    # those happen depends on the order functions were emitted in -- it moved
    # by 98 between `-j1` and `-j N` while the tree stayed identical.
    _folded = getattr(ctx, 'folded_addrs', set())
    if _folded:
        _live = sum(1 for a in _folded
                    if ('f_%08x.c' % a) in writer.written)
        ctx.notes.append(('subset functions folded into their container',
                          _live, ''))
    if unreachable:
        stats['files'] -= unreachable
        print('  %d unreachable function files removed (orphan jump-table arms '
              'their owning function already emits)' % unreachable)



    # Audit trail: every decision that could be wrong is written down.
    print("  Emitting audit...                   ", end = "\r")
    audit = {
        'binary': os.path.abspath(args.binary),
        'translated': ['%#x' % a for a in sorted(done)],
        'untranslated_referenced': ['%#x' % a for a in missing],
        'imports': sorted(ctx.imports_used),
        # DEDUPED, and order-preserving.  The raw log records one entry per
        # rewrite PERFORMED, so the same constant appears once for every block
        # that mentions it -- and how many times a block is walked is work, not
        # output: `-j N` reaches the same tree having lifted some blocks a
        # different number of times, which moved this count by 288 and nothing
        # else.  An audit of what the tree contains should not move with that.
        'const_rewrites': [{'addr': '%#x' % a, 'kind': k, 'name': n}
                           for a, k, n in _dedupe(ctx.const_log)[:20000]],
        'const_rewrite_count': len(_dedupe(ctx.const_log)),
        'text_read_as_data': ctx.text_data_used,
        'notes': [list(map(str, n)) for n in ctx.notes],
    }
    json.dump(audit, open(os.path.join(args.outdir, 'audit.json'), 'w'), indent=1)

    n_changed = len(writer.changed_files)
    n_files = len(writer.written)
    print('  %d of %d function files changed on disk -- that is what make will '
          'rebuild (%d write calls; a folded function is written twice)'
          % (n_changed, n_files, writer.write_calls))
    print('wrote %s: %d source files, %d functions, %d stubs, %d pruned, %.1f s'
          % (args.outdir, stats['files'], len(done), len(missing),
             stats.get('pruned', 0), time.time() - t0))
    for n in ctx.notes[:20]:
        print('  note:', n)


if __name__ == '__main__':
    main()