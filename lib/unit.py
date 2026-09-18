"""
unit.py -- assemble the whole generated translation unit.

Split out from gen.py because this part is about the *shape* of the output
file (arrays, relocation, thunks, wrappers) rather than about instruction
semantics.
"""

import os
import re

_HELPER_SIG = re.compile(
    r'^(?:static inline\s+)?((?:U128|U256|uint\d+_t)\s+v[\w]*\s*\([^)]*\))\s*\{')

from gen import (ALL_SIGS, DATA_IMPORTS, EXTERN_PROTOS, IGNORED_IMPORTS,
                 RUNTIME_IMPORTS, SETJMP_NAMES, CTYPE, cname, marshal_call)

import elfcompat


# ------------------------------------------------------------- byte arrays

_ESCAPES = {0x22: '\\"', 0x5C: '\\\\', 0x3F: '\\?'}


def c_bytes_literal(data, per_line=100):
    """Render bytes as concatenated C string literals.

    Printable bytes go out as themselves, everything else as a three-digit
    octal escape (octal avoids the "\\xAB" + hex-digit run-on that bites hex
    escapes).  This is several times smaller than a 0x00, array and compiles
    much faster.
    """
    lines = []
    cur = []
    width = 0
    for b in data:
        if b in _ESCAPES:
            piece = _ESCAPES[b]
        elif 0x20 <= b < 0x7F:
            piece = chr(b)
        else:
            piece = '\\%03o' % b
        cur.append(piece)
        width += len(piece)
        if width >= per_line:
            lines.append('"%s"' % ''.join(cur))
            cur, width = [], 0
    if cur:
        lines.append('"%s"' % ''.join(cur))
    if not lines:
        lines.append('""')
    return lines


def emit_ro(ctx, out):
    """The read-only image, pulled in from a sibling binary file.

    `#embed` (C23) and nothing else: the bytes are data, they are not C, and
    they are not assembly.  Any other spelling -- a C array of ~3 MB, or an
    `.incbin` in an `__asm__` block -- is a conversion of the same bytes into a
    second language, and each of those languages has its own dialects to get
    wrong.  So this requires GCC 15 / clang 19 or newer, deliberately.
    """
    if not ctx.ro:
        return
    lo, hi, _ = ctx.ro
    data = bytes(ctx.proj.loader.memory.load(lo, hi - lo))
    ctx.ro_blob = data              # layout.py writes it beside this file
    n = len(data)
    out.append('/* read-only image: [%#x,%#x) of the input, %d bytes.'
               % (lo, hi, n))
    out.append(' * The bytes are in data_ro.bin; see emit_ro() in unit.py. */')
    out.append('')
    out.append('#if !defined(__has_embed)')
    out.append('#  error "a C23 compiler with #embed is required '
               '(GCC 15+, clang 19+)"')
    out.append('#elif !__has_embed("data_ro.bin")')
    out.append('#  error "data_ro.bin must sit beside this file"')
    out.append('#endif')
    out.append('')
    out.append('/* The path is relative to THIS file, so it does not depend')
    out.append(' * on the directory make happens to run from; and the array is')
    out.append(" * unbounded because the size is data_ro.bin's, which #embed")
    out.append(' * already knows. */')
    out.append('const uint8_t g_ro[] = {')
    out.append('#embed "data_ro.bin"')
    out.append('};')
    out.append('')


def emit_rw(ctx, out):
    """The writable image, as an array of relocating slots.

    Every pointer in this image used to be patched at startup by a generated
    guest_relocate() -- 44,241 stores, plus the ~1 MB of C that held them, plus
    a byte array holding the un-relocated bytes those stores immediately
    overwrote.

    All of that is what a C initialiser already expresses.  A slot naming an
    address becomes `.p = &f_00401480`, which the LINKER resolves; a slot
    holding data becomes `.u = <bits>`.  So the relocation pass, its output
    file and its startup cost all disappear, and the loader maps the finished
    image straight from .data.

    Two properties of this binary make it work, both checked rather than
    assumed: every relocated slot is 8-byte aligned (all 44,241 of them), and
    the image is a whole number of slots.  A misaligned slot would need the old
    byte-wise patching, so it is a hard error rather than a silent miss.
    """
    lo, hi, fsz = ctx.rw
    size = hi - lo
    if size % 8:
        raise RuntimeError('RW image %#x is not a whole number of 8-byte slots'
                           % size)
    data = bytearray(ctx.proj.loader.memory.load(lo, fsz))
    data.extend(b'\0' * (size - fsz))            # .bss
    nslots = size // 8

    reloc = {}
    for off, slot, note in ctx.reloc_rows:
        if off % 8:
            raise RuntimeError('relocation at RW offset %#x is not slot aligned'
                               % off)
        reloc[off // 8] = (slot, note)

    out.append('/* writable image: [%#x,%#x), %d bytes from file + %d bytes bss.'
               % (lo, hi, fsz, size - fsz))
    out.append(' * %d slots, of which %d are relocated pointers the linker')
    out[-1] = out[-1] % (nslots, len(reloc))
    out.append(' * resolves and the rest are data.  Slots that are zero in both')
    out.append(' * the image and the relocations are omitted: a designated')
    out.append(' * initialiser zero-fills them, which is also what .bss needs. */')
    out.append('g_rw_slot g_rw[%d] = {' % nslots)

    emitted = 0
    for i in range(nslots):
        if i in reloc:
            (field, expr), note = reloc[i]
            out.append('    [%d] = { .%s = %s },   /* %s */'
                       % (i, field, expr, note))
            emitted += 1
            continue
        word = int.from_bytes(data[i * 8:(i + 1) * 8], 'little')
        if word:
            out.append('    [%d] = { .u = UINT64_C(%#018x) },' % (i, word))
            emitted += 1
    out.append('};')
    out.append('')
    ctx.notes.append(('rw slots', nslots,
                      '%d initialised (%d relocated), %d left zero'
                      % (emitted, len(reloc), nslots - emitted)))


def emit_sections(ctx, out):
    ld = ctx.proj.loader

    # --- code image, only when the binary reads its own text as data -------
    if ctx.text_data_used:
        lo, hi, fsz = ctx.rx
        data = bytes(ld.memory.load(lo, hi - lo))
        out.append('/* code image, referenced as DATA by the translated code */')
        out.append('const uint8_t g_text_data[%d] =' % len(data))
        out.extend(c_bytes_literal(data))
        out.append(';')
        out.append('')


# ------------------------------------------------------------- relocation

def collect_relocations(ctx):
    """Resolve every relocated pointer in the RW image to a host address.

    Each RELATIVE relocation names a guest address; the slot gets the host
    address of whatever now holds that address -- an array element, a
    generated function, or an import thunk.  JUMP_SLOT/GLOB_DAT slots get the
    thunk for the imported symbol.

    This used to EMIT the stores that did the patching.  It now only resolves
    them; emit_rw() turns the result into initialisers, so the linker performs
    the relocation and nothing runs at startup.  The expressions are unchanged
    -- still symbolic, never a literal address.

    Must run before the declarations are computed: resolving a relocation can
    be what first marks a function as referenced, or an import as used.
    """
    rwlo = ctx.rw[0]
    rows = []
    unresolved = 0

    for r in ctx.mo.relocs:
        kind = type(r).__name__
        slot = r.rebased_addr
        if not ctx.in_rw(slot):
            continue                      # spec: only RW gets relocated
        off = slot - rwlo

        # Matched by CLASS, not by class name: a packed RELR entry (DT_RELR)
        # is a GenericRelativeReloc, of which R_AARCH64_RELATIVE is a
        # subclass, and a name test would see none of subsdk0.elf's 70,917
        # relative relocations -- every pointer in .data would then be left as
        # an unrelocated guest address and fault on first use.
        if elfcompat.is_relative(r):
            target = r.value
            slot = ctx.reloc_slot(target)
            if slot is None:
                unresolved += 1
                continue
            rows.append((off, slot, '%#x' % target))
        elif kind in ('R_AARCH64_JUMP_SLOT', 'R_AARCH64_GLOB_DAT',
                      'R_AARCH64_ABS64'):
            sym = r.symbol
            nm = sym.name if sym is not None else None
            if not nm:
                unresolved += 1
                continue
            # ABS64 carries an addend, and it is not decorative: a C++ typeinfo
            # object stores `vtable + 0x10`, the address of the vtable's first
            # virtual slot, and that is the value the exception matcher
            # compares against.  JUMP_SLOT and GLOB_DAT never have one.
            addend = getattr(r, 'addend', 0) or 0
            if nm in IGNORED_IMPORTS:
                # Left NULL: the port does not model these, and calls to them
                # are dropped at the call site rather than routed to a thunk.
                rows.append((off, ('u', 'UINT64_C(0)'), '%s (not modelled)' % nm))
                continue
            if nm in ctx.defined_syms:
                # Defined here and merely routed through the GOT.
                target = ctx.defined_syms[nm]
                # A CODE target goes through reloc_slot() so that it gets the
                # one representation of a guest code pointer -- the guest
                # address -- exactly as a relative relocation to the same
                # function would.  Two GOT slots for the same function, one
                # written here and one written there, otherwise held values
                # that did not compare equal (gen.py, under reloc_addr()).
                # The addend is applied to the GUEST address, which is what it
                # means: `typeinfo + 0x10` is 16 bytes into the guest object,
                # not 16 bytes into a host function's machine code.
                slot = ctx.reloc_slot(target + addend)
                if slot is not None:
                    rows.append((off, slot, '%s (defined locally)' % nm))
                    continue
                ctx.referenced.add(target)
                ctx.func_set.add(target)
                expr = '(const void *)&%s' % cname(target)
                if addend:
                    expr = '(const void *)((const char *)&%s + %d)' % (
                        cname(target), addend)
                rows.append((off, ('p', expr),
                             '%s (defined locally)' % nm))
                continue
            if nm in DATA_IMPORTS:
                # An imported OBJECT, not an imported function.  Pointing the
                # slot at a `plt_` thunk would hand the guest the address of
                # host code and it would load the first eight bytes of that
                # code as the object's contents.
                ctx.imports_used.add(nm)
                base = DATA_IMPORTS[nm][0]
                if addend:
                    expr = '(const void *)((const char *)(%s) + %d)' % (base, addend)
                else:
                    expr = '(const void *)(%s)' % base
                rows.append((off, ('p', expr), '%s (data)' % nm))
                continue
            ctx.imports_used.add(nm)
            expr = '(const void *)&plt_%s' % nm
            if addend:
                expr = '(const void *)((const char *)&plt_%s + %d)' % (nm, addend)
            rows.append((off, ('p', expr), nm))
        else:
            unresolved += 1

    ctx.reloc_rows = rows
    ctx.notes.append(('relocations', len(rows), 'unresolved=%d' % unresolved))
    return len(rows), unresolved


def emit_thunks(ctx, out):
    """One C function per imported symbol, moving arguments between the guest
    register file and the host ABI."""
    xo = [ctx.off['x%d' % i] for i in range(8)]
    qo = ctx.qoff
    todo = []

    out.append('/* ---- imported symbols ---- */')
    protos = [EXTERN_PROTOS[n] for n in sorted(ctx.imports_used)
              if n in EXTERN_PROTOS]
    if protos:
        out.append('/* not declared by any C library header */')
        out.extend(protos)
        out.append('')

    for nm in sorted(ctx.imports_used):
        if nm in ctx.defined_syms:
            continue
        if nm in DATA_IMPORTS and nm not in ALL_SIGS:
            # Data only: the declaration above is the whole of it.
            continue
        if nm in IGNORED_IMPORTS:
            # Not modelled and not emitted at all: calls to these are dropped
            # at the call site, so no symbol needs to exist.
            continue
        if nm in RUNTIME_IMPORTS:
            continue                      # hand-written in guest_va.c
        if nm in SETJMP_NAMES:
            # Reached only if something takes setjmp's address; a real call is
            # expanded inline and never comes through here.
            out.append('void plt_%s(cpu_t *cpu, uint64_t entry) { (void)entry; guest_unsupported_import(cpu, "%s via pointer"); }'
                       % (nm, nm))
            out.append('')
            continue

        sig = ALL_SIGS.get(nm)
        if sig is None:
            # Not a C library function and no signature known: a weak stub the
            # integrator can override with the real implementation.
            out.append('__attribute__((weak)) uint64_t %s(uint64_t a0, uint64_t a1, uint64_t a2,' % nm)
            out.append('        uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {')
            out.append('    (void)a0; (void)a1; (void)a2; (void)a3;')
            out.append('    (void)a4; (void)a5; (void)a6; (void)a7;')
            out.append('    guest_missing_import("%s");' % nm)
            out.append('    return 0;')
            out.append('}')
            out.append('void plt_%s(cpu_t *cpu, uint64_t entry) { (void)entry;' % nm)
            out.append('    GST_I64(%d) = %s(%s);' % (
                xo[0], nm, ', '.join('GST_I64(%d)' % o for o in xo)))
            out.append('}')
            out.append('')
            todo.append(nm)
            continue

        ret, args = sig
        if 'V' in args or ret == 'J':
            out.append('void plt_%s(cpu_t *cpu, uint64_t entry) { (void)entry; guest_unsupported_import(cpu, "%s"); }'
                       % (nm, nm))
            out.append('')
            todo.append(nm + (' (variadic)' if 'V' in args else ' (setjmp)'))
            continue

        # A direct call site pastes this same marshalling inline; the thunk
        # exists only so the symbol has an address for vtable slots and other
        # indirect uses.
        out.append('void plt_%s(cpu_t *cpu, uint64_t entry) { (void)entry;' % nm)
        out.extend(marshal_call(ctx, nm, sig))
        out.append('}')
        out.append('')

    ctx.notes.append(('imports needing work', len(todo), ', '.join(todo)))
    return todo


def data_import_decls(ctx):
    """Declarations for the imported OBJECTS this binary uses.

    These go in guest_decls.h rather than in thunks.c, because the file that
    names them is data_rw.c: an imported object's address is a static
    initialiser of the writable image, so the declaration has to be visible
    where the image is defined, not where the thunks are.
    """
    names = [n for n in sorted(ctx.imports_used) if n in DATA_IMPORTS]
    if not names:
        return []
    out = ['/* Imported DATA objects.  A GOT slot for one of these holds the',
           ' * address of an OBJECT, so it cannot point at a `plt_` thunk --',
           ' * the guest would load the first eight bytes of host code as the',
           ' * object.  guest_cxx.c defines them. */']
    for n in names:
        out.append(DATA_IMPORTS[n][1])
    out.append('')
    return out


def thunk_names(ctx):
    """Imports that actually get a plt_ symbol.

    An imported OBJECT gets no thunk (there is nothing to call), so declaring
    one would be a prototype for a function that is never defined -- and where
    the object is also named by a relocation, a link error.  The exception is
    an import that is both: __gxx_personality_v0 is stored in .data by a
    relocation AND has a signature, so it gets both a declaration and a thunk.
    """
    return sorted(n for n in ctx.imports_used
                  if n not in ctx.defined_syms and n not in IGNORED_IMPORTS
                  and (n not in DATA_IMPORTS or n in ALL_SIGS))


def emit_dispatch(ctx, out, table):
    """Table mapping an original guest address to its translated entry.

    Needed because a computed branch target is only meaningful in the ORIGINAL
    layout: the guest adds a jump-table offset to a code address, which lands
    in g_text_data.  guest_addr_of() turns that back into the address the
    original binary would have jumped to, and this table turns THAT into the
    C function that now implements it.
    """
    rows = sorted(table.items())
    base = ctx.rx[0]        # the executable segment's vaddr; see Ctx.rx

    # THREE PARALLEL ARRAYS, not an array of 24-byte structs.
    #
    # The struct form was { uint64_t addr; guest_fn fn; uint64_t entry; }, and
    # every one of those three fields was bigger than it needed to be:
    #
    #   * `entry` is either 0 (the address IS the function's own start) or
    #     EXACTLY `addr` -- checked over all 801,609 entries of glslc.elf and
    #     all of subsdk0.elf's, no exceptions.  So it is one bit, not 8 bytes.
    #   * `addr` is the image base plus an offset that is smaller than the
    #     text segment (0x601cf4 here, 0x1136900 on subsdk0), so it is a
    #     uint32 offset.
    #   * `fn` repeats: 801,609 entries name only 20,541 distinct functions,
    #     so it is a uint32 index into a table of them.
    #
    # 19.24 MB -> 6.58 MB on glslc.elf, and the SEARCH gets faster with it:
    # it now walks a contiguous uint32 array instead of striding 24 bytes
    # through 19 MB, which is a quarter of the cache footprint per probe.
    #
    # The interior-block bit rides in g_entry_fn, not in g_entry_off.  Guest
    # addresses are NOT all 4-byte aligned -- glslc.elf has an entry at offset
    # 1 -- so bit 0 of the offset is not free; and keeping the searched array
    # free of flag bits means the hot loop compares raw values with no mask.
    fns = []
    fn_index = {}
    for _addr, (fn_addr, _entry) in rows:
        if fn_addr not in fn_index:
            fn_index[fn_addr] = len(fns)
            fns.append(fn_addr)

    out.append('/* %d reachable guest addresses, sorted; %d distinct functions */'
               % (len(rows), len(fns)))
    out.append('#define GUEST_ENTRY_COUNT %d' % len(rows))
    out.append('#define GUEST_ENTRY_BASE UINT64_C(%#x)' % base)
    out.append('#define GUEST_ENTRY_INTERIOR UINT32_C(0x80000000)')
    out.append('')
    out.append('/* guest address - GUEST_ENTRY_BASE, ascending.  The only array')
    out.append(' * the binary search reads. */')
    out.append('static const uint32_t g_entry_off[GUEST_ENTRY_COUNT] = {')
    _chunk = []
    for addr, (_fn_addr, _entry) in rows:
        _chunk.append('%#x,' % (addr - base))
        if len(_chunk) == 12:
            out.append('    ' + ' '.join(_chunk)); _chunk = []
    if _chunk:
        out.append('    ' + ' '.join(_chunk))
    out.append('};')
    out.append('')
    out.append('/* index into g_entry_fns, with GUEST_ENTRY_INTERIOR set when the')
    out.append(' * address is a block INSIDE the function rather than its start. */')
    out.append('static const uint32_t g_entry_fn[GUEST_ENTRY_COUNT] = {')
    _chunk = []
    for addr, (fn_addr, entry) in rows:
        v = fn_index[fn_addr] | (0x80000000 if entry else 0)
        _chunk.append('%#x,' % v)
        if len(_chunk) == 12:
            out.append('    ' + ' '.join(_chunk)); _chunk = []
    if _chunk:
        out.append('    ' + ' '.join(_chunk))
    out.append('};')
    out.append('')
    out.append('static const guest_fn g_entry_fns[%d] = {' % len(fns))
    _chunk = []
    for fn_addr in fns:
        _chunk.append('&%s,' % cname(fn_addr))
        if len(_chunk) == 4:
            out.append('    ' + ' '.join(_chunk)); _chunk = []
    if _chunk:
        out.append('    ' + ' '.join(_chunk))
    out.append('};')
    out.append('')
    out.append('/* Resolve an original guest address to an index, or -1. */')
    out.append('static long guest_lookup(uint64_t addr) {')
    out.append('    uint64_t rel = addr - GUEST_ENTRY_BASE;')
    out.append('    if (rel > UINT32_MAX) return -1;')
    out.append('    uint32_t key = (uint32_t)rel;')
    out.append('    size_t lo = 0, hi = GUEST_ENTRY_COUNT;')
    out.append('    while (lo < hi) {')
    out.append('        size_t mid = lo + (hi - lo) / 2;')
    out.append('        uint32_t v = g_entry_off[mid];')
    out.append('        if (v == key) return (long)mid;')
    out.append('        if (v < key) lo = mid + 1; else hi = mid;')
    out.append('    }')
    out.append('    return -1;')
    out.append('}')
    out.append('')
    # Opt-in ABI check.  A jump-table arm is usually an interior continuation
    # that ends in a shared epilogue, so it POPS a frame it never pushed.  That
    # is correct when the arm is reached by a jump (the pop unwinds the jumping
    # function's frame), and wrong when it is reached by a call whose caller
    # then continues.  Build with -DGUEST_CHECK_ABI to catch the latter.
    out.append('#ifdef GUEST_CHECK_ABI')
    out.append('static void guest_abi_check(uint64_t addr, uint64_t before, uint64_t after) {')
    out.append('    if (before != after)')
    # The newline matters: this fires thousands of times on a real run, and
    # without it every report ran together into one unreadable line.
    out.append('        fprintf(stderr, "guest: dispatch to %#llx changed sp %#llx -> %#llx"')
    out.append('                        " (interior arm reached by a call?)\\n",')
    out.append('                (unsigned long long)addr, (unsigned long long)before,')
    out.append('                (unsigned long long)after);')
    out.append('}')
    out.append('#define GUEST_SP_BEFORE uint64_t _sp_before = GST_I64(%d);' % ctx.off['sp'])
    out.append('#define GUEST_SP_AFTER(a) guest_abi_check((a), _sp_before, GST_I64(%d));'
               % ctx.off['sp'])
    out.append('#else')
    out.append('#define GUEST_SP_BEFORE')
    out.append('#define GUEST_SP_AFTER(a)')
    out.append('#endif')
    out.append('')
    out.append('void guest_dispatch_addr(cpu_t *cpu, uint64_t addr) {')
    out.append('    long i = guest_lookup(addr);')
    out.append('    if (i >= 0) {')
    out.append('        uint32_t f = g_entry_fn[i];')
    # The selector the callee wants is the address itself for an interior
    # block and 0 for a function's own start -- which is what the removed
    # `entry` field held, one bit's worth of information in 8 bytes.
    out.append('        GUEST_SP_BEFORE')
    out.append('        g_entry_fns[f & ~GUEST_ENTRY_INTERIOR](')
    out.append('            cpu, (f & GUEST_ENTRY_INTERIOR) ? addr : UINT64_C(0));')
    out.append('        GUEST_SP_AFTER(addr)')
    out.append('        return;')
    out.append('    }')
    out.append('    guest_unresolved(cpu, addr, "no translation for computed target");')
    out.append('}')
    out.append('')
    out.append('/*')
    out.append(' * An indirect branch or call.  The value arriving here is one of THREE')
    out.append(' * things, and telling them apart is the whole job:')
    out.append(' *')
    out.append(' *   1. a guest address in the code range -- a computed target, look it up;')
    out.append(' *   2. a real host function pointer that relocation stored in a vtable;')
    out.append(' *   3. a HOST pointer derived from an image array by a DATA-RELATIVE')
    out.append(' *      JUMP TABLE, which has to be mapped back to a guest address first.')
    out.append(' *')
    out.append(' * Case 3 is the one that is easy to miss.  The compiler emits switch')
    out.append(' * tables in .rodata holding offsets relative to THE TABLE ITSELF:')
    out.append(' *')
    out.append(' *     adrp x9, <page>; add x9, x9, #<off>   ; x9 = &table   (.rodata)')
    out.append(' *     ldrsw x8, [x9, x8, lsl #2]           ; x8 = table[i]  (signed)')
    out.append(' *     add   x8, x8, x9                     ; target = table[i] + &table')
    out.append(' *     br    x8')
    out.append(' *')
    out.append(' * That one register is used for two incompatible purposes.  The LOAD')
    out.append(" * needs a host pointer, so const_addr rewrites &table to `g_ro + off`")
    out.append(' * and it must -- otherwise ldrsw reads nothing.  But the BRANCH')
    out.append(' * arithmetic is guest-relative: the correct target is')
    out.append(' * `table[i] + <guest address of the table>`, and adding the entry to a')
    out.append(' * host pointer instead produces a host address that points into the')
    out.append(' * read-only image, typically BELOW g_ro because the offsets are')
    out.append(' * negative.  Branching to it lands in data or in unrelated host code.')
    out.append(' *')
    out.append(" * So the host value is converted back: subtract the array's host base")
    out.append(' * and add its guest base.  Note this deliberately does NOT require the')
    out.append(' * value to lie inside the array -- it usually does not, which is why')
    out.append(' * guest_addr_of() (a plain range check) cannot be used here.  The')
    out.append(' * candidate is instead validated by asking whether it names a block the')
    out.append(' * translation actually produced, which a coincidence could not satisfy.')
    out.append(' */')
    lo, hi, _ = ctx.rx
    out.append('void guest_dispatch(cpu_t *cpu, uint64_t p) {')
    out.append('    if (!p) { guest_unresolved(cpu, 0, "call through null pointer"); return; }')
    out.append('    /* 1. already a guest address in the code range. */')
    out.append('    if (p >= UINT64_C(%#x) && p < UINT64_C(%#x)) {' % (lo, hi))
    out.append('        guest_dispatch_addr(cpu, p);')
    out.append('        return;')
    out.append('    }')
    out.append('    /* 3. host pointer produced by data-relative jump-table arithmetic. */')
    out.append('    {')
    out.append('        uint64_t c, in_image = 0;')
    if ctx.ro:
        rlo = ctx.ro[0]
        out.append('        c = p - (uint64_t)(uintptr_t)g_ro + UINT64_C(%#x);' % rlo)
        out.append('        if (c >= UINT64_C(%#x) && c < UINT64_C(%#x)) {' % (lo, hi))
        out.append('            if (guest_lookup(c) >= 0) { guest_dispatch_addr(cpu, c); return; }')
        out.append('            in_image = c;')
        out.append('        }')
    wlo = ctx.rw[0]
    out.append('        c = p - (uint64_t)(uintptr_t)G_RW + UINT64_C(%#x);' % wlo)
    out.append('        if (c >= UINT64_C(%#x) && c < UINT64_C(%#x)) {' % (lo, hi))
    out.append('            if (guest_lookup(c) >= 0) { guest_dispatch_addr(cpu, c); return; }')
    out.append('            if (!in_image) in_image = c;')
    out.append('        }')
    out.append('        /* The value maps into the code segment, so it IS a')
    out.append('         * data-relative branch target -- the translation just')
    out.append('         * has no block there.  Say so, with the GUEST address.')
    out.append('         *')
    out.append('         * Falling through to the host-pointer case instead is')
    out.append('         * what made this class so expensive to find: the port')
    out.append('         * would CALL INTO THE MIDDLE OF A HOST INSTRUCTION and')
    out.append('         * die with SIGILL or a wild store, hundreds of')
    out.append('         * thousands of blocks after the real mistake and with')
    out.append('         * nothing left on the stack to say where it came from.')
    out.append('         * A missing arm is a resolver gap; it should read as')
    out.append('         * one. */')
    out.append('        if (in_image) {')
    out.append('            guest_unresolved(cpu, in_image,')
    out.append('                "data-relative branch target has no translated block");')
    out.append('            return;')
    out.append('        }')
    out.append('    }')
    out.append('    /* 2. a genuine host function pointer. */')
    out.append('    ((guest_fn)(uintptr_t)p)(cpu, 0);')
    out.append('}')
    out.append('')


def emit_addrmap(ctx, out):
    """Map a host pointer back to the guest address it represents.

    Constants that name locations in the image are rewritten to host addresses
    at translation time, so a jump table's computed target comes out as a host
    pointer into one of the arrays.  Recovering the guest address is what lets
    the dispatch switch on the addresses the CFG recovered.
    """
    out.append('/* host pointer -> original guest address */')
    out.append('static inline uint64_t guest_addr_of(uint64_t p) {')
    out.append('    uintptr_t u = (uintptr_t)p;')
    if ctx.ro:
        lo, hi, _ = ctx.ro
        out.append('    if (u >= (uintptr_t)g_ro && u < (uintptr_t)g_ro + %#x)' % (hi - lo))
        out.append('        return UINT64_C(%#x) + (uint64_t)(u - (uintptr_t)g_ro);' % lo)
    lo, hi, _ = ctx.rw
    out.append('    if (u >= (uintptr_t)G_RW && u < (uintptr_t)G_RW + %#x)' % (hi - lo))
    out.append('        return UINT64_C(%#x) + (uint64_t)(u - (uintptr_t)G_RW);' % lo)
    out.append('    return p;   /* already a guest address, or heap */')
    out.append('}')
    out.append('')


def emit_hostmap(ctx, out):
    """Guest address -> host pointer: the inverse of guest_addr_of().

    Needed by the exception support, which reads the .gcc_except_table out of
    the image at run time.  Every pointer inside that table is a GUEST address
    (a pcrel offset is relative to the address of the offset itself), so the
    reader works in guest addresses and converts once, here, to touch the byte.
    """
    out.append('/* original guest address -> host pointer */')
    out.append('static inline void *guest_host_ptr(uint64_t a) {')
    if ctx.ro:
        lo, hi, _ = ctx.ro
        out.append('    if (a >= UINT64_C(%#x) && a < UINT64_C(%#x))' % (lo, hi))
        out.append('        return (void *)(uintptr_t)(g_ro + (a - UINT64_C(%#x)));' % lo)
    lo, hi, _ = ctx.rw
    out.append('    if (a >= UINT64_C(%#x) && a < UINT64_C(%#x))' % (lo, hi))
    out.append('        return (void *)((char *)G_RW + (a - UINT64_C(%#x)));' % lo)
    out.append('    return (void *)(uintptr_t)a;   /* already a host pointer */')
    out.append('}')
    out.append('')


def emit_eh(ctx, out):
    """The parts of the exception support only the generator can know.

    Three things: which address ranges have an exception table and where it is,
    how to snapshot the registers an unwinder restores, and how to hand a
    landing pad its two arguments.  Everything else -- reading the table,
    matching a type, walking the frames -- is in guest_eh.c, which is ordinary
    hand-written code and is the same for every binary.

    A binary with no .eh_frame emits none of this and the weak defaults in
    guest_eh.c stand, so the whole feature costs it nothing.
    """
    if not ctx.eh_regions:
        return

    out.append('/* ---- C++ exception tables ---- */')
    out.append('/* %d functions carry a language-specific data area. */'
               % len(ctx.eh_regions))
    out.append('typedef struct { uint64_t lo, hi, lsda; } guest_eh_region_t;')
    out.append('static const guest_eh_region_t g_eh_regions[] = {')
    for lo, hi, lsda in ctx.eh_regions:
        out.append('    { UINT64_C(%#x), UINT64_C(%#x), UINT64_C(%#x) },'
                   % (lo, hi, lsda))
    out.append('};')
    out.append('#define GUEST_EH_REGION_COUNT %d' % len(ctx.eh_regions))
    out.append('')
    out.append('static const guest_eh_region_t *guest_eh_find(uint64_t pc) {')
    out.append('    size_t lo = 0, hi = GUEST_EH_REGION_COUNT;')
    out.append('    while (lo < hi) {')
    out.append('        size_t mid = lo + (hi - lo) / 2;')
    out.append('        if (pc < g_eh_regions[mid].lo) hi = mid;')
    out.append('        else if (pc >= g_eh_regions[mid].hi) lo = mid + 1;')
    out.append('        else return &g_eh_regions[mid];')
    out.append('    }')
    out.append('    return NULL;')
    out.append('}')
    out.append('')
    out.append('uint64_t guest_eh_region_lsda(uint64_t pc) {')
    out.append('    const guest_eh_region_t *r = guest_eh_find(pc);')
    out.append('    return r ? r->lsda : 0;')
    out.append('}')
    out.append('')
    out.append('uint64_t guest_eh_region_start(uint64_t pc) {')
    out.append('    const guest_eh_region_t *r = guest_eh_find(pc);')
    out.append('    return r ? r->lo : 0;')
    out.append('}')
    out.append('')
    out.append('void *guest_eh_host_of(uint64_t guest_addr) {')
    out.append('    return guest_host_ptr(guest_addr);')
    out.append('}')
    out.append('')

    # The registers a landing pad is entitled to see: the callee-saved integer
    # set, the frame pointer, the stack pointer, and the callee-saved half of
    # the vector file.  The order is private to this pair of functions.
    offs = [ctx.off['x%d' % i] for i in range(19, 30)]     # x19..x29
    offs.append(ctx.off['sp'])
    vecs = [ctx.qoff + 16 * i for i in range(8, 16)]       # d8..d15
    total = len(offs) + len(vecs)
    out.append('/*')
    out.append(' * x19..x29, sp, and the low halves of q8..q15 -- exactly the')
    out.append(' * registers AAPCS64 makes a callee preserve, which is exactly the')
    out.append(' * set an unwinder restores.  %d words; guest_rt.h reserves' % total)
    out.append(' * GUEST_EH_SAVE_WORDS for them.')
    out.append(' */')
    out.append('void guest_eh_snapshot(cpu_t *cpu, uint64_t *out) {')
    for i, o in enumerate(offs + vecs):
        out.append('    out[%d] = GST_I64(%d);' % (i, o))
    out.append('}')
    out.append('')
    out.append('void guest_eh_unsnapshot(cpu_t *cpu, const uint64_t *in) {')
    for i, o in enumerate(offs + vecs):
        out.append('    GST_I64(%d) = in[%d];' % (o, i))
    out.append('}')
    out.append('')
    out.append('/* A landing pad is entered with the exception object in x0 and the')
    out.append(' * handler selector in x1, exactly as __gxx_personality_v0 leaves them. */')
    out.append('void guest_eh_set_handler_args(cpu_t *cpu, uint64_t x0, uint64_t x1) {')
    out.append('    GST_I64(%d) = x0;' % ctx.off['x0'])
    out.append('    GST_I64(%d) = x1;' % ctx.off['x1'])
    out.append('}')
    out.append('')


# --------------------------------------------------------------- SIMD helpers

def emit_simd(ctx, out, defs=None):
    if defs is None:
        defs = out
    if not ctx.simd_helpers:
        return
    defs.append('/* ---- vector helpers (generated on demand) ---- */')
    for name, (kind, op, lane, count, sym) in sorted(ctx.simd_helpers.items()):
        ut = {8: 'uint8_t', 16: 'uint16_t', 32: 'uint32_t', 64: 'uint64_t'}[lane]
        st = {8: 'int8_t', 16: 'int16_t', 32: 'int32_t', 64: 'int64_t'}[lane]
        total = lane * count
        vt = 'U128' if total <= 128 else 'U256'
        nl = total // lane

        if kind == 'varshift':
            # USHL/SSHL: each lane shifts by its own signed amount; a negative
            # amount shifts right, and an out-of-range amount clears the lane.
            signed = (op == 'S')
            ct = st if signed else ut
            defs.append('%s %s(%s a, %s b) {' % (vt, name, vt, vt))
            defs.append('    %s r; %s av[%d], rv[%d]; %s bv[%d];' % (vt, ut, nl, nl, st, nl))
            defs.append('    memcpy(av, &a, sizeof(av)); memcpy(bv, &b, sizeof(bv));')
            defs.append('    for (int i = 0; i < %d; i++) {' % nl)
            # ARM64 USHL/SSHL take the shift from the LOW 8 BITS of the
            # lane, as a signed byte -- not from the whole lane.  Reading the
            # whole lane made every shift whose control word had rubbish above
            # bit 7 clear the lane instead of shifting it, and on 64-bit lanes
            # the (int) cast truncated as well.  VEX does no masking of its
            # own (`ushl` lifts to a bare Sh32Ux4), so the rule belongs here.
            defs.append('        int sh = (int)(int8_t)(uint8_t)bv[i];')
            defs.append('        if (sh >= %d) rv[i] = 0;' % lane)
            defs.append('        else if (sh >= 0) rv[i] = (%s)(av[i] << sh);' % ut)
            defs.append('        else if (sh <= -%d) rv[i] = %s;'
                        % (lane, ('(%s)((%s)av[i] >> %d)' % (ut, st, lane - 1)) if signed else '0'))
            defs.append('        else rv[i] = (%s)((%s)av[i] >> (-sh));' % (ut, ct))
            defs.append('    }')
            defs.append('    memcpy(&r, rv, sizeof(rv)); return r;')
            defs.append('}')
            continue

        if kind == 'fp3':
            # Packed fused multiply-add: one rounding per lane, exactly as
            # FMLA/FMLS do.  Written out per lane rather than through the
            # two-operand `fp` path above because that path has nowhere to put
            # a third operand -- and because the whole point is that the
            # multiply and the add must NOT be separate operations.
            defs.append('%s %s(%s a, %s b, %s c) {' % (vt, name, vt, vt, vt))
            defs.append('    %s r; %s av[%d], bv[%d], cv[%d], rv[%d];'
                        % (vt, ut, nl, nl, nl, nl))
            defs.append('    memcpy(av, &a, sizeof(av)); memcpy(bv, &b, sizeof(bv));')
            defs.append('    memcpy(cv, &c, sizeof(cv));')
            defs.append('    for (int i = 0; i < %d; i++)' % nl)
            defs.append('        rv[i] = guest_fma%d(av[i], bv[i], cv[i]);' % lane)
            defs.append('    memcpy(&r, rv, sizeof(rv)); return r;')
            defs.append('}')
            continue

        if kind == 'fpneg':
            conv, back = ('f32_of', 'f32_to') if lane == 32 else ('f64_of', 'f64_to')
            defs.append('%s %s(%s a) {' % (vt, name, vt))
            defs.append('    %s r; %s av[%d], rv[%d];' % (vt, ut, nl, nl))
            defs.append('    memcpy(av, &a, sizeof(av));')
            defs.append('    for (int i = 0; i < %d; i++) rv[i] = %s(-%s(av[i]));'
                        % (nl, back, conv))
            defs.append('    memcpy(&r, rv, sizeof(rv)); return r;')
            defs.append('}')
            continue

        if kind == 'fp':
            # Packed float lanes: operate as float/double, and comparisons
            # produce an all-ones mask per lane the way AArch64 does.
            ft = 'float' if lane == 32 else 'double'
            conv, back = ('f32_of', 'f32_to') if lane == 32 else ('f64_of', 'f64_to')
            defs.append('%s %s(%s a, %s b) {' % (vt, name, vt, vt))
            defs.append('    %s r; %s av[%d], bv[%d], rv[%d];' % (vt, ut, nl, nl, nl))
            defs.append('    memcpy(av, &a, sizeof(av)); memcpy(bv, &b, sizeof(bv));')
            sym = {'Add': '+', 'Sub': '-', 'Mul': '*', 'Div': '/'}.get(op)
            cmp_ = {'CmpLT': '<', 'CmpLE': '<=', 'CmpEQ': '=='}.get(op)
            defs.append('    for (int i = 0; i < %d; i++) {' % nl)
            # The min/max forms work on the raw bit patterns (NaN and
            # signed-zero handling needs them), so they get no float locals.
            if sym or cmp_:
                defs.append('        %s x = %s(av[i]), y = %s(bv[i]);'
                           % (ft, conv, conv))
            if sym:
                # Same NaN-sign correction as the scalar path in irtoc.py.
                defs.append('        rv[i] = guest_fcanon%d_2(%s(x %s y), av[i], bv[i]);'
                           % (lane, back, sym))
            elif cmp_:
                defs.append('        rv[i] = (x %s y) ? (%s)~(%s)0 : 0;' % (cmp_, ut, ut))
            elif op in ('Min', 'Max', 'MinNM', 'MaxNM'):
                # NaN and signed-zero handling differs between FMIN/FMAX and
                # FMINNM/FMAXNM; guest_rt.h documents the four rules.  VEX
                # lifts all four to one Iop, so gen.py picks the variant from
                # the guest instruction and it arrives here in `op`.
                defs.append('        rv[i] = guest_f%s%d(av[i], bv[i]);'
                           % (op.lower(), lane))
            else:
                defs.append('        rv[i] = 0; /* unhandled packed-FP op */')
            defs.append('    }')
            defs.append('    memcpy(&r, rv, sizeof(rv)); return r;')
            defs.append('}')
            continue

        if kind == 'shift':
            # ShlN/ShrN/SarN shift every lane by one scalar amount.
            defs.append('%s %s(%s a, uint8_t n) {' % (vt, name, vt))
            defs.append('    %s r; %s av[%d], rv[%d];' % (vt, ut, nl, nl))
            defs.append('    memcpy(av, &a, sizeof(av));')
            if op == 'Shl':
                expr = '(%s)(av[i] << n)' % ut
            elif op == 'Shr':
                expr = '(%s)(av[i] >> n)' % ut
            else:
                expr = '(%s)((%s)av[i] >> n)' % (ut, st)
            defs.append('    for (int i = 0; i < %d; i++) rv[i] = n >= %d ? 0 : %s;'
                       % (nl, lane, expr))
            defs.append('    memcpy(&r, rv, sizeof(rv)); return r;')
            defs.append('}')
            continue

        defs.append('%s %s(%s a, %s b) {' % (vt, name, vt, vt))
        defs.append('    %s r; %s av[%d], bv[%d], rv[%d];' % (vt, ut, nl, nl, nl))
        defs.append('    memcpy(av, &a, sizeof(av)); memcpy(bv, &b, sizeof(bv));')
        if kind == 'arith':
            defs.append('    for (int i = 0; i < %d; i++) rv[i] = (%s)(av[i] %s bv[i]);' % (nl, ut, sym))
        elif kind == 'cmp':
            if op == 'CmpEQ':
                defs.append('    for (int i = 0; i < %d; i++) rv[i] = av[i] == bv[i] ? (%s)~(%s)0 : 0;' % (nl, ut, ut))
            else:
                # CmpGT defaults to signed; CmpGTU/CmpGTS say so explicitly.
                ct = ut if op.endswith('U') else st
                defs.append('    for (int i = 0; i < %d; i++) rv[i] = (%s)av[i] > (%s)bv[i] ? (%s)~(%s)0 : 0;'
                           % (nl, ct, ct, ut, ut))
        elif kind == 'interleave':
            # VEX puts arg2 in the EVEN (low-index) result lanes, arg1 in the
            # odd ones -- the same order the Cat* helpers below already use.
            # Verified from the lifter: `zip1 v0.4s, v1.4s, v2.4s` becomes
            # InterleaveLO32x4(q2, q1) and zip1's result is [Vn0,Vm0,Vn1,Vm1],
            # so the SECOND argument (Vn=v1) supplies lanes 0 and 2.
            # This was the wrong way round and made every widening `sxtl`
            # (lifted as InterleaveLO(src,0) then SarN) return 0.
            half = nl // 2
            if op == 'InterleaveLO':
                defs.append('    for (int i = 0; i < %d; i++) { rv[2*i] = bv[i]; rv[2*i+1] = av[i]; }' % half)
            else:
                defs.append('    for (int i = 0; i < %d; i++) { rv[2*i] = bv[%d+i]; rv[2*i+1] = av[%d+i]; }'
                           % (half, half, half))
        elif kind == 'cat':
            # CatOddLanes takes the odd lanes of b then of a (VEX order).
            first = 1 if op == 'CatOddLanes' else 0
            defs.append('    for (int i = 0; i < %d; i++) rv[i] = bv[2*i+%d];' % (nl // 2, first))
            defs.append('    for (int i = 0; i < %d; i++) rv[%d+i] = av[2*i+%d];'
                       % (nl // 2, nl // 2, first))
        elif kind == 'minmax':
            signed = op.endswith('S')
            ct = st if signed else ut
            cmp_ = '>' if op.startswith('Max') else '<'
            defs.append('    for (int i = 0; i < %d; i++) rv[i] = ((%s)av[i] %s (%s)bv[i]) ? av[i] : bv[i];'
                       % (nl, ct, cmp_, ct))
        defs.append('    memcpy(&r, rv, sizeof(rv)); return r;')
        defs.append('}')
    # fixed helpers
    defs.append('U128 v128_and(U128 a, U128 b){U128 r;r.w[0]=a.w[0]&b.w[0];r.w[1]=a.w[1]&b.w[1];return r;}')
    defs.append('U128 v128_or (U128 a, U128 b){U128 r;r.w[0]=a.w[0]|b.w[0];r.w[1]=a.w[1]|b.w[1];return r;}')
    defs.append('U128 v128_xor(U128 a, U128 b){U128 r;r.w[0]=a.w[0]^b.w[0];r.w[1]=a.w[1]^b.w[1];return r;}')
    defs.append('U128 v128_not(U128 a){U128 r;r.w[0]=~a.w[0];r.w[1]=~a.w[1];return r;}')
    defs.append('U128 v128_from_u64(uint64_t v){U128 r;r.w[0]=v;r.w[1]=0;return r;}')
    defs.append('U128 v128_from_hl(uint64_t h,uint64_t l){U128 r;r.w[0]=l;r.w[1]=h;return r;}')
    defs.append('U128 v128_zero_hi64(U128 a){U128 r;r.w[0]=a.w[0];r.w[1]=0;return r;}')
    defs.append('U128 v128_zero_hi96(U128 a){U128 r;r.w[0]=(uint32_t)a.w[0];r.w[1]=0;return r;}')
    defs.append('U128 v128_zero_hi112(U128 a){U128 r;r.w[0]=(uint16_t)a.w[0];r.w[1]=0;return r;}')
    defs.append('U128 v128_zero_hi120(U128 a){U128 r;r.w[0]=(uint8_t)a.w[0];r.w[1]=0;return r;}')
    defs.append('')



    # Prototypes go in the shared header; the bodies stay in one file, so a
    # new helper does not invalidate every object in the tree.
    for line in list(defs):
        m = _HELPER_SIG.match(line)
        if m:
            out.append(m.group(1) + ';')

# ------------------------------------------------------------ entry wrappers

# Real signatures for the documented entry points.  Anything exported but not
# listed gets a generic wrapper.
ENTRY_SIGS = {
    'glslcInitialize':        ('uint8_t',  [('GLSLCcompileObject *', 'obj')], None),
    'glslcFinalize':          ('void',     [('GLSLCcompileObject *', 'obj')], None),
    'glslcCompile':           ('uint8_t',  [('GLSLCcompileObject *', 'obj')], None),
    'glslcGetDefaultOptions': ('GLSLCoptions', [], 'sret'),
    'glslcGetVersion':        ('GLSLCversion', [], 'sret'),
    'glslcSetAllocator':      ('void', [
        ('void *(*)(size_t, size_t, void *)', 'alloc_fn'),
        ('void (*)(void *, void *)', 'free_fn'),
        ('void *(*)(void *, size_t, void *)', 'realloc_fn'),
        ('void *', 'user_ptr')], None),
    # Added by API 17.24 (subsdk0.elf).  Both were read off the code: each
    # copies the four build-id words and the two hash words between the
    # compile object at +0x768 and the caller's GLSLCdebugDataHash, and
    # returns 1 on success and 0 when either pointer is null.
    'glslcGetDebugDataHash':  ('uint8_t', [('GLSLCcompileObject *', 'obj'),
                                           ('GLSLCdebugDataHash *', 'out')], None),
    'glslcSetDebugDataHash':  ('uint8_t', [('GLSLCcompileObject *', 'obj'),
                                           ('const GLSLCdebugDataHash *', 'hash')], None),
}

# Exports whose exact prototype has not been established.  They still get an
# entry point, because they ARE the library's API and a caller that knows the
# real prototype must be able to reach them; what is not claimed is a typed
# signature.  The wrapper forwards x0..x7 and returns x0, which is what AAPCS64
# does for any all-integer signature -- and all of these were checked not to
# use x8, so none of them returns a struct indirectly.
#
# Documenting them this way rather than guessing is deliberate: a wrong typed
# prototype in a header is worse than an honest untyped one, because the caller
# cannot tell it is wrong.
GENERIC_ENTRY_NOTE = (
    'Prototype not established; arguments are forwarded in x0..x7 and the '
    'result comes back in x0, which is correct for any all-integer signature.')


def _param_decl(t, n):
    """Render a parameter, handling function-pointer types."""
    if '(*)' in t:
        return t.replace('(*)', '(*%s)' % n, 1)
    return '%s%s' % (t, n)


def emit_entries(ctx, out, exports, header=None):
    xo = [ctx.off['x%d' % i] for i in range(9)]

    # The loader runs .init_array at dlopen; nothing in the image calls these.
    # They initialise RW globals the library reads much later, so the port runs
    # them once, from guest_init(), before the first entry point does anything.
    # guest_run_ctors() is declared in guest_rt.h and called there; this is the
    # per-binary body, because only the generator knows the list and its order.
    out.append('/* ---- start-up, in the order a dynamic loader performs it ---- */')
    out.append('/*')
    out.append(' * DT_INIT first, then DT_INIT_ARRAY.  That order, and the fact that it')
    out.append(' * is BOTH and not just the array, is what the reference does -- and in')
    out.append(' * this library `_init` walks the array itself, so every constructor')
    out.append(' * runs twice.  They guard themselves, so the second pass is nearly a')
    out.append(' * no-op; "nearly" is load-bearing, because the few allocations it does')
    out.append(' * make shift every later pointer, and the compiler hashes type objects')
    out.append(' * BY POINTER.  See gen.py IGNORED_FUNCS for the full account.')
    out.append(' */')
    out.append('void guest_run_ctors(cpu_t *cpu) {')
    body = []
    if getattr(ctx, 'init_func', None) is not None:
        body.append('    %s(cpu, 0);   /* DT_INIT */' % cname(ctx.init_func))
    for a in ctx.init_array_order:
        body.append('    %s(cpu, 0);' % cname(a))
    if body:
        out.extend(body)
    else:
        out.append('    (void)cpu;   /* this binary has no start-up code */')
    out.append('}')
    out.append('')

    out.append('/* ---- exported entry points ---- */')
    if header is not None:
        header.append('/* Entry points of the translated binary. */')
        header.append('#ifndef GUEST_API_H')
        header.append('#define GUEST_API_H')
        header.append('#include <stdint.h>')
        header.append('#include <stddef.h>')
        header.append('#include "glslcinterface.h"')
        header.append('#ifdef __cplusplus')
        header.append('extern "C" {')
        header.append('#endif')
    generic = sorted(n for n in exports
                     if n not in ENTRY_SIGS and n.startswith('glslc'))
    for name, addr in sorted(exports.items()):
        sig = ENTRY_SIGS.get(name)
        if sig is None:
            continue
        ret, params, mode = sig
        plist = ', '.join(_param_decl(t, n) for t, n in params) or 'void'
        if header is not None:
            header.append('%s %s(%s);' % (ret, name, plist))
        out.append('%s %s(%s) {' % (ret, name, plist))
        out.append('    cpu_t cpu_s; cpu_t *cpu = &cpu_s;')
        out.append('    guest_init(cpu);')
        if mode == 'sret':
            out.append('    %s _ret;' % ret)
            out.append('    memset(&_ret, 0, sizeof(_ret));')
            # AAPCS64: an indirectly-returned struct is addressed by x8
            out.append('    GST_I64(%d) = (uint64_t)(uintptr_t)&_ret;' % xo[8])
        for i, (t, n) in enumerate(params):
            out.append('    GST_I64(%d) = (uint64_t)(uintptr_t)%s;' % (xo[i], n))
        out.append('    %s(cpu, 0);' % cname(addr))
        out.append('    guest_fini(cpu);')
        if mode == 'sret':
            out.append('    return _ret;')
        elif ret != 'void':
            out.append('    return (%s)GST_I64(%d);' % (ret, xo[0]))
        out.append('}')
        out.append('')
    if generic:
        out.append('/* ---- exported, prototype not established ---- */')
        out.append('/* %s */' % GENERIC_ENTRY_NOTE)
        if header is not None:
            header.append('/* Exports whose prototype is not established.')
            header.append(' * %s */' % GENERIC_ENTRY_NOTE)
    for name in generic:
        addr = exports[name]
        params = ', '.join('uint64_t a%d' % i for i in range(8))
        if header is not None:
            header.append('uint64_t %s(%s);' % (name, params))
        out.append('uint64_t %s(%s) {' % (name, params))
        out.append('    cpu_t cpu_s; cpu_t *cpu = &cpu_s;')
        out.append('    guest_init(cpu);')
        for i in range(8):
            out.append('    GST_I64(%d) = a%d;' % (xo[i], i))
        out.append('    %s(cpu, 0);' % cname(addr))
        out.append('    guest_fini(cpu);')
        out.append('    return GST_I64(%d);' % xo[0])
        out.append('}')
        out.append('')

    if header is not None:
        header.append('#ifdef __cplusplus')
        header.append('}')
        header.append('#endif')
        header.append('#endif /* GUEST_API_H */')
