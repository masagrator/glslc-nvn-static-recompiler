"""
elfcompat.py -- loader compatibility shims shared by every stage.

The toolchain is written against CLE/pyelftools, and those two disagree with
the ELF specification on inputs that the ORIGINAL binary (glslc.elf) never
exercised.  A second version of the same library (subsdk0.elf, a static-PIE
NSO conversion) does exercise them, so the fixes live here rather than being
repeated -- or, worse, only half-applied -- in analyze.py, gen.py, elf2c.py
and vecref.py.

Nothing here is specific to one input: every shim is a correctness fix that is
a no-op on a binary that does not need it, so the old path is unchanged.

  1. RELR (DT_RELR / SHT_RELR) relocations.  glslc.elf stores its ~44,000
     relative relocations as full R_AARCH64_RELATIVE entries in .rela.dyn;
     subsdk0.elf stores 70,917 of them in the packed RELR form.  See
     `_patch_relr()` for the bug that made CLE decode them wrongly.

  2. Relative relocations are not always spelled R_AARCH64_RELATIVE.  CLE
     builds RELR entries as the architecture-independent GenericRelativeReloc,
     of which R_AARCH64_RELATIVE is a subclass, so callers must test by
     isinstance and not by class NAME.  `is_relative()` is that test.

  3. Exact function starts from .eh_frame.  Every FDE names the start of the
     function it describes, which is far better evidence than anything a
     scanner can infer.  `fde_function_starts()` returns them.
"""

import logging

log = logging.getLogger(__name__)

_patched = False


def _patch_relr():
    """Make pyelftools read a RELR table from the stream it was GIVEN.

    `RelrRelocationTable.iter_relocations()` parses its entries out of
    `self._elffile.stream` -- the FILE stream -- while `sh_offset` comes from
    the header it was constructed with.  That is only self-consistent when the
    table came from a real section header, where the offset is a file offset.

    CLE builds a synthetic section for DT_RELR (elf.py, `__register_relocs`)
    whose `sh_offset` is an RVA, and hands it the loaded image by assigning
    `section.stream = self.memory`.  pyelftools ignores that assignment, so it
    reads the RVA as a file offset.  For subsdk0.elf the two differ by 0x2f8
    bytes, and decoding a stream of RELR anchors and bitmaps from 0x2f8 bytes
    early does not fail -- it silently yields a DIFFERENT, plausible-looking
    set: 66,586 relocations instead of 70,917, of which 32 point outside the
    image (CLE logs those as "Malformed relocation: access to unmapped ...",
    which is the only visible symptom) and 4,394 real ones are missing.  Every
    one of those is a pointer in .data that would never be rewritten to a host
    address, so the guest would load an unrelocated guest address and fault on
    the first dereference.

    The fix is one line: prefer the stream the section actually carries.  For a
    real SHT_RELR section that stream IS the file stream and the offset IS a
    file offset, so this is exactly equivalent there.
    """
    from elftools.elf.relocation import RelrRelocationTable, Relocation
    from elftools.common.utils import struct_parse
    from elftools.common.utils import elf_assert
    from elftools.construct.lib import Container

    if getattr(RelrRelocationTable, '_elf2c_patched', False):
        return

    def iter_relocations(self):
        if self._size == 0:
            return
        # The stream assigned to the section wins; fall back to the file.
        stream = getattr(self, 'stream', None)
        if stream is None:
            stream = self._elffile.stream
        addr_size = self._elffile.structs.Elf_addr('').sizeof()

        limit = self._offset + self._size
        relr = self._offset
        base = None
        while relr < limit:
            entry = struct_parse(self._relr_struct, stream, stream_pos=relr)
            entry_offset = entry['r_offset']
            if (entry_offset & 1) == 0:
                base = entry_offset + self._entrysize
                yield Relocation(entry, self._elffile)
            else:
                elf_assert(base is not None, 'RELR bitmap without base address')
                i = 0
                while True:
                    entry_offset = entry_offset >> 1
                    if entry_offset == 0:
                        break
                    if (entry_offset & 1) != 0:
                        yield Relocation(
                            Container(r_offset=base + i * self._entrysize),
                            self._elffile)
                    i += 1
                base += (8 * self._entrysize - 1) * addr_size
            relr += self._entrysize

    RelrRelocationTable.iter_relocations = iter_relocations
    RelrRelocationTable._elf2c_patched = True


def apply():
    """Install every shim.  Idempotent; call it before loading a binary."""
    global _patched
    if _patched:
        return
    _patch_relr()
    _patched = True


def is_relative(reloc):
    """True for a relative (base-only) relocation, however it was spelled.

    R_AARCH64_RELATIVE from .rela.dyn and a packed RELR entry are the same
    thing to this toolchain -- "the image's load base has to be added here" --
    but CLE gives them different classes, so a name test misses one of them.
    """
    from cle.backends.elf.relocation.generic import GenericRelativeReloc
    return isinstance(reloc, GenericRelativeReloc)


def fde_function_starts(main_object):
    """Function start addresses taken from .eh_frame, as rebased addresses.

    Every FDE's `initial_location` is the first byte of the region its unwind
    information describes, which for a compiler's output is a function start.
    This is the single best seed source there is: it is recorded by the
    compiler rather than inferred by a scanner, and it covers functions that
    are only ever reached by a computed branch -- exactly the case where a
    scanner leaves a 637 KB hole and one recovered "function" swallows it
    (HANDOVER.md section 16).

    Parsed with `ehframe.parse`, the same reader the exception support uses,
    rather than through pyelftools' DWARF layer: this binary class carries a
    section header table that pyelftools declines to read .eh_frame through,
    and having one parser means the seeds and the LSDA lookups can never
    disagree about where an FDE starts.

    Returns an empty set when the binary has no .eh_frame, so a caller can use
    it unconditionally.
    """
    import ehframe

    starts = set()
    try:
        fdes = ehframe.from_object(main_object)
    except Exception as exc:                 # pragma: no cover
        log.warning('.eh_frame could not be parsed (%s); no FDE seeds', exc)
        return starts

    lo, hi = None, None
    for seg in main_object.segments:
        if seg.is_executable:
            lo, hi = seg.vaddr, seg.vaddr + seg.memsize
            break
    for a in fdes:
        if lo is not None and not (lo <= a < hi):
            continue
        starts.add(a)
    return starts
