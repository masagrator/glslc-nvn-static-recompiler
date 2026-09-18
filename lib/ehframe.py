"""
ehframe.py -- .eh_frame reader: which functions carry an LSDA.

The generator needs one fact per function: does it have a language-specific
data area (an exception table), and therefore can control ever re-enter it at a
landing pad?  Only those functions pay for the exception machinery -- the entry
snapshot, the setjmp, and the return-address store at every call.

The tables themselves are NOT decoded here.  The call-site table, the action
table and the type table are read at RUN TIME, out of the image the port
already carries, by guest_eh.c.  That split is deliberate:

  * the type table's entries are usually `indirect | pcrel | sdata4`, i.e. an
    offset to a GOT slot that holds the real `std::type_info *`.  In the file
    that slot is ZERO -- it is filled by relocation.  The port's relocation
    rewrites it to a HOST pointer, which is exactly what has to be compared
    against the pointer `__cxa_throw` was given, so reading it at run time
    gets the right answer and reading it at generation time cannot;
  * a pcrel offset is relative to the address of the offset itself, which is a
    guest address; the run-time reader has `guest_addr_of` and works in the
    same space the encoding assumes;
  * and it keeps ~200 lines of encoding rules in one place instead of two.

So this module answers only "where is the LSDA for the function at A", which
is a plain walk of .eh_frame's CIEs and FDEs.

A binary without .eh_frame (glslc.elf has none) yields an empty mapping and
every consumer degrades to the pre-exception behaviour.
"""

import struct

# DWARF exception-header pointer encodings.
DW_EH_PE_omit = 0xFF
DW_EH_PE_uleb128 = 0x01
DW_EH_PE_udata2 = 0x02
DW_EH_PE_udata4 = 0x03
DW_EH_PE_udata8 = 0x04
DW_EH_PE_sleb128 = 0x09
DW_EH_PE_sdata2 = 0x0A
DW_EH_PE_sdata4 = 0x0B
DW_EH_PE_sdata8 = 0x0C

DW_EH_PE_pcrel = 0x10
DW_EH_PE_textrel = 0x20
DW_EH_PE_datarel = 0x30
DW_EH_PE_funcrel = 0x40
DW_EH_PE_aligned = 0x50
DW_EH_PE_indirect = 0x80


class _Reader:
    """A cursor over a bytes object that also knows the address of byte 0.

    `addr` is what a pcrel encoding is relative to, so the two have to travel
    together; keeping them in one object is what stops the offsets and the
    addresses from drifting apart.
    """

    def __init__(self, data, base_addr, pos=0):
        self.d = data
        self.base = base_addr
        self.p = pos

    @property
    def addr(self):
        return self.base + self.p

    def u8(self):
        v = self.d[self.p]
        self.p += 1
        return v

    def u16(self):
        v = struct.unpack_from('<H', self.d, self.p)[0]
        self.p += 2
        return v

    def u32(self):
        v = struct.unpack_from('<I', self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self):
        v = struct.unpack_from('<Q', self.d, self.p)[0]
        self.p += 8
        return v

    def s16(self):
        v = struct.unpack_from('<h', self.d, self.p)[0]
        self.p += 2
        return v

    def s32(self):
        v = struct.unpack_from('<i', self.d, self.p)[0]
        self.p += 4
        return v

    def s64(self):
        v = struct.unpack_from('<q', self.d, self.p)[0]
        self.p += 8
        return v

    def uleb(self):
        r = 0
        shift = 0
        while True:
            b = self.u8()
            r |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                return r

    def sleb(self):
        r = 0
        shift = 0
        while True:
            b = self.u8()
            r |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if b & 0x40:
                    r -= 1 << shift
                return r

    def cstr(self):
        e = self.d.index(b'\0', self.p)
        s = self.d[self.p:e]
        self.p = e + 1
        return s

    def encoded(self, enc):
        """Read one pointer in DWARF exception-header encoding `enc`.

        Returns None for DW_EH_PE_omit.  The indirect bit is NOT followed:
        this module only needs the FDE and LSDA pointers, which are never
        indirect, and following it would mean reading relocated memory that
        does not have its final value until the port is running.
        """
        if enc == DW_EH_PE_omit:
            return None
        fmt = enc & 0x0F
        rel = enc & 0x70
        here = self.addr
        if rel == DW_EH_PE_aligned:
            pad = (-self.p) % 8
            self.p += pad
            here = self.addr
        if fmt == 0x00:
            v = self.u64()
        elif fmt == DW_EH_PE_uleb128:
            v = self.uleb()
        elif fmt == DW_EH_PE_udata2:
            v = self.u16()
        elif fmt == DW_EH_PE_udata4:
            v = self.u32()
        elif fmt == DW_EH_PE_udata8:
            v = self.u64()
        elif fmt == DW_EH_PE_sleb128:
            v = self.sleb()
        elif fmt == DW_EH_PE_sdata2:
            v = self.s16()
        elif fmt == DW_EH_PE_sdata4:
            v = self.s32()
        elif fmt == DW_EH_PE_sdata8:
            v = self.s64()
        else:
            raise ValueError('unknown eh_frame pointer format %#x' % enc)

        if v == 0 and rel == DW_EH_PE_pcrel:
            # A zero pcrel pointer means "absent"; adding `here` would turn it
            # into a bogus address inside the table itself.
            return 0
        if rel == DW_EH_PE_pcrel:
            v += here
        elif rel in (DW_EH_PE_textrel, DW_EH_PE_datarel, DW_EH_PE_funcrel):
            # Not produced by any AArch64 toolchain for these two pointers.
            raise ValueError('unsupported eh_frame relative base %#x' % enc)
        return v & 0xFFFFFFFFFFFFFFFF


class Cie:
    __slots__ = ('code_align', 'data_align', 'ra_reg', 'fde_encoding',
                 'lsda_encoding', 'personality', 'has_aug_len')

    def __init__(self):
        self.code_align = 1
        self.data_align = -4
        self.ra_reg = 30
        self.fde_encoding = 0x00
        self.lsda_encoding = DW_EH_PE_omit
        self.personality = None
        self.has_aug_len = False


def _parse_cie(r, end):
    cie = Cie()
    version = r.u8()
    aug = r.cstr()
    if version >= 4:
        r.u8()          # address_size
        r.u8()          # segment_size
    cie.code_align = r.uleb()
    cie.data_align = r.sleb()
    cie.ra_reg = r.uleb() if version >= 3 else r.u8()
    if aug.startswith(b'z'):
        cie.has_aug_len = True
        aug_len = r.uleb()
        aug_end = r.p + aug_len
        for c in aug[1:]:
            ch = chr(c)
            if ch == 'R':
                cie.fde_encoding = r.u8()
            elif ch == 'L':
                cie.lsda_encoding = r.u8()
            elif ch == 'P':
                enc = r.u8()
                cie.personality = r.encoded(enc & ~DW_EH_PE_indirect)
            elif ch == 'S':
                pass            # signal frame; nothing to read
            elif ch == 'B' or ch == 'G':
                pass            # AArch64 PAuth / MTE markers, no operand
            else:
                # Unknown augmentation: the remaining bytes cannot be parsed,
                # but the augmentation length tells us how to skip them.
                break
        r.p = aug_end
    return cie


def parse(data, base_addr):
    """Walk an .eh_frame image.

    `data` is the section's bytes and `base_addr` the address its first byte
    has when the image is loaded (a rebased address, the toolchain's canonical
    space).

    Returns a dict: function start address -> {'size': n, 'lsda': addr or None}
    """
    out = {}
    cies = {}
    r = _Reader(data, base_addr)
    n = len(data)
    while r.p + 4 <= n:
        entry_start = r.p
        length = r.u32()
        if length == 0:
            break                       # terminator
        if length == 0xFFFFFFFF:
            length = r.u64()
        end = r.p + length
        if end > n:
            break                       # truncated table; stop rather than guess
        cie_id_pos = r.p
        cie_id = r.u32()
        if cie_id == 0:
            cies[entry_start] = _parse_cie(r, end)
        else:
            cie_off = cie_id_pos - cie_id
            cie = cies.get(cie_off)
            if cie is None:
                r.p = end
                continue                # FDE before its CIE: not something a
                                        # linker emits, and unrecoverable here
            pc_begin = r.encoded(cie.fde_encoding)
            # The range is a length, so it is read with the SIZE of the FDE
            # encoding but never its relative base.
            pc_range = r.encoded(cie.fde_encoding & 0x0F)
            lsda = None
            if cie.has_aug_len:
                aug_len = r.uleb()
                aug_end = r.p + aug_len
                if cie.lsda_encoding != DW_EH_PE_omit:
                    v = r.encoded(cie.lsda_encoding)
                    lsda = v if v else None
                r.p = aug_end
            if pc_begin:
                prev = out.get(pc_begin)
                if prev is None or (prev['lsda'] is None and lsda is not None):
                    out[pc_begin] = {'size': pc_range or 0, 'lsda': lsda}
        r.p = end
    return out


def from_object(main_object):
    """Convenience: parse the .eh_frame of a CLE main object.

    Returns ({}, None) when the binary has no .eh_frame, which is how a
    pre-exception input (glslc.elf) takes the old path unchanged.
    """
    sec = None
    for s in main_object.sections:
        if s.name == '.eh_frame' and s.occupies_memory:
            sec = s
            break
    if sec is None:
        return {}
    data = main_object.memory.load(sec.vaddr - main_object.mapped_base, sec.memsize)
    return parse(bytes(data), sec.vaddr)

# --------------------------------------------------------------- landing pads

def landing_pads(read, lsda_addr, func_start):
    """Every landing-pad address in one function's exception table.

    This is the ONE thing the generator has to know about the table's
    contents, and it has to know it before anything is emitted: a landing pad
    is reached only by an unwind, never by a branch, so a CFG scanner never
    discovers it and the code would simply not be translated.  Registering
    them the way a recovered jump-table arm is registered makes them blocks of
    their owning function, with a dispatch case, which is exactly what
    resuming at one needs.

    Only the call-site table is read.  The action and type tables are left for
    run time, where the type pointers have been relocated (see the module
    comment); a landing pad, by contrast, is a plain offset from the landing
    pad base and is fully known here.

    `read(addr, n) -> bytes` reads the loaded image.  Returns a set of
    rebased addresses; an unreadable or malformed table yields an empty set
    rather than raising, because a missing landing pad degrades to "this
    function has no exception support" and a raised exception would lose the
    whole binary.
    """
    out = set()
    try:
        head = read(lsda_addr, 64)
        if not head:
            return out
        r = _Reader(head, lsda_addr)

        lp_enc = r.u8()
        lp_start = func_start
        if lp_enc != DW_EH_PE_omit:
            v = r.encoded(lp_enc)
            if v:
                lp_start = v

        ttype_enc = r.u8()
        if ttype_enc != DW_EH_PE_omit:
            r.uleb()

        cs_enc = r.u8()
        cs_len = r.uleb()
        table_at = r.addr
        if cs_len > (1 << 20):
            return out
        data = read(table_at, cs_len)
        if data is None or len(data) < cs_len:
            return out
        c = _Reader(data, table_at)
        while c.p < cs_len:
            c.encoded(cs_enc)                     # call site start
            c.encoded(cs_enc & 0x0F)              # its length
            lp = c.encoded(cs_enc & 0x0F)         # landing pad, or 0
            c.uleb()                              # action record
            if lp:
                out.add(lp_start + lp)
    except Exception:
        return set()
    return out
