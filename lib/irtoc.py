"""
irtoc.py -- translate VEX IR into C.

The whole point of going through VEX is that instruction semantics are libVEX's
problem, not ours.  What is left here is a mechanical mapping of a small IR:
five statement kinds, a handful of expression kinds, and a set of IROps that is
finite and driven by what the input binary actually uses.

Anything not covered raises UnsupportedIR with the exact op name, so growing
coverage is evidence-driven rather than speculative.
"""

import re

import pyvex


class UnsupportedIR(Exception):
    def __init__(self, what, detail=''):
        super(UnsupportedIR, self).__init__('%s %s' % (what, detail))
        self.what = what
        self.detail = detail


# --------------------------------------------------------------------- types

# VEX IRType -> (C type, width in bits)
TYPES = {
    'Ity_I1':   ('uint8_t',  1),
    'Ity_I8':   ('uint8_t',  8),
    'Ity_I16':  ('uint16_t', 16),
    'Ity_I32':  ('uint32_t', 32),
    'Ity_I64':  ('uint64_t', 64),
    'Ity_I128': ('U128',     128),
    'Ity_F32':  ('uint32_t', 32),    # carried as bit pattern
    'Ity_F64':  ('uint64_t', 64),    # carried as bit pattern
    'Ity_V128': ('U128',     128),
    'Ity_V256': ('U256',     256),
}

UINT = {8: 'uint8_t', 16: 'uint16_t', 32: 'uint32_t', 64: 'uint64_t'}
SINT = {8: 'int8_t', 16: 'int16_t', 32: 'int32_t', 64: 'int64_t'}

# Temp names carry their C type as a suffix.
#
# Temps used to be declared per block, as `t5`, scoped to that block's braces.
# They are now declared once at the top of the function instead, which is what
# removes the duplicate declarations -- the same index is live in many blocks
# and was being redeclared in every one of them.
#
# That only works if a name has ONE type across the whole function, and it does
# not: VEX numbers temps per IRSB, so `t5` is uint32_t in one block and U128 in
# the next.  Putting the type in the name makes the collision impossible rather
# than merely unlikely, so `t5_u32` and `t5_v128` are simply different
# variables and each gets its own declaration.
TSUFFIX = {
    'uint8_t': 'u8', 'uint16_t': 'u16', 'uint32_t': 'u32',
    'uint64_t': 'u64', 'U128': 'v128', 'U256': 'v256',
}


def ctype(ty):
    if ty not in TYPES:
        raise UnsupportedIR('IRType', ty)
    return TYPES[ty][0]


def twidth(ty):
    if ty not in TYPES:
        raise UnsupportedIR('IRType', ty)
    return TYPES[ty][1]


# ------------------------------------------------------------------- helpers

def _mask(bits):
    return (1 << bits) - 1


# Matches a temp that is ALREADY uint64_t.  This used to be `^t\d+$` plus a
# separate `bits == 64` test, because the name alone did not say what type the
# temp had.  Now that the type is in the name the match is exact, so the test
# below cannot elide a cast on a temp that merely happens to be used at 64 bits.
_IS_TEMP_U64 = re.compile(r'^t\d+_u64$')


def _u(bits, e):
    """Reinterpret expression e as an unsigned value of the given width.

    A 64-bit temp is already uint64_t, so re-casting it adds only text -- and
    at roughly a million statements that text was gigabytes.
    """
    if bits == 64 and _IS_TEMP_U64.match(e):
        return e
    return '(%s)(%s)' % (UINT[bits], e)


def _s(bits, e):
    """Reinterpret expression e as a signed value of the given width."""
    return '(%s)(%s)' % (SINT[bits], e)


# ------------------------------------------------------------- op templates
#
# Binops that follow a regular width-suffixed pattern are handled generically;
# only the irregular ones need a table entry.

_ARITH = {
    'Add': '({a} + {b})',
    'Sub': '({a} - {b})',
    'Mul': '({a} * {b})',
    'And': '({a} & {b})',
    'Or':  '({a} | {b})',
    'Xor': '({a} ^ {b})',
}

_SHIFT = {
    'Shl': '({a} << ({b} & {sm}))',
    'Shr': '({a} >> ({b} & {sm}))',            # logical: operand is unsigned
    'Sar': '({sa} >> ({b} & {sm}))',           # arithmetic: signed operand
}

_CMP = {
    'CmpEQ':  '({a} == {b})',
    'CmpNE':  '({a} != {b})',
    'CmpLT':  None,      # needs signedness suffix
    'CmpLE':  None,
    'CmpGT':  None,
    'CmpGE':  None,
}

_DIV = {
    'DivU': '({b} ? ({a} / {b}) : 0)',
    'DivS': '({b} ? ({sa} / {sb}) : 0)',
}


class IRToC(object):
    """Translates one IRSB's expressions and statements into C fragments.

    `ctx` supplies target-specific decisions the IR cannot make on its own:
    how a constant address maps to a section array, what a call target is
    called in C, and so on.
    """

    def __init__(self, ctx, irsb, out):
        self.ctx = ctx
        self.irsb = irsb
        self.out = out            # list of C lines
        self.helpers = set()      # SIMD/FP helpers this block needs
        # `used` (a set of temp INDICES) lived here until temps moved to
        # function scope.  declare_temps() was its only reader and now works
        # from temp_decls instead, which is keyed by NAME -- the index alone can
        # no longer identify a declaration, since one index yields several
        # variables when it appears at several types.  Dropped rather than left
        # write-only.
        self.temp_decls = {}      # name -> declaration, hoisted to function top
        self.cur_insn = None      # guest address of the instruction being lifted
        self.helper_names = set() # vector helpers this block calls
        # Which IR temp each WrTmp defined, and in which guest instruction.
        # Read only by the fused-multiply-add fold: libVEX splits an FMADD
        # into a multiply and an add, and putting them back together needs to
        # know that the add's operand IS that multiply and came from the SAME
        # instruction.  See ctx.fp_is_fused_mac().
        self.tmp_def = {}
        self.dead_mul = None      # temp whose product the fold made unreachable
        self._tname_cache = {}    # temp index -> name; see tname()

    # ------------------------------------------------------------ expressions

    # Statement and expression dispatch, resolved ONCE per class rather than
    # per node.  `getattr(self, '_e_' + type(e).__name__)` builds a string and
    # walks the MRO for every expression in the program; the two dispatchers
    # together were 2.9% of a full run's samples, all of it lookup.  The class
    # of an IR node is a perfectly good dict key, and the table fills itself on
    # first sight of each class, so nothing has to be enumerated by hand.
    _E_DISPATCH = {}
    _S_DISPATCH = {}

    def expr(self, e):
        cls = e.__class__
        fn = IRToC._E_DISPATCH.get(cls)
        if fn is None:
            fn = getattr(IRToC, '_e_' + cls.__name__, None)
            if fn is None:
                raise UnsupportedIR('IRExpr', cls.__name__)
            IRToC._E_DISPATCH[cls] = fn
        return fn(self, e)

    def tname(self, i):
        """Name of temp `i`, carrying its C type so it is unique per type.

        Also records the declaration, since the function -- not the block --
        now owns it and needs the full set at its top.

        Memoised per block: a temp is typically read several times, and this
        was 2.7% of a full run -- rebuilding the same name and rewriting the
        same declaration entry each time.  The type of a temp cannot change
        within an IRSB (tyenv is fixed once the block is lifted), so the first
        answer is the only answer.
        """
        nm = self._tname_cache.get(i)
        if nm is not None:
            return nm
        ct = ctype(self.irsb.tyenv.types[i])
        nm = 't%d_%s' % (i, TSUFFIX[ct])
        self._tname_cache[i] = nm
        self.temp_decls[nm] = '    %s %s;' % (ct, nm)
        return nm

    def _e_RdTmp(self, e):
        return self.tname(e.tmp)

    def _e_Const(self, e):
        return self.const(e.con)

    def _e_Get(self, e):
        w = twidth(e.ty)
        if w in (128, 256):
            return 'gst_get_v%d(cpu, %d)' % (w, e.offset)
        if w == 1:
            return '(GST_I8(%d) & 1)' % e.offset
        return 'GST_I%d(%d)' % (w, e.offset)

    def _e_Load(self, e):
        w = twidth(e.ty)
        if w == 1:
            raise UnsupportedIR('Load', 'Ity_I1')
        return 'ld_%s(%s)' % ('v%d' % w if w >= 128 else 'i%d' % w,
                              self.expr(e.addr))

    def _e_ITE(self, e):
        return '((%s) ? (%s) : (%s))' % (self.expr(e.cond),
                                         self.expr(e.iftrue),
                                         self.expr(e.iffalse))

    def _e_Unop(self, e):
        return self.unop(e.op, self.expr(e.args[0]), e.args[0])

    def _e_Binop(self, e):
        return self.binop(e.op, self.expr(e.args[0]), self.expr(e.args[1]))

    # Iop names of the floating-point add/sub forms a fused multiply-add can
    # arrive as, mapped to the multiply that would have fed them.
    _FMA_PAIRS = {
        'AddF32': 'MulF32', 'SubF32': 'MulF32',
        'AddF64': 'MulF64', 'SubF64': 'MulF64',
    }

    def _fma_fold(self, e):
        """Rebuild a fused multiply-add that libVEX split in two.

        Returns the C expression, or None when this is not one.

        The shape libVEX emits is always the same -- the product is the SECOND
        operand of the add or subtract, and both come from one guest
        instruction:

            t11 = MulF64(rm, x, y)
            t10 = AddF64(rm, acc, t11)        FMADD:  acc + x*y
            t10 = SubF64(rm, acc, t11)        FMSUB:  acc + (-x)*y

        The FNMADD/FNMSUB forms wrap that in a NegF, which needs nothing here:
        negating a correctly-rounded result is exact.

        Three conditions, all necessary.  The instruction must be one of the
        fused forms by its ENCODING (the IR cannot say); the add's second
        operand must be a temp defined by a multiply of the matching type; and
        that multiply must belong to the same guest instruction, so that an
        ordinary `fmul` followed by an unrelated `fadd` is never folded.
        """
        n = e.op[4:] if e.op.startswith('Iop_') else e.op
        packed = re.match(r'^(Add|Sub)(32|64)Fx(\d+)$', n)
        scalar = n in self._FMA_PAIRS
        if not (packed or scalar):
            return None
        if not self.ctx.fp_is_fused_mac(self.cur_insn):
            return None
        prod = e.args[2]
        if type(prod).__name__ != 'RdTmp':
            return None
        # Follow copies.  At opt_level 0 libVEX routinely emits the product
        # into one temp and reads it back through another (`t2 = t11`), so
        # looking only at the immediate definition finds an RdTmp and gives up
        # -- which is exactly what happened to the packed FMLA forms while the
        # scalar ones, which have no copy, folded correctly.
        prod_tmp = prod.tmp
        rec = None
        for _ in range(8):
            rec = self.tmp_def.get(prod_tmp)
            if rec is None:
                return None
            if type(rec[1]).__name__ != 'RdTmp':
                break
            if rec[0] != self.cur_insn:
                return None
            prod_tmp = rec[1].tmp
        else:
            return None
        insn, mul = rec
        if insn != self.cur_insn or type(mul).__name__ != 'Triop':
            return None
        mn = mul.op[4:] if mul.op.startswith('Iop_') else mul.op
        if scalar:
            if mn != self._FMA_PAIRS[n]:
                return None
            w = int(n[-2:])
            x, y = self.expr(mul.args[1]), self.expr(mul.args[2])
            if n.startswith('Sub'):
                x = 'guest_negf%d(%s)' % (w, x)
            self.dead_mul = prod_tmp
            return 'guest_fma%d(%s, %s, %s)' % (w, x, y, self.expr(e.args[1]))

        kind, lane, count = packed.group(1), int(packed.group(2)), int(packed.group(3))
        if mn != 'Mul%dFx%d' % (lane, count):
            return None
        x, y = self.expr(mul.args[1]), self.expr(mul.args[2])
        if kind == 'Sub':
            neg = 'v_neg%dfx%d' % (lane, count)
            self.ctx.need_simd_neg(neg, lane, count)
            self.helper_names.add(neg)
            x = '%s(%s)' % (neg, x)
        h = 'v_fma%dfx%d' % (lane, count)
        self.ctx.need_simd_fma(h, lane, count)
        self.helper_names.add(h)
        self.dead_mul = prod_tmp
        return '%s(%s, %s, %s)' % (h, x, y, self.expr(e.args[1]))

    def _e_Triop(self, e):
        fused = self._fma_fold(e)
        if fused is not None:
            return fused
        return self.triop(e.op, [self.expr(a) for a in e.args])

    def _e_Qop(self, e):
        return self.qop(e.op, [self.expr(a) for a in e.args])

    def _e_CCall(self, e):
        name = e.cee.name
        args = [self.expr(a) for a in e.args]
        if name == 'arm64g_calculate_condition':
            if len(args) != 4:
                raise UnsupportedIR('CCall arity', name)
            return 'arm64g_calculate_condition(%s)' % ', '.join(args)
        if name == 'arm64g_calculate_flags_nzcv':
            return 'arm64g_calculate_flags_nzcv(%s)' % ', '.join(args)
        if name.startswith('arm64g_calculate_flag_'):
            return '%s(%s)' % (name, ', '.join(args))
        raise UnsupportedIR('CCall', name)

    # -------------------------------------------------------------- constants

    def const(self, con):
        ty = con.type
        v = con.value
        if ty == 'Ity_I1':
            return '1' if v else '0'

        # V128/V256 constants are bit patterns: each bit of the (16- or 32-bit)
        # value selects 0x00 or 0xff for one byte lane.
        if ty in ('Ity_V128', 'Ity_V256'):
            nbytes = 16 if ty == 'Ity_V128' else 32
            words = []
            for wi in range(nbytes // 8):
                word = 0
                for byte in range(8):
                    if (v >> (wi * 8 + byte)) & 1:
                        word |= 0xFF << (byte * 8)
                words.append(word)
            return '((%s){{%s}})' % (ctype(ty),
                                     ', '.join('UINT64_C(%#x)' % w for w in words))

        # F32/F64 constants: emit the bit pattern, since temps are containers.
        if ty in ('Ity_F32', 'Ity_F64'):
            import struct
            if ty == 'Ity_F32':
                bits = struct.unpack('<I', struct.pack('<f', float(v)))[0]
                return '%#xU' % bits
            bits = struct.unpack('<Q', struct.pack('<d', float(v)))[0]
            return 'UINT64_C(%#x)' % bits

        w = twidth(ty)
        if w > 64:
            raise UnsupportedIR('Const', ty)
        v &= _mask(w)
        # A constant that lands inside a loaded section is USUALLY an address
        # and must be rewritten to point into the generated arrays.  ctx
        # decides; it also records every rewrite for audit.
        #
        # But "lands inside a section" is a statement about the value, and some
        # integers collide with that range by coincidence.  A move-immediate
        # cannot be an address in this binary, so it is left alone -- see
        # ctx.const_is_immediate_data() for why that is safe.
        if w == 64 and not self.ctx.const_is_immediate_data(self.cur_insn, v):
            repl = self.ctx.const_addr(v)
            if repl is not None:
                return repl
        return 'UINT64_C(%#x)' % v if w == 64 else '%#xU' % v

    # ------------------------------------------------------------------ unops

    def unop(self, op, a, arg=None):
        n = op[4:] if op.startswith('Iop_') else op

        # I128/V128 are C structs, so their halves come out by field access.
        # This must precede the generic width patterns below, which would
        # otherwise emit a shift on a struct.
        if n in ('128to64', 'V128to64'):
            return '((%s).w[0])' % a
        if n in ('128HIto64', 'V128HIto64'):
            return '((%s).w[1])' % a

        # width conversions: <from>Uto<to>, <from>Sto<to>, <from>to<to>
        m = re.match(r'^(\d+)([US])to(\d+)$', n)
        if m:
            fw, sign, tw = int(m.group(1)), m.group(2), int(m.group(3))
            if fw == 1:
                # 1Uto8/32/64: the temp already holds 0/1
                return '(%s)(%s)' % (UINT[tw], a)
            if sign == 'U':
                return '(%s)(%s)' % (UINT[tw], _u(fw, a))
            return '(%s)(%s)' % (UINT[tw], _s(fw, a))

        m = re.match(r'^(\d+)to(\d+)$', n)
        if m:
            fw, tw = int(m.group(1)), int(m.group(2))
            if tw == 1:
                return '(uint8_t)((%s) & 1)' % a
            return '(%s)(%s)' % (UINT[tw], a)

        m = re.match(r'^(\d+)HIto(\d+)$', n)
        if m:
            fw, tw = int(m.group(1)), int(m.group(2))
            return '(%s)((%s) >> %d)' % (UINT[tw], a, tw)

        m = re.match(r'^Not(\d+)$', n)
        if m:
            w = int(m.group(1))
            if w == 1:
                return '(uint8_t)(!(%s))' % a
            return '(%s)(~(%s))' % (UINT[w], a)

        if n == 'NotV128':
            self.helpers.add('v128_not')
            return 'v128_not(%s)' % a

        m = re.match(r'^Clz(\d+)$', n)
        if m:
            return 'guest_clz%s(%s)' % (m.group(1), a)
        m = re.match(r'^Ctz(\d+)$', n)
        if m:
            return 'guest_ctz%s(%s)' % (m.group(1), a)

        if n == '64UtoV128':
            self.helpers.add('v128_from_u64')
            return 'v128_from_u64(%s)' % a
        if n == 'V128to64':
            return '((%s).w[0])' % a
        if n == 'V128HIto64':
            return '((%s).w[1])' % a
        if n == 'ZeroHI64ofV128':
            self.helpers.add('v128_zero_hi64')
            return 'v128_zero_hi64(%s)' % a
        if n == 'ZeroHI96ofV128':
            self.helpers.add('v128_zero_hi96')
            return 'v128_zero_hi96(%s)' % a
        if n == 'ZeroHI112ofV128':
            self.helpers.add('v128_zero_hi112')
            return 'v128_zero_hi112(%s)' % a
        if n == 'ZeroHI120ofV128':
            self.helpers.add('v128_zero_hi120')
            return 'v128_zero_hi120(%s)' % a
        if n == '128to64':
            return '((%s).w[0])' % a
        if n == '128HIto64':
            return '((%s).w[1])' % a

        # Reinterpretations are no-ops in the bit-container model.
        if n in ('ReinterpF64asI64', 'ReinterpI64asF64',
                 'ReinterpF32asI32', 'ReinterpI32asF32'):
            return '(%s)' % a

        # --- floating point, unary ---------------------------------------
        m = re.match(r'^Neg(32|64)Fx(\d+)$', n)
        if m:
            lane, count = int(m.group(1)), int(m.group(2))
            h = 'v_neg%dfx%d' % (lane, count)
            self.ctx.need_simd_neg(h, lane, count)
            return '%s(%s)' % (h, a)

        _UN_FP = {
            'AbsF64': 'guest_absf64', 'NegF64': 'guest_negf64',
            'AbsF32': 'guest_absf32', 'NegF32': 'guest_negf32',
            'F32toF64': 'guest_f32_to_f64',
            'I32StoF64': 'guest_i32s_to_f64', 'I32UtoF64': 'guest_i32u_to_f64',
        }
        if n in _UN_FP:
            return '%s(%s)' % (_UN_FP[n], a)

        # --- vector, unary ------------------------------------------------
        _UN_V = {
            'Cnt8x16': 'guest_cnt8x16',
            'Reverse32sIn64_x2': 'guest_reverse32sin64_x2',
            'NarrowUn64to32x2': 'guest_narrowun64to32x2',
            'NarrowUn32to16x4': 'guest_narrowun32to16x4',
            'NarrowUn16to8x8': 'guest_narrowun16to8x8',
        }
        if n in _UN_V:
            return '%s(%s)' % (_UN_V[n], a)

        raise UnsupportedIR('Iop(unop)', op)

    # ----------------------------------------------------------------- binops

    def binop(self, op, a, b):
        n = op[4:] if op.startswith('Iop_') else op

        m = re.match(r'^(Add|Sub|Mul|And|Or|Xor)(\d+)$', n)
        if m:
            kind, w = m.group(1), int(m.group(2))
            if w == 1:
                sym = {'And': '&', 'Or': '|', 'Xor': '^'}.get(kind)
                if sym:
                    return '(uint8_t)((%s) %s (%s))' % (a, sym, b)
            expr = _ARITH[kind].format(a=_u(w, a), b=_u(w, b))
            return expr if w == 64 else '(%s)%s' % (UINT[w], expr)

        m = re.match(r'^(Shl|Shr|Sar)(\d+)$', n)
        if m:
            kind, w = m.group(1), int(m.group(2))
            return '(%s)%s' % (UINT[w], _SHIFT[kind].format(
                a=_u(w, a), sa=_s(w, a), b='(unsigned)(%s)' % b, sm=w - 1))

        m = re.match(r'^Cmp(EQ|NE)(\d+)$', n)
        if m:
            kind, w = m.group(1), int(m.group(2))
            sym = '==' if kind == 'EQ' else '!='
            return '(uint8_t)(%s %s %s)' % (_u(w, a), sym, _u(w, b))

        m = re.match(r'^Cmp(LT|LE|GT|GE)(\d+)([SU])$', n)
        if m:
            kind, w, sign = m.group(1), int(m.group(2)), m.group(3)
            sym = {'LT': '<', 'LE': '<=', 'GT': '>', 'GE': '>='}[kind]
            conv = _s if sign == 'S' else _u
            return '(uint8_t)(%s %s %s)' % (conv(w, a), sym, conv(w, b))

        m = re.match(r'^Div([US])(\d+)$', n)
        if m:
            sign, w = m.group(1), int(m.group(2))
            tmpl = _DIV['DivS'] if sign == 'S' else _DIV['DivU']
            return '(%s)%s' % (UINT[w], tmpl.format(
                a=_u(w, a), b=_u(w, b), sa=_s(w, a), sb=_s(w, b)))

        m = re.match(r'^Mull([US])(\d+)$', n)
        if m:
            sign, w = m.group(1), int(m.group(2))
            dw = w * 2
            if dw > 64:
                return 'guest_mull%s64(%s, %s)' % (sign.lower(), a, b)
            if sign == 'S':
                return '(%s)((%s)%s * (%s)%s)' % (UINT[dw], SINT[dw], _s(w, a),
                                                  SINT[dw], _s(w, b))
            return '(%s)((%s)%s * (%s)%s)' % (UINT[dw], UINT[dw], _u(w, a),
                                              UINT[dw], _u(w, b))

        if n in ('AndV128', 'OrV128', 'XorV128'):
            h = 'v128_' + n[:-4].lower()
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)

        if n == '64HLtoV128':
            self.helpers.add('v128_from_hl')
            return 'v128_from_hl(%s, %s)' % (a, b)
        if n == '32HLto64':
            return '(((uint64_t)(uint32_t)(%s) << 32) | (uint32_t)(%s))' % (a, b)
        if n == '64HLto128':
            self.helpers.add('v128_from_hl')
            return 'v128_from_hl(%s, %s)' % (a, b)

        # --- floating point compares and conversions ----------------------
        if n == 'CmpF64':
            return 'guest_cmpf64(%s, %s)' % (a, b)
        if n == 'CmpF32':
            return 'guest_cmpf32(%s, %s)' % (a, b)

        # These carry an IRRoundingMode as the first operand.
        _BIN_RM = {
            'F64toF32': 'guest_f64_to_f32',
            'F64toI32S': 'guest_f64_to_i32s', 'F64toI32U': 'guest_f64_to_i32u',
            'F64toI64S': 'guest_f64_to_i64s', 'F64toI64U': 'guest_f64_to_i64u',
            'F32toI32S': 'guest_f32_to_i32s', 'F32toI32U': 'guest_f32_to_i32u',
            'F32toI64S': 'guest_f32_to_i64s', 'F32toI64U': 'guest_f32_to_i64u',
            'I64StoF64': 'guest_i64s_to_f64', 'I64UtoF64': 'guest_i64u_to_f64',
            'I32StoF32': 'guest_i32s_to_f32', 'I32UtoF32': 'guest_i32u_to_f32',
            'I64StoF32': 'guest_i64s_to_f32', 'I64UtoF32': 'guest_i64u_to_f32',
            'RoundF64toInt': 'guest_roundf64toint',
            'RoundF32toInt': 'guest_roundf32toint',
            'SqrtF64': 'guest_sqrtf64', 'SqrtF32': 'guest_sqrtf32',
        }
        if n in _BIN_RM:
            return '%s(%s, %s)' % (_BIN_RM[n], a, b)

        # A few conversions take no rounding mode in VEX's AArch64 output.
        if n == 'I32StoF64':
            return 'guest_i32s_to_f64(%s)' % b
        if n == 'I32UtoF64':
            return 'guest_i32u_to_f64(%s)' % b

        # --- 64x64 -> 128 multiply ----------------------------------------
        if n == 'MullU64':
            return 'guest_mullu64(%s, %s)' % (a, b)
        if n == 'MullS64':
            return 'guest_mulls64(%s, %s)' % (a, b)

        if n == 'Perm8x16':
            return 'guest_perm8x16(%s, %s)' % (a, b)
        if n == 'ShlV128':
            return 'guest_shlv128(%s, (uint8_t)(%s))' % (a, b)
        if n == 'ShrV128':
            return 'guest_shrv128(%s, (uint8_t)(%s))' % (a, b)

        # Sh<lane><S|U>x<n>: per-lane shift by a per-lane signed amount
        # (negative shifts right).  AArch64 USHL/SSHL.
        m = re.match(r'^Sh(\d+)([SU])x(\d+)$', n)
        if m:
            lane, sign, count = int(m.group(1)), m.group(2), int(m.group(3))
            h = 'v_sh%s%dx%d' % (sign.lower(), lane, count)
            self.ctx.need_simd_varshift(h, sign, lane, count)
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)

        if n == 'CatOddLanes32x4':
            return 'guest_catoddlanes32x4(%s, %s)' % (a, b)
        if n == 'CatEvenLanes32x4':
            return 'guest_catevenlanes32x4(%s, %s)' % (a, b)

        # --- packed floating point: Add32Fx4, Mul64Fx2, Min32Fx4, ... ------
        m = re.match(r'^([A-Za-z]+?)(32|64)Fx(\d+)$', n)
        if m:
            kind, lane, count = m.group(1), int(m.group(2)), int(m.group(3))
            # See the triop path: FMAX/FMAXNM share one Iop.
            if kind in ('Min', 'Max') and self.ctx.fp_minmax_is_nm(self.cur_insn):
                kind += 'NM'
            h = 'v_%s%dfx%d' % (kind.lower(), lane, count)
            self.ctx.need_simd_fp(h, kind, lane, count)
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)

        # --- lane shifts by a scalar amount: ShrN16x8 and friends ----------
        m = re.match(r'^(Shl|Shr|Sar)N(\d+)x(\d+)$', n)
        if m:
            kind, lane, count = m.group(1), int(m.group(2)), int(m.group(3))
            h = 'v_%sn%dx%d' % (kind.lower(), lane, count)
            self.ctx.need_simd_shift(h, kind, lane, count)
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)

        # SIMD lane ops: <Op><lane>[S|U]x<count>
        m = re.match(r'^([A-Za-z]+?)(\d+)([SU]?)x(\d+)$', n)
        if m:
            return self.simd_binop(m.group(1), int(m.group(2)), int(m.group(4)),
                                   a, b, op, sign=m.group(3))

        raise UnsupportedIR('Iop(binop)', op)

    def simd_binop(self, kind, lane, count, a, b, op, sign=''):
        if lane not in UINT:
            raise UnsupportedIR('Iop(simd lane)', op)
        # 'CmpGT' + sign 'S'/'U' selects the comparison's signedness; VEX
        # defaults CmpGT to signed when no letter is present.
        if kind in ('CmpGT', 'Max', 'Min') and sign:
            kind = kind + sign
        table = {'Add': '+', 'Sub': '-', 'Mul': '*',
                 'And': '&', 'Or': '|', 'Xor': '^'}
        if kind in table:
            h = 'v_%s%dx%d' % (kind.lower(), lane, count)
            self.ctx.need_simd(h, kind, lane, count, table[kind])
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)
        if kind in ('CmpEQ', 'CmpGT', 'CmpGTU', 'CmpGTS'):
            h = 'v_%s%dx%d' % (kind.lower(), lane, count)
            self.ctx.need_simd_cmp(h, kind, lane, count)
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)
        if kind in ('Max', 'Min', 'MaxU', 'MinU', 'MaxS', 'MinS'):
            h = 'v_%s%dx%d' % (kind.lower(), lane, count)
            self.ctx.need_simd_minmax(h, kind, lane, count)
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)
        if kind in ('CatOddLanes', 'CatEvenLanes'):
            h = 'v_%s%dx%d' % (kind.lower(), lane, count)
            self.ctx.need_simd_cat(h, kind, lane, count)
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)
        if kind in ('InterleaveLO', 'InterleaveHI'):
            h = 'v_%s%dx%d' % (kind.lower(), lane, count)
            self.ctx.need_simd_interleave(h, kind, lane, count)
            self.helpers.add(h)
            self.helper_names.add(h)
            return '%s(%s, %s)' % (h, a, b)
        raise UnsupportedIR('Iop(simd)', op)

    # ----------------------------------------------------------------- triops

    def triop(self, op, args):
        n = op[4:] if op.startswith('Iop_') else op
        if n == 'SliceV128':
            return 'guest_slicev128(%s, %s, %s)' % (args[0], args[1], args[2])
        # AArch64 FP arithmetic carries a rounding mode as arg0; the C
        # equivalent uses the ambient mode, which matches the guest default.
        # Packed FP arithmetic carries a rounding mode as arg0 in this VEX
        # version, so it arrives as a triop rather than a binop.
        m = re.match(r'^([A-Za-z]+?)(32|64)Fx(\d+)$', n)
        if m:
            kind, lane, count = m.group(1), int(m.group(2)), int(m.group(3))
            # VEX lifts FMAX and FMAXNM (and FMIN/FMINNM) to the SAME Iop, so
            # the IR cannot distinguish them; the context decodes the guest
            # instruction and says which one it is.
            if kind in ('Min', 'Max') and self.ctx.fp_minmax_is_nm(self.cur_insn):
                kind += 'NM'
            h = 'v_%s%dfx%d' % (kind.lower(), lane, count)
            self.ctx.need_simd_fp(h, kind, lane, count)
            return '%s(%s, %s)' % (h, args[1], args[2])

        m = re.match(r'^(Add|Sub|Mul|Div)F(32|64)$', n)
        if m:
            kind, w = m.group(1), int(m.group(2))
            sym = {'Add': '+', 'Sub': '-', 'Mul': '*', 'Div': '/'}[kind]
            cv, back = ('f32_of', 'f32_to') if w == 32 else ('f64_of', 'f64_to')
            # guest_fcanonNN_2 replaces a NaN this operation MANUFACTURED with
            # AArch64's positive default NaN; x86 would give the negative one.
            return 'guest_fcanon%d_2(%s(%s(%s) %s %s(%s)), %s, %s)' % (
                w, back, cv, args[1], sym, cv, args[2], args[1], args[2])
        raise UnsupportedIR('Iop(triop)', op)

    def qop(self, op, args):
        raise UnsupportedIR('Iop(qop)', op)

    # ------------------------------------------------------------- statements

    def stmt(self, s):
        cls = s.__class__
        fn = IRToC._S_DISPATCH.get(cls)
        if fn is None:
            fn = getattr(IRToC, '_s_' + cls.__name__, None)
            if fn is None:
                raise UnsupportedIR('IRStmt', cls.__name__)
            IRToC._S_DISPATCH[cls] = fn
        return fn(self, s)

    def _s_IMark(self, s):
        # Which guest instruction the following statements came from.  The
        # constant handler needs it to tell an address from an integer that
        # merely looks like one -- see ctx.const_is_immediate_data().
        self.cur_insn = s.addr

        # One line per guest instruction: invaluable when reading the output,
        # but 21% of its size.  On by default, off with --no-comments when the
        # tree has to fit a disk quota.
        if getattr(self.ctx, 'emit_comments', True):
            self.out.append('    /* %s */' % self.ctx.disasm(s.addr, s.len))

    def _s_AbiHint(self, s):
        pass                       # advisory only

    def _s_NoOp(self, s):
        pass

    def _s_WrTmp(self, s):
        self.dead_mul = None
        rhs = self.expr(s.data)
        if self.dead_mul is not None:
            # The multiply this add consumed was folded into a single fused
            # operation, so the temp libVEX wrote it into now has no reader.
            # It is still ASSIGNED (the statement above emitted it), so the
            # value is computed and thrown away; saying so keeps a reader of
            # the output -- and any -Wunused-but-set-variable build -- from
            # having to work out why.
            self.out.append('    (void)%s;   /* product folded into the fused '
                            'multiply-add below; this VEX temp has no '
                            'remaining reader */' % self.tname(self.dead_mul))
            self.dead_mul = None
        self.out.append('    %s = %s;' % (self.tname(s.tmp), rhs))
        self.tmp_def[s.tmp] = (self.cur_insn, s.data)

    def _s_Put(self, s):
        # A code constant stored into the link register is a return address;
        # control returns there through a C return, never through dispatch, so
        # it must not become a re-entry point.
        if s.offset == getattr(self.ctx, 'lr_offset', -1) \
                and type(s.data).__name__ == 'Const':
            v = s.data.con.value
            if isinstance(v, int) and self.ctx.in_rx(v):
                self.out.append('    GST_I64(%d) = UINT64_C(%#x);' % (s.offset, v))
                return

        # Writes to the guest PC are dead here: control flow is expressed as C
        # gotos and calls, and nothing reads the guest PC back.  Emitting them
        # would also feed code addresses into the constant-address rewriter and
        # drag in a data copy of .text that the binary never actually reads.
        if s.offset == self.ctx.pc_offset:
            return
        ty = s.data.result_type(self.irsb.tyenv)
        w = twidth(ty)
        val = self.expr(s.data)
        if w in (128, 256):
            self.out.append('    gst_put_v%d(cpu, %d, %s);' % (w, s.offset, val))
        elif w == 1:
            self.out.append('    GST_I8(%d) = (uint8_t)((%s) & 1);' % (s.offset, val))
        else:
            self.out.append('    GST_I%d(%d) = %s;' % (w, s.offset, val))

    def _s_Store(self, s):
        ty = s.data.result_type(self.irsb.tyenv)
        w = twidth(ty)
        fn = 'st_%s' % ('v%d' % w if w >= 128 else 'i%d' % w)
        self.out.append('    %s(%s, %s);' % (fn, self.expr(s.addr), self.expr(s.data)))

    def _s_LLSC(self, s):
        """Load-linked / store-conditional.

        The generated code is a single flow of control per guest thread, so an
        exclusive pair degenerates to a plain load or store, and the store
        always reports success.  That is faithful for the uncontended case the
        binary relies on (it guards shared state with NvOs mutexes), but it is
        NOT a real atomic: two threads inside the same translated region could
        interleave.  Recorded in the audit as a known limitation.
        """
        self.ctx.notes.append(('LLSC degraded to non-atomic', self.irsb.addr, ''))
        if s.storedata is None:
            ty = self.irsb.tyenv.types[s.result]
            w = twidth(ty)
            fn = 'ld_%s' % ('v%d' % w if w >= 128 else 'i%d' % w)
            self.out.append('    %s = %s(%s);   /* load-linked */'
                            % (self.tname(s.result), fn, self.expr(s.addr)))
        else:
            ty = s.storedata.result_type(self.irsb.tyenv)
            w = twidth(ty)
            fn = 'st_%s' % ('v%d' % w if w >= 128 else 'i%d' % w)
            self.out.append('    %s(%s, %s);   /* store-conditional */'
                            % (fn, self.expr(s.addr), self.expr(s.storedata)))
            self.out.append('    %s = 1;   /* always succeeds */' % self.tname(s.result))

    def _s_MBE(self, s):
        self.out.append('    __atomic_thread_fence(__ATOMIC_SEQ_CST);')

    def _s_Exit(self, s):
        cond = self.expr(s.guard)
        dst = s.dst.value
        self.out.append('    if (%s) { %s }' % (cond, self.ctx.goto_or_call(dst, s.jumpkind)))

    # ------------------------------------------------------------ temporaries

    def declare_temps(self):
        """Declarations for the temps this block references.

        Only the referenced ones: VEX's tyenv spans the whole IRSB, so
        declaring all of it emitted dozens of unused locals per block.  Once
        jump-table arms split the code into many small blocks, those
        declarations became a large fraction of the generated source.

        These are no longer emitted inside the block.  emit_function() merges
        this set across every block and declares each name once at the top of
        the function, which is what collapses the duplicates -- a temp index
        live across twenty blocks was declared twenty times.  Names carry their
        C type (see TSUFFIX), so merging cannot produce a type conflict.
        """
        return sorted(self.temp_decls.values())
