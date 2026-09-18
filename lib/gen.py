import bisect
"""
gen.py -- turn an AArch64 ELF into C.

Layout of the generated translation unit:

    guest_rt.h              runtime (fixed, not generated)
    g_ro[]                  read-only image, const  -- bytes come from
                            data_ro.bin via #embed, not from C source
    g_rw[]                  writable image (.data + .bss) -- an array of
                            g_rw_slot unions, each statically initialised, so
                            the LINKER relocates every pointer in it
    g_text_data[]           code image, only if the binary reads its own text
    plt_*()                 one thunk per imported symbol
    f_<addr>()              one function per discovered guest function
    <exported name>()       real-signature wrappers for the ELF's exports

Address model: a guest pointer stored anywhere in the image is already a host
pointer by the time main() runs -- the linker resolved it -- so loads and stores
need no translation and nothing is patched at startup.
"""

import json
import logging
import os
import re
import sys

for _n in ('angr', 'cle', 'pyvex', 'claripy', 'ailment'):
    logging.getLogger(_n).setLevel(logging.CRITICAL)

import angr          # noqa: E402
import archinfo      # noqa: E402
import pyvex         # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN   # noqa: E402

from irtoc import IRToC, UnsupportedIR   # noqa: E402

import cachekey      # noqa: E402
import ehframe       # noqa: E402
import elfcompat     # noqa: E402


# ----------------------------------------------------------- import signatures
#
# Kinds: p=pointer, i=signed int, u=unsigned/size_t, d=double, f=float, v=void,
#        V=variadic (needs a format-driven marshaller), J=setjmp-family.
# Only what this class of binary imports; unknown names fall back to a weak
# stub so the output still links.

# Imports the port deliberately does not model.  These are Nintendo SDK / musl
# loader hooks and the linker-supplied relocation-table bounds; the translated
# code never depends on them doing anything, so their GOT slots are left NULL
# instead of pointing at a thunk that could only abort.
# Implemented by hand in guest_va.c: variadic calls need the format string
# walked to know where each argument lives, which a generated thunk cannot do.
RUNTIME_IMPORTS = {
    'printf', 'fprintf', 'sprintf', 'snprintf',
    'vfprintf', 'vsprintf', 'vsnprintf', 'sscanf',
    'longjmp',
    # Added for the exception-enabled build: same reason as the rest -- the
    # format string decides where each argument lives, so a generated thunk
    # cannot marshal them.
    'vsscanf', 'vasprintf',
}

# setjmp is expanded inline at the call site (see term()).
SETJMP_NAMES = {'setjmp', '_setjmp', '__setjmp', 'sigsetjmp'}
LONGJMP_NAMES = {'longjmp', '_longjmp', 'siglongjmp'}

# Tear-down stubs.  `_fini` and the `.fini_array` have no meaning for a port
# that is driven through the API and never unloaded.
#
# `_init` USED to be here, on the reasoning that it is "start-up machinery the
# loader would run and this port does not".  That reasoning was wrong, and in
# a way that only shows up as wrong output.  Both versions of this library
# have an `_init` that WALKS THE .init_array ITSELF -- it is not the classic
# empty stub -- and the dynamic loader then walks DT_INIT_ARRAY as well.  So
# under the QEMU reference every constructor runs TWICE, and it was running
# once in the port.
#
# The second run is nearly a no-op: the constructors guard themselves with a
# flag.  "Nearly" is the problem.  On subsdk0.elf it still performs four more
# string internments, so every pointer allocated afterwards sits four
# allocations further along -- and the compiler's type table is a hash map
# whose hash is computed OVER POINTERS (0xf3bd9c: `ldr x9,[x19,#0x10]; eor
# x20,x9,x8`).  Different pointers, different bucket order, a different type
# object returned for the same type, and two dwords of the reflection section
# come out different.  The first divergence in a 6.8-million-block trace is
# exactly there.
#
# So the port does what the loader does: DT_INIT first, then DT_INIT_ARRAY.
# Whatever `_init` does -- including running the array a first time -- then
# falls out of the binary's own content instead of being special-cased.
IGNORED_FUNCS = {'_fini', '__libc_csu_fini'}

IGNORED_IMPORTS = {
    '__nnDetailNintendoSdkRuntimeObjectFile',
    '__nnmusl_init_dso',
    # The fini counterpart of __nnmusl_init_dso.  Same argument, same
    # treatment: it is a hook the Nintendo loader calls to tear down the musl
    # DSO bookkeeping for this object, and a port whose "image" is two C
    # arrays has no such bookkeeping to tear down.  Imported by the five
    # pre-17.22 binaries (17.10, 17.16, 17.17, 17.20.0.62, 17.20.0.68); the
    # 17.22+ ones dropped it.
    '__nnmusl_fini_dso',
    '__rel_dyn_start', '__rel_dyn_end',
    '__rel_plt_start', '__rel_plt_end',
    # nn::ro::ProtectRelro(...) asks the Nintendo loader to make the RELRO
    # range read-only.  There is no RELRO to protect in a port whose "image"
    # is two C arrays, and the call has no other effect, so it is dropped at
    # the call site the same way the musl loader hooks are.
    '_ZN2nn2ro12ProtectRelroEPKvS2_S2_S2_S2_',
}

# Imports that are NOT in the C library and so need a prototype emitted.
# `glslc_*` are deliberately declared and not defined here: the project already
# has implementations (glslc_Alloc/Free/Realloc route through the user-supplied
# GLSLCallocateFunction callbacks), and those are the ones that must be linked
# in.  The NvOs* family gets wrappers in guest_host.c.
# Imported symbols whose HOST name differs from the guest's.  The C++ ABI
# mangles `operator new(size_t)` after the size_t type, so the guest's
# AArch64/LP64 `_Znwm` is `_Znwy` on a MinGW-w64 host (where size_t is
# unsigned long long) and `_Znwj` on a 32-bit one.  Importing the mangled name
# therefore fails to link on Windows.  Route both operators through plain C
# shims in guest_host.c instead: one name on every platform, and libstdc++ is
# no longer needed to link at all.
IMPORT_ALIAS = {
    '_Znwm': 'guest_operator_new',      '_Znwj': 'guest_operator_new',
    '_Znwy': 'guest_operator_new',
    '_Znam': 'guest_operator_new',      '_Znaj': 'guest_operator_new',
    '_Znay': 'guest_operator_new',
    '_ZdlPv': 'guest_operator_delete',  '_ZdaPv': 'guest_operator_delete',
    # qsort's comparator is a GUEST function pointer; see guest_qsort(). 
    'qsort': 'guest_qsort',

    # ---- the Itanium C++ ABI ------------------------------------------------
    # Same argument as operator new, one level up: these are the ABI, not the
    # C library, and a host libstdc++ cannot implement them for a GUEST stack.
    # guest_eh.c does, so every one of them is routed to a plain C name that
    # exists on every platform and needs no -lstdc++.
    '__cxa_allocate_exception':  'guest_cxa_allocate_exception',
    '__cxa_free_exception':      'guest_cxa_free_exception',
    '__cxa_throw':               'guest_cxa_throw',
    '__cxa_rethrow':             'guest_cxa_rethrow',
    '__cxa_begin_catch':         'guest_cxa_begin_catch',
    '__cxa_end_catch':           'guest_cxa_end_catch',
    '__cxa_uncaught_exceptions': 'guest_cxa_uncaught_exceptions',
    '__cxa_guard_acquire':       'guest_cxa_guard_acquire',
    '__cxa_guard_release':       'guest_cxa_guard_release',
    '__cxa_guard_abort':         'guest_cxa_guard_abort',
    '_Unwind_Resume':            'guest_unwind_resume',
    '__gxx_personality_v0':      'guest_gxx_personality',
    '_ZSt9terminatev':           'guest_std_terminate',

    # ---- the std:: classes the binary leaves outside ------------------------
    # guest_cxx.c explains the layouts and where they come from.
    '_ZNKSt13runtime_error4whatEv':   'guest_std_runtime_error_what',
    '_ZNSt13runtime_errorD1Ev':       'guest_std_runtime_error_dtor',
    '_ZNSt13runtime_errorD2Ev':       'guest_std_runtime_error_dtor',
    '_ZNSt12length_errorD1Ev':        'guest_std_length_error_dtor',
    '_ZNSt9exceptionD2Ev':            'guest_std_exception_dtor',
    '_ZNSt9bad_allocC1Ev':            'guest_std_bad_alloc_ctor',
    '_ZNSt9bad_allocD1Ev':            'guest_std_bad_alloc_dtor',
    '_ZNSt8bad_castC1Ev':             'guest_std_bad_cast_ctor',
    '_ZNSt8bad_castD1Ev':             'guest_std_bad_cast_dtor',
    '_ZNSt20bad_array_new_lengthC1Ev': 'guest_std_bad_array_new_length_ctor',
    '_ZNSt20bad_array_new_lengthD1Ev': 'guest_std_bad_array_new_length_dtor',

    # ---- host libc calls that need a wrapper --------------------------------
    # newlocale's category MASK is not the same number on musl (which this
    # guest was linked against) and on the host's C library, so the mask
    # cannot be passed through; guest_newlocale() explains what it does
    # instead.
    'newlocale':  'guest_newlocale',
    # strtold returns a long double, which is binary128 on AArch64 and the
    # x87 80-bit format on x86-64.  guest_strtold_l() produces the guest's
    # format explicitly rather than letting the host's differ silently.
    'strtold_l':  'guest_strtold_l',
    'isdigit_l': 'guest_isdigit_l',
    'isxdigit_l': 'guest_isxdigit_l',
    'islower_l': 'guest_islower_l',
    'isupper_l': 'guest_isupper_l',
    'iswlower_l': 'guest_iswlower_l',
    'NvOsFcloseEx': 'guest_NvOsFcloseEx',
    # POSIX and GNU disagree about what strerror_r returns; see the wrapper.
    'strerror_r': 'guest_strerror_r',

    # ---- POSIX 2008 that Windows does not have ------------------------------
    # uselocale, freelocale, strftime_l, strtod_l and strtof_l are POSIX, not
    # ISO C, and MSVCRT has none of them -- a direct call is a link error on
    # MinGW.  The wrappers are pass-throughs on glibc, so the Linux behaviour
    # the corpus was verified against does not move.  guest_host.c.
    'uselocale':   'guest_uselocale',
    'freelocale':  'guest_freelocale',
    'strftime_l':  'guest_strftime_l',
    'strtod_l':    'guest_strtod_l',
    'strtof_l':    'guest_strtof_l',
    # MSVCRT spells this ___mb_cur_max_func; MB_CUR_MAX is the portable name.
    '__ctype_get_mb_cur_max': 'guest_ctype_get_mb_cur_max',

    # ---- the wide-character family ------------------------------------------
    # Two problems at once: mbsnrtowcs and wcsnrtombs do not exist on Windows
    # at all, and the guest's wchar_t is 32 bits where Windows' is 16 -- so the
    # host would write UTF-16 code units into an array the guest reads as
    # UTF-32.  guest_wide.c converts with musl's own UTF-8 code, on an explicit
    # uint32_t.  (It is also the more faithful answer on Linux: musl's C locale
    # is UTF-8 and glibc's is not.  For ASCII the two agree byte for byte.)
    'mbrtowc':     'guest_mbrtowc',
    'mbrlen':      'guest_mbrlen',
    'mbtowc':      'guest_mbtowc',
    'mbsrtowcs':   'guest_mbsrtowcs',
    'mbsnrtowcs':  'guest_mbsnrtowcs',
    'wcrtomb':     'guest_wcrtomb',
    'wcsrtombs':   'guest_wcsrtombs',
    'wcsnrtombs':  'guest_wcsnrtombs',
    'wcslen':      'guest_wcslen',
    'wmemchr':     'guest_wmemchr',
    'fputwc':      'guest_fputwc',
    'getwc':       'guest_getwc',
    'ungetwc':     'guest_ungetwc',
}


# Imported symbols that are DATA, not code.
#
# A GOT slot for one of these must hold the address of an OBJECT, and the old
# path -- point every GOT slot at `plt_<name>` -- would give the guest the
# address of a function and it would load whatever the first eight bytes of
# host code happen to be.  glslc.elf imports no data at all, which is why this
# table did not exist before.
#
# Each entry gives the C expression for the object's address and, when the
# object cannot be initialised statically, the declaration that has to be
# emitted for it.  guest_cxx.c defines them all and fills in the ones whose
# value is not a constant expression (see guest_data_imports_init).
DATA_IMPORTS = {
    # musl's stdio objects.  The guest loads the FILE * out of them.
    'stdin':  ('&guest_data_stdin',  'extern FILE *guest_data_stdin;'),
    'stdout': ('&guest_data_stdout', 'extern FILE *guest_data_stdout;'),
    'stderr': ('&guest_data_stderr', 'extern FILE *guest_data_stderr;'),

    # The three __cxxabiv1 typeinfo vtables.  A guest typeinfo object stores
    # `symbol + 0x10` as its vptr, and that value is what identifies its shape
    # to the matcher in guest_eh.c.
    '_ZTVN10__cxxabiv117__class_type_infoE':
        ('guest_cxxabi_class_vtable',
         'extern const void *const guest_cxxabi_class_vtable[4];'),
    '_ZTVN10__cxxabiv120__si_class_type_infoE':
        ('guest_cxxabi_si_class_vtable',
         'extern const void *const guest_cxxabi_si_class_vtable[4];'),
    '_ZTVN10__cxxabiv121__vmi_class_type_infoE':
        ('guest_cxxabi_vmi_class_vtable',
         'extern const void *const guest_cxxabi_vmi_class_vtable[4];'),

    # std:: typeinfo objects, with their real base chains.
    '_ZTISt9bad_alloc':
        ('&guest_ti_std_bad_alloc', 'extern const struct guest_ti_si_s guest_ti_std_bad_alloc;'),
    '_ZTISt20bad_array_new_length':
        ('&guest_ti_std_bad_array_new_length',
         'extern const struct guest_ti_si_s guest_ti_std_bad_array_new_length;'),
    '_ZTISt8bad_cast':
        ('&guest_ti_std_bad_cast', 'extern const struct guest_ti_si_s guest_ti_std_bad_cast;'),
    '_ZTISt12length_error':
        ('&guest_ti_std_length_error', 'extern const struct guest_ti_si_s guest_ti_std_length_error;'),
    '_ZTISt13runtime_error':
        ('&guest_ti_std_runtime_error', 'extern const struct guest_ti_si_s guest_ti_std_runtime_error;'),

    # std:: class vtables.  The guest defines the constructors, so it is the
    # guest that stores `symbol + 0x10`; the slots have to be the port's own
    # thunks because a virtual call reaches them through guest_dispatch.
    '_ZTVSt11logic_error':
        ('guest_vtable_std_logic_error', 'extern const void *guest_vtable_std_logic_error[5];'),
    '_ZTVSt12length_error':
        ('guest_vtable_std_length_error', 'extern const void *guest_vtable_std_length_error[5];'),
    '_ZTVSt13runtime_error':
        ('guest_vtable_std_runtime_error', 'extern const void *guest_vtable_std_runtime_error[5];'),

    # Named by the CIE's personality field and stored in .data by a relocation.
    # It is never CALLED -- guest_eh.c does the personality routine's job --
    # but the relocation still has to resolve to something.
    '__gxx_personality_v0': ('&plt___gxx_personality_v0',
                             'void plt___gxx_personality_v0(cpu_t *cpu, uint64_t entry);'),
}


def host_name(nm):
    """The name the generated C calls for guest import `nm`."""
    return IMPORT_ALIAS.get(nm, nm)


EXTERN_PROTOS = {
    '_Znwm':              'void *guest_operator_new(unsigned long long);',
    '_Znwj':              'void *guest_operator_new(unsigned long long);',
    '_Znwy':              'void *guest_operator_new(unsigned long long);',
    '_Znam':              'void *guest_operator_new(unsigned long long);',
    '_Znaj':              'void *guest_operator_new(unsigned long long);',
    '_Znay':              'void *guest_operator_new(unsigned long long);',
    '_ZdlPv':             'void guest_operator_delete(void *);',
    '_ZdaPv':             'void guest_operator_delete(void *);',
    'qsort':              'void guest_qsort(void *base, uint64_t n, uint64_t size, uint64_t cmp);',
    'glslc_Alloc':        'void *glslc_Alloc(size_t size);',
    'glslc_Free':         'void glslc_Free(void *ptr);',
    'glslc_Realloc':      'void *glslc_Realloc(void *ptr, size_t newSz);',
    'glslc_GetAllocator': 'void *glslc_GetAllocator(void);',
    'NvOsFopen':          'int64_t NvOsFopen(const char *path, uint64_t flags, void **out);',
    'NvOsFclose':         'void NvOsFclose(void *file);',
    'NvOsFread':          'int64_t NvOsFread(void *file, void *buf, uint64_t size, uint64_t *read);',
    'NvOsFwrite':         'int64_t NvOsFwrite(void *file, const void *buf, uint64_t size);',
    'NvOsFseek':          'int64_t NvOsFseek(void *file, int64_t offset, uint64_t whence);',
    'NvOsFtell':          'int64_t NvOsFtell(void *file, uint64_t *pos);',
    'NvOsMutexCreate':    'void NvOsMutexCreate(void **out);',
    'NvOsMutexDestroy':   'void NvOsMutexDestroy(void *m);',
    'NvOsMutexLock':      'void NvOsMutexLock(void *m);',
    'NvOsMutexUnlock':    'void NvOsMutexUnlock(void *m);',
    'NvOsFcloseEx':       'void guest_NvOsFcloseEx(void *file, uint64_t flags);',
    'glslc_AllocAlign':   'void *glslc_AllocAlign(size_t size, size_t align);',
    'nninitStartup':      'void nninitStartup(void);',

    # ---- the C++ ABI, implemented in guest_eh.c --------------------------
    '__cxa_allocate_exception':  'uint64_t guest_cxa_allocate_exception(uint64_t size);',
    '__cxa_free_exception':      'void guest_cxa_free_exception(uint64_t obj);',
    '__cxa_throw':               'void guest_cxa_throw(cpu_t *cpu, uint64_t obj, uint64_t tinfo, uint64_t dtor);',
    '__cxa_rethrow':             'void guest_cxa_rethrow(cpu_t *cpu);',
    '__cxa_begin_catch':         'uint64_t guest_cxa_begin_catch(uint64_t obj);',
    '__cxa_end_catch':           'void guest_cxa_end_catch(cpu_t *cpu);',
    '__cxa_uncaught_exceptions': 'uint64_t guest_cxa_uncaught_exceptions(void);',
    '__cxa_guard_acquire':       'uint64_t guest_cxa_guard_acquire(uint64_t guard);',
    '__cxa_guard_release':       'void guest_cxa_guard_release(uint64_t guard);',
    '__cxa_guard_abort':         'void guest_cxa_guard_abort(uint64_t guard);',
    '_Unwind_Resume':            'void guest_unwind_resume(cpu_t *cpu, uint64_t obj);',
    '__gxx_personality_v0':      'void guest_gxx_personality(cpu_t *cpu);',
    '_ZSt9terminatev':           'void guest_std_terminate(void);',

    # ---- the std:: classes, implemented in guest_cxx.c -------------------
    '_ZNKSt13runtime_error4whatEv':    'const char *guest_std_runtime_error_what(const void *self);',
    '_ZNSt13runtime_errorD1Ev':        'void guest_std_runtime_error_dtor(void *self);',
    '_ZNSt13runtime_errorD2Ev':        'void guest_std_runtime_error_dtor(void *self);',
    '_ZNSt12length_errorD1Ev':         'void guest_std_length_error_dtor(void *self);',
    '_ZNSt9exceptionD2Ev':             'void guest_std_exception_dtor(void *self);',
    '_ZNSt9bad_allocC1Ev':             'void guest_std_bad_alloc_ctor(void *self);',
    '_ZNSt9bad_allocD1Ev':             'void guest_std_bad_alloc_dtor(void *self);',
    '_ZNSt8bad_castC1Ev':              'void guest_std_bad_cast_ctor(void *self);',
    '_ZNSt8bad_castD1Ev':              'void guest_std_bad_cast_dtor(void *self);',
    '_ZNSt20bad_array_new_lengthC1Ev': 'void guest_std_bad_array_new_length_ctor(void *self);',
    '_ZNSt20bad_array_new_lengthD1Ev': 'void guest_std_bad_array_new_length_dtor(void *self);',

    # ---- host wrappers ---------------------------------------------------
    'newlocale':  'void *guest_newlocale(int64_t mask, const char *name, void *base);',
    'strtold_l':  'void guest_strtold_l(void *out, const char *s, void **end, void *loc);',
    # `finite` is the one import whose declaration cannot simply be written
    # down, because the two toolchains disagree in opposite directions.
    #
    # On glibc it is not declared by every header set even with _GNU_SOURCE, so
    # the prototype has to be supplied -- that is why this entry exists.
    #
    # mingw-w64's math.h DOES declare it, and with __declspec(dllimport),
    # because it lives in the CRT DLL.  Repeating the declaration there is
    # legal and links, and GCC warns about it every single time:
    #
    #     warning: 'finite' redeclared without dllimport attribute:
    #              previous dllimport ignored [-Wattributes]
    #
    # This line lands in guest_decls.h, which every one of the ~43,000
    # generated files includes, so that is one warning per object -- tens of
    # thousands of them, burying anything worth reading.  And DROPPING the
    # declaration on Windows does not work either: mingw hides `finite` behind
    # __STRICT_ANSI__, which -std=c11 (the Makefile's, deliberately) defines,
    # so the header stops declaring it exactly when we stop declaring it and
    # -Werror=implicit-function-declaration fires.
    #
    # The MSVCRT spelling is `_finite`, declared by float.h in every language
    # mode, so Windows gets that under the name the generated call already
    # uses.  Only ever emitted as a direct call (marshal_call), never as a
    # function pointer, so a macro is a complete substitute.
    'finite':     ('#ifdef _WIN32\n'
                   '#include <float.h>   /* _finite: declared in all language '
                   'modes, unlike finite */\n'
                   '#define finite(x) _finite(x)\n'
                   '#else\n'
                   'int finite(double);\n'
                   '#endif'),
    'isdigit_l':  'int guest_isdigit_l(int64_t c, void *loc);',
    'isxdigit_l': 'int guest_isxdigit_l(int64_t c, void *loc);',
    'islower_l':  'int guest_islower_l(int64_t c, void *loc);',
    'isupper_l':  'int guest_isupper_l(int64_t c, void *loc);',
    'iswlower_l': 'int guest_iswlower_l(int64_t c, void *loc);',
    'strerror_r': 'int guest_strerror_r(int64_t err, char *buf, uint64_t len);',

    # ---- POSIX 2008 the Windows C library does not have (guest_host.c) ----
    'uselocale':   'void *guest_uselocale(void *loc);',
    'freelocale':  'void guest_freelocale(void *loc);',
    'strftime_l':  'uint64_t guest_strftime_l(void *s, uint64_t max, const char *fmt, void *tm, void *loc);',
    'strtod_l':    'double guest_strtod_l(const char *s, void **end, void *loc);',
    'strtof_l':    'float guest_strtof_l(const char *s, void **end, void *loc);',
    '__ctype_get_mb_cur_max': 'uint64_t guest_ctype_get_mb_cur_max(void);',

    # ---- the wide-character family (guest_wide.c) --------------------------
    'mbrtowc':     'uint64_t guest_mbrtowc(void *wc, const void *src, uint64_t n, void *st);',
    'mbrlen':      'uint64_t guest_mbrlen(const void *s, uint64_t n, void *st);',
    'mbtowc':      'int64_t guest_mbtowc(void *wc, const void *src, uint64_t n);',
    'mbsrtowcs':   'uint64_t guest_mbsrtowcs(void *ws, void *src, uint64_t wn, void *st);',
    'mbsnrtowcs':  'uint64_t guest_mbsnrtowcs(void *ws, void *src, uint64_t n, uint64_t wn, void *st);',
    'wcrtomb':     'uint64_t guest_wcrtomb(void *s, uint64_t wc, void *st);',
    'wcsrtombs':   'uint64_t guest_wcsrtombs(void *dst, void *wcs, uint64_t n, void *st);',
    'wcsnrtombs':  'uint64_t guest_wcsnrtombs(void *dst, void *wcs, uint64_t wn, uint64_t n, void *st);',
    'wcslen':      'uint64_t guest_wcslen(const void *s);',
    'wmemchr':     'void *guest_wmemchr(const void *s, uint64_t c, uint64_t n);',
    'fputwc':      'int64_t guest_fputwc(int64_t c, void *f);',
    'getwc':       'int64_t guest_getwc(void *f);',
    'ungetwc':     'int64_t guest_ungetwc(int64_t c, void *f);',
}

HOST_SIGS = {
    'glslc_Alloc':        ('p', 'u'),
    'glslc_Free':         ('v', 'p'),
    'glslc_Realloc':      ('p', 'pu'),
    'glslc_GetAllocator': ('p', ''),
    'NvOsFopen':          ('i', 'pup'),
    'NvOsFclose':         ('v', 'p'),
    'NvOsFread':          ('i', 'ppup'),
    'NvOsFwrite':         ('i', 'ppu'),
    'NvOsFseek':          ('i', 'piu'),
    'NvOsFtell':          ('i', 'pp'),
    'NvOsMutexCreate':    ('v', 'p'),
    'NvOsMutexDestroy':   ('v', 'p'),
    'NvOsMutexLock':      ('v', 'p'),
    'NvOsMutexUnlock':    ('v', 'p'),
    'NvOsFcloseEx':       ('v', 'pu'),
    'glslc_AllocAlign':   ('p', 'uu'),
    # The Nintendo SDK start-up hook.  Empty body, returns nothing -- see the
    # definition in guest_host.c for why.
    'nninitStartup':      ('v', ''),
}

LIBC_SIGS = {
    'memcpy':   ('p', 'ppu'),   'memmove': ('p', 'ppu'),  'memset': ('p', 'piu'),
    'memcmp':   ('i', 'ppu'),   'strlen':  ('u', 'p'),    'strcmp': ('i', 'pp'),
    'strncmp':  ('i', 'ppu'),   'strcpy':  ('p', 'pp'),   'strncpy': ('p', 'ppu'),
    'strcat':   ('p', 'pp'),    'strncat': ('p', 'ppu'),  'strchr': ('p', 'pi'),
    'strrchr':  ('p', 'pi'),    'strstr':  ('p', 'pp'),   'strtok': ('p', 'pp'),
    'strcasecmp': ('i', 'pp'),  'strtol':  ('i', 'ppi'),
    'atoi':     ('i', 'p'),     'atof':    ('d', 'p'),
    'tolower':  ('i', 'i'),     'toupper': ('i', 'i'),
    'isalnum':  ('i', 'i'),     'isalpha': ('i', 'i'),    'isspace': ('i', 'i'),
    'exit':     ('v', 'i'),
    # The comparator is a guest address, not a host pointer: 'u', so it reaches
    # guest_qsort() unchanged instead of being handed to the C library.
    'qsort':   ('v', 'puuu'),
    '__errno_location': ('p', ''),
    'getenv':   ('p', 'p'),
    'fwrite':   ('u', 'puup'),  'fread':   ('u', 'puup'),
    'fputc':    ('i', 'ip'),    'fputs':   ('i', 'pp'),   'putc': ('i', 'ip'),
    'puts':     ('i', 'p'),     'feof':    ('i', 'p'),    'fflush': ('i', 'p'),
    'ferror':   ('i', 'p'),
    'fseek':    ('i', 'pii'),   'ftell':   ('i', 'p'),
    'sqrt': ('d', 'd'), 'sin': ('d', 'd'), 'cos': ('d', 'd'), 'tan': ('d', 'd'),
    'asin': ('d', 'd'), 'acos': ('d', 'd'), 'atan': ('d', 'd'), 'atan2': ('d', 'dd'),
    'tanh': ('d', 'd'), 'exp': ('d', 'd'), 'exp2': ('d', 'd'), 'log': ('d', 'd'),
    'pow': ('d', 'dd'), 'fmod': ('d', 'dd'), 'ldexp': ('d', 'di'),
    'frexp': ('d', 'dp'), 'exp2f': ('f', 'f'), 'logf': ('f', 'f'),
    'sqrtf': ('f', 'f'),
    'printf': ('i', 'V'), 'fprintf': ('i', 'pV'), 'sprintf': ('i', 'pV'),
    'snprintf': ('i', 'puV'), 'vfprintf': ('i', 'ppp'), 'vsprintf': ('i', 'ppp'),
    'vsnprintf': ('i', 'pupp'), 'sscanf': ('i', 'pV'),
    'setjmp': ('J', 'p'), 'longjmp': ('J', 'pi'),
    '_Znwm': ('p', 'u'), '_Znwj': ('p', 'u'), '_Znwy': ('p', 'u'),
    '_Znam': ('p', 'u'), '_Znaj': ('p', 'u'), '_Znay': ('p', 'u'),
    '_ZdlPv': ('v', 'p'), '_ZdaPv': ('v', 'p'),

    # ---- added for the exception-enabled build ---------------------------
    # Kinds: p=pointer, i=signed, u=unsigned, d=double, f=float, v=void,
    #        V=variadic, J=setjmp-family, C=pass `cpu` (consumes no guest
    #        register), Q=return a guest long double (binary128) through q0.
    'malloc':  ('p', 'u'),      'free':    ('v', 'p'),   'realloc': ('p', 'pu'),
    'abort':   ('v', ''),       'clock':   ('i', ''),
    # srand takes an `unsigned int`, not an int: the guest passes it in w0 and
    # a signed reading would sign-extend a seed above 2^31 into a different
    # number.  rand() takes nothing and returns int.
    'rand':    ('i', ''),       'srand':   ('v', 'u'),
    'memchr':  ('p', 'piu'),
    'expf':    ('f', 'f'),      'finite':  ('i', 'd'),
    'strtok_r': ('p', 'ppp'),
    'strtoll':  ('i', 'ppi'),   'strtoull': ('u', 'ppi'),
    'strerror_r': ('i', 'ipu'),
    'getc':    ('i', 'p'),      'ungetc':  ('i', 'ip'),
    'getwc':   ('i', 'p'),      'ungetwc': ('i', 'ip'),  'fputwc': ('i', 'ip'),
    '__ctype_get_mb_cur_max': ('u', ''),

    # Threads.  The library's own multithread flag is a no-op that only sets a
    # bit in the output header, so these are only ever called on an
    # uncontended object; they are still routed to the real host primitives so
    # that a future threaded caller is not silently unsynchronised.
    'pthread_mutex_lock':     ('i', 'p'),
    'pthread_mutex_unlock':   ('i', 'p'),
    'pthread_cond_wait':      ('i', 'pp'),
    'pthread_cond_broadcast': ('i', 'p'),

    # Locale.  newlocale goes through a wrapper because the category mask is
    # not the same number on musl and on the host; the rest take the locale_t
    # that wrapper returned, so they can be called directly.
    'newlocale':   ('p', 'ipp'),
    'uselocale':   ('p', 'p'),
    'freelocale':  ('v', 'p'),
    'isdigit_l':   ('i', 'ip'),  'isxdigit_l': ('i', 'ip'),
    'islower_l':   ('i', 'ip'),  'isupper_l':  ('i', 'ip'),
    'iswlower_l':  ('i', 'ip'),
    'strftime_l':  ('u', 'puppp'),
    'strtod_l':    ('d', 'ppp'), 'strtof_l':  ('f', 'ppp'),
    'strtold_l':   ('Q', 'ppp'),

    # Wide characters and multibyte conversion.
    'wcslen':      ('u', 'p'),   'wmemchr':   ('p', 'puu'),
    'wcrtomb':     ('u', 'pup'),
    'wcsnrtombs':  ('u', 'ppuup'),
    'mbrlen':      ('u', 'pup'),
    'mbrtowc':     ('u', 'ppup'),
    'mbsrtowcs':   ('u', 'ppup'),
    # Not imported by either binary seen so far; listed because its wrapper
    # exists (guest_wide.c implements musl's own, since wcsnrtombs is not a
    # substitute for it -- musl writes them separately) and an alias without a
    # signature would silently become a weak stub.
    'wcsrtombs':   ('u', 'ppup'),
    'mbsnrtowcs':  ('u', 'ppuup'),
    'mbtowc':      ('i', 'ppu'),

    # The C++ ABI.  'C' passes `cpu`: these unwind the GUEST stack, so they
    # need the register file, and they do not return through it.
    '__cxa_allocate_exception':  ('u', 'u'),
    '__cxa_free_exception':      ('v', 'u'),
    '__cxa_throw':               ('v', 'Cuuu'),
    '__cxa_rethrow':             ('v', 'C'),
    '__cxa_begin_catch':         ('u', 'u'),
    '__cxa_end_catch':           ('v', 'C'),
    '__cxa_uncaught_exceptions': ('u', ''),
    '__cxa_guard_acquire':       ('u', 'u'),
    '__cxa_guard_release':       ('v', 'u'),
    '__cxa_guard_abort':         ('v', 'u'),
    '_Unwind_Resume':            ('v', 'Cu'),
    '__gxx_personality_v0':      ('v', 'C'),
    '_ZSt9terminatev':           ('v', ''),

    # The std:: members the binary imports.  Every one of them takes `this`.
    '_ZNKSt13runtime_error4whatEv':    ('p', 'p'),
    '_ZNSt13runtime_errorD1Ev':        ('v', 'p'),
    '_ZNSt13runtime_errorD2Ev':        ('v', 'p'),
    '_ZNSt12length_errorD1Ev':         ('v', 'p'),
    '_ZNSt9exceptionD2Ev':             ('v', 'p'),
    '_ZNSt9bad_allocC1Ev':             ('v', 'p'),
    '_ZNSt9bad_allocD1Ev':             ('v', 'p'),
    '_ZNSt8bad_castC1Ev':              ('v', 'p'),
    '_ZNSt8bad_castD1Ev':              ('v', 'p'),
    '_ZNSt20bad_array_new_lengthC1Ev': ('v', 'p'),
    '_ZNSt20bad_array_new_lengthD1Ev': ('v', 'p'),
}

ALL_SIGS = dict(LIBC_SIGS)
ALL_SIGS.update(HOST_SIGS)

CTYPE = {'p': 'void *', 'i': 'int64_t', 'u': 'uint64_t', 'd': 'double',
         'f': 'float', 'v': 'void'}


def cname(addr):
    return 'f_%08x' % addr


# Minimum block count before trim_blocks() will cut a function at a function
# start found inside it.  Override with GEN_TRIM_MIN to measure a different
# setting; 1 means "trim purely on the evidence, whatever the size".
TRIM_MIN_BLOCKS = int(os.environ.get('GEN_TRIM_MIN', '3000'))

# Blocks whose lift emit_function() keeps for its second pass; see the memo
# there.  ~30 KB each, and per worker process under `-j N`.
LIFT_MEMO_MAX = 1024


def marshal_call(ctx, nm, sig, indent='    '):
    """C statements that call an imported function using the guest registers.

    Shared by two callers: the direct-call path, which pastes these straight
    into the translated function so the generated C reads as a plain
    `memcpy(...)` call the compiler can inline, and the thunk emitter, which
    wraps them in a function for the cases where only a pointer will do (a
    libc address stored in a vtable, say).
    """
    xo = [ctx.off['x%d' % i] for i in range(8)]
    qo = ctx.qoff
    ret, args = sig

    call_args = []
    gi = fi = 0
    for k in args:
        if k == 'C':
            # Not an argument the guest passed: this import needs the guest
            # register file itself (the C++ ABI entry points unwind it), so
            # `cpu` is handed over and no guest register is consumed.
            call_args.append('cpu')
        elif k in ('d', 'f'):
            conv = 'f64_of' if k == 'd' else 'f32_of'
            width = ('GST_I64(%d)' % (qo + 16 * fi)) if k == 'd' else ('GST_I32(%d)' % (qo + 16 * fi))
            call_args.append('%s(%s)' % (conv, width))
            fi += 1
        elif k == 'p' or k == 'P':
            call_args.append('(void *)(uintptr_t)GST_I64(%d)' % xo[gi]); gi += 1
        elif k == 'i':
            call_args.append('(int64_t)GST_I64(%d)' % xo[gi]); gi += 1
        elif k == 'u':
            call_args.append('GST_I64(%d)' % xo[gi]); gi += 1

    if ret == 'Q':
        # A guest `long double` is IEEE binary128 and comes back in q0.  The
        # host's `long double` is a different format on x86-64, so the wrapper
        # is handed the destination and writes the guest's format into it
        # rather than returning a value that would have to be converted.
        return ['%s%s((void *)(cpu->g + %d), %s);'
                % (indent, host_name(nm), qo, ', '.join(call_args))]

    call = '%s(%s)' % (host_name(nm), ', '.join(call_args))
    if ret == 'v':
        return ['%s%s;' % (indent, call)]
    if ret == 'd':
        return ['%sGST_I64(%d) = f64_to(%s);' % (indent, qo, call)]
    if ret == 'f':
        return ['%sGST_I32(%d) = f32_to(%s);' % (indent, qo, call)]
    if ret == 'p':
        return ['%sGST_I64(%d) = (uint64_t)(uintptr_t)%s;' % (indent, xo[0], call)]
    return ['%sGST_I64(%d) = (uint64_t)%s;' % (indent, xo[0], call)]


class _EntrySet(set):
    """The set of indirectly-reachable code addresses, with one rule enforced.

    AArch64 instructions are 4-byte aligned WITHOUT EXCEPTION, so an address
    with either low bit set is not a code address, whatever produced it.  One
    reaches here in glslc.elf: the Itanium C++ ABI stores a pointer to a
    VIRTUAL member function as `vtable_offset + 1`, and that `+ 1` makes the
    relocated word look like a code pointer to anything matching on range
    alone.  Left in, it became `f_7100000001` -- a function whose whole body
    is `guest_nodecode`, because libVEX cannot decode at an unaligned address
    either -- plus a dispatch entry pointing at it.

    Dropping it is not a loss of coverage: the slot still holds the guest
    address the guest wrote, so a pointer-to-member-function still compares
    and dereferences exactly as it did; what goes away is the pretence that
    the value names something to execute.
    """

    def add(self, v):
        if v & 3:
            return
        set.add(self, v)

    def update(self, other):
        for v in other:
            self.add(v)

    def __ior__(self, other):
        self.update(other)
        return self


def _cache_mismatch(cachedir, binary, why, base):
    """The one wording for "wrong cache", from either half of the check."""
    return ('cache %s/ does not match %s:\n  %s\n'
            'Re-run:  python3 analyze.py %s %s %s'
            % (cachedir, binary, why, binary, cachedir,
               ('%#x' % base) if base else '0x7100000000'))


class Ctx(object):
    def __init__(self, binary, cachedir='cache', base_addr=None):
        # The cache is keyed by ADDRESS, so it is only valid at the base it was
        # built at.  Take the base from the cache unless one is given, so the
        # two can never silently disagree.
        if base_addr is None:
            try:
                meta = json.load(open(os.path.join(cachedir, 'meta.json')))
                base_addr = meta.get('base')
            except Exception:
                base_addr = None
        # THE CHEAP HALF OF THE CACHE CHECK, BEFORE ANY LOADING.  A stamped
        # cache is settled by a hash and nothing else, so a mismatch stops here
        # rather than after a minute of angr work the answer was never going to
        # depend on.  An unstamped one needs the load base and text span, so it
        # is finished in _check_cache() once the image is open.
        self._cache_verified = False
        if cachekey.load_meta(cachedir) is not None:
            why, self._cache_verified = cachekey.check(cachedir, binary)
            if why and self._cache_verified is False and \
               (cachekey.load_meta(cachedir) or {}).get('sha256'):
                raise SystemExit(_cache_mismatch(cachedir, binary, why,
                                                 base_addr))

        opts = {'base_addr': base_addr} if base_addr is not None else {}
        # Loader fixes that have to be in place before anything is read.
        elfcompat.apply()
        self.binary = binary          # kept for __setstate__; see below
        self.proj = angr.Project(binary, auto_load_libs=False, main_opts=opts)
        self.mo = self.proj.loader.main_object
        self.arch = self.proj.arch
        self.base = self.mo.mapped_base
        self.cachedir = cachedir

        self._check_cache()

        self._segments()
        self._regoffsets()

        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.skipdata = True

        self.funcs = {}          # addr -> info
        self.func_set = set()
        self.open_branch_funcs = set()   # functions with an unrecovered jump table
        self.indirect_branch_funcs = set()   # functions containing any computed branch
        self.forced_entries = {}         # function -> interior blocks reachable indirectly
        self.owned_blocks = set()        # interior blocks, translated as part of their owner
        self.emitted_funcs = set()       # functions that actually got a definition
        self._text_cache = None
        self._br_at = None    # see _br_addresses()
        self._sorted_starts = None
        self._sorted_entries = None
        self._arm_owner = None
        self.false_starts = None
        self.jump_table_cap = 320   # measured max index 271, with headroom
        self._entries_len = -1
        self._starts_len = -1
        self.blocks_of = {}
        self.jumptables = {}
        self._load_cache()

        self.plt_by_addr = dict(self.mo.reverse_plt)      # stub addr -> name

        # Symbols this object DEFINES.  A defined symbol can still be reached
        # through the GOT/PLT (glslcGetVersion is), and when it is, the right
        # target is the generated function -- not an import thunk.
        # Addresses of the start-up stubs, so they can be skipped by name
        # rather than by hard-coded address.
        self.ignored_funcs = set()
        self.init_array_funcs = set()
        self.init_array_order = []   # constructors, in the order the loader runs them

        self.defined_syms = {}
        for s_ in self.mo.symbols:
            a = s_.rebased_addr
            if s_.name and not s_.is_import and s_.is_function and a and self.in_rx(a):
                self.defined_syms.setdefault(s_.name, a)
        for a, nm in list(self.plt_by_addr.items()):
            if nm in self.defined_syms:
                del self.plt_by_addr[a]      # local call, not an import

        for nm in IGNORED_FUNCS:
            if nm in self.defined_syms:
                self.ignored_funcs.add(self.defined_syms[nm])

        # DT_INIT.  Run before the constructors, exactly as the loader does.
        #
        # Read from the DYNAMIC TABLE rather than from the `_init` symbol,
        # because the dynamic table is what the loader itself reads: a binary
        # can have DT_INIT without exporting the name (both of these export
        # it, but nothing guarantees that), and a binary with no DT_INIT at
        # all -- most of them -- simply gets None here and the port's start-up
        # is the .init_array alone, as before.
        self.init_func = None
        dyn = getattr(self.mo, '_dynamic', None) or {}
        if 'DT_INIT' in dyn:
            cand = self.base + dyn['DT_INIT']
            if self.in_rx(cand):
                self.init_func = cand
        elif '_init' in self.defined_syms:
            cand = self.defined_syms['_init']
            if self.in_rx(cand):
                self.init_func = cand

        # Destructors are start-up machinery this port has no use for.
        # CONSTRUCTORS ARE NOT: the loader runs them at dlopen and they
        # initialise RW globals the library reads much later.  Read out of the
        # arrays rather than named, since they carry no symbols; the slots are
        # relocated, so the target comes from the relocation, not the raw word.
        # Order is part of the contract -- .preinit_array before .init_array,
        # and within an array, slot order -- so they are kept in a list.
        reloc_at = {}
        for r in self.mo.relocs:
            # Matched by class, not by class NAME: a packed RELR entry is a
            # GenericRelativeReloc, of which R_AARCH64_RELATIVE is a subclass,
            # and a name test finds none of them (elfcompat.is_relative).
            if elfcompat.is_relative(r):
                reloc_at[r.rebased_addr] = r.value
        by_name = {}
        for sec in self.mo.sections:
            if sec.name in ('.init_array', '.fini_array', '.preinit_array'):
                by_name.setdefault(sec.name, []).append(sec)
        for nm in ('.preinit_array', '.init_array', '.fini_array'):
          for sec in by_name.get(nm, []):
            for off in range(0, sec.memsize, 8):
                slot = sec.vaddr + off
                target = reloc_at.get(slot)
                if target is None:
                    raw = self.proj.loader.memory.load(slot, 8)
                    target = int.from_bytes(raw, 'little')
                if target and self.in_rx(target):
                    if sec.name == '.fini_array':
                        # Tear-down has no meaning for a port that is driven
                        # through the API and never unloaded.
                        self.ignored_funcs.add(target)
                    elif target not in self.init_array_funcs:
                        # Constructors: translated like any other function and
                        # run, in this order, the first time guest_init() runs.
                        # Stubbing them out left a table at 0x9c6514 zeroed,
                        # and --opt-level none then wrote a zero into the debug
                        # info where the original library writes a real value.
                        self.init_array_funcs.add(target)
                        self.init_array_order.append(target)
        # ---- C++ exception tables ------------------------------------
        # Which functions carry a language-specific data area, and where it is.
        # Only these can be re-entered at a landing pad, so only these pay for
        # the exception machinery (ehframe.py explains the split between what
        # is read here and what guest_eh.c reads at run time).  A binary with
        # no .eh_frame -- glslc.elf has none -- gets an empty mapping and every
        # path below is unchanged.
        self.lsda_of = {}
        self.eh_regions = []
        self.eh_frame_error = None
        try:
            fdes = ehframe.from_object(self.mo)
        except Exception as exc:
            fdes = {}
            self.eh_frame_error = str(exc)
        for fa, info in fdes.items():
            if info['lsda'] and self.in_rx(fa):
                self.lsda_of[fa] = info['lsda']
                self.eh_regions.append((fa, fa + (info['size'] or 4),
                                        info['lsda']))
        self.eh_regions.sort()

        # Landing pads have to be recovered HERE, before anything is
        # translated.  A landing pad is reached only by an unwind, never by a
        # branch, so no CFG scanner discovers it -- without this the code
        # simply would not be in the tree, and resuming at one would find
        # nothing to resume into.  They are registered exactly the way a
        # recovered jump-table arm is (elf2c.py), which gives each one a block
        # in its owning function and a dispatch entry.
        self.landing_pads = set()
        for fa, lsda in self.lsda_of.items():
            self.landing_pads |= ehframe.landing_pads(self._read_image, lsda, fa)
        self.landing_pads = {a for a in self.landing_pads if self.in_rx(a)}

        self.imports_used = set()
        self.simd_helpers = {}
        self.const_log = []
        self.referenced = set()      # functions named by emitted code
        self.potential_entries = _EntrySet()   # code addresses reachable indirectly
        self.entry_blocks = {}           # function -> its re-entrable blocks
        self.text_data_used = False
        self.notes = []
        if getattr(self, '_unaligned_dropped', 0):
            self.notes.append(
                ('unaligned function starts dropped from the cache',
                 self._unaligned_dropped, 'not code; see _EntrySet'))
        if self.eh_frame_error:
            self.notes.append(('.eh_frame unreadable', 0, self.eh_frame_error))
        if self.lsda_of:
            self.notes.append(('functions with an exception table',
                               len(self.lsda_of), ''))
            self.notes.append(('landing pads recovered from .gcc_except_table',
                               len(self.landing_pads), ''))
        # Filled in by unit.collect_relocations()/emit_ro(); declared here so
        # the attribute exists even on a path that never emits an image.
        self.reloc_rows = []
        self.ro_blob = None
        # Move-immediate lookups are per guest instruction and repeat across
        # every block that lifts it, so the decode is cached.
        self._immcache = {}
        # How far back _feeds_from_pc_relative() walks looking for the write
        # that defines an add-immediate's source register.  64 instructions;
        # the walk normally stops at the first writer long before that, and
        # running out answers conservatively.
        self.PC_REL_SCAN = 256
        # How many add/sub-immediate links the same walk will follow before
        # giving up and answering conservatively.
        self.PC_REL_HOPS = 8
        # A PIE cannot embed an absolute address as an immediate; a non-PIE
        # can.  const_is_immediate_data() relies on this, so it is read once
        # from the image rather than assumed.
        self.pic_image = bool(getattr(self.proj.loader.main_object, 'pic', False))

        # Whether an immediate can be mistaken for an address AT ALL.  The
        # whole immediate-vs-address problem exists only because the image is
        # mapped where ordinary integers live: at CLE's default PIE base of
        # 0x400000 a 10 MB image covers 0x400000..0xe00000, and a packed word
        # such as 0xb90000 (opcode 185 shifted into the top half) lands inside
        # it by coincidence.  Map the image above 4 GB and no immediate a
        # compiler emits as data can reach it -- a 64-bit constant that big is
        # produced only by address arithmetic -- so classifying BY VALUE
        # becomes exact and every heuristic below is switched off.
        self.image_above_4g = all(
            s.vaddr >= (1 << 32) for s in self.mo.segments if s.memsize)

        self.cur_func = None
        self.cur_labels = set()
        self.local_dispatch = False
        self.file_deps = {}      # function addr -> names it references

    # ---- pickling for spawn-based worker pools -------------------------
    #
    # `proj` (an angr Project), `mo` (its main object), `arch` (an
    # archinfo.Arch) and `md` (a Capstone disassembler) all wrap native
    # state that does not survive pickle -- Capstone's handle is a raw
    # ctypes pointer, and angr's Project carries CLE loader internals and
    # memory backers pickle cannot reconstruct. Everything else on Ctx is
    # plain data loaded from JSON caches (_load_cache) or built out of
    # ints/strings/sets/tuples, so it pickles for free.
    #
    # A fork()-based pool never calls this: the worker inherits proj/mo/
    # arch/md by copy-on-write like everything else, and pickling them
    # would only waste time. It exists for platforms with no fork() at
    # all (Windows), where a spawned worker starts empty and the built
    # ctx has to be shipped to it once via Pool(..., initargs=(ctx,)).
    # Rebuilding proj/mo/arch/md there is just re-loading the ELF image --
    # seconds -- not redoing the CFG recovery and jump-table resolution
    # that produced the rest of this object, which is what makes shipping
    # the finished analysis cheaper than repeating it in every worker.
    _UNPICKLED_ATTRS = ('proj', 'mo', 'arch', 'md')

    def __getstate__(self):
        state = self.__dict__.copy()
        for k in self._UNPICKLED_ATTRS:
            state.pop(k, None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        elfcompat.apply()
        opts = {'base_addr': self.base} if self.base is not None else {}
        self.proj = angr.Project(self.binary, auto_load_libs=False, main_opts=opts)
        self.mo = self.proj.loader.main_object
        self.arch = self.proj.arch
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.skipdata = True

    # ------------------------------------------------------------- segments

    def _check_cache(self):
        """Finish the cache check for a cache too old to carry a hash.

        Everything in cache/ is keyed by address, so a mismatched cache does
        not fail -- it produces a tree assembled from one binary's function
        list and another binary's bytes, which is a translation of neither.
        The hash case was settled in __init__ before anything was loaded; what
        is left is the pre-hash cache, where the load base and the text span
        are the only evidence there is.  Unlike analyze.py this stage cannot
        rebuild the cache (that is the ~20-minute CFG recovery), so a mismatch
        stops and says what to run.  See lib/cachekey.py.
        """
        if self._cache_verified:
            return

        lo = hi = None
        try:
            # The same span analyze.py recorded: the executable part of the
            # image.
            for seg in self.mo.segments:
                if not getattr(seg, 'is_executable', False):
                    continue
                a = seg.vaddr
                b = a + seg.memsize
                lo = a if lo is None else min(lo, a)
                hi = b if hi is None else max(hi, b)
        except Exception:
            lo = hi = None

        why, _ = cachekey.check(self.cachedir, self.binary,
                                base=self.base, text_lo=lo, text_hi=hi)
        if why:
            raise SystemExit(_cache_mismatch(self.cachedir, self.binary, why,
                                             self.base))
        print('warning: cache %s/ predates the sha256 stamp -- its load base '
              'and text span match this binary, but that is not proof they '
              'were built from it.  Re-running analyze.py would settle it.'
              % self.cachedir)

    def _segments(self):
        self.rx = self.ro = self.rw = None
        for s in self.mo.segments:
            span = (s.vaddr, s.vaddr + s.memsize, s.filesize)
            if s.is_executable:
                self.rx = span
            elif s.is_writable:
                self.rw = span
            else:
                self.ro = span
        if self.rx is None:
            raise RuntimeError('no executable segment')

    def _read_image(self, addr, n):
        """Raw bytes of the loaded image, or None if the range is not mapped.

        Used by the .gcc_except_table reader; returning None rather than
        raising lets a malformed table degrade to "no landing pads here".
        """
        try:
            return bytes(self.proj.loader.memory.load(addr, n))
        except Exception:
            return None

    def in_rx(self, a):
        return self.rx and self.rx[0] <= a < self.rx[1]

    def in_ro(self, a):
        return self.ro and self.ro[0] <= a < self.ro[1]

    def in_rw(self, a):
        return self.rw and self.rw[0] <= a < self.rw[1]

    def _regoffsets(self):
        r = self.arch.registers
        self.off = {}
        for nm in ['x%d' % i for i in range(31)] + ['sp', 'pc', 'x30']:
            if nm in r:
                self.off[nm] = r[nm][0]
        # vector registers: q0.. are named differently across archinfo versions
        self.qoff = None
        for cand in ('q0', 'v0', 'd0'):
            if cand in r:
                self.qoff = r[cand][0]
                break
        self.pc_offset = r['pc'][0] if 'pc' in r else -1
        self.lr_offset = r['x30'][0] if 'x30' in r else -1
        self.state_size = max(o + s for o, s in r.values())

    # ---------------------------------------------------------------- cache

    def _load_cache(self):
        fp = os.path.join(self.cachedir, 'funcs.json')
        if os.path.exists(fp):
            data = json.load(open(fp))
            dropped = 0
            for k, v in data.items():
                a = int(k, 16)
                # Same rule as _EntrySet: an AArch64 instruction is 4-byte
                # aligned, so a "function" at an unaligned address is not code.
                # analyze.py no longer seeds one, but a cache built before that
                # still names it -- and this one, from a C++ pointer-to-member
                # function's `vtable_offset + 1`, translated to a single
                # `guest_nodecode` body.  Dropping it here means an existing
                # cache does not have to be rebuilt to be rid of it.
                if a & 3:
                    dropped += 1
                    continue
                self.funcs[a] = v
                self.blocks_of[a] = [int(b, 16) for b in v['blocks']]
            # self.notes does not exist yet -- _load_cache() runs before it is
            # created -- so the count is stashed and reported once it does.
            self._unaligned_dropped = dropped
            self.func_set = set(self.funcs)
            self._trim_pending = True
        fp = os.path.join(self.cachedir, 'indirect.json')
        if os.path.exists(fp):
            for k, v in json.load(open(fp)).items():
                if v['resolved']:
                    self.jumptables[int(k, 16)] = [int(t, 16) for t in v['resolved']]
                else:
                    # The CFG could not recover this jump table, so a computed
                    # branch here can reach any block of the function.  Every
                    # one of them therefore needs to be re-enterable, or the
                    # branch lands on an address with no translation.
                    try:
                        self.open_branch_funcs.add(int(v['func'], 16))
                    except (KeyError, ValueError):
                        pass
        fp = os.path.join(self.cachedir, 'seeds.json')
        if os.path.exists(fp) and not self.func_set:
            self.func_set = set(int(x, 16) if isinstance(x, str) else x
                                for x in json.load(open(fp)))

    # ------------------------------------------------------- lazy discovery

    def scan_function(self, addr):
        """Discovery-only pass: find the addresses a function references.

        Pass 1 exists to learn which code addresses appear as constants and
        which functions get called, so pass 2 can give owners their re-entry
        cases.  Running the full emitter for that was wasteful -- it formats a
        C statement for every IR statement and discards all of it.  This walks
        the same IR and only records the addresses.
        """
        blocks = self.blocks_of.get(addr) or self.discover(addr)
        self.cur_func = addr
        self.cur_labels = set(blocks)
        for b in blocks:
            irsb = self.lift(b, limit=self.next_block_start(b, blocks))
            if irsb is None:
                continue
            lr_off = self.off.get('x30')
            for st in irsb.statements:
                stt = type(st).__name__
                # A conditional branch's destination is a DIRECT target: it
                # already gets a label and is reached by goto, never through
                # dispatch.  Registering those as re-entry points added a case
                # for essentially every block in the binary.
                if stt == 'Exit':
                    d = st.dst.value
                    if d not in self.cur_labels:
                        self.call_name(d)
                    continue
                is_lr = (stt == 'Put' and st.offset == lr_off)
                for e in st.expressions:
                    if type(e).__name__ == 'Const':
                        v = e.con.value
                        if isinstance(v, int) and self.in_rx(v):
                            self.const_addr(v, register=not is_lr)
            if irsb.jumpkind == 'Ijk_Call':
                ret = irsb.addr + irsb.size
                if ret not in self.cur_labels and self.in_rx(ret) \
                        and ret not in self.owned_blocks:
                    self.call_name(ret)   # continuation of a split function
            nxt = irsb.next
            if type(nxt).__name__ == 'Const':
                d = nxt.con.value
                if irsb.jumpkind == 'Ijk_Call' or d not in self.cur_labels:
                    if not self.is_ignored_import(d) and not self.direct_import(d):
                        self.call_name(d)
            elif irsb.jumpkind != 'Ijk_Ret':
                # A computed branch.  Recording it here is essential: pass 2
                # gives such functions a local dispatch so the branch becomes a
                # goto.  Without it the branch leaves through guest_dispatch and
                # re-enters the SAME function as a nested call -- the inner
                # instance then runs the epilogue, pops the frame, and the outer
                # one resumes with a corrupted stack pointer.
                self.indirect_branch_funcs.add(addr)

    def _br_addresses(self):
        """Sorted addresses of every unconditional `br Xn` in the text.

        AArch64 encodes it as 1101011000011111000000 Rn 00000, i.e.
        `0xD61F0000 | (Rn << 5)`, so little-endian the top two bytes are always
        1f d6 and only five bits of the rest vary.  Searching the text image
        for that two-byte tail and checking alignment and the full mask finds
        them all in one pass, which is what lets resolve_jump_tables() skip the
        blocks that cannot possibly hold a jump table.

        BRAA/BRAB (pointer authentication) encode differently and capstone
        names them `braa`/`brab`, so the old scan never matched them either --
        this is the same set of instructions, found a cheaper way.
        """
        if self._br_at is None:
            lo, hi, _ = self.rx
            if self._text_cache is None:
                self._text_cache = (lo, bytes(self.proj.loader.memory.load(lo, hi - lo)))
            tlo, buf = self._text_cache
            out = []
            pos = buf.find(b'\x1f\xd6')
            while pos >= 0:
                off = pos - 2
                if off >= 0 and off % 4 == 0:
                    word = int.from_bytes(buf[off:off + 4], 'little')
                    if word & 0xFFFFFC1F == 0xD61F0000:
                        out.append(tlo + off)
                pos = buf.find(b'\x1f\xd6', pos + 1)
            self._br_at = out
        return self._br_at

    def resolve_jump_tables(self):
        """Recover jump-table targets the CFG could not.

        The compiler emits one dominant shape:

            adr  xB, #base                  ; branch base, inside this function
            ldrh wV, [xT, xI, lsl #1]       ; 16-bit offset out of .rodata
            add  xB, xB, wV, lsl #2         ; target = base + offset*4
            br   xB

        (also with ldrb, and with the table reached via adrp+add).  Reading the
        table out of the read-only image gives the arms directly.  This matters
        because an arm can sit in the MIDDLE of a block -- no label exists there
        otherwise, so a computed branch has nothing to land on.

        The table length is not encoded, so entries are read until one points
        outside the function's own span, which is what bounds a real table.
        """
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        targets = set()

        # Only a block that CONTAINS a `br` can reach the `br` arm below, and
        # base/scale are reset for every block, so a block with no `br` cannot
        # affect the result no matter what capstone would have said about it.
        # Disassembling all 779,898 of them to find that out was 8.6% of a full
        # run; the addresses of every `br` in the image are found once, with a
        # byte search, and a block is skipped unless one lands inside it.
        br_at = self._br_addresses()

        for fa, blocks in list(self.blocks_of.items()):
            if not blocks:
                continue
            flo, fhi = min(blocks), max(blocks) + 0x400
            for b in blocks:
                nb = self.next_block_start(b, blocks)
                n = (nb - b) if nb else 0x100
                end = b + min(n, 0x200)
                k = bisect.bisect_left(br_at, b)
                if k >= len(br_at) or br_at[k] >= end:
                    continue                  # no `br` here: nothing to find
                try:
                    data = self.proj.loader.memory.load(b, min(n, 0x200))
                except Exception:
                    continue
                base = tbl = scale = None
                # The `cmp wI, #N` that bounds the index is very often in the
                # PRECEDING block: the compiler puts `cmp` + `b.hi default` at
                # the end of one block and starts a new one at the load, so a
                # per-block scan never sees it.  Look back a little first; the
                # in-block scan below overrides this if it finds a nearer one.
                guard = None
                pre = max(flo, b - 0x40)
                if pre < b:
                    try:
                        pdata = self.proj.loader.memory.load(pre, b - pre)
                        for pi in md.disasm(pdata, pre):
                            if pi.mnemonic in ('cmp', 'subs'):
                                pm = re.search(r',#(\w+)$', pi.op_str.replace(' ', ''))
                                if pm:
                                    try:
                                        guard = int(pm.group(1), 0)
                                    except ValueError:
                                        pass
                    except Exception:
                        pass
                for i in md.disasm(data, b):
                    op = i.op_str.replace(' ', '')
                    if i.mnemonic in ('cmp', 'subs'):
                        m = re.search(r',#(\w+)$', op)
                        if m:
                            try:
                                guard = int(m.group(1), 0)
                            except ValueError:
                                guard = None
                    if i.mnemonic == 'adr':
                        parts = op.split(',#')
                        if len(parts) == 2:
                            try:
                                base = int(parts[1], 0)
                            except ValueError:
                                pass
                    elif i.mnemonic in ('ldrh', 'ldrb', 'ldrsh', 'ldrsw'):
                        m = re.search(r'\[(\w+),(\w+)(?:,lsl#(\d+))?\]', op)
                        if m:
                            scale = {'ldrb': 1, 'ldrh': 2, 'ldrsh': 2, 'ldrsw': 4}[i.mnemonic]
                    elif i.mnemonic == 'br' and scale:
                        # Find the table: the most recent adrp+add pair feeding
                        # the load is resolved by VEX, so re-lift and take any
                        # read-only constant address the block computes.
                        irsb = self.lift(b, min(n, 0x200))
                        cands = []
                        if irsb is not None:
                            for st in irsb.statements:
                                for e in st.expressions:
                                    if type(e).__name__ == 'Const':
                                        v = e.con.value
                                        if self.in_ro(v):
                                            cands.append(v)
                        if not cands:
                            # The table address is not computed in this block:
                            # the compiler hoisted `adrp/add` into an earlier
                            # one and the `br` block only does
                            # `ldrh wV, [xTable, xI, lsl #1]`.  Widen the search
                            # to every read-only constant the FUNCTION computes.
                            # A wrong guess costs nothing -- the arms it
                            # produces have to land inside this function's span,
                            # and there have to be at least two of them, or the
                            # candidate is dropped below.
                            #
                            # Without this, f_7100096220's 101-arm table was
                            # missed entirely and a computed branch aborted with
                            # "no translation for computed target 0x7100096c20"
                            # on any shader compiled with --enable-warp-culling.
                            cands = self._ro_consts_of_function(fa, blocks)
                        for tbl in cands:
                            # Hard cap from the binary's own bounds checks: the
                            # largest case index guarded by a `cmp #N` before an
                            # adr/br table dispatch is 271 across this image
                            # (99th percentile 209).  The previous limit of 512
                            # let a table run past its end into whatever
                            # followed, inventing arms that belong to no
                            # function -- the "no dispatch entry" warnings.
                            if base is not None:
                                arms = set()
                                for k in range(0, self.jump_table_cap):
                                    raw = self.proj.loader.memory.load(tbl + k * scale, scale)
                                    val = int.from_bytes(raw, 'little')
                                    t = base + val * 4
                                    if not (flo <= t < fhi):
                                        break
                                    arms.add(t)
                                if len(arms) >= 2:
                                    targets |= arms
                            # THE SECOND SHAPE: a SELF-RELATIVE table.
                            #
                            #     adrp x9, <page> ; add x9, x9, #<off>   ; x9 = &table
                            #     ldrsw x8, [x9, x8, lsl #2]             ; signed entry
                            #     add   x8, x8, x9                       ; target = &table + entry
                            #     br    x8
                            #
                            # Three things differ from the shape above and all
                            # three defeat it: the base register holds the
                            # TABLE's own address rather than a code address
                            # from `adr`, the entries are SIGNED (they point
                            # backwards, from .rodata into .text), and they are
                            # NOT scaled by 4.  There is no `adr` at all, which
                            # is why the guard above had to stop requiring one.
                            #
                            # Missing this shape is not cosmetic.  Its arms
                            # never become blocks, so nothing can land on them;
                            # the computed branch then leaves the guest address
                            # space entirely and guest_dispatch, finding no
                            # entry, falls through to its "must be a host
                            # function pointer" case and CALLS INTO THE MIDDLE
                            # OF A HOST FUNCTION.  Observed on glslc.elf 17.10
                            # as a fault at f_71006ec5a8+866 with a garbage
                            # frame -- see HANDOVER sec.31.8.
                            if scale == 4:
                                # LENGTH comes from the binary's own bounds
                                # check when there is one.  A self-relative
                                # table routinely reaches arms OUTSIDE the
                                # function the CFG recovered -- the compiler
                                # lays the switch arms out past the end of what
                                # angr called a function -- so bounding the
                                # read by the function's span truncates the
                                # table at its first far arm and silently drops
                                # the rest.  That is how 0x55810c went missing
                                # while its neighbours at 0x557920..0x557ec0
                                # were found: same table, later entry.
                                #
                                # `cmp wI, #N` + `b.hi default` immediately
                                # before the dispatch states the real length,
                                # N+1, and it is the guest's own guarantee
                                # rather than a guess.  With it the arms only
                                # have to be plausible branch targets:
                                # executable and instruction-aligned.
                                n = (guard + 1) if guard is not None else 0
                                if 0 < n <= self.jump_table_cap:
                                    arms = set()
                                    for k in range(0, n):
                                        raw = self.proj.loader.memory.load(tbl + k * 4, 4)
                                        val = int.from_bytes(raw, 'little', signed=True)
                                        t = tbl + val
                                        if (t & 3) or not self.in_rx(t):
                                            # Stop here, but KEEP what has
                                            # already been read.  The guard is
                                            # a hint, not a contract -- the cmp
                                            # may bound something other than
                                            # this table, in which case the
                                            # walk simply runs off the end of a
                                            # shorter one.  Discarding the
                                            # whole table on the first bad
                                            # entry threw away 23k good arms
                                            # (39,835 -> 16,973) and put back
                                            # the very unresolved transfers
                                            # this shape was added to fix.
                                            break
                                        arms.add(t)
                                    if len(arms) >= 2:
                                        targets |= arms
                                else:
                                    # No usable guard: fall back to the span
                                    # bound, which at least cannot invent arms
                                    # outside the function.
                                    arms = set()
                                    for k in range(0, self.jump_table_cap):
                                        raw = self.proj.loader.memory.load(tbl + k * 4, 4)
                                        val = int.from_bytes(raw, 'little', signed=True)
                                        t = tbl + val
                                        if not (flo <= t < fhi):
                                            break
                                        arms.add(t)
                                    if len(arms) >= 2:
                                        targets |= arms
                        base = scale = None
        return targets

    def _ro_consts_of_function(self, fa, blocks):
        """Every read-only address the function's blocks compute.

        Cached per function: resolve_jump_tables() may ask for it once per
        unresolved `br`, and lifting a large function's blocks again is not
        free.
        """
        cache = getattr(self, '_ro_const_cache', None)
        if cache is None:
            cache = self._ro_const_cache = {}
        if fa in cache:
            return cache[fa]
        out = []
        for b in blocks:
            nb = self.next_block_start(b, blocks)
            n = (nb - b) if nb else 0x100
            irsb = self.lift(b, min(n, 0x200))
            if irsb is None:
                continue
            for st in irsb.statements:
                for e in st.expressions:
                    if type(e).__name__ == 'Const' and self.in_ro(e.con.value):
                        out.append(e.con.value)
        cache[fa] = out
        return out

    def sweep_missed_blocks(self):
        """Block starts the CFG never enumerated.

        A jump-table arm that follows a `ret` (and its `udf` padding) is
        reachable only through the table, so if the table was not recovered the
        CFG never sees the block at all -- it is neither a function nor part of
        one.  A computed branch there then has nothing to land on.

        A linear sweep finds them: an instruction directly after a ret/b/br,
        skipping padding, that no known block already covers.  On this binary
        that is 32 addresses, so the sweep costs almost nothing.
        """
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        md.skipdata = True
        lo, hi, _ = self.rx
        known = set(self.funcs)
        for fi in self.funcs.values():
            for b in fi.get('blocks', ()):
                known.add(int(b, 16) if isinstance(b, str) else b)
        for a, blks in self.blocks_of.items():
            known.add(a)
            known.update(blks)

        data = bytes(self.proj.loader.memory.load(lo, hi - lo))
        insns = list(md.disasm(data, lo))
        found = set()
        for idx, i in enumerate(insns):
            if i.mnemonic not in ('ret', 'b', 'br', 'udf'):
                continue
            j = idx + 1
            while j < len(insns) and insns[j].mnemonic == 'udf':
                j += 1
            if j < len(insns):
                a = insns[j].address
                if a not in known and insns[j].mnemonic != 'udf':
                    found.add(a)
        return found

    def detect_false_starts(self):
        """CFG "functions" that are really continuation blocks.

        A genuine function entry receives its arguments in x0-x7, so the only
        legitimate reason to READ a callee-saved register before writing it is
        to save it.  Any other use means the value belongs to a caller's frame,
        which can only happen if control arrived by a jump from inside that
        frame -- i.e. the address is a jump-table target, not a function.

        Translating one of these as a function is what produced the crash that
        motivated this: entering at such a block skips the real prologue, so
        x19 kept whatever the previous call had left in it.
        """
        # x0-x7 carry arguments and x8 the indirect result pointer, so those
        # may legitimately be read at entry.  Everything else -- the scratch
        # registers x9-x17 as much as the callee-saved x19-x28 -- holds nothing
        # defined at a real entry, so reading one (other than to save it) means
        # the value belongs to a caller's frame and this is a continuation
        # block.  x9 is what exposed 0x80c324, which the callee-saved-only
        # check had missed.
        cs = {self.arch.registers['x%d' % i][0]
              for i in list(range(9, 18)) + list(range(19, 29))}
        out = set()
        for a in self.funcs:
            if a in self.ignored_funcs:
                continue          # _init/_fini and the constructors are not folded
            irsb = self.lift(a, 96)
            if irsb is None:
                continue
            written, saved = set(), set()
            flagged = False
            for st in irsb.statements:
                t = type(st).__name__
                if t == 'WrTmp' and type(st.data).__name__ == 'Get' \
                        and st.data.offset in cs:
                    if st.data.offset not in written:
                        saved.add(st.tmp)
                    continue
                if t == 'Store':
                    continue                    # saving it is legitimate
                if t == 'Put' and st.offset in cs:
                    written.add(st.offset)

                def uses(e):
                    if type(e).__name__ == 'RdTmp' and e.tmp in saved:
                        return True
                    return any(uses(ch) for ch in getattr(e, 'child_expressions', []))

                if any(uses(e) for e in st.expressions):
                    flagged = True
                    break
            if flagged:
                out.add(a)
        return out

    def reattach_false_starts(self, false_starts):
        """Fold each false start into the function that encloses it."""
        real = sorted(a for a in self.funcs if a not in false_starts)
        attached = 0
        for a in sorted(false_starts):
            owner = None
            lo, hi = 0, len(real)
            while lo < hi:                       # nearest real start below a
                mid = (lo + hi) // 2
                if real[mid] < a:
                    owner, lo = real[mid], mid + 1
                else:
                    hi = mid
            if owner is None:
                continue
            self.forced_entries.setdefault(owner, set()).add(a)
            blocks = set(self.blocks_of.get(owner) or [])
            blocks |= set(self.discover(a))      # the tail reachable from here
            self.blocks_of[owner] = sorted(blocks)
            # The false start was a jump-table target, so this function has a
            # table the CFG never recovered: any of its blocks can be branched
            # to, and all of them need a re-entry case.
            self.open_branch_funcs.add(owner)
            self.func_set.discard(a)
            self.funcs.pop(a, None)
            attached += 1
        return attached

    def apply_trimming(self):
        """Truncate over-merged functions once the whole function set is known."""
        for a in list(self.blocks_of):
            self.blocks_of[a] = self.trim_blocks(a, self.blocks_of[a])

    def complete_blocks(self, entry):
        """Union the CFG's block list with our own walk from the entry.

        angr's list can be INCOMPLETE: f_008716a0 was reported as 45 blocks
        ending at 0x871e2c, but the function continues past there and its
        epilogue -- the `add sp, #0x70` matching its prologue -- lies in the
        missing tail.  Any path reaching that tail never restored SP, leaking
        0x70 per call and corrupting the caller's saved registers.

        Walking the branches ourselves finds the rest, so the two are merged
        rather than trusting either alone.
        """
        cfg = set(self.blocks_of.get(entry) or [])
        walked = set(self._walk_blocks(entry))
        merged = cfg | walked
        if walked - cfg:
            self.notes.append(('CFG block list incomplete', entry,
                               '%d blocks added by walking' % len(walked - cfg)))
        self.blocks_of[entry] = sorted(merged)
        return self.blocks_of[entry]

    def discover(self, entry):
        """Walk one function's blocks with pyvex alone.

        Used when the CFG cache has no entry for `entry`; a constant branch to
        another known function start is a tail call, anything else is a local
        block of this function.
        """
        if entry in self.blocks_of:
            return self.blocks_of[entry]
        self.blocks_of[entry] = self.trim_blocks(entry, sorted(self._walk_blocks(entry)))
        return self.blocks_of[entry]

    def _walk_blocks(self, entry):
        """Blocks reachable from `entry` by following branches."""
        seen, work, order = set(), [entry], []
        while work:
            a = work.pop()
            if a in seen:
                continue
            seen.add(a)
            order.append(a)
            irsb = self.lift(a)
            if irsb is None:
                continue
            for s in irsb.statements:
                if type(s).__name__ == 'Exit':
                    d = s.dst.value
                    if d not in self.func_set or d == entry:
                        work.append(d)
            nxt = irsb.next
            if irsb.jumpkind == 'Ijk_Call':
                ret = irsb.addr + irsb.size
                if self.in_rx(ret):
                    work.append(ret)
            elif irsb.jumpkind == 'Ijk_Boring' and type(nxt).__name__ == 'Const':
                d = nxt.con.value
                if d not in self.func_set or d == entry:
                    work.append(d)
        return order

    def lift(self, addr, max_bytes=400, limit=None):
        """Lift one block.

        `limit` caps the block at the next known block start, so a block that
        is also branched into does not get duplicated inside its predecessor.
        """
        if limit is not None and limit > addr:
            max_bytes = min(max_bytes, limit - addr)
        # Slice a cached copy of the code image rather than calling into CLE's
        # paged memory.  Recovering jump-table arms multiplied the number of
        # (much smaller) blocks, so lift() is called far more often, and the
        # per-call cost of CLE's lookup came to dominate generation.
        if self._text_cache is None:
            lo, hi, _ = self.rx
            self._text_cache = (lo, bytes(self.proj.loader.memory.load(lo, hi - lo)))
        tlo, tbuf = self._text_cache
        off = addr - tlo
        if off < 0 or off >= len(tbuf):
            try:
                data = self.proj.loader.memory.load(addr, max_bytes)
            except Exception:
                return None
        else:
            data = tbuf[off:off + max_bytes]
        if not data:
            return None
        try:
            return pyvex.lift(data, addr, self.arch, opt_level=1)
        except Exception:
            return None

    def trim_blocks(self, addr, blocks):
        """Cut a function short at the first other function that starts inside it.

        CFG recovery sometimes glues a long stretch of code into one function:
        on this binary a single "function" absorbed 626 KB and 23,074 blocks,
        nine times the next largest, which gcc could not even compile.  If a
        known function starts inside that span, the merge is simply wrong -- so
        the span is truncated at the EARLIEST such start, which cuts away the
        most incorrectly-absorbed code.
        """
        if not blocks:
            return blocks

        # A function that absorbed folded jump-table targets legitimately spans
        # a wide range: those targets ARE its blocks.  Trimming it at the first
        # following function start would throw them away again, and the
        # re-entry cases built from them would name blocks that never got
        # emitted.
        # Blocks folded into this function must survive, but exempting it from
        # trimming ENTIRELY brought back the over-merge: 0x8b7c10 is a
        # five-instruction jump-table stub that had absorbed 1,773 real
        # functions, and it grew to 712,000 lines of C again.  So protect only
        # as far as the highest folded block, and trim normally beyond it.
        protected = self.forced_entries.get(addr)
        floor = max(protected) if protected else None

        # Trimming exists to contain the over-merge, where a jump-table stub
        # absorbed 23,074 blocks and 626 KB of code.  Cutting at the first
        # inner start used to drop legitimate tails -- f_00980630 lost the
        # block at 0x98462c and f_008716a0 lost its epilogue -- so it was
        # gated on a block count large enough that only the pathological case
        # could reach it.  The gate is a proxy, though, and the real evidence
        # (a genuine function entry inside the span) is already computed
        # below; TRIM_MIN_BLOCKS exists so the two can be measured against
        # each other.  See HANDOVER section 16.
        if len(blocks) < TRIM_MIN_BLOCKS:
            return blocks

        hi = max(blocks)
        # Binary search over a sorted snapshot of the function starts.  The
        # linear scan this replaces was O(functions) per call and discover()
        # calls it once per function -- tolerable at a few thousand functions,
        # but it became the dominant cost once jump-table arms multiplied the
        # number of blocks.
        # Snapshot once.  func_set keeps growing as emission discovers new call
        # targets, so invalidating whenever its size changed re-sorted thousands
        # of entries on nearly every call.  Trimming only needs the boundaries
        # known before emission began: a function found later should not
        # retroactively cut one that was already emitted.
        if self._sorted_starts is None:
            # Only cut at addresses that look like REAL function entries.
            # func_set also holds jump-table arms and continuation blocks, and
            # cutting there splits a genuine function in half: f_008716a0 lost
            # everything past 0x871884, so the tail (including its epilogue)
            # became separate translations that skip the prologue and pop a
            # frame nobody pushed.
            bad = self.false_starts if self.false_starts is not None else set()
            self._sorted_starts = sorted(a for a in self.func_set
                                         if a not in bad and a in self.funcs)
        starts = self._sorted_starts
        after = max(addr, floor) if floor is not None else addr
        idx = bisect.bisect_right(starts, after)
        cut = starts[idx] if idx < len(starts) and starts[idx] <= hi else None
        if cut is None:
            return blocks
        trimmed = [b for b in blocks if b < cut]
        if len(trimmed) != len(blocks):
            self.notes.append(('function truncated at overlapping start', addr,
                               'cut at %#x, %d of %d blocks kept'
                               % (cut, len(trimmed), len(blocks))))
        return trimmed or blocks[:1]

    def next_block_start(self, addr, blocks):
        """First block start strictly after `addr`, or None."""
        # `blocks` is sorted, so this is a binary search rather than the linear
        # scan it used to be -- that scan ran once per block, making emission
        # quadratic in the number of blocks per function.
        idx = bisect.bisect_right(blocks, addr)
        return blocks[idx] if idx < len(blocks) else None

    # ------------------------------------------------------ emitter callbacks

    def disasm(self, addr, size):
        try:
            data = self.proj.loader.memory.load(addr, max(size, 4))
        except Exception:
            return '%#x' % addr
        parts = []
        for i in self.md.disasm(data[:size or 4], addr):
            parts.append('%s %s' % (i.mnemonic, i.op_str))
        return '%#x  %s' % (addr, '; '.join(parts) if parts else '?')

    def arms_owned_by(self, addr):
        """Recovered arms whose nearest preceding function start is `addr`."""
        if self._arm_owner is None:
            starts = sorted(self.func_set)
            self._arm_owner = {}
            for a in sorted(self.potential_entries):
                i = bisect.bisect_right(starts, a) - 1
                if i >= 0:
                    self._arm_owner.setdefault(starts[i], set()).add(a)
        return self._arm_owner.get(addr, set())

    def _plausible_target(self, v):
        """Could this code constant really be a computed branch target?

        ADRP yields a page-aligned address that merely lands in the text range,
        and taking a function's address for a call is not a branch either.  A
        genuine computed target is instruction-aligned and lies inside the
        function doing the branching; anything else was noise inflating the
        re-entry switches by hundreds of thousands of cases.
        """
        if not self.cur_labels:
            return False
        lo = self.cur_func or min(self.cur_labels)
        return lo <= v < max(self.cur_labels) + 0x400

    def const_is_immediate_data(self, insn_addr, v):
        """True when a constant is a plain integer, not an address to rewrite.

        const_addr() classifies by VALUE: anything landing inside a loaded
        section is treated as an address and rewritten to point at the
        generated arrays.  For a 3 MB read-only image that range is wide enough
        for ordinary integers to collide with it by coincidence, and rewriting
        one corrupts it -- the constant stops being the number the guest wrote.

        The observed case was `mov w9, #0xb90000`, an opcode (185) shifted into
        the top half of a packed {op:16, flags:16} word.  0xb90000 also happens
        to fall inside the read-only image, so it was rewritten to a host
        pointer; the guest then OR-ed that in and read the opcode back as 4692.

        A move-wide immediate settles it, because this input is a PIE: the
        compiler does not know the load address, so it CANNOT embed an absolute
        address as an immediate.  Address formation is adrp/adr (PC-relative)
        or a GOT load, and both stay eligible for rewriting.  So a constant
        coming from movz/movn/movk is data, categorically, not heuristically.

        Decoded straight from the 4-byte encoding rather than through capstone,
        since this runs on every 64-bit constant in the program:

            sf  opc  1 0 0 1 0 1  hw  imm16  Rd
            31 30-29 <-- 28..23 -->

        Move-wide is not the only such family.  Three more, all decided by the
        same PIE argument:

        * **Logical immediate** (and/orr/eor/ands, bits 28..23 = 100100).  A
          bitmask immediate is a repeating run of ones -- a mask, never an
          address -- and an address pair never folds onto one.

        * **Flag-setting add/sub immediate** (adds/subs, i.e. cmp/cmn, bits
          28..23 = 100010 with S = 1).  This is the family that broke the
          fragment path: `cmp w8, #0xb90, lsl #12` compares an opcode (185)
          shifted into the top half of a packed {op:16, flags:16} word, and
          0xb90000 lands in the read-only image, so the comparand became
          `g_ro + 0x18e000` and the comparison could never be true.  The
          effect was that the comma node was never lowered and CreateDag
          later rejected it.  The exclusion below (do not extend to
          add/sub-immediate) is about the address-pair fold, and a fold never
          lands on a flag-setting form: an adrp/add pair uses plain `add`,
          because `adds` would clobber the flags.  So S = 1 is categorically
          data.

        * **Plain add immediate** (S = 0) -- the case the note below warns
          about, now decided rather than assumed.  VEX only produces a
          CONSTANT here when the whole address computation folded, and in a
          PIE that computation must start at an adrp/adr; a GOT load yields a
          runtime value, not a constant.  So the encoding is scanned backwards
          for an adrp/adr writing the add's own source register: found means
          this really is the second half of an address pair and the constant
          stays an address (the old, conservative answer); not found means
          nothing PC-relative feeds it and the constant is data.

        The original warning, kept because the reasoning still holds:

        Extending this to add/sub-immediate BLINDLY looks equally justified by
        the PIE argument and is wrong, because VEX folds an adrp/add address
        pair into a single constant and attributes it to the SECOND
        instruction:

            IMark(adrp) ; IMark(add) ; PUT(x0) = 0x304c73c

        so the constant sitting at an add-immediate is routinely a complete
        address.  Suppressing those unconditionally left raw guest addresses
        in the output and crashed on the first dereference.  That is why the
        add-immediate case is gated on the backwards scan rather than waved
        through.

        adr/adrp (bits 28..24 = 10000) do not collide with any pattern above
        and stay eligible, as does a literal-pool load, whose address is
        PC-relative rather than an immediate.

        Guarded on the image actually being position-independent; for a
        non-PIE input an absolute address in an immediate is legitimate and the
        old value-based classification is the best available.
        """
        if insn_addr is None or not self.pic_image:
            return False
        if self.image_above_4g:
            # Nothing to disambiguate: see Ctx.image_above_4g.  Answering
            # False here keeps classification purely value-based, which is
            # what makes a mapped-high image the stronger fix -- the encoding
            # rules below can only ever demote a real address by mistake.
            return False
        key = (insn_addr, v)
        hit = self._immcache.get(key)
        if hit is None:
            hit = self._classify_immediate(insn_addr, v)
            self._immcache[key] = hit
        if hit:
            self.const_log.append((v, 'immediate-data', '%#x' % insn_addr))
        return hit

    def fp_minmax_is_nm(self, insn_addr):
        """True when the guest instruction is FMAXNM/FMINNM rather than FMAX/FMIN.

        VEX lifts all four to the same Iop (Max32Fx4 and friends), losing the
        distinction, and they differ in NaN handling: FMAX propagates a quiet
        NaN, FMAXNM ignores it and returns the other operand.  The encoding
        does distinguish them, so read it back here.

        Scalar (FMAX/FMIN/FMAXNM/FMINNM, register form):
            0 0 0 1 1 1 1 0 type 1 Rm  opcode 1 0 Rn Rd     bits 31..24 = 0x1E/0x1F
            opcode (bits 15..12): 0100 FMAX, 0101 FMIN, 0110 FMAXNM, 0111 FMINNM
        Vector (three-same):
            FMAX/FMIN  opcode 11110 (bits 15..11), U=0, with bit 23 selecting min
            FMAXNM/FMINNM opcode 11000
        """
        if insn_addr is None:
            return False
        w = self._insn_word(insn_addr)
        if w is None:
            return False
        # Scalar FP data-processing (2 source): 0001 1110 xx1x xxxx xxxx 10xx xxxx xxxx
        if (w & 0xFF200C00) == 0x1E200800:
            return ((w >> 12) & 0xF) in (0x6, 0x7)      # FMAXNM / FMINNM
        # Vector three-same, floating point: opcode field bits 15..11.
        if (w & 0x9F20FC00) in (0x0E20C400, 0x0EA0C400):
            return True                                  # FMAXNM / FMINNM
        return False

    def fp_is_fused_mac(self, insn_addr):
        """True when the guest instruction is a FUSED multiply-add.

        libVEX lifts every AArch64 fused multiply-add as an ordinary multiply
        followed by an ordinary add:

            fmadd d0, d0, d2, d1  ->  t11 = MulF64(rm, t13, t12)
                                      t10 = AddF64(rm, t14, t11)

        which rounds TWICE.  The hardware rounds once, and the difference is
        one unit in the last place -- enough that the shader compiler's own
        cost model took a different branch and emitted a different register
        assignment in the GLASM it embeds in the debug info.  `vecref.py`
        catches it directly: fmadd, fmla and their double-precision forms
        mismatched in 2 to 14 of 256 random states.

        This is the same shape of VEX limitation as FMAX vs FMAXNM (section
        11.3): the IR cannot express the distinction, so it is recovered from
        the ENCODING here and passed to irtoc.py through the context.  A false
        positive cannot do damage on its own -- irtoc only fuses when VEX
        really did produce a multiply feeding an add WITHIN THIS INSTRUCTION.

        The encodings, all of which are fused by definition:

          Scalar, floating-point data-processing (3 source) -- FMADD, FMSUB,
          FNMADD, FNMSUB.  There is nothing else in the class:
              0001 1111 type:2 o1 Rm:5 o0 Ra:5 Rn:5 Rd:5

          Vector FMLA/FMLS, three-same:
              0 Q 0 01110 0sz 1 Rm:5 11001 1 Rn:5 Rd:5
          bit 23 selects FMLS; U (bit 29) must be 0, or it is a different
          instruction entirely.

          Vector and scalar FMLA/FMLS, by element:
              0 Q 0 01111 sz L M Rm:4 0001 H 0 Rn:5 Rd:5      (0101 = FMLS)
              01 0 11111 sz L M Rm:4 0001 H 0 Rn:5 Rd:5       (scalar form)
        """
        if insn_addr is None:
            return False
        w = self._insn_word(insn_addr)
        if w is None:
            return False
        if (w & 0xFF000000) == 0x1F000000:
            return True                                  # FMADD/FMSUB/FNM*
        if (w & 0xBF20FC00) in (0x0E20CC00, 0x0EA0CC00):
            return True                                  # FMLA/FMLS vector
        if (w & 0xBF00F400) in (0x0F001000, 0x0F005000):
            return True                                  # FMLA/FMLS by element
        if (w & 0xFF00F400) in (0x5F001000, 0x5F005000):
            return True                                  # ... scalar form
        return False

    def _insn_word(self, a):
        """The 4 raw bytes of the instruction at a, as a little-endian word."""
        try:
            return int.from_bytes(self.proj.loader.memory.load(a, 4), 'little')
        except Exception:
            return 0

    def _classify_immediate(self, insn_addr, v):
        """Decide one constant.  See const_is_immediate_data() for the rules.

        Decoded straight from the 4-byte encoding rather than through
        capstone, since this runs on every 64-bit constant in the program:

            sf  opc  1 0 0 1 0 1  hw  imm16  Rd      move wide
            sf  opc  1 0 0 1 0 0  N immr imms Rn Rd  logical immediate
            sf op S  1 0 0 0 1 0  sh imm12  Rn Rd    add/sub immediate
            31 30-29 <-- 28..23 -->
        """
        word = self._insn_word(insn_addr)
        fam = (word >> 23) & 0x3F
        if fam == 0b100101:                     # movz / movn / movk
            return True
        if fam == 0b100100:                     # and / orr / eor / ands, imm
            return True
        if fam == 0b100010:                     # add / sub immediate
            if (word >> 29) & 1:                # S=1: adds/subs (cmp/cmn)
                return True
            if not (self.in_rx(v) or self.in_ro(v) or self.in_rw(v)):
                return False                    # const_addr would decline too
            return not self._feeds_from_pc_relative(insn_addr, word)
        return False

    def _feeds_from_pc_relative(self, insn_addr, word):
        """True when the add's source register is defined by an adrp/adr.

        That is the shape VEX folds into a single constant, so such a constant
        belongs to an address and must keep being rewritten.  Nothing else in
        a PIE produces a constant address at an add-immediate: a GOT load
        yields a runtime value, not something the folder can collapse.

        The add and its adrp need not be adjacent -- the scheduler routinely
        separates them -- so this walks backwards over the fixed-width
        encodings looking for the DEFINING write of the source register, and
        answers on that instruction alone.  "Defining write" is taken from
        capstone's register-access information rather than guessed from the
        opcode, because anything else would mistake a later, unrelated write
        to the same register for the address pair.

        The fold is not limited to two instructions.  A displaced address is
        built as a CHAIN of immediate adds and subs on the same register:

            adrp x8, 0xdc5000
            add  x8, x8, #0x968
            sub  x8, x8, #0x408      <- VEX attributes 0xdc5560 to this one

        so when the definer is itself a plain add/sub-immediate the walk
        retargets onto ITS source register and keeps going.  Stopping at the
        first definer instead reported "no adrp feeds this" for the third
        instruction above, left 0xdc5560 as a bare guest address, and crashed
        on the first dereference -- which is the same failure the original
        warning below describes.

        Conservative on doubt: an undecodable window, or one that reaches the
        start of the function without resolving, answers True, which is the
        behaviour this classifier had before the add-immediate family was
        handled at all.
        """
        md = self._capstone()
        if md is None:
            return True
        lo = insn_addr - self.PC_REL_SCAN
        if self.cur_func is not None and self.cur_func > lo:
            lo = self.cur_func
        if self.rx and self.rx[0] > lo:
            lo = self.rx[0]
        rn = (word >> 5) & 0x1F
        a = insn_addr - 4
        hops = 0
        while a >= lo:
            names = {'x%d' % rn, 'w%d' % rn}
            try:
                raw = self.proj.loader.memory.load(a, 4)
                ins = next(md.disasm(raw, a, 1))
                written = ins.regs_access()[1]
            except Exception:
                return True                     # cannot tell -- keep old answer
            if any(md.reg_name(r) in names for r in written):
                if ins.mnemonic in ('adrp', 'adr'):
                    return True
                w = self._insn_word(a)
                if ((w >> 23) & 0x3F) == 0b100010 and not ((w >> 29) & 1):
                    # another link of the displacement chain: follow its source
                    rn = (w >> 5) & 0x1F
                    hops += 1
                    if hops > self.PC_REL_HOPS:
                        return True
                    a -= 4
                    continue
                return False                    # defined by something else
            a -= 4
        return True                             # no definition in reach

    def _capstone(self):
        """A detail-enabled AArch64 decoder, created once, or None if absent.

        Only the add-immediate path needs it, and only for constants that
        actually land in the image, so this stays off the hot path.
        """
        if hasattr(self, '_cs'):
            return self._cs
        try:
            import capstone
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
            md.detail = True
        except Exception:
            md = None
        self._cs = md
        return md

    def const_addr(self, v, register=True):
        """Rewrite a constant that names a location in the loaded image."""
        if self.in_rx(v):
            # A code address stays exactly the number the original binary had.
            #
            # It is only ever used to compute a branch target: the guest does
            # base + (table_entry << 2) and branches.  Leaving the base as the
            # ORIGINAL address means that arithmetic produces the original
            # target address directly, and the branch is a straight lookup --
            # no mapping into a code image and back out again.
            #
            # This is only safe because the binary never reads its own code as
            # data: a load through such a value would dereference an address
            # that is not mapped.  Verified by scanning the IR of every
            # function for a load whose address derives from a .text constant;
            # if a future input has literal pools in .text, this is the line
            # that has to change.
            if v in self.func_set:
                self.referenced.add(v)
            elif register and (v & 3) == 0 and self._plausible_target(v):
                self.potential_entries.add(v)
            self.const_log.append((v, 'code-addr', ''))
            return 'UINT64_C(%#x)' % v
        if self.in_ro(v):
            self.const_log.append((v, 'ro', ''))
            return '(uint64_t)(uintptr_t)(g_ro + %#x)' % (v - self.ro[0])
        if self.in_rw(v):
            self.const_log.append((v, 'rw', ''))
            return '(uint64_t)(uintptr_t)(G_RW + %#x)' % (v - self.rw[0])
        return None

    def reloc_addr(self, v):
        """Rewrite a relocation target.

        A relocated slot holds a pointer the guest dereferences or calls --
        vtable entries and the like.

        A CODE target becomes the GUEST address, never `&f_<addr>`.  See
        the comment below this function for why; reloc_slot() follows it too.
        """
        if self.in_rx(v):
            self.potential_entries.add(v)
            return 'UINT64_C(%#x)' % v
        return self.const_addr(v)

    # ---- why a guest code pointer is always the GUEST address -------------
    # (referenced from reloc_addr() and reloc_slot())
    #
    # A code address reaches the guest by two routes, and the guest compares
    # the two against each other:
    #
    #   * materialised in the INSTRUCTION STREAM by `adr` / `adrp`+`add`, which
    #     libVEX constant-folds into an absolute address.  The translation has
    #     nothing else it could put there -- a host function pointer is not a
    #     number the guest's own arithmetic works on -- so this is the guest
    #     address;
    #   * loaded from a RELOCATED SLOT in the image (a vtable entry, a table of
    #     handlers), which used to become `&f_<addr>`, a HOST pointer, because
    #     calling it directly is faster than a dispatch.
    #
    # Those two are never equal, and subsdk0.elf contains the test that cares:
    #
    #     00f76230  adr  x8, #0xee2f60      ; the default handler
    #     00f76234  cmp  x3, x8             ; is this callback the default one?
    #     00f76238  b.ne #0xf76490          ; no -> call it
    #
    # `x3` came from a vtable, so it was a host pointer and the answer was
    # always "no".  The port then called a handler the original skips, which
    # set one extra bit in a component mask, and that difference reached the
    # output as a wrong source location in the debug-info section -- 34 of the
    # first 200 corpus shaders (HANDOVER.md sec.26).
    #
    # So there is ONE representation of a guest code pointer: the guest
    # address.  It compares equal whichever route it arrived by, and guest
    # pointer arithmetic on code addresses (a delta between two functions, a
    # switch table base) stays meaningful, which a host pointer cannot make it.
    # `guest_dispatch` already resolves guest addresses -- that path existed
    # for interior blocks, which never had an `f_<addr>` symbol to point at and
    # so were ALREADY emitted this way; the inconsistency was that the others
    # were not.  It keeps its host-pointer path for the things that really are
    # host code: the `plt_` thunks and the C++ typeinfo vtables in guest_cxx.c.
    #
    # The cost is a lookup per indirect call through a relocated slot instead
    # of a direct call.  guest_lookup is a binary search over the entry table;
    # measured on the corpus it is not visible against the compile itself.

    def reloc_slot(self, v):
        """Initialiser for a relocated RW slot, as (union field, expression).

        The same resolution as reloc_addr(), but shaped for a static
        initialiser rather than a runtime store, so an address stays a real
        address the LINKER resolves instead of being cast down to uint64_t.

        Returns 'p' for a DATA address, which stays a real address the linker
        resolves, and 'u' for a CODE address, which is the guest address as a
        plain integer -- one representation, for the reason set out under
        reloc_addr().  guest_dispatch resolves that number when the guest calls
        through the slot.
        """
        if self.in_rx(v):
            # Always the guest address -- see the comment under reloc_addr().
            self.potential_entries.add(v)
            return ('u', 'UINT64_C(%#x)' % v)
        if self.in_ro(v):
            return ('p', '(const void *)(g_ro + %#x)' % (v - self.ro[0]))
        if self.in_rw(v):
            return ('p', '(const void *)(G_RW + %#x)' % (v - self.rw[0]))
        return None

    def label(self, addr):
        return 'L_%08x' % addr

    def goto_or_call(self, dst, jumpkind):
        """C for a constant-target control transfer."""
        if jumpkind == 'Ijk_Call':
            if dst in self.owned_blocks:
                return 'guest_dispatch_addr(cpu, UINT64_C(%#x)); goto %s;' % (dst, self.label(dst))
            return '%s(cpu, 0); goto %s;' % (self.call_name(dst), self.label(dst))
        if dst in self.cur_labels:
            return 'goto %s;' % self.label(dst)
        if dst in self.owned_blocks:
            # A mid-function label belonging to another function: reached by
            # re-entering that function, never by calling a translation that
            # starts there (which would skip its prologue).
            return 'guest_dispatch_addr(cpu, UINT64_C(%#x)); return;' % dst
        if self.is_ignored_import(dst):
            return 'return;   /* tail call to %s: not modelled */' % self.plt_by_addr[dst]
        di = self.direct_import(dst)
        if di:
            # The binary reaches most C library functions through a one
            # instruction local thunk (`b plt_memcpy`), so the import shows up
            # as a tail call rather than a call.  Handled here, those thunks
            # become a plain call to the C library function.
            nm, sig = di
            self.imports_used.add(nm)
            self._note_dep('libc:' + nm)
            return '%s return;' % ' '.join(marshal_call(self, nm, sig, indent=''))
        # leaves this function: tail call
        return '%s(cpu, 0); return;' % self.call_name(dst)

    def direct_import(self, dst):
        """(name, signature) if dst is an import that can be called directly.

        Variadic and setjmp-family entries are excluded: those need the
        hand-written marshallers in guest_va.c rather than a plain call.
        """
        nm = self.plt_by_addr.get(dst)
        if not nm or nm in IGNORED_IMPORTS or nm in RUNTIME_IMPORTS:
            return None
        if nm in SETJMP_NAMES or nm in self.defined_syms:
            return None
        sig = ALL_SIGS.get(nm)
        if sig is None or 'V' in sig[1] or sig[0] == 'J':
            return None
        return (nm, sig)

    def is_ignored_import(self, dst):
        """True if dst is a PLT stub for a symbol the port does not model."""
        return self.plt_by_addr.get(dst) in IGNORED_IMPORTS

    def _note_dep(self, name):
        if self.cur_func is not None:
            self.file_deps.setdefault(self.cur_func, set()).add(name)

    def call_name(self, dst):
        if dst in self.plt_by_addr:
            nm = self.plt_by_addr[dst]
            self.imports_used.add(nm)
            self._note_dep('plt_%s' % nm)
            return 'plt_%s' % nm
        self.func_set.add(dst)
        self.referenced.add(dst)
        self._note_dep(cname(dst))
        return cname(dst)

    def need_simd(self, name, kind, lane, count, op):
        self.simd_helpers[name] = ('arith', kind, lane, count, op)

    def need_simd_cmp(self, name, kind, lane, count):
        self.simd_helpers[name] = ('cmp', kind, lane, count, None)

    def need_simd_interleave(self, name, kind, lane, count):
        self.simd_helpers[name] = ('interleave', kind, lane, count, None)

    def need_simd_varshift(self, name, sign, lane, count):
        self.simd_helpers[name] = ('varshift', sign, lane, count, None)

    def need_simd_neg(self, name, lane, count):
        self.simd_helpers[name] = ('fpneg', 'Neg', lane, count, None)

    def need_simd_fp(self, name, kind, lane, count):
        self.simd_helpers[name] = ('fp', kind, lane, count, None)

    def need_simd_fma(self, name, lane, count):
        # Three operands rather than two, so it gets its own kind: the packed
        # form of FMLA/FMLS, which libVEX splits into a multiply and an add
        # (see fp_is_fused_mac).
        self.simd_helpers[name] = ('fp3', 'FMA', lane, count, None)

    def need_simd_cat(self, name, kind, lane, count):
        self.simd_helpers[name] = ('cat', kind, lane, count, None)

    def need_simd_shift(self, name, kind, lane, count):
        self.simd_helpers[name] = ('shift', kind, lane, count, None)

    def need_simd_minmax(self, name, kind, lane, count):
        self.simd_helpers[name] = ('minmax', kind, lane, count, None)


# --------------------------------------------------------------- function gen


# How sparse a function's block offsets have to be before a `switch` is
# replaced by a binary search.  See emit_local_dispatch().
LOCAL_DISPATCH_SPARSE = 8

# Which form emit_local_dispatch() uses.  Kept switchable so the variants can
# be measured against each other: 'plain' is the original.
LOCAL_DISPATCH_MODE = 'offset'      # 'plain' | 'offset'


def emit_local_dispatch(ctx, out, addr, blocks):
    """Map a computed target back to a block, without a giant jump table.

    The obvious form is `switch (_disp)` over the block ADDRESSES.  It is
    correct, but the cases are guest addresses, so the compiler sees a range it
    can index and builds a jump table spanning (max-min)/4 entries, padded with
    the default label.  Measured over this binary: 918,303 real arms asking for
    20,719,506 table slots, 95.6% of them padding, and about 19.8 MB of
    anonymous .rodata in the linked binary -- roughly a quarter of it.  Two
    functions alone wanted 1.5 M slots each to hold 2 and 5 arms, because their
    blocks sit at opposite ends of a 6 MB range.  Each arm also costs a 64-bit
    immediate, which on most targets is materialised rather than encoded.

    So normalise first:

        uint64_t off = _disp - BASE;          BASE = the lowest block
        if (off <= SPAN) { switch (off >> 2) { ... } }
        guest_dispatch(cpu, _disp);

    * `- BASE` and `>> 2` make the keys small -- block 0, 1, 2, ... rather than
      0x71003d7460 -- so the comparisons use short immediates instead of a
      materialised 64-bit constant.
    * `>> 2` alone makes every jump table 4x smaller: block addresses are
      4-byte aligned, so three of every four slots were dead.
    * `off <= SPAN` is unsigned, so an address BELOW the base wraps to a huge
      value and is rejected by the same compare.  One test rules out every
      address outside the function, which is what makes the truncated key safe:
      within the range `off >> 2` is injective, so a key match IS an address
      match and no arm has to recheck `_disp`.

    When the blocks are still too spread out for a table -- the arms are a
    small fraction of SPAN/4 -- emit a balanced binary search over `off`
    instead: no table at all, and 32-bit comparisons.
    """
    cases = sorted(set([addr] + list(blocks)))
    if len(cases) < 2 or LOCAL_DISPATCH_MODE == 'plain':
        out.append('    switch (_disp) {')
        for b in cases:
            out.append('    case UINT64_C(%#x): goto %s;' % (b, ctx.label(b)))
        out.append('    default: break;')
        out.append('    }')
        return

    base = cases[0]
    # One CFG artefact (a guest_nodecode stub at ELF offset 1) is not 4-byte
    # aligned; the key would not be injective for it, so leave it alone.
    if any((c - base) & 3 for c in cases):
        out.append('    /* a block is not 4-byte aligned: keep the plain switch */')
        out.append('    switch (_disp) {')
        for b in cases:
            out.append('    case UINT64_C(%#x): goto %s;' % (b, ctx.label(b)))
        out.append('    default: break;')
        out.append('    }')
        return
    offs = [(c - base) >> 2 for c in cases]
    span = offs[-1] + 1

    out.append('    /* block index from the function base: small keys, and one')
    out.append('     * unsigned range test rejects every address outside. */')
    out.append('    {')
    out.append('    uint64_t _off = _disp - UINT64_C(%#x);' % base)
    # `(_off & 3) == 0` keeps this EXACTLY equivalent to the switch it
    # replaces: an unaligned target would otherwise truncate onto a valid key
    # and jump into a block, where the original fell through to guest_dispatch.
    out.append('    if (_off <= UINT64_C(%#x) && (_off & 3) == 0) {'
               % (cases[-1] - base))

    if span <= LOCAL_DISPATCH_SPARSE * len(cases):
        out.append('        switch ((uint32_t)(_off >> 2)) {')
        for b, k in zip(cases, offs):
            out.append('        case %#x: goto %s;' % (k, ctx.label(b)))
        out.append('        default: break;')
        out.append('        }')
    else:
        out.append('        /* %d blocks over %d slots: a table here would be'
                   % (len(cases), span))
        out.append('         * %.0f%% padding, so search instead. */'
                   % (100.0 * (span - len(cases)) / span))
        out.append('        uint32_t _k = (uint32_t)(_off >> 2);')

        def rec(lo, hi, ind):
            pad = '    ' * ind
            if lo > hi:
                return
            if hi - lo < 4:                 # a short run: straight compares
                for i in range(lo, hi + 1):
                    out.append('%sif (_k == %#x) goto %s;'
                               % (pad, offs[i], ctx.label(cases[i])))
                return
            mid = (lo + hi) // 2
            out.append('%sif (_k < %#x) {' % (pad, offs[mid]))
            rec(lo, mid - 1, ind + 1)
            out.append('%s} else if (_k == %#x) {' % (pad, offs[mid]))
            out.append('%s    goto %s;' % (pad, ctx.label(cases[mid])))
            out.append('%s} else {' % pad)
            rec(mid + 1, hi, ind + 1)
            out.append('%s}' % pad)

        rec(0, len(cases) - 1, 2)

    out.append('    }')
    out.append('    }')


def emit_function(ctx, addr, out):
    blocks = ctx.blocks_of.get(addr) or ctx.discover(addr)

    # Every block of this function is lifted TWICE: once by the call-return
    # scan below, which needs each block's jumpkind and size, and again by the
    # emission loop at the bottom, which needs the statements.  Both ask for
    # exactly the same thing -- ctx.lift(b, limit=next_block_start(b, blocks))
    # -- and pyvex.lift is by far the most expensive call in the generator: a
    # profile of a 58,911-function run put 58.7% of the whole runtime inside
    # it, and 17% in this second lift alone.
    #
    # So the two passes share one memo.  The key carries the LIMIT as well as
    # the address, because the block list can grow between the two passes (the
    # scan adds call return addresses, and forced jump-table arms are merged in
    # after it): a block whose successor changed has a different limit, is a
    # different lift, and correctly misses.
    #
    # An IRSB costs about 30 KB, so the memo is capped rather than unbounded --
    # the largest function here has 23,496 blocks, which would be ~700 MB, and
    # with `-j N` that is per worker.  At 1,024 the memo covers 99.98% of the
    # binary's functions and 95.6% of its blocks for about 31 MB; a function
    # bigger than that simply lifts twice, as before.
    lift_memo = {}

    def lift_block(b, blocks):
        key = (b, ctx.next_block_start(b, blocks))
        if key in lift_memo:
            return lift_memo[key]
        irsb = ctx.lift(b, limit=key[1])
        if len(lift_memo) < LIFT_MEMO_MAX:
            lift_memo[key] = irsb
        return irsb

    # If indirect targets were handed to this function, its block list must
    # still contain them.  Truncation of over-merged functions can have cut
    # them away, and a re-entry case cannot name a block that was not emitted.
    # Every call's RETURN ADDRESS must be a block of this function.  If it is
    # missing, the emitter has nowhere to continue after the call and bails out
    # with `return;`, abandoning the rest of the function -- including its
    # epilogue.  That silently leaked the frame (0x70 in f_008716a0) and
    # corrupted the caller's saved registers.
    if blocks:
        span_lo, span_hi = min(blocks), max(blocks) + 0x400
        known = set(blocks)
        added = set()
        for b in list(blocks):
            irsb = lift_block(b, blocks)
            if irsb is None or irsb.jumpkind != 'Ijk_Call':
                continue
            ret = irsb.addr + irsb.size
            if ret not in known and span_lo <= ret < span_hi:
                added.add(ret)
        if added:
            blocks = sorted(known | added)
            ctx.blocks_of[addr] = blocks
            ctx.notes.append(('call return addresses added as blocks', addr,
                              '%d added' % len(added)))

    forced = set(ctx.forced_entries.get(addr, set()))
    # A recovered jump-table arm inside this function's span must be its own
    # block, otherwise it sits in the middle of one and has no label.
    # Each arm belongs to exactly ONE function: the nearest preceding start.
    #
    # Claiming every arm inside a function's span looks equivalent but feeds
    # back on itself -- an over-merged function has a huge span, so it claims
    # distant arms, which raises its trim floor, so it is never trimmed.  Two
    # "functions" 0x9c bytes apart each emitted 51 MB of C that way.
    forced |= ctx.arms_owned_by(addr)
    missing_forced = forced - set(blocks)
    if missing_forced:
        cfg_blocks = ctx.funcs.get(addr, {}).get('blocks', ())
        extra = set()
        for b in cfg_blocks:
            ba = int(b, 16) if isinstance(b, str) else b
            extra.add(ba)
        # Union, not intersection: a recovered jump-table arm is exactly the
        # case that is NOT already a CFG block, so intersecting with the CFG
        # list threw away the addresses this is meant to add.
        # Only the folded blocks come back -- NOT the function's whole CFG block
        # list.  Restoring all of it undid the over-merge trimming: the
        # jump-table stub at 0x8b7c10 reclaimed its 23,074 absorbed blocks and
        # ballooned to 712,000 lines of C.
        blocks = sorted(set(blocks) | forced)
        ctx.blocks_of[addr] = blocks
        ctx.notes.append(('untrimmed for indirect targets', addr,
                          '%d blocks restored' % len(missing_forced)))

    ctx.cur_func = addr
    ctx.cur_labels = set(blocks)

    # Does any part of this function have an exception table?  If it does, an
    # exception can resume control at a landing pad inside it, so it gets a
    # wrapper that establishes a frame the unwinder can find, and every call
    # in its body records where it is.  163 of subsdk0.elf's 42,355 functions
    # answer yes; glslc.elf has no .eh_frame at all and none do, so nothing
    # below changes for it.
    #
    # The test is over the BLOCKS and not just the entry: angr can merge two
    # FDE regions into one function, and the table belongs to whichever region
    # the landing pad is in.
    ctx.cur_func_eh = bool(ctx.lsda_of) and (
        addr in ctx.lsda_of or any(b in ctx.lsda_of for b in blocks))
    body_name = cname(addr) + ('__eh' if ctx.cur_func_eh else '')

    name = ctx.funcs.get(addr, {}).get('name') or cname(addr)
    out.append('/* %s  (%d blocks) */' % (cname(addr), len(blocks)))
    if ctx.cur_func_eh:
        out.append('static void %s(cpu_t *cpu, uint64_t entry);' % body_name)
        out.append('')
        out.append('/*')
        out.append(' * Exception frame wrapper.  guest_eh.c has the design; in short, the')
        out.append(' * frame is what an unwind walks, and resuming at a landing pad is just')
        out.append(' * re-entering the body with the pad as the entry selector -- the same')
        out.append(' * path a computed branch into the middle of a function already takes.')
        out.append(' */')
        out.append('void %s(cpu_t *cpu, uint64_t entry) {' % cname(addr))
        out.append('    guest_eh_frame _ehf;')
        # `entry` is written between setjmp() and longjmp(), so it cannot live
        # in a register the jump would restore: the C standard leaves the value
        # of such an object indeterminate unless it is volatile.
        out.append('    volatile uint64_t _entry = entry;')
        out.append('    guest_eh_push(cpu, &_ehf);')
        out.append('    if (setjmp(_ehf.jb) != 0) _entry = _ehf.lp;')
        out.append('    %s(cpu, (uint64_t)_entry);' % body_name)
        out.append('    guest_eh_pop(&_ehf);')
        out.append('}')
        out.append('')
        out.append('static void %s(cpu_t *cpu, uint64_t entry) {' % body_name)
    else:
        out.append('void %s(cpu_t *cpu, uint64_t entry) {' % cname(addr))

    # A computed branch can land on a block in the middle of this function.
    # Those blocks get a case here, so the function can be re-entered at them
    # without duplicating the code into a translation of its own.
    # A function that computes a branch target keeps the whole thing local: the
    # switch below turns any target inside this function into a goto.  That is
    # what the guest does -- it jumps within a frame its own prologue pushed --
    # and it avoids the external call that would otherwise skip the prologue
    # and then run the shared epilogue, popping a frame nobody pushed.
    # EVERY function gets a dispatch switch over all its blocks.
    #
    # Restricting this to functions with a recovered indirect branch kept
    # producing "no translation for computed target" one address at a time:
    # a table this tool could not resolve can land on any block of any
    # function.  Since the entry selector and the local dispatch now share one
    # switch, the cost is a single case per block, and it makes every block
    # that exists reachable by construction rather than by prediction.
    wants_local = len(blocks) > 1
    forced = ctx.forced_entries.get(addr, set())
    if wants_local:
        inner = [b for b in blocks if b != addr]
    else:
        inner = [b for b in blocks
                 if b != addr and (b in ctx.potential_entries or b in forced)]
    ctx.local_dispatch = bool(wants_local and len(blocks) > 1)
    if ctx.local_dispatch:
        out.append('    uint64_t _disp = 0;')
        # The entry selector and the local dispatch resolve the SAME set of
        # addresses, so they share one switch: entering mid-function is just a
        # computed branch that happens to arrive from outside.  Listing the
        # blocks twice doubled the case labels, which are the single largest
        # part of the output for switch-heavy functions.
        out.append('    if (entry) { _disp = entry; goto _local_dispatch; }')
    if inner and not ctx.local_dispatch:
        out.append('    switch (entry) {')
        for b in inner:
            out.append('    case UINT64_C(%#x): goto %s;' % (b, ctx.label(b)))
        out.append('    default: break;')
        out.append('    }')
        ctx.entry_blocks[addr] = inner
    elif inner:
        ctx.entry_blocks[addr] = inner      # handled by the shared dispatch
    else:
        out.append('    (void)entry;')

    # Blocks are emitted in address order, but a function's entry is not
    # necessarily its lowest address -- angr attributes shared/merged tails to
    # a function too.  Without this jump, control would fall into whichever
    # block happens to sort first.
    if blocks and blocks[0] != addr:
        out.append('    goto %s;' % ctx.label(addr))

    # Blocks are buffered rather than appended straight to `out` because the
    # temp declarations they produce belong at the TOP of the function, above
    # the first block, and are only fully known once every block is translated.
    block_out = []
    decls = {}          # declaration text -> itself, deduplicated across blocks
    for b in blocks:
        irsb = lift_block(b, blocks)
        if irsb is None:
            block_out.append('%s: guest_nodecode(cpu, UINT64_C(%#x)); return;'
                             % (ctx.label(b), b))
            continue
        body = []
        tr = IRToC(ctx, irsb, body)
        try:
            for s in irsb.statements:
                tr.stmt(s)
            term(ctx, irsb, tr, body)
        except UnsupportedIR as ex:
            body = ['    guest_unresolved(cpu, UINT64_C(%#x), "%s"); return;'
                    % (b, str(ex).replace('"', "'"))]
            ctx.notes.append(('unsupported', b, str(ex)))
        else:
            # Only a block that translated cleanly contributes declarations.
            # The failure path above replaces the body wholesale, so any temps
            # it named are gone and declaring them would emit unused locals.
            for d in tr.declare_temps():
                decls[d] = d
        block_out.append('%s: {' % ctx.label(b))
        block_out.extend(body)
        block_out.append('}')

    # One declaration per (index, type) for the whole function, in place of one
    # per (index, type, block).  The braces around each block stay: they cost
    # nothing and keep the labelled-statement shape the emitter relies on.
    out.extend(sorted(decls))
    out.extend(block_out)

    if ctx.local_dispatch:
        # One dispatch site per function rather than one per branch: each
        # computed branch assigns _disp and jumps here.
        out.append('_local_dispatch:')
        emit_local_dispatch(ctx, out, addr, blocks)
        out.append('    guest_dispatch(cpu, _disp);')
        out.append('    return;')
    out.append('}')
    out.append('')


def term(ctx, irsb, tr, body):
    """Emit the block terminator."""
    jk = irsb.jumpkind
    nxt = irsb.next
    is_const = type(nxt).__name__ == 'Const'

    if jk == 'Ijk_Ret':
        body.append('    return;')
        return
    if jk == 'Ijk_NoDecode':
        body.append('    guest_nodecode(cpu, UINT64_C(%#x));' % (irsb.addr + irsb.size))
        body.append('    return;')
        return

    if jk == 'Ijk_Call':
        ret = irsb.addr + irsb.size
        if getattr(ctx, 'cur_func_eh', False):
            # Where control is, for the unwinder, plus the registers the ABI
            # says a landing pad will see.  Taken at the CALL and not at
            # function entry: a callee that throws never runs its epilogue, so
            # the callee-saved registers it was holding for us are only intact
            # here.  guest_eh.c's header comment has the full argument.
            body.append('    guest_eh_mark(cpu, UINT64_C(%#x));' % ret)
        if is_const and ctx.plt_by_addr.get(nxt.con.value) in SETJMP_NAMES:
            # setjmp must execute in THIS function's frame, or the jmp_buf
            # names a frame that is gone before longjmp can use it.
            x0 = ctx.off['x0']
            ctx.notes.append(('setjmp inlined', irsb.addr, ''))
            body.append('    {   /* setjmp, expanded inline */')
            body.append('        guest_jb *_jb = guest_setjmp_slot(cpu, GST_I64(%d));' % x0)
            body.append('        int _r = setjmp(*guest_jb_env(_jb));')
            body.append('        GST_I64(%d) = (uint64_t)(int64_t)_r;' % x0)
            body.append('    }')
        elif is_const and ctx.direct_import(nxt.con.value):
            nm, sig = ctx.direct_import(nxt.con.value)
            ctx.imports_used.add(nm)
            ctx._note_dep('libc:' + nm)
            body.append('    /* %s */' % nm)
            body.extend(marshal_call(ctx, nm, sig))
        elif is_const and ctx.is_ignored_import(nxt.con.value):
            body.append('    /* call to %s: not modelled, skipped */'
                        % ctx.plt_by_addr[nxt.con.value])
        elif is_const and nxt.con.value in ctx.owned_blocks:
            body.append('    guest_dispatch_addr(cpu, UINT64_C(%#x));' % nxt.con.value)
        elif is_const:
            body.append('    %s(cpu, 0);' % ctx.call_name(nxt.con.value))
        else:
            body.append('    guest_dispatch(cpu, %s);' % tr.expr(nxt))
        if ret in ctx.cur_labels:
            body.append('    goto %s;' % ctx.label(ret))
        elif ctx.in_rx(ret):
            # The return address is not a block of THIS function -- the CFG
            # split the region and trimming dropped the tail.  Continuing there
            # by dispatch is still correct; simply returning is not, because it
            # abandons the rest of the function including its epilogue, which
            # leaks the frame (0x70 in f_008716a0) and corrupts the caller's
            # saved registers.
            # call_name registers it so the fixpoint translates it as its own
            # function; merely adding it to potential_entries happened too late
            # for the dispatch table and left the branch unresolvable.
            #
            # Unless it is a block owned by another function -- then it has no
            # standalone definition to call, and dispatch is the only way in.
            if ret in ctx.owned_blocks:
                body.append('    guest_dispatch_addr(cpu, UINT64_C(%#x));' % ret)
            else:
                body.append('    %s(cpu, 0);' % ctx.call_name(ret))
            body.append('    return;')
        else:
            body.append('    return;   /* callee does not return here */')
        return

    # Ijk_Boring and friends
    if is_const:
        body.append('    %s' % ctx.goto_or_call(nxt.con.value, 'Ijk_Boring'))
        return

    targets = ctx.jumptables.get(irsb.addr)
    if targets:
        # A jump table routinely sends several indices to the same block, so
        # the target list has duplicates; C case labels must be unique.
        seen = set()
        uniq = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        local = [t for t in uniq if t in ctx.cur_labels]
        if local:
            body.append('    {')
            body.append('        uint64_t _t = %s;' % tr.expr(nxt))
            body.append('        switch (_t) {')
            for t in local:
                body.append('        case UINT64_C(%#x): goto %s;' % (t, ctx.label(t)))
            body.append('        default: break;')
            body.append('        }')
            outside = [t for t in uniq if t not in ctx.cur_labels]
            for t in outside:
                body.append('        if (_t == UINT64_C(%#x)) { guest_dispatch_addr(cpu, _t); return; }'
                            % t)
            if ctx.local_dispatch:
                body.append('        _disp = _t; goto _local_dispatch;')
            else:
                body.append('        guest_dispatch(cpu, _t);')
                body.append('        return;')
            body.append('    }')
            return

    # An indirect branch with no resolved table.  If this function has a local
    # dispatch block, route through it: a computed target that lands in this
    # same function then becomes a goto.  That matters for threaded dispatch
    # loops (the lexer's state machine is one), where treating each guest jump
    # as a C call would grow the host stack without bound and eventually
    # overflow it -- the guest is jumping, not calling.
    ctx.indirect_branch_funcs.add(ctx.cur_func)
    if ctx.local_dispatch:
        body.append('    _disp = %s; goto _local_dispatch;' % tr.expr(nxt))
    else:
        body.append('    guest_dispatch(cpu, %s); return;' % tr.expr(nxt))