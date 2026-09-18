/*
 * guest_cxx.c -- the C++ runtime objects the guest imports, supplied by hand.
 *
 * The second version of the shader compiler is a C++ binary that leaves part
 * of its standard library outside: it imports three __cxxabiv1 typeinfo
 * vtables, five std:: typeinfo objects, three std:: class vtables and a
 * handful of member functions.  A port cannot satisfy those by linking a host
 * libstdc++ -- see below -- so it defines them here.
 *
 * WHY NOT JUST LINK -lstdc++
 *
 *   * The mangled names are not portable.  `operator new(size_t)` is _Znwm on
 *     LP64 and _Znwy on MinGW-w64; the same reasoning that put operator new
 *     behind guest_operator_new (HANDOVER.md section 15) applies to every name
 *     here.
 *   * A host std::type_info is only useful if the HOST unwinder is the one
 *     matching it, and it is not: guest_eh.c does the matching, over guest
 *     frames.  What it needs is objects whose SHAPE it can walk, and the
 *     guest's own typeinfo objects have the __cxxabiv1 shape, so the imported
 *     ones have to have it too.  Defining them here is what makes both kinds
 *     identical to the matcher.
 *   * A host vtable's slots hold HOST function pointers, and the guest calls
 *     through them with `blr`, which goes to guest_dispatch.  Only a
 *     `void (*)(cpu_t *, uint64_t)` thunk can be called that way.
 *
 * WHICH STANDARD LIBRARY THIS BINARY WAS BUILT AGAINST
 *
 * libc++.  The binary contains its own copy of
 * `std::runtime_error::runtime_error(const std::string &)` (at guest 0x11115f4),
 * and reading it settles both layouts that matter here:
 *
 *     ldrb w8, [x1] ; ldr x9, [x1,#0x10] ; tst w8,#1 ; csinc x20,x9,x1,ne
 *
 * is libc++'s short-string check -- bit 0 of the first byte is the "long"
 * flag, the data pointer is at +0x10 and a short string's data is the object
 * itself.  It then allocates strlen+0x19, writes {len,len} at +0 and a zero
 * refcount word at +0x10, and stores buffer+0x18 into the exception at +8.
 * That is libc++'s `__libcpp_refstring`: a 24-byte header (size, capacity,
 * refcount) in front of the characters, with the object holding a pointer to
 * the CHARACTERS.
 *
 * So std::runtime_error is { vptr, const char *__imp_ }, and what() returns
 * __imp_.  That is implemented exactly.  The destructors are the one place
 * this file knowingly does less than libc++: see the comment on them.
 */

#include "guest_rt.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* __cxxabiv1 typeinfo vtables                                                */
/* ------------------------------------------------------------------------ */

/*
 * A typeinfo object's first word points 16 bytes into one of these, which is
 * how guest_eh.c tells the three shapes apart.  Only the ADDRESS is ever used:
 * the guest never calls a typeinfo's virtual functions (it does no dynamic_cast
 * of its own -- __dynamic_cast is not imported), and the port's matcher walks
 * the structures directly instead of asking them.  The slots are therefore
 * null, and a call through one would land in guest_dispatch's null check with
 * a clear message rather than running something arbitrary.
 *
 * The layout is the standard vtable prefix: [0] offset-to-top, [1] typeinfo,
 * [2..] the virtual functions.  `+16` from the symbol is slot [2].
 */
const void *const guest_cxxabi_class_vtable[4]     = { 0, 0, 0, 0 };
const void *const guest_cxxabi_si_class_vtable[4]  = { 0, 0, 0, 0 };
const void *const guest_cxxabi_vmi_class_vtable[4] = { 0, 0, 0, 0 };

/*
 * An object's vptr points at slot [2] -- past the offset-to-top and typeinfo
 * words -- which is what "symbol + 0x10" means in the guest's relocations.
 * Written as &vt[2] rather than as byte arithmetic because &vt[2] is an
 * ADDRESS CONSTANT: it can initialise a static object, so every table below
 * is built by the linker and nothing has to be filled in at run time.  That
 * matters for more than tidiness -- the first version of this file did the
 * fill-in at startup and stored through a pointer to a `const` object, which
 * is in .rodata, and the process died on the first write.
 */
#define VPTR(vt) ((const void *)&(vt)[2])

/* ------------------------------------------------------------------------ */
/* std:: typeinfo objects                                                     */
/* ------------------------------------------------------------------------ */

/*
 * These have to carry their real base-class chains, because a `catch` in the
 * guest names a base and the thrown object names the most derived type.  A
 * guest class deriving from std::runtime_error (the binary has several) gets a
 * __si_class_type_info whose __base_type relocation names _ZTISt13runtime_error
 * -- the object below -- so the chain has to continue from here or a
 * `catch (std::exception &)` would not match.
 *
 * std::exception's own typeinfo is NOT imported by this binary, which means no
 * catch clause in it can name std::exception... today.  It is defined anyway:
 * it is where the chains terminate, and getting that wrong would be a silent
 * mismatch rather than a link error.
 */
/*
 * Tagged, because the generated relocation rows name these types by tag: the
 * declaration emitted into thunks.c is `extern const struct guest_ti_si_s ...`.
 */
struct guest_ti_class_s {
    const void *vptr;
    const char *name;
};

struct guest_ti_si_s {
    const void *vptr;
    const char *name;
    const void *base_type;
};

typedef struct guest_ti_class_s guest_ti_class;
typedef struct guest_ti_si_s guest_ti_si;

/* Names are the mangled ones type_info::name() returns under the Itanium ABI. */
const guest_ti_class guest_ti_std_exception = {
    VPTR(guest_cxxabi_class_vtable), "St9exception"
};
const guest_ti_si guest_ti_std_bad_alloc = {
    VPTR(guest_cxxabi_si_class_vtable), "St9bad_alloc", &guest_ti_std_exception
};
const guest_ti_si guest_ti_std_bad_array_new_length = {
    VPTR(guest_cxxabi_si_class_vtable), "St20bad_array_new_length",
    &guest_ti_std_bad_alloc
};
const guest_ti_si guest_ti_std_bad_cast = {
    VPTR(guest_cxxabi_si_class_vtable), "St8bad_cast", &guest_ti_std_exception
};
const guest_ti_si guest_ti_std_logic_error = {
    VPTR(guest_cxxabi_si_class_vtable), "St11logic_error",
    &guest_ti_std_exception
};
const guest_ti_si guest_ti_std_length_error = {
    VPTR(guest_cxxabi_si_class_vtable), "St12length_error",
    &guest_ti_std_logic_error
};
const guest_ti_si guest_ti_std_runtime_error = {
    VPTR(guest_cxxabi_si_class_vtable), "St13runtime_error",
    &guest_ti_std_exception
};

/* ------------------------------------------------------------------------ */
/* std:: class vtables                                                        */
/* ------------------------------------------------------------------------ */

/*
 * libc++'s layout for these classes is
 *
 *     [0] offset-to-top (0)
 *     [1] &typeinfo
 *     [2] ~T()                 complete-object destructor  (D1)
 *     [3] ~T() + operator delete   deleting destructor      (D0)
 *     [4] what()
 *
 * and an object's vptr is the symbol + 16, i.e. &slot[2].  The guest stores
 * that word itself (it defines the constructors; only the destructors and
 * what() are imported), so the offsets here are load-bearing.
 *
 * The function slots hold THUNKS -- `void (*)(cpu_t *, uint64_t)` -- because a
 * virtual call in the guest is `blr`, which reaches them through
 * guest_dispatch.  gen.py emits `plt_<name>` for each imported function; those
 * are the symbols named here.
 */
/* WEAK, because gen.py emits `plt_<name>` only for symbols the input binary
 * actually imports, and not every input imports these.
 *
 * subsdk0.elf (17.24) imports the whole std:: exception surface, so the
 * thunks exist and these declarations bind to them normally.  The eight
 * NVN 1.9-1.16 binaries import NONE of it -- no `__cxa_*`, no `_ZNSt*`, and
 * no `.gcc_except_table` -- so the thunks are not emitted, and a strong
 * declaration made the tables below reference symbols that do not exist.
 *
 * That was invisible until 17.22, and only because of WHICH OBJECT GETS
 * LINKED: guest_cxx.o is pulled out of the archive only if something
 * references it, and for 17.22+ something does -- those three binaries import
 * stdin/stdout/stderr, and guest_data_imports_init() lives in this file.  The
 * five older binaries import no data at all, so guest_cxx.o was never pulled
 * in and its dangling references were never resolved.  Same defect in all
 * eight; a link-order accident decided which ones showed it.
 *
 * Weak is the honest spelling rather than a workaround, because the slot is
 * reachable only when the thunk exists.  These words are virtual-table entries
 * for std:: exception classes; the guest reaches one only by destroying or
 * calling what() on such an object, which it can only do if it imported that
 * destructor -- which is precisely the condition under which the thunk is
 * emitted.  So an unresolved slot holds NULL, and nothing can reach a NULL
 * slot.  A strong declaration asserts the opposite -- that every input uses
 * the entire surface -- and that assertion is false for seven of the nine
 * binaries seen so far.
 */
#define GUEST_WEAK_THUNK __attribute__((weak))
GUEST_WEAK_THUNK void plt__ZNSt13runtime_errorD1Ev(cpu_t *cpu, uint64_t entry);
GUEST_WEAK_THUNK void plt__ZNSt13runtime_errorD2Ev(cpu_t *cpu, uint64_t entry);
GUEST_WEAK_THUNK void plt__ZNKSt13runtime_error4whatEv(cpu_t *cpu, uint64_t entry);
GUEST_WEAK_THUNK void plt__ZNSt12length_errorD1Ev(cpu_t *cpu, uint64_t entry);
GUEST_WEAK_THUNK void plt__ZNSt9bad_allocD1Ev(cpu_t *cpu, uint64_t entry);
GUEST_WEAK_THUNK void plt__ZNSt8bad_castD1Ev(cpu_t *cpu, uint64_t entry);
GUEST_WEAK_THUNK void plt__ZNSt20bad_array_new_lengthD1Ev(cpu_t *cpu, uint64_t entry);

/* what() for the three vptr-only classes has no imported name, so there is no
 * generated `plt_` thunk for their vtables; these are defined further down. */
static void vt_bad_alloc_what(cpu_t *cpu, uint64_t entry);
static void vt_bad_cast_what(cpu_t *cpu, uint64_t entry);
static void vt_bad_array_new_length_what(cpu_t *cpu, uint64_t entry);

/*
 * Three of these are imported by name (_ZTVSt11logic_error,
 * _ZTVSt12length_error, _ZTVSt13runtime_error) because the guest defines the
 * constructors and needs the vptr to store.  The other three are NOT imported
 * -- bad_alloc, bad_cast and bad_array_new_length have their constructors
 * imported instead -- but those constructors have to store SOMETHING, so the
 * vtables exist here for them to name.
 */
/*
 * [2] is the complete-object destructor (D1) and [3] the DELETING one (D0).
 * libc++'s D0 runs D1 and then `operator delete`; the port has no deallocator
 * for a guest-allocated object (see refstring_release), so both slots run the
 * destructor and neither frees.  A `delete` through a base pointer therefore
 * leaks the object rather than corrupting a heap, which is the same trade this
 * file makes for the string.
 */
/*
 * Declared with mutable elements (`const void *[5]`, not `const void *const`)
 * to match the declaration the generator emits into guest_decls.h.  The
 * contents never change; only the spelling has to agree, because a mismatch
 * there is a compile error in data_rw.c, which is where these are named.
 */
const void *guest_vtable_std_runtime_error[5] = {
    NULL, &guest_ti_std_runtime_error,
    (const void *)&plt__ZNSt13runtime_errorD1Ev,
    (const void *)&plt__ZNSt13runtime_errorD1Ev,
    (const void *)&plt__ZNKSt13runtime_error4whatEv,
};
const void *guest_vtable_std_logic_error[5] = {
    NULL, &guest_ti_std_logic_error,
    (const void *)&plt__ZNSt12length_errorD1Ev,
    (const void *)&plt__ZNSt12length_errorD1Ev,
    (const void *)&plt__ZNKSt13runtime_error4whatEv,
};
const void *guest_vtable_std_length_error[5] = {
    NULL, &guest_ti_std_length_error,
    (const void *)&plt__ZNSt12length_errorD1Ev,
    (const void *)&plt__ZNSt12length_errorD1Ev,
    (const void *)&plt__ZNKSt13runtime_error4whatEv,
};
const void *guest_vtable_std_bad_alloc[5] = {
    NULL, &guest_ti_std_bad_alloc,
    (const void *)&plt__ZNSt9bad_allocD1Ev,
    (const void *)&plt__ZNSt9bad_allocD1Ev,
    (const void *)&vt_bad_alloc_what,
};
const void *guest_vtable_std_bad_cast[5] = {
    NULL, &guest_ti_std_bad_cast,
    (const void *)&plt__ZNSt8bad_castD1Ev,
    (const void *)&plt__ZNSt8bad_castD1Ev,
    (const void *)&vt_bad_cast_what,
};
const void *guest_vtable_std_bad_array_new_length[5] = {
    NULL, &guest_ti_std_bad_array_new_length,
    (const void *)&plt__ZNSt20bad_array_new_lengthD1Ev,
    (const void *)&plt__ZNSt20bad_array_new_lengthD1Ev,
    (const void *)&vt_bad_array_new_length_what,
};

/* ------------------------------------------------------------------------ */
/* The member functions the guest imports                                     */
/* ------------------------------------------------------------------------ */

/*
 * what() -- exact.  The object is { vptr, const char *__imp_ } and __imp_
 * already points at the characters.
 */
const char *guest_std_runtime_error_what(const void *self) {
    const char *const *p = (const char *const *)((const char *)self + 8);
    return *p;
}

/* The three vptr-only classes answer with a fixed string, as libc++ does. */
const char *guest_std_bad_alloc_what(const void *self) {
    (void)self;
    return "std::bad_alloc";
}

const char *guest_std_bad_cast_what(const void *self) {
    (void)self;
    return "std::bad_cast";
}

const char *guest_std_bad_array_new_length_what(const void *self) {
    (void)self;
    return "bad_array_new_length";
}

/*
 * The destructors of the string-carrying classes.
 *
 * libc++'s ~runtime_error() releases a __libcpp_refstring: it decrements the
 * refcount word 8 bytes in front of the characters and, when that goes
 * negative, frees the 24-byte block that starts 24 bytes in front of them.
 *
 * The port does NOT free it, and the reason is specific rather than lazy: the
 * block was allocated by the GUEST, by the internal allocator at 0x1d8e0, and
 * the matching deallocator is a guest function this file has no way to name.
 * Calling host free() on it would be a heap error.  The refcount is still
 * decremented, so a string that is copied and destroyed behaves correctly;
 * what is given up is the memory of the last copy.
 *
 * That memory is bounded by the number of exceptions a compilation throws, and
 * these are error paths -- an exception that is never caught traps instead
 * (guest_eh.c), and one that is caught happens once per diagnostic.
 */
static void refstring_release(void *self) {
    char **slot = (char **)((char *)self + 8);
    char *chars = *slot;
    if (!chars) return;
    int32_t *count = (int32_t *)(chars - 8);
    if (*count < 0) return;             /* not shared: nothing to decrement */
    (*count)--;
    *slot = NULL;
}

void guest_std_runtime_error_dtor(void *self) { refstring_release(self); }
void guest_std_length_error_dtor(void *self) { refstring_release(self); }

/*
 * std::exception::~exception() is trivial in libc++ -- it only exists so the
 * class has a key function -- so a no-op is exact, not an approximation.  The
 * same is true of the three vptr-only classes.
 */
void guest_std_exception_dtor(void *self) { (void)self; }
void guest_std_bad_alloc_dtor(void *self) { (void)self; }
void guest_std_bad_cast_dtor(void *self) { (void)self; }
void guest_std_bad_array_new_length_dtor(void *self) { (void)self; }

/*
 * The constructors of the vptr-only classes: set the vptr, and that is the
 * whole object.  Exact.
 */
void guest_std_bad_alloc_ctor(void *self) {
    *(const void **)self = VPTR(guest_vtable_std_bad_alloc);
}

void guest_std_bad_cast_ctor(void *self) {
    *(const void **)self = VPTR(guest_vtable_std_bad_cast);
}

void guest_std_bad_array_new_length_ctor(void *self) {
    *(const void **)self = VPTR(guest_vtable_std_bad_array_new_length);
}

/*
 * what() for the three vptr-only classes has no imported name, so there is no
 * generated `plt_` thunk to put in their vtables.  These are the thunks: the
 * shape a virtual call reaches through guest_dispatch, writing the result into
 * x0 with the generated accessor rather than open-coding a register offset.
 */
static void vt_bad_alloc_what(cpu_t *cpu, uint64_t entry) {
    (void)entry;
    guest_eh_set_handler_args(cpu, (uint64_t)(uintptr_t)guest_std_bad_alloc_what(NULL), 0);
}

static void vt_bad_cast_what(cpu_t *cpu, uint64_t entry) {
    (void)entry;
    guest_eh_set_handler_args(cpu, (uint64_t)(uintptr_t)guest_std_bad_cast_what(NULL), 0);
}

static void vt_bad_array_new_length_what(cpu_t *cpu, uint64_t entry) {
    (void)entry;
    guest_eh_set_handler_args(cpu,
        (uint64_t)(uintptr_t)guest_std_bad_array_new_length_what(NULL), 0);
}

/* ------------------------------------------------------------------------ */
/* Data imports whose value is not a constant expression                      */
/* ------------------------------------------------------------------------ */

/*
 * The guest imports `stdin`, `stdout` and `stderr`.  In musl -- which this
 * binary was linked against -- each is an ordinary object holding a FILE *,
 * and the guest reads through the GOT slot to get the object's ADDRESS and
 * then loads the pointer out of it.  So the port needs three real objects,
 * and their values are not constant expressions in C: they are filled in
 * before any guest code runs.
 */
FILE *guest_data_stdin;
FILE *guest_data_stdout;
FILE *guest_data_stderr;

void guest_data_imports_init(void) {
    static int done;
    if (done) return;
    done = 1;

    /*
     * Everything else in this file is initialised by the LINKER: every value
     * needed is an address constant.  These three are not -- stdin, stdout and
     * stderr are objects the C library defines, and their addresses are not
     * constant expressions -- so they are the whole of the run-time work.
     */
    guest_data_stdin = stdin;
    guest_data_stdout = stdout;
    guest_data_stderr = stderr;
}
