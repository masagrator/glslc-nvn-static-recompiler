/*
 * guest_eh.c -- partial C++ exception support for translated AArch64 code.
 *
 * WHAT THIS IS FOR
 *
 * The second version of the shader compiler is built with exceptions enabled.
 * It imports the Itanium C++ ABI entry points (__cxa_throw, __cxa_begin_catch,
 * _Unwind_Resume, ...), and 163 of its 42,355 functions carry a language
 * specific data area -- a .gcc_except_table -- describing where control has to
 * resume when an exception passes through them.
 *
 * A host C++ runtime cannot do this job.  Its unwinder walks HOST frames using
 * HOST unwind tables, and the thing that has to be unwound here is the GUEST:
 * the guest's callee-saved registers live in `cpu`, its stack is an array, and
 * a landing pad is a guest address that only the translated function knows how
 * to jump to.  So the unwinder is written here, over the port's own model.
 *
 * WHAT IS SUPPORTED, AND WHAT TRAPS
 *
 * Supported: throwing, matching a handler by type (including base classes and
 * catch-all), running cleanup landing pads and resuming past them, rethrow,
 * nested catches, and the one-time-initialisation guards (__cxa_guard_*).
 *
 * Trapped: anything that would terminate the process anyway.  An exception
 * with no handler anywhere on the guest stack, a throw with no active
 * exception to rethrow, an unwind that runs off the end of the shadow stack --
 * all of these end in guest_eh_fatal(), which prints what happened and aborts.
 * The Itanium ABI calls std::terminate() in exactly these cases, so nothing
 * that could have kept running is being cut short.
 *
 * HOW A FRAME IS REPRESENTED
 *
 * Only a function that HAS an LSDA pushes anything.  Its generated wrapper is
 *
 *     void f_X(cpu_t *cpu, uint64_t entry) {
 *         guest_eh_frame _ehf;
 *         guest_eh_push(cpu, &_ehf);
 *         if (setjmp(_ehf.jb) != 0) entry = _ehf.lp;
 *         f_X__eh(cpu, entry);
 *         guest_eh_pop(&_ehf);
 *     }
 *
 * so resuming at a landing pad is just re-entering the body with the landing
 * pad as the entry selector -- the same mechanism a computed branch into the
 * middle of a function already uses.  Nothing about the body changes except
 * that each call is preceded by
 *
 *     guest_eh_mark(cpu, <guest return address>);
 *
 * which records where in the function control is, and snapshots the registers
 * an unwinder would restore.
 *
 * WHY THE SNAPSHOT IS TAKEN AT THE CALL AND NOT AT ENTRY
 *
 * A landing pad expects the frame's own x19..x28, x29 and sp -- the values the
 * function established in its prologue and has been using since.  A real
 * unwinder recovers them from the CALLEE's frame description, because the
 * callee is required to preserve them; a callee that THROWS never runs its
 * epilogue, so in this port they are still whatever the throwing callee left
 * behind.  Taking the snapshot at the call captures precisely the values the
 * ABI promises, and taking it at function entry would capture the CALLER's
 * values instead, which is a different and wrong answer.
 *
 * WHY INTERMEDIATE FRAMES NEED NO SNAPSHOT
 *
 * Frames between the throw and the handler are abandoned, exactly as a real
 * unwinder abandons them.  Their guest stack memory is simply left; sp is
 * restored from the handler frame's snapshot, so it never leaks.
 */

#include "guest_rt.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Hooks the GENERATED code supplies.  Weak defaults keep the small harnesses  */
/* that link guest_rt.c alone (cctest, the QEMU reference build) linkable.     */
/* ------------------------------------------------------------------------ */

__attribute__((weak)) uint64_t guest_eh_region_lsda(uint64_t pc) {
    (void)pc;
    return 0;
}

__attribute__((weak)) uint64_t guest_eh_region_start(uint64_t pc) {
    (void)pc;
    return 0;
}

__attribute__((weak)) void *guest_eh_host_of(uint64_t guest_addr) {
    return (void *)(uintptr_t)guest_addr;
}

__attribute__((weak)) void guest_eh_snapshot(cpu_t *cpu, uint64_t *out) {
    (void)cpu;
    (void)out;
}

__attribute__((weak)) void guest_eh_unsnapshot(cpu_t *cpu, const uint64_t *in) {
    (void)cpu;
    (void)in;
}

__attribute__((weak)) void guest_eh_set_handler_args(cpu_t *cpu, uint64_t x0,
                                                     uint64_t x1) {
    (void)cpu;
    (void)x0;
    (void)x1;
}

/* ------------------------------------------------------------------------ */
/* The shadow stack                                                           */
/* ------------------------------------------------------------------------ */

/* The stack POINTER lives in guest_rt.c; see the comment there for why. */

void guest_eh_push(cpu_t *cpu, guest_eh_frame *f) {
    (void)cpu;
    f->prev = guest_eh_top();
    f->ra = 0;
    f->lp = 0;
    f->have_save = 0;
    guest_eh_set_top(f);
}

void guest_eh_pop(guest_eh_frame *f) {
    /* Restore rather than "pop one": a guest longjmp can have skipped the
     * pops of frames above this one, and this is where that is noticed and
     * repaired.  Assigning f->prev is correct in both cases. */
    guest_eh_set_top(f->prev);
}

void guest_eh_mark(cpu_t *cpu, uint64_t ra) {
    guest_eh_frame *f = guest_eh_top();
    if (!f) return;                 /* not inside an LSDA-carrying function */
    f->ra = ra;
    guest_eh_snapshot(cpu, f->save);
    f->have_save = 1;
}

/* ------------------------------------------------------------------------ */
/* The exception object                                                       */
/* ------------------------------------------------------------------------ */

/*
 * The header the ABI puts in FRONT of the thrown object.  This is the port's
 * own layout, not libstdc++'s: nothing outside this file ever sees it, because
 * the guest only ever holds the pointer __cxa_allocate_exception returned and
 * that pointer is the object, not the header.
 */
typedef struct guest_exception {
    uint64_t type_info;             /* guest/host pointer to the std::type_info */
    uint64_t destructor;            /* guest address of the destructor, or 0 */
    struct guest_exception *next;   /* next in the caught chain */
    int handler_count;              /* how many catch blocks currently hold it */
    int uncaught;                   /* thrown and not yet caught */
    uint64_t resume_ra;             /* where _Unwind_Resume should continue */
    guest_eh_frame *resume_frame;   /* the frame that has to be unwound past */
    uint64_t magic;
} guest_exception;

#define GUEST_EXC_MAGIC UINT64_C(0x4748534c43584545)   /* "GHSLCXEE" */

/* The allocation is header-then-object, so the object is 16-byte aligned. */
#define GUEST_EXC_HDR ((sizeof(guest_exception) + 15u) & ~(size_t)15u)

static guest_exception *g_caught;      /* innermost caught exception */
static guest_exception *g_in_flight;   /* the one currently being unwound */
static int g_uncaught_count;

static guest_exception *exc_of(uint64_t obj) {
    if (!obj) return NULL;
    guest_exception *e =
        (guest_exception *)((char *)(uintptr_t)obj - GUEST_EXC_HDR);
    if (e->magic != GUEST_EXC_MAGIC) return NULL;
    return e;
}

static uint64_t obj_of(guest_exception *e) {
    return (uint64_t)(uintptr_t)((char *)e + GUEST_EXC_HDR);
}

void guest_eh_fatal(const char *what, uint64_t detail) {
    fflush(stdout);
    fprintf(stderr,
            "guest: C++ exception support: %s (%#llx)\n"
            "guest: this path ends in std::terminate() in the original too;\n"
            "guest: the port traps here rather than pretending to continue.\n",
            what, (unsigned long long)detail);
    fflush(stderr);
    abort();
}

/* ------------------------------------------------------------------------ */
/* std::type_info matching                                                    */
/* ------------------------------------------------------------------------ */

/*
 * The three class-typeinfo vtables the guest imports.  A typeinfo object's
 * first word points 16 bytes into one of them, which is how its shape is
 * identified.  The port supplies its own stand-ins (guest_cxx.c) so that both
 * the guest's OWN typeinfo objects -- which name the imported vtables through
 * a relocation -- and the std:: ones the port has to invent are laid out the
 * same way and can be walked by one piece of code.
 */
extern const void *const guest_cxxabi_class_vtable[4];
extern const void *const guest_cxxabi_si_class_vtable[4];
extern const void *const guest_cxxabi_vmi_class_vtable[4];

#define VPTR_OF(vt) ((const void *)((const char *)(vt) + 16))

typedef struct {
    uint64_t vptr;
    uint64_t name;
} ti_class;

typedef struct {
    uint64_t vptr;
    uint64_t name;
    uint64_t base_type;
} ti_si_class;

typedef struct {
    uint64_t base_type;
    uint64_t offset_flags;
} vmi_base;

typedef struct {
    uint64_t vptr;
    uint64_t name;
    uint32_t flags;
    uint32_t base_count;
    vmi_base bases[1];
} ti_vmi_class;

#define VMI_PUBLIC_MASK UINT64_C(0x2)

static int ti_is(uint64_t ti, const void *const *vt) {
    if (!ti) return 0;
    const ti_class *c = (const ti_class *)(uintptr_t)ti;
    return (const void *)(uintptr_t)c->vptr == VPTR_OF(vt);
}

/*
 * Does an object of type `thrown` satisfy `catch (caught)`?
 *
 * `caught == 0` is `catch (...)`.  Otherwise the answer is pointer identity
 * or public inheritance: a catch clause names a base, the thrown object names
 * the most derived type, and the walk goes from the thrown type upwards.
 *
 * Only class types occur here.  The pointer and fundamental typeinfo vtables
 * (__pointer_type_info, __fundamental_type_info) are not imported by this
 * binary at all, which is the categorical statement that no `catch (T*)` and
 * no `catch (int)` exists in it.
 */
static int ti_matches(uint64_t thrown, uint64_t caught, int depth) {
    if (!caught) return 1;                  /* catch (...) */
    if (!thrown) return 0;
    if (thrown == caught) return 1;
    if (depth > 32) return 0;               /* pathological / cyclic table */

    if (ti_is(thrown, guest_cxxabi_si_class_vtable)) {
        const ti_si_class *s = (const ti_si_class *)(uintptr_t)thrown;
        return ti_matches(s->base_type, caught, depth + 1);
    }
    if (ti_is(thrown, guest_cxxabi_vmi_class_vtable)) {
        const ti_vmi_class *v = (const ti_vmi_class *)(uintptr_t)thrown;
        uint32_t n = v->base_count;
        if (n > 1024) return 0;              /* not a table we wrote */
        for (uint32_t i = 0; i < n; i++) {
            /* A private or protected base is not reachable by a catch. */
            if (!(v->bases[i].offset_flags & VMI_PUBLIC_MASK)) continue;
            if (ti_matches(v->bases[i].base_type, caught, depth + 1)) return 1;
        }
        return 0;
    }
    /* __class_type_info: no bases, so identity was the only chance. */
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Reading the LSDA                                                           */
/* ------------------------------------------------------------------------ */

#define DW_EH_PE_omit     0xFF
#define DW_EH_PE_uleb128  0x01
#define DW_EH_PE_udata2   0x02
#define DW_EH_PE_udata4   0x03
#define DW_EH_PE_udata8   0x04
#define DW_EH_PE_sleb128  0x09
#define DW_EH_PE_sdata2   0x0A
#define DW_EH_PE_sdata4   0x0B
#define DW_EH_PE_sdata8   0x0C

#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_textrel  0x20
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_funcrel  0x40
#define DW_EH_PE_aligned  0x50
#define DW_EH_PE_indirect 0x80

/*
 * A cursor that tracks BOTH the host address it is reading from and the guest
 * address that byte has, because a pcrel encoding is relative to the latter.
 * Keeping the two in one object is what stops them from drifting apart.
 */
typedef struct {
    const uint8_t *p;
    uint64_t guest;     /* guest address of *p */
} eh_cursor;

static uint8_t eh_u8(eh_cursor *c) {
    uint8_t v = *c->p++;
    c->guest++;
    return v;
}

static uint64_t eh_uleb(eh_cursor *c) {
    uint64_t r = 0;
    unsigned shift = 0;
    for (;;) {
        uint8_t b = eh_u8(c);
        r |= (uint64_t)(b & 0x7Fu) << shift;
        shift += 7;
        if (!(b & 0x80u)) return r;
        if (shift > 63) return r;
    }
}

static int64_t eh_sleb(eh_cursor *c) {
    uint64_t r = 0;
    unsigned shift = 0;
    uint8_t b;
    do {
        b = eh_u8(c);
        r |= (uint64_t)(b & 0x7Fu) << shift;
        shift += 7;
    } while ((b & 0x80u) && shift <= 63);
    if (shift < 64 && (b & 0x40u)) r |= ~(uint64_t)0 << shift;
    return (int64_t)r;
}

static uint64_t eh_raw(eh_cursor *c, uint8_t fmt) {
    uint64_t v = 0;
    switch (fmt) {
    case 0x00: memcpy(&v, c->p, 8); c->p += 8; c->guest += 8; break;
    case DW_EH_PE_uleb128: return eh_uleb(c);
    case DW_EH_PE_udata2: { uint16_t t; memcpy(&t, c->p, 2); c->p += 2; c->guest += 2; v = t; break; }
    case DW_EH_PE_udata4: { uint32_t t; memcpy(&t, c->p, 4); c->p += 4; c->guest += 4; v = t; break; }
    case DW_EH_PE_udata8: { memcpy(&v, c->p, 8); c->p += 8; c->guest += 8; break; }
    case DW_EH_PE_sleb128: return (uint64_t)eh_sleb(c);
    case DW_EH_PE_sdata2: { int16_t t; memcpy(&t, c->p, 2); c->p += 2; c->guest += 2; v = (uint64_t)(int64_t)t; break; }
    case DW_EH_PE_sdata4: { int32_t t; memcpy(&t, c->p, 4); c->p += 4; c->guest += 4; v = (uint64_t)(int64_t)t; break; }
    case DW_EH_PE_sdata8: { int64_t t; memcpy(&t, c->p, 8); c->p += 8; c->guest += 8; v = (uint64_t)t; break; }
    default:
        guest_eh_fatal("unknown LSDA pointer format", fmt);
    }
    return v;
}

/*
 * Read one encoded pointer.  The result is a GUEST address.
 *
 * The indirect bit matters here and did not in ehframe.py: a type table entry
 * is normally `indirect | pcrel | sdata4`, an offset to a GOT slot that holds
 * the real std::type_info *.  In the FILE that slot is zero -- it is filled by
 * relocation -- so the value is only knowable at run time, and what relocation
 * put there is a HOST pointer, which is exactly what has to be compared
 * against the pointer __cxa_throw was given.
 */
static uint64_t eh_encoded(eh_cursor *c, uint8_t enc, uint64_t func_start) {
    if (enc == DW_EH_PE_omit) return 0;
    uint64_t here = c->guest;
    if ((enc & 0x70) == DW_EH_PE_aligned) {
        while (c->guest & 7u) { c->p++; c->guest++; }
        here = c->guest;
    }
    uint64_t v = eh_raw(c, (uint8_t)(enc & 0x0F));
    switch (enc & 0x70) {
    case 0:
        break;
    case DW_EH_PE_pcrel:
        if (v == 0) return 0;
        v += here;
        break;
    case DW_EH_PE_funcrel:
        if (v == 0) return 0;
        v += func_start;
        break;
    case DW_EH_PE_aligned:
        break;
    default:
        guest_eh_fatal("unsupported LSDA relative base", enc);
    }
    if (enc & DW_EH_PE_indirect) {
        if (!v) return 0;
        const uint64_t *slot = (const uint64_t *)guest_eh_host_of(v);
        uint64_t t;
        memcpy(&t, slot, 8);
        return t;
    }
    return v;
}

/*
 * The result of consulting one frame's exception table.
 *
 *   found == 0   nothing here; keep unwinding
 *   found == 1   resume at `landing_pad` with selector `selector`
 *                (selector 0 is a cleanup, > 0 is a catch)
 */
typedef struct {
    int found;
    uint64_t landing_pad;
    int64_t selector;
} eh_action;

static eh_action lsda_lookup(uint64_t lsda, uint64_t func_start, uint64_t ra,
                             uint64_t thrown_type, int want_handler) {
    eh_action r = {0, 0, 0};
    if (!lsda || !ra) return r;

    eh_cursor c;
    c.p = (const uint8_t *)guest_eh_host_of(lsda);
    c.guest = lsda;

    uint8_t lp_enc = eh_u8(&c);
    uint64_t lp_start = func_start;
    if (lp_enc != DW_EH_PE_omit) {
        uint64_t v = eh_encoded(&c, lp_enc, func_start);
        if (v) lp_start = v;
    }

    uint8_t ttype_enc = eh_u8(&c);
    uint64_t ttype_base = 0;
    if (ttype_enc != DW_EH_PE_omit) {
        uint64_t off = eh_uleb(&c);
        ttype_base = c.guest + off;
    }

    uint8_t cs_enc = eh_u8(&c);
    uint64_t cs_len = eh_uleb(&c);
    uint64_t cs_end = c.guest + cs_len;

    /* The ABI looks the site up by (return address - 1): the return address
     * is the first byte AFTER the call, which for a call in the last slot of
     * a try region would fall outside it. */
    uint64_t pc = ra - 1;

    uint64_t action_rec = 0;
    uint64_t lp = 0;
    int hit = 0;
    while (c.guest < cs_end) {
        uint64_t cs_start = eh_encoded(&c, cs_enc, func_start);
        uint64_t cs_size = eh_raw(&c, (uint8_t)(cs_enc & 0x0F));
        uint64_t cs_lp = eh_raw(&c, (uint8_t)(cs_enc & 0x0F));
        uint64_t cs_act = eh_uleb(&c);
        /* cs_start is func-relative for the udata4 form GCC and clang emit;
         * the pcrel forms already resolved above. */
        uint64_t lo = (cs_enc & 0x70) ? cs_start : func_start + cs_start;
        if (pc < lo) break;                 /* the table is sorted by address */
        if (pc < lo + cs_size) {
            hit = 1;
            lp = cs_lp ? lp_start + cs_lp : 0;
            action_rec = cs_act;
            break;
        }
    }

    if (!hit || !lp) return r;              /* no landing pad covers this call */

    if (action_rec == 0) {
        /* A landing pad with no action record is a pure cleanup. */
        if (want_handler) return r;
        r.found = 1;
        r.landing_pad = lp;
        r.selector = 0;
        return r;
    }

    /* Walk the action chain looking for a type that matches. */
    eh_cursor a;
    uint64_t action_table = cs_end;
    a.guest = action_table + action_rec - 1;
    a.p = (const uint8_t *)guest_eh_host_of(a.guest);

    int saw_cleanup = 0;
    for (int guard = 0; guard < 4096; guard++) {
        uint64_t rec_at = a.guest;
        int64_t ttype_index = eh_sleb(&a);
        uint64_t next_at = a.guest;
        int64_t next_off = eh_sleb(&a);

        if (ttype_index == 0) {
            saw_cleanup = 1;
        } else if (ttype_index > 0) {
            /* Catch clause: entry `index` counts BACK from the type base. */
            uint8_t fmt = (uint8_t)(ttype_enc & 0x0F);
            unsigned esz = (fmt == DW_EH_PE_udata2 || fmt == DW_EH_PE_sdata2) ? 2
                         : (fmt == DW_EH_PE_udata8 || fmt == DW_EH_PE_sdata8 || fmt == 0) ? 8
                         : 4;
            eh_cursor t;
            t.guest = ttype_base - (uint64_t)ttype_index * esz;
            t.p = (const uint8_t *)guest_eh_host_of(t.guest);
            uint64_t caught = eh_encoded(&t, ttype_enc, func_start);
            if (ti_matches(thrown_type, caught, 0)) {
                r.found = 1;
                r.landing_pad = lp;
                r.selector = ttype_index;
                return r;
            }
        } else {
            /*
             * A negative index is an exception specification (a throw() list).
             * Violating one calls std::unexpected() and then terminates, and
             * this binary imports neither __cxa_call_unexpected nor
             * std::unexpected, so no such clause can exist in it.  Treat the
             * record as non-matching rather than inventing a semantics.
             */
            (void)rec_at;
        }

        if (next_off == 0) break;
        a.guest = next_at + (uint64_t)next_off;
        a.p = (const uint8_t *)guest_eh_host_of(a.guest);
    }

    if (saw_cleanup && !want_handler) {
        r.found = 1;
        r.landing_pad = lp;
        r.selector = 0;
    }
    return r;
}

/* ------------------------------------------------------------------------ */
/* Unwinding                                                                  */
/* ------------------------------------------------------------------------ */

static int frame_action(guest_eh_frame *f, uint64_t thrown_type,
                        int want_handler, eh_action *out) {
    if (!f->have_save || !f->ra) return 0;
    uint64_t lsda = guest_eh_region_lsda(f->ra - 1);
    if (!lsda) return 0;
    uint64_t start = guest_eh_region_start(f->ra - 1);
    *out = lsda_lookup(lsda, start, f->ra, thrown_type, want_handler);
    return out->found;
}

/*
 * Phase one: is there a handler anywhere above `from`?
 *
 * This is separate from phase two for the reason the ABI separates them: if
 * nothing catches, the standard requires std::terminate() to run with the
 * stack INTACT, and no destructor to have run yet.  The port traps instead of
 * terminating, and doing that before any cleanup has run keeps the trap at the
 * point where the state still describes what went wrong.
 */
static int find_handler(guest_eh_frame *from, uint64_t thrown_type) {
    eh_action act;
    for (guest_eh_frame *f = from; f; f = f->prev)
        if (frame_action(f, thrown_type, 1, &act)) return 1;
    return 0;
}

/* Jump to `f`'s landing pad.  Does not return. */
static void resume_at(guest_eh_frame *f, eh_action *act, guest_exception *e,
                      cpu_t *cpu) {
    guest_eh_unsnapshot(cpu, f->save);
    guest_eh_set_handler_args(cpu, obj_of(e), (uint64_t)act->selector);
    f->lp = act->landing_pad;
    /* Everything above `f` is abandoned; the stack pointer came back with the
     * snapshot, so the guest frames they used are simply left behind, exactly
     * as a real unwinder leaves them. */
    guest_eh_set_top(f);
    longjmp(f->jb, 1);
}

/*
 * Phase two: run cleanups and enter the handler.
 *
 * `from` is the frame to start looking at.  The walk stops at the first frame
 * with any landing pad -- cleanup or catch.  A cleanup pad ends in a call to
 * _Unwind_Resume, which comes back here with `from` set to that frame's
 * parent, so the loop is spread across as many returns into the guest as there
 * are cleanups.
 */
static void unwind_from(guest_eh_frame *from, guest_exception *e, cpu_t *cpu) {
    eh_action act;
    for (guest_eh_frame *f = from; f; f = f->prev) {
        if (!frame_action(f, e->type_info, 0, &act)) continue;
        e->resume_frame = f->prev;
        if (act.selector != 0) {
            e->uncaught = 0;
            if (g_uncaught_count > 0) g_uncaught_count--;
        }
        g_in_flight = e;
        resume_at(f, &act, e, cpu);
    }
    guest_eh_fatal("no handler for the exception being unwound",
                   e->type_info);
}

/* ------------------------------------------------------------------------ */
/* The Itanium C++ ABI entry points, as the port's own shims                   */
/* ------------------------------------------------------------------------ */

uint64_t guest_cxa_allocate_exception(uint64_t size) {
    void *p = malloc(GUEST_EXC_HDR + (size_t)size + 16u);
    if (!p) guest_eh_fatal("out of memory allocating an exception", size);
    memset(p, 0, GUEST_EXC_HDR);
    guest_exception *e = (guest_exception *)p;
    e->magic = GUEST_EXC_MAGIC;
    return obj_of(e);
}

void guest_cxa_free_exception(uint64_t obj) {
    guest_exception *e = exc_of(obj);
    if (!e) return;
    e->magic = 0;
    free(e);
}

void guest_cxa_throw(cpu_t *cpu, uint64_t obj, uint64_t tinfo, uint64_t dtor) {
    guest_exception *e = exc_of(obj);
    if (!e) guest_eh_fatal("__cxa_throw with an object this port did not allocate",
                           obj);
    e->type_info = tinfo;
    e->destructor = dtor;
    e->uncaught = 1;
    e->handler_count = 0;
    g_uncaught_count++;

    if (!find_handler(guest_eh_top(), tinfo))
        guest_eh_fatal("uncaught exception", tinfo);
    unwind_from(guest_eh_top(), e, cpu);
}

/*
 * _Unwind_Resume(exception) -- continue the unwind a cleanup interrupted.
 *
 * The argument the guest passes is the value its landing pad received in x0,
 * which is the object pointer this port handed it.
 */
void guest_unwind_resume(cpu_t *cpu, uint64_t obj) {
    guest_exception *e = exc_of(obj);
    if (!e) e = g_in_flight;
    if (!e) guest_eh_fatal("_Unwind_Resume with no exception in flight", obj);
    unwind_from(e->resume_frame, e, cpu);
}

uint64_t guest_cxa_begin_catch(uint64_t obj) {
    guest_exception *e = exc_of(obj);
    if (!e) guest_eh_fatal("__cxa_begin_catch on a foreign exception", obj);
    if (e->handler_count == 0) {
        e->next = g_caught;
        g_caught = e;
    }
    e->handler_count++;
    e->uncaught = 0;
    g_in_flight = NULL;
    return obj;
}

void guest_cxa_end_catch(cpu_t *cpu) {
    (void)cpu;
    guest_exception *e = g_caught;
    if (!e) return;                 /* a catch that rethrew has already left */
    if (--e->handler_count > 0) return;
    g_caught = e->next;
    /*
     * The destructor is a GUEST function and is called through dispatch, with
     * the object in x0.  Running it here rather than leaking the object keeps
     * the guest's own accounting (string buffers, arena links) consistent with
     * what the original does.
     */
    if (e->destructor) {
        cpu_t *c = guest_current_cpu();
        if (c) {
            uint64_t saved[GUEST_STATE_SIZE / 8];
            memcpy(saved, c->g, GUEST_STATE_SIZE);
            guest_eh_set_handler_args(c, obj_of(e), 0);
            guest_dispatch(c, e->destructor);
            memcpy(c->g, saved, GUEST_STATE_SIZE);
        }
    }
    e->magic = 0;
    free(e);
}

void guest_cxa_rethrow(cpu_t *cpu) {
    guest_exception *e = g_caught;
    if (!e) guest_eh_fatal("__cxa_rethrow with no caught exception", 0);
    e->uncaught = 1;
    g_uncaught_count++;
    /* The rethrown object stays "caught" until its handler exits, exactly as
     * the ABI says; __cxa_end_catch for that handler will not run because the
     * handler is being left by an exception. */
    if (!find_handler(guest_eh_top(), e->type_info))
        guest_eh_fatal("rethrown exception has no handler", e->type_info);
    unwind_from(guest_eh_top(), e, cpu);
}

uint64_t guest_cxa_uncaught_exceptions(void) {
    return (uint64_t)(unsigned)g_uncaught_count;
}

void guest_std_terminate(void) {
    guest_eh_fatal("std::terminate() called by the guest", 0);
}

/* __gxx_personality_v0 is named by the CIE, never called: this port does the
 * personality routine's job itself, in lsda_lookup().  A definition exists so
 * that the relocation naming it resolves. */
void guest_gxx_personality(cpu_t *cpu) {
    (void)cpu;
    guest_eh_fatal("__gxx_personality_v0 was called; the port unwinds itself", 0);
}

/* ------------------------------------------------------------------------ */
/* One-time initialisation guards                                             */
/* ------------------------------------------------------------------------ */

/*
 * __cxa_guard_acquire/release/abort implement `static T x = f();`.
 *
 * The guard object is 8 bytes of guest memory.  The Itanium ABI on ARM uses
 * byte 0 as "initialised" and byte 1 as "in use"; that is the layout the
 * generated code sees, so it is the layout implemented here.  The port is
 * single-threaded (the library's own multithread flag is a no-op that only
 * sets a bit in the output header), so "in use" can only be set by a
 * recursive initialisation, which is undefined behaviour in C++ and is
 * reported rather than deadlocked on.
 */
uint64_t guest_cxa_guard_acquire(uint64_t guard) {
    volatile uint8_t *g = (volatile uint8_t *)(uintptr_t)guard;
    if (g[0]) return 0;                 /* already initialised */
    if (g[1]) guest_eh_fatal("recursive initialisation of a function-local static",
                             guard);
    g[1] = 1;
    return 1;
}

void guest_cxa_guard_release(uint64_t guard) {
    volatile uint8_t *g = (volatile uint8_t *)(uintptr_t)guard;
    g[0] = 1;
    g[1] = 0;
}

void guest_cxa_guard_abort(uint64_t guard) {
    volatile uint8_t *g = (volatile uint8_t *)(uintptr_t)guard;
    g[1] = 0;
}
