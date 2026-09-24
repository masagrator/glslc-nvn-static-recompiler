/*
 * glslc_cli.c -- a command-line front end for the translated glslc library.
 *
 *   glslc_cli -i <file>:<stage> [-i <file>:<stage> ...] -o <output-folder>
 *             [option overrides ...]
 *
 * Every field of GLSLCoptions can be set from the command line; see --help.
 * The whole GLSLCoutput blob is written to <output-folder>/output.nvn, and
 * each section is written out separately as well:
 *
 *     GPU code      -> .ctrl (control words) and .code (the shader itself)
 *     assembly dump -> .asdm
 *     perf stats    -> .perf
 *     reflection    -> .refl
 *     debug info    -> .dbgi
 *     anything else -> .sec
 *
 * plus a manifest.txt listing what was written, with each section's offset,
 * size and type, so the dump can be checked against shaderDumpInfo.py.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdarg.h>
#include <stddef.h>          /* offsetof, used by the Windows asserts below */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#  define strcasecmp _stricmp
#else
#  include <strings.h>          /* strcasecmp */
#endif
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#ifdef _WIN32
#include <windows.h>
#include <direct.h>             /* _mkdir -- Windows has no two-argument one */

/* WINDOWS 10 ADDED A FIELD AND mingw-w64's HEADER DOES NOT HAVE IT.
 *
 * PROCESSOR_RELATIONSHIP is documented as
 *     BYTE Flags; BYTE EfficiencyClass; BYTE Reserved[20]; WORD GroupCount;
 *     GROUP_AFFINITY GroupMask[];
 * since Windows 10, which is where EfficiencyClass came from.  mingw-w64's
 * <winnt.h> here still carries the ORIGINAL declaration, `BYTE Flags; BYTE
 * Reserved[21];` -- so the byte is there, at the same offset, under another
 * name, and naming it costs a compile error rather than a wrong answer.
 *
 * Rather than reading Reserved[0] -- which would be right today and silently
 * wrong the day mingw-w64 catches up and shifts Reserved by one -- the
 * documented layout is declared here and the OS's structure is read through
 * it.  The asserts below are what make that safe: if either declaration ever
 * stops agreeing about the size or about where GroupCount sits, this fails to
 * compile instead of miscounting cores.
 */
typedef struct {
    BYTE Flags;
    BYTE EfficiencyClass;
    BYTE Reserved[20];
    WORD GroupCount;
    GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
} cli_proc_rel_t;

_Static_assert(sizeof(cli_proc_rel_t) == sizeof(PROCESSOR_RELATIONSHIP),
               "PROCESSOR_RELATIONSHIP layout is not the documented one");
_Static_assert(offsetof(cli_proc_rel_t, GroupCount)
               == offsetof(PROCESSOR_RELATIONSHIP, GroupCount),
               "PROCESSOR_RELATIONSHIP.GroupCount moved");
_Static_assert(offsetof(cli_proc_rel_t, GroupMask)
               == offsetof(PROCESSOR_RELATIONSHIP, GroupMask),
               "PROCESSOR_RELATIONSHIP.GroupMask moved");
#else
#include <sys/wait.h>
#endif
#ifdef __linux__
#include <sched.h>
#endif

#include "guest_api.h"

/* ------------------------------------------------------------------ memory */

static void *cli_alloc(size_t size, size_t align, void *user) {
    (void)align; (void)user;
    return malloc(size);
}
static void cli_free(void *p, void *user) { (void)user; free(p); }
static void *cli_realloc(void *p, size_t n, void *user) { (void)user; return realloc(p, n); }

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("glslc_cli: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(2);
}

/* ------------------------------------------------------------------- input */

/* The number of shaders in ONE program.  `input.count` is a uint8_t, and a
 * linked program is capped at 5 anyway; this only bounds the arrays a single
 * compilation needs.  The number of INPUTS is not bounded -- `-I` without
 * --enable-linking compiles a whole folder, one file at a time. */
#define MAX_PROGRAM_INPUTS 255

typedef struct {
    const char   *path;
    NVNshaderStage stage;
    char         *text;
} input_t;

static const struct { const char *name; NVNshaderStage stage; } STAGE_NAMES[] = {
    { "vertex",          NVN_SHADER_STAGE_VERTEX },
    { "vert",            NVN_SHADER_STAGE_VERTEX },
    { "fragment",        NVN_SHADER_STAGE_FRAGMENT },
    { "frag",            NVN_SHADER_STAGE_FRAGMENT },
    { "pixel",           NVN_SHADER_STAGE_FRAGMENT },
    { "geometry",        NVN_SHADER_STAGE_GEOMETRY },
    { "geom",            NVN_SHADER_STAGE_GEOMETRY },
    { "tess_control",    NVN_SHADER_STAGE_TESS_CONTROL },
    { "tesc",            NVN_SHADER_STAGE_TESS_CONTROL },
    { "tess_evaluation", NVN_SHADER_STAGE_TESS_EVALUATION },
    { "tese",            NVN_SHADER_STAGE_TESS_EVALUATION },
    { "compute",         NVN_SHADER_STAGE_COMPUTE },
    { "comp",            NVN_SHADER_STAGE_COMPUTE },
};

static const char *stage_name(NVNshaderStage s) {
    switch (s) {
    case NVN_SHADER_STAGE_VERTEX:          return "vertex";
    case NVN_SHADER_STAGE_FRAGMENT:        return "fragment";
    case NVN_SHADER_STAGE_GEOMETRY:        return "geometry";
    case NVN_SHADER_STAGE_TESS_CONTROL:    return "tess_control";
    case NVN_SHADER_STAGE_TESS_EVALUATION: return "tess_evaluation";
    case NVN_SHADER_STAGE_COMPUTE:         return "compute";
    default:                               return "stage?";
    }
}

static int parse_stage(const char *s, NVNshaderStage *out) {
    for (unsigned i = 0; i < sizeof STAGE_NAMES / sizeof STAGE_NAMES[0]; ++i)
        if (!strcmp(s, STAGE_NAMES[i].name)) { *out = STAGE_NAMES[i].stage; return 1; }
    char *end;
    long v = strtol(s, &end, 0);
    if (*s && !*end && v >= 0 && v <= 5) { *out = (NVNshaderStage)v; return 1; }
    return 0;
}

/* Name section `idx` after `stem`, but only if it is really of type `want`:
 * see the call site. */
static void claim(const GLSLCoutput *out, const char **sec_stem,
                  uint32_t idx, int want, const char *stem) {
    if (idx >= out->numSections || idx >= 256) return;
    if ((int)out->headers[idx].genericHeader.common.type != want) return;
    sec_stem[idx] = stem;
}

/* The file name the outputs are named after: the input's own name, path
 * stripped and extension kept, so shader/example.frag becomes
 * example.frag.ctrl / example.frag.code / example.frag.nvn. */
static const char *base_name(const char *path) {
    const char *b = path;
    for (const char *p = path; *p; ++p)
        if (*p == '/' || *p == '\\') b = p + 1;
    return *b ? b : path;
}

/* Read a whole file and NUL-terminate it: the API takes C strings. */
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open %s: %s", path, strerror(errno));
    if (fseek(f, 0, SEEK_END)) die("cannot seek %s", path);
    long n = ftell(f);
    if (n < 0) die("cannot size %s", path);
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) die("out of memory reading %s", path);
    if (n && fread(buf, 1, (size_t)n, f) != (size_t)n)
        die("short read on %s", path);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* Extension -> stage, for `-i file` written without an explicit stage.  Both
 * the GLSL reference-compiler names and the common short ones. */
static const struct { const char *ext; NVNshaderStage stage; } STAGE_EXTS[] = {
    { "vert", NVN_SHADER_STAGE_VERTEX },
    { "vs",   NVN_SHADER_STAGE_VERTEX },
    { "vsh",  NVN_SHADER_STAGE_VERTEX },
    { "frag", NVN_SHADER_STAGE_FRAGMENT },
    { "fs",   NVN_SHADER_STAGE_FRAGMENT },
    { "fsh",  NVN_SHADER_STAGE_FRAGMENT },
    { "pix",  NVN_SHADER_STAGE_FRAGMENT },
    { "geom", NVN_SHADER_STAGE_GEOMETRY },
    { "geo",  NVN_SHADER_STAGE_GEOMETRY },
    { "gs",   NVN_SHADER_STAGE_GEOMETRY },
    { "gsh",  NVN_SHADER_STAGE_GEOMETRY },
    { "tesc", NVN_SHADER_STAGE_TESS_CONTROL },
    { "tcs",  NVN_SHADER_STAGE_TESS_CONTROL },
    { "tese", NVN_SHADER_STAGE_TESS_EVALUATION },
    { "tes",  NVN_SHADER_STAGE_TESS_EVALUATION },
    { "comp", NVN_SHADER_STAGE_COMPUTE },
    { "cs",   NVN_SHADER_STAGE_COMPUTE },
    { "csh",  NVN_SHADER_STAGE_COMPUTE },
};

/* Extensions that say nothing about the stage, so `a.frag.glsl` still works:
 * they are skipped and the next one to the left is tried. */
static int generic_ext(const char *e) {
    static const char *const G[] = { "glsl", "glslv", "txt", "shader", "sh",
                                     "spv", "spirv", "in", "inc" };
    for (unsigned i = 0; i < sizeof G / sizeof G[0]; ++i)
        if (!strcasecmp(e, G[i])) return 1;
    return 0;
}

/* Work right to left through a file name's extensions and take the first that
 * names a stage. */
static int stage_from_path(const char *path, NVNshaderStage *out) {
    const char *base = base_name(path);
    char buf[512];
    if (strlen(base) >= sizeof buf) return 0;
    strcpy(buf, base);
    for (;;) {
        char *dot = strrchr(buf, '.');
        if (!dot) return 0;
        *dot = '\0';
        const char *e = dot + 1;
        if (generic_ext(e)) continue;
        for (unsigned i = 0; i < sizeof STAGE_EXTS / sizeof STAGE_EXTS[0]; ++i)
            if (!strcasecmp(e, STAGE_EXTS[i].ext)) {
                *out = STAGE_EXTS[i].stage;
                return 1;
            }
        return 0;
    }
}

/* --fast-math-mask is a mask of SHADER STAGES, not an opaque number: bit N is
 * 1 << N of NVNshaderStage, so 0x2 is the fragment stage.  Accept the stage
 * names joined by '+' or '|' as well as a decimal or 0x number, and refuse the
 * compute bit, which this compiler does not support. */
static uint32_t parse_stage_mask(const char *opt, const char *v) {
    if ((v[0] >= '0' && v[0] <= '9')) {
        char *end;
        unsigned long m = strtoul(v, &end, 0);          /* 0x.. or decimal */
        if (*end) die("%s: trailing junk in '%s'", opt, v);
        if (m > 0x3f) die("%s: mask is 6 bits (0..0x3f), got %#lx", opt, m);
        if (m & NVN_SHADER_STAGE_COMPUTE_BIT)
            die("%s: the compute bit (0x20) is not supported", opt);
        return (uint32_t)m;
    }
    uint32_t mask = 0;
    char buf[256];
    if (strlen(v) >= sizeof buf) die("%s: value too long", opt);
    strcpy(buf, v);
    for (char *tok = buf, *next; tok; tok = next) {
        next = strpbrk(tok, "+|,");
        if (next) *next++ = '\0';
        while (*tok == ' ') ++tok;
        if (!*tok) continue;
        NVNshaderStage st;
        if (!parse_stage(tok, &st))
            die("%s: unknown stage '%s' (vertex|fragment|geometry|"
                "tess_control|tess_evaluation)", opt, tok);
        if (st == NVN_SHADER_STAGE_COMPUTE)
            die("%s: the compute stage is not supported", opt);
        mask |= 1u << (unsigned)st;
    }
    if (!mask) die("%s: empty mask", opt);
    return mask;
}

/* Append one input, growing the list.  There is no fixed ceiling: a folder
 * compiled file by file can hold as many shaders as it likes. */
static void add_input(input_t **list, unsigned *n, unsigned *cap,
                      const char *path, NVNshaderStage stage) {
    if (*n == *cap) {
        unsigned want = *cap ? *cap * 2 : 8;
        input_t *bigger = realloc(*list, want * sizeof **list);
        if (!bigger) die("out of memory tracking %u inputs", want);
        *list = bigger;
        *cap = want;
    }
    (*list)[*n].path  = path;
    (*list)[*n].stage = stage;
    (*list)[*n].text  = NULL;
    ++*n;
}

/* ------------------------------------------------------------------ output */

static void write_blob(const char *dir, const char *name,
                       const void *data, size_t len, FILE *manifest) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) die("cannot write %s: %s", path, strerror(errno));
    if (len && fwrite(data, 1, len, f) != len) die("short write on %s", path);
    fclose(f);
    printf("  %-40s %9zu bytes\n", name, len);
    if (manifest) fprintf(manifest, "%-40s %9zu\n", name, len);
}

/* An .epicshf is the GPU-code section's two halves in one file:
 *
 *      u64 codeSize;  <code bytes>  u64 controlSize;  <control bytes>
 *
 * The sizes are written little-endian byte by byte rather than as a raw
 * uint64_t, so the file is the same on any host. */
static void write_epicshf(const char *dir, const char *name,
                          const void *code, uint32_t code_len,
                          const void *ctrl, uint32_t ctrl_len, FILE *manifest) {
    unsigned char *buf = malloc((size_t)code_len + ctrl_len + 16);
    if (!buf) die("out of memory building %s", name);
    size_t n = 0;
    uint64_t v = code_len;
    for (int i = 0; i < 8; ++i) buf[n++] = (unsigned char)(v >> (8 * i));
    memcpy(buf + n, code, code_len); n += code_len;
    v = ctrl_len;
    for (int i = 0; i < 8; ++i) buf[n++] = (unsigned char)(v >> (8 * i));
    memcpy(buf + n, ctrl, ctrl_len); n += ctrl_len;
    write_blob(dir, name, buf, n, manifest);
    free(buf);
}

/* Which fields the command line actually named; see the OVR block below. */
typedef struct { unsigned
    glslSeparable:1, outputAssembly:1, outputGpuBinaries:1, outputPerfStats:1,
    outputShaderReflection:1, outputThinGpuBinaries:1, tessGS:1, prioritizeTex:1,
    errorOnScratch:1, cbf:1, warpCulling:1, multithread:1,
    language:1, debugInfo:1, spillControl:1, optLevel:1, unrollControl:1,
    warnUninit:1, fastMathMask:1, wholeWord:1;
} set_flags_t;

/* Everything the command line settled, so one compilation can be run more than
 * once -- `-I` without --enable-linking compiles each file on its own. */
typedef struct {
    const char *outdir;
    int         epicsh;
    int         print_log;
    GLSLCoptionFlags flags;
    set_flags_t set;
    const char *force_include;
    const char *spirv_entry;     /* --spirv-entry, default "main" */
    const char *const *include_paths; unsigned n_includes;
    const char *const *xfb_varyings;  unsigned n_xfb;
    const unsigned char *opt_reserved; int opt_reserved_set;
} opts_t;

/* ------------------------------------------------------------------- flags */

/* Set every bitfield of GLSLCoptionFlags from the command line.  The boolean
 * ones take an optional =0/=1 so a default-on field can be cleared, not only
 * set; that is why they are not plain presence flags. */
/* How many workers to run.  "Cores" here means PERFORMANCE cores: on a hybrid
 * CPU the efficiency cores are much slower, and a static every-Nth split gives
 * every worker the same number of files, so the run finishes only when the
 * slowest worker does.  Counting just the fast cores is what keeps that split
 * honest.
 *
 * The CPUs this process may actually use come from its affinity mask, not from
 * the machine's total; a container or a taskset run gets the smaller number.
 * Among those:
 *   - Intel hybrid parts publish the P-core list directly, as the CPU list in
 *     /sys/devices/cpu_core/cpus.
 *   - Otherwise (big.LITTLE and the like) the fast cores are the ones whose
 *     cpufreq ceiling equals the highest ceiling on the machine.
 *   - A CPU with neither file is uniform, and every CPU counts.
 * Anything unreadable falls back to the online-CPU count, which is what this
 * did before. */
#ifdef __linux__
static int cpu_usable(const unsigned char *mask, size_t nmask, unsigned cpu) {
    if (!mask) return 1;
    size_t byte = cpu / 8;
    return byte < nmask && (mask[byte] >> (cpu % 8)) & 1;
}

static unsigned count_cpu_list(const char *path, const unsigned char *mask,
                               size_t nmask) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[512];
    if (!fgets(buf, sizeof buf, f)) { fclose(f); return 0; }
    fclose(f);
    unsigned n = 0;
    for (char *p = buf; *p; ) {
        char *end;
        unsigned long lo = strtoul(p, &end, 10);
        if (end == p) break;
        unsigned long hi = lo;
        p = end;
        if (*p == '-') { hi = strtoul(p + 1, &end, 10); p = end; }
        for (unsigned long c = lo; c <= hi && c < 4096; ++c)
            if (cpu_usable(mask, nmask, (unsigned)c)) ++n;
        while (*p == ',' || *p == ' ' || *p == '\n') ++p;
    }
    return n;
}

static unsigned long cpu_max_freq(unsigned cpu) {
    char path[128];
    snprintf(path, sizeof path,
             "/sys/devices/system/cpu/cpu%u/cpufreq/cpuinfo_max_freq", cpu);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long v = 0;
    if (fscanf(f, "%lu", &v) != 1) v = 0;
    fclose(f);
    return v;
}
#endif

static unsigned perf_cores(void) {
#ifdef _WIN32
    /* Windows names the fast cores through the efficiency class of each
     * processor core: higher is faster, and on a uniform machine every core
     * reports 0.  Cores outside the process affinity mask do not count. */
    DWORD_PTR proc_mask = 0, sys_mask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &proc_mask, &sys_mask))
        proc_mask = 0;

    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    unsigned fallback = 1;
    {   SYSTEM_INFO si; GetSystemInfo(&si);
        if (si.dwNumberOfProcessors) fallback = (unsigned)si.dwNumberOfProcessors; }
    if (len) {
        unsigned char *buf = (unsigned char *)malloc(len);
        if (buf && GetLogicalProcessorInformationEx(
                       RelationProcessorCore,
                       (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)buf, &len)) {
            BYTE best = 0;
            unsigned at_best = 0;
            for (int pass = 0; pass < 2; ++pass) {
                DWORD off = 0;
                while (off < len) {
                    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *e =
                        (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)(buf + off);
                    off += e->Size;
                    if (e->Relationship != RelationProcessorCore) continue;
                    /* Skip a core the process may not run on.  A core with
                     * several groups is counted when any of its masks is
                     * usable; the affinity mask covers this process's group. */
                    int usable = (proc_mask == 0);
                    for (WORD g = 0; !usable && g < e->Processor.GroupCount; ++g)
                        if (e->Processor.GroupMask[g].Mask & proc_mask) usable = 1;
                    if (!usable) continue;
                    BYTE ec = ((const cli_proc_rel_t *)
                               &e->Processor)->EfficiencyClass;
                    if (pass == 0) { if (ec > best) best = ec; }
                    else if (ec == best) ++at_best;
                }
            }
            free(buf);
            if (at_best) return at_best;
        }
        free(buf);
    }
    return fallback;
#else
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    unsigned fallback = (online > 0) ? (unsigned)online : 1u;
#endif
#ifdef __linux__
    cpu_set_t set;
    unsigned char *mask = NULL;
    size_t nmask = 0;
    unsigned navail = 0;
    if (sched_getaffinity(0, sizeof set, &set) == 0) {
        mask = (unsigned char *)&set;
        nmask = sizeof set;
        navail = (unsigned)CPU_COUNT(&set);
        if (navail) fallback = navail;
    }

    /* Intel hybrid: the kernel names the P-cores for us. */
    unsigned p = count_cpu_list("/sys/devices/cpu_core/cpus", mask, nmask);
    if (p) return p;

    /* Otherwise separate by clock ceiling. */
    unsigned long best = 0;
    unsigned at_best = 0, seen = 0;
    for (unsigned c = 0; c < 4096; ++c) {
        if (!cpu_usable(mask, nmask, c)) continue;
        unsigned long f = cpu_max_freq(c);
        if (!f) continue;
        ++seen;
        if (f > best) { best = f; at_best = 1; }
        else if (f == best) ++at_best;
    }
    if (seen && at_best) return at_best;
#endif
#ifndef _WIN32
    return fallback;
#endif
}

static int bool_arg(const char *v) { return !v || !*v || !strcmp(v, "1") ||
                                            !strcmp(v, "true") || !strcmp(v, "yes"); }

static unsigned enum_arg(const char *opt, const char *v,
                         const char *const *names, unsigned n) {
    for (unsigned i = 0; i < n; ++i)
        if (!strcmp(v, names[i])) return i;
    char *end;
    unsigned long x = strtoul(v, &end, 0);
    if (*v && !*end && x < n) return (unsigned)x;
    die("%s: unknown value '%s'", opt, v);
    return 0;
}

static const char *const LANGUAGES[]  = { "glsl", "gles", "spirv" };
static const char *const DEBUGLEVEL[] = { "none", "g0", "g1", "g2" };
static const char *const SPILL[]      = { "default", "no-spill" };
static const char *const OPTLEVEL[]   = { "default", "none" };
static const char *const UNROLL[]     = { "default", "none", "all" };
static const char *const WARNUNINIT[] = { "default", "none", "all" };

/* Render a stage mask the way --fast-math-mask accepts it back. */
static void mask_str(uint32_t m, char *out, size_t cap) {
    static const char *const N[] = { "vertex", "fragment", "geometry",
                                     "tess_control", "tess_evaluation",
                                     "compute" };
    out[0] = '\0';
    if (!m) { snprintf(out, cap, "0 (none)"); return; }
    size_t n = 0;
    for (unsigned i = 0; i < 6; ++i)
        if (m & (1u << i))
            n += (size_t)snprintf(out + n, n < cap ? cap - n : 0, "%s%s",
                                  n ? "|" : "", N[i]);
    snprintf(out + n, n < cap ? cap - n : 0, " (%#x)", m);
}

/* The defaults are the LIBRARY's, read at run time rather than written down
 * here: they are not all zero (outputGpuBinaries is on and enableFastMathMask
 * is the fragment bit), and a hard-coded list would drift. */
static void print_defaults(void) {
    /* main() has already installed the allocator. */
    GLSLCoptions d = glslcGetDefaultOptions();
    GLSLCoptionFlags o = d.optionFlags;
    uint32_t w; memcpy(&w, &o, sizeof w);
    char fm[128];
    mask_str(o.enableFastMathMask, fm, sizeof fm);
    static const char *const LANG[] = { "glsl", "gles", "spirv" };
    static const char *const DBG[]  = { "none", "g0", "g1", "g2" };
    static const char *const SPL[]  = { "default", "no-spill" };
    static const char *const OPT[]  = { "default", "none" };
    static const char *const UNR[]  = { "default", "none", "all" };
    static const char *const WRN[]  = { "default", "none", "all" };
    printf(
"\ndefaults, from glslcGetDefaultOptions() at run time (flags word %#010x):\n"
"  glsl-separable                             %u   <- set unless --enable-linking\n"
"  output-assembly                            %u\n"
"  output-gpu-binaries                        %u\n"
"  output-perf-stats                          %u\n"
"  output-shader-reflection                   %u\n"
"  output-thin-gpu-binaries                   %u\n"
"  tessellation-and-passthrough-gs            %u\n"
"  prioritize-consecutive-texture-instructions %u\n"
"  error-on-scratch-mem-usage                 %u\n"
"  enable-cbf-optimization                    %u\n"
"  enable-warp-culling                        %u\n"
"  enable-multithread-compilation             %u\n"
"  language                                   %s\n"
"  debug-info                                 %s\n"
"  spill-control                              %s\n"
"  opt-level                                  %s\n"
"  unroll-control                             %s\n"
"  warn-uninit                                %s\n"
"  fast-math-mask                             %s\n"
"  force-include-std-header                   %s\n"
"  include paths / xfb varyings               %u / %u\n",
        w, 1u, o.outputAssembly, o.outputGpuBinaries, o.outputPerfStats,
        o.outputShaderReflection, o.outputThinGpuBinaries,
        o.tessellationAndPassthroughGS,
        o.prioritizeConsecutiveTextureInstructions,
        o.errorOnScratchMemUsage, o.enableCBFOptimization,
        o.enableWarpCulling, o.enableMultithreadCompilation,
        (unsigned)o.language < 3 ? LANG[o.language] : "?",
        (unsigned)o.outputDebugInfo < 4 ? DBG[o.outputDebugInfo] : "?",
        (unsigned)o.spillControl < 2 ? SPL[o.spillControl] : "?",
        (unsigned)o.optLevel < 2 ? OPT[o.optLevel] : "?",
        (unsigned)o.unrollControl < 3 ? UNR[o.unrollControl] : "?",
        (unsigned)o.warnUninitControl < 3 ? WRN[o.warnUninitControl] : "?",
        fm,
        d.ptrforceIncludeStdHeader ? (const char *)(uintptr_t)d.ptrforceIncludeStdHeader
                                   : "(none)",
        d.includeInfo.numPaths, d.xfbVaryingInfo.numVaryings);
    printf("\nAnything not named on the command line keeps the value above.\n");
}

static void usage(const char *argv0) {
    printf(
"usage: %s -i <file>[:<stage>] [-i ...] -o <folder> [options]\n"
"       %s -I <shader-folder> -o <folder> [options]\n"
"\n"
"  -I, --input-folder <folder>  every file in <folder> whose extension names a\n"
"                               stage.  With --enable-linking they become one\n"
"                               program (at most 5, one per stage, no compute);\n"
"                               without it each file is compiled on its own.\n"
"  -i, --input <file>[:<stage>] a shader to compile; repeat to link several\n"
"                               stages into one program.  <stage> is one of\n"
"                               vertex|fragment|geometry|tess_control|\n"
"                               tess_evaluation|compute (or 0..5).\n"
"                               Omit it and the extension decides: .vert .vs\n"
"                               .vsh .frag .fs .fsh .pix .geom .geo .gs .gsh\n"
"                               .tesc .tcs .tese .tes .comp .cs .csh, with a\n"
"                               trailing .glsl/.txt/.spv/... skipped, so\n"
"                               shader.frag.glsl works too.\n"
"  -o, --output <folder>        where to write output.nvn and the sections\n"
"                               (created if it does not exist)\n"
"\n"
"GLSLCoptions -- every field:\n"
"  --force-include-std-header <s>   options.forceIncludeStdHeader\n"
"  --include-path <p>               append to options.includeInfo.paths\n"
"  --xfb-varying <name>             append to options.xfbVaryingInfo.varyings\n"
"  --options-reserved <i>=<byte>    options.reserved[i] (0..31)\n"
"\n"
"GLSLCoptionFlags -- every bitfield ([=0|1] where shown):\n"
"  --enable-linking                 link the given stages into one program\n"
"                                   (clears glslSeparable, which this tool\n"
"                                   otherwise leaves set)\n"
"  --output-assembly[=B]\n"
"  --output-gpu-binaries[=B]        --output-perf-stats[=B]\n"
"  --output-shader-reflection[=B]   --output-thin-gpu-binaries[=B]\n"
"  --tessellation-and-passthrough-gs[=B]\n"
"  --prioritize-consecutive-texture-instructions[=B]\n"
"  --error-on-scratch-mem-usage[=B] --enable-cbf-optimization[=B]\n"
"  --enable-warp-culling[=B]        --enable-multithread-compilation[=B|N]\n"
"                                   the library is single-threaded and only\n"
"                                   records this as a bit in the output, so\n"
"                                   with -I and no --enable-linking the CLI\n"
"                                   itself compiles the files in parallel\n"
"                                   =N caps the parallel jobs at N, never\n"
"                                   above the number of cores\n"
"  --language glsl|gles|spirv       --debug-info none|g0|g1|g2\n"
"  --spirv-entry <name>             SPIR-V entry point (default main)\n"
"  --spill-control default|no-spill --opt-level default|none\n"
"  --unroll-control default|none|all\n"
"  --warn-uninit default|none|all\n"
"  --fast-math-mask <stages>        a mask of SHADER STAGES: names joined by\n"
"                                   + or | (fragment, vertex|fragment, ...),\n"
"                                   or a number (0x2 == fragment).  The\n"
"                                   compute bit (0x20) is not supported.\n"
"  --flags-word <u32>               set the whole 32-bit flags word at once\n"
"                                   (applied first, so later flags refine it)\n"
"\n"
"other:\n"
"  --generate-epicsh <0|1|2>        merge each GPU-code section's code and\n"
"                                   control halves into one <input>.epicshf:\n"
"                                     0  off (default)\n"
"                                     1  alongside the other files\n"
"                                     2  ONLY the .epicshf files -- the .nvn\n"
"                                        blob, the other sections and the\n"
"                                        manifest are not written\n"
"  --print-log                      always print the info log, not only on error\n"
"  -h, --help\n", argv0, argv0);
}

/* One compilation: `n` sources become one program, and its output is written
 * to o->outdir.  Called once for a linked build and once per file for `-I`
 * without --enable-linking.  Returns 0 on success. */
static int compile_and_dump(const opts_t *o, input_t *inputs, unsigned n_inputs)
{
    GLSLCcompileObject obj;
    memset(&obj, 0, sizeof obj);
    if (!glslcInitialize(&obj))
        die("glslcInitialize failed (initStatus=%d)", (int)obj.initStatus);

    /* glslcInitialize fills in the defaults, so overrides are applied AFTER it
     * -- otherwise every one of them would be overwritten. */
    /* --flags-word replaces the whole word; otherwise only the named fields
     * change, so the library's defaults survive. */
    if (o->set.wholeWord) {
        obj.options.optionFlags = o->flags;
    } else {
#define OVR(m, f) do { if (o->set.m) obj.options.optionFlags.f = o->flags.f; } while (0)
        OVR(glslSeparable, glslSeparable);
        OVR(outputAssembly, outputAssembly);
        OVR(outputGpuBinaries, outputGpuBinaries);
        OVR(outputPerfStats, outputPerfStats);
        OVR(outputShaderReflection, outputShaderReflection);
        OVR(outputThinGpuBinaries, outputThinGpuBinaries);
        OVR(tessGS, tessellationAndPassthroughGS);
        OVR(prioritizeTex, prioritizeConsecutiveTextureInstructions);
        OVR(errorOnScratch, errorOnScratchMemUsage);
        OVR(cbf, enableCBFOptimization);
        OVR(warpCulling, enableWarpCulling);
        OVR(multithread, enableMultithreadCompilation);
        OVR(language, language);
        OVR(debugInfo, outputDebugInfo);
        OVR(spillControl, spillControl);
        OVR(optLevel, optLevel);
        OVR(unrollControl, unrollControl);
        OVR(warnUninit, warnUninitControl);
        OVR(fastMathMask, enableFastMathMask);
#undef OVR
    }
    /* Separable shaders are the useful default for compiling one stage at a
     * time, and the library's own default is 0.  Only force it when the
     * command line did not decide (--flags-word counts as deciding). */
    if (!o->set.glslSeparable && !o->set.wholeWord)
        obj.options.optionFlags.glslSeparable = 1;
    if (o->force_include) obj.options.forceIncludeStdHeader = o->force_include;
    if (o->n_includes) {
        obj.options.includeInfo.paths = o->include_paths;
        obj.options.includeInfo.numPaths = o->n_includes;
    }
    if (o->n_xfb) {
        obj.options.xfbVaryingInfo.varyings = o->xfb_varyings;
        obj.options.xfbVaryingInfo.numVaryings = o->n_xfb;
    }
    if (o->opt_reserved_set)
        memcpy(obj.options.reserved, o->opt_reserved, sizeof obj.options.reserved);

    if (n_inputs > MAX_PROGRAM_INPUTS)
        die("%u shaders in one program; the limit is %d",
            n_inputs, MAX_PROGRAM_INPUTS);
    const char   *sources[MAX_PROGRAM_INPUTS];
    NVNshaderStage stages[MAX_PROGRAM_INPUTS];
    /* SPIR-V input: the library needs every module's size in bytes, its entry
     * point name and a (possibly null) specialization table per module; with
     * those three arrays left null it dereferences a null pointer. */
    uint32_t spv_sizes[MAX_PROGRAM_INPUTS];
    const char *spv_entries[MAX_PROGRAM_INPUTS];
    const GLSLCspirvSpecializationInfo *spv_spec[MAX_PROGRAM_INPUTS];
    const int is_spirv = obj.options.optionFlags.language == GLSLC_LANGUAGE_SPIRV;
    for (unsigned i = 0; i < n_inputs; ++i) {
        inputs[i].text = read_file(inputs[i].path);
        sources[i] = inputs[i].text;
        stages[i]  = inputs[i].stage;
        if (is_spirv) {
            struct stat sb;
            if (stat(inputs[i].path, &sb)) die("cannot stat %s", inputs[i].path);
            if (sb.st_size % 4) die("%s: SPIR-V size is not a multiple of 4", inputs[i].path);
            spv_sizes[i]   = (uint32_t)sb.st_size;
            spv_entries[i] = o->spirv_entry ? o->spirv_entry : "main";
            spv_spec[i]    = NULL;
        }
        printf("  in  %-50s %s\n", inputs[i].path, stage_name(inputs[i].stage));
    }
    obj.input.sources = sources;
    obj.input.stages  = stages;
    obj.input.count   = (uint8_t)n_inputs;
    if (is_spirv) {
        obj.input.spirvModuleSizes     = spv_sizes;
        obj.input.spirvEntryPointNames = spv_entries;
        obj.input.spirvSpecInfo        = spv_spec;
    }

    uint8_t ok = glslcCompile(&obj);

    GLSLCresults *res = (GLSLCresults *)(uintptr_t)obj.ptrlastCompiledResults;
    GLSLCcompilationStatus *st =
        res ? (GLSLCcompilationStatus *)(uintptr_t)res->ptrcompilationStatus : NULL;
    const char *log = st ? (const char *)(uintptr_t)st->ptrinfoLog : NULL;

    if (!ok || !st || !st->success) {
        fprintf(stderr, "compilation FAILED\n");
        if (log && *log) fprintf(stderr, "%s\n", log);
        glslcFinalize(&obj);
        return 1;
    }
    if (o->print_log && log && *log) printf("%s\n", log);

    GLSLCoutput *out = (GLSLCoutput *)(uintptr_t)res->ptrglslcOutput;
    if (!out) die("compilation succeeded but produced no output");

    char path[4096];
    const char *prog_stem = base_name(inputs[0].path);

    /* Named after the program like everything else: `-I` without
     * --enable-linking runs one compilation per file into the same folder, and
     * a bare "manifest.txt" would be overwritten by each in turn.
     * --generate-epicsh 2 asks for the .epicshf files and nothing else, so
     * there is no manifest at all then. */
    FILE *manifest = NULL;
    if (o->epicsh != 2) {
        snprintf(path, sizeof path, "%s/%s.manifest.txt", o->outdir, prog_stem);
        manifest = fopen(path, "w");
        if (!manifest) die("cannot write %s: %s", path, strerror(errno));
        fprintf(manifest, "magic 0x%08x  size %u  sections %u  dataOffset %u\n",
                out->magic, out->size, out->numSections, out->dataOffset);
    }

    printf("output: magic 0x%08x, %u bytes, %u sections\n",
           out->magic, out->size, out->numSections);
    const uint8_t *blob = (const uint8_t *)out;

    /* Everything is named after the input it came from.  A GPU-code header
     * says which stage it is, and it also POINTS AT its own perf-stats and
     * asm-dump sections, so those inherit the same name; what is left
     * (reflection, debug info) belongs to the program as a whole and takes
     * the first input's name. */
    const char *sec_stem[256];
    for (uint32_t i = 0; i < out->numSections && i < 256; ++i) sec_stem[i] = NULL;

    for (uint32_t i = 0; i < out->numSections && i < 256; ++i) {
        const GLSLCsectionHeaderUnion *h = &out->headers[i];
        if ((int)h->genericHeader.common.type != GLSLC_SECTION_TYPE_GPU_CODE)
            continue;
        const GLSLCgpuCodeHeader *g = &h->gpuCodeHeader;
        const char *stem = base_name(inputs[0].path);
        for (unsigned k = 0; k < n_inputs; ++k)
            if (inputs[k].stage == g->stage) { stem = base_name(inputs[k].path); break; }
        sec_stem[i] = stem;
        /* Both indices read 0 when the section does not exist -- which is a
         * valid section number -- so follow one only when the section it
         * points at is really of that kind. */
        claim(out, sec_stem, g->asmDumpSectionIdx, GLSLC_SECTION_TYPE_ASM_DUMP, stem);
        claim(out, sec_stem, g->perfStatsSectionNdx, GLSLC_SECTION_TYPE_PERF_STATS, stem);
    }

    if (o->epicsh != 2) {
        snprintf(path, sizeof path, "%s.nvn", prog_stem);
        write_blob(o->outdir, path, blob, out->size, NULL);
    }

    for (uint32_t i = 0; i < out->numSections; ++i) {
        const GLSLCsectionHeaderUnion *h = &out->headers[i];
        const GLSLCsectionHeaderCommon *c = &h->genericHeader.common;
        const uint8_t *data = blob + c->dataOffset;
        const char *stem = (i < 256 && sec_stem[i]) ? sec_stem[i] : prog_stem;
        char name[4096];

        if (manifest)
            fprintf(manifest, "section %u type %d offset %u size %u\n",
                    i, (int)c->type, c->dataOffset, c->size);

        switch ((int)c->type) {
        case GLSLC_SECTION_TYPE_GPU_CODE: {
            const GLSLCgpuCodeHeader *g = &h->gpuCodeHeader;
            /* controlOffset/dataOffset are relative to the section's data.
             * Checked rather than assumed: the control block starts with
             * 0x98761234 and the code block with 0x12345678 (graphics) or
             * 0x12345679 (compute), so a wrong base shows up immediately. */
            const uint8_t *ctrl = data + g->controlOffset;
            const uint8_t *code = data + g->dataOffset;
            uint32_t cm, dm;
            memcpy(&cm, ctrl, 4); memcpy(&dm, code, 4);
            if (cm != 0x98761234u)
                fprintf(stderr, "  warning: section %u control magic is 0x%08x,"
                        " expected 0x98761234\n", i, cm);
            if (dm != 0x12345678u && dm != 0x12345679u)
                fprintf(stderr, "  warning: section %u code magic is 0x%08x,"
                        " expected 0x1234567[89]\n", i, dm);
            if (o->epicsh != 2) {
                snprintf(name, sizeof name, "%s.ctrl", stem);
                write_blob(o->outdir, name, ctrl, g->controlSize, manifest);
                snprintf(name, sizeof name, "%s.code", stem);
                write_blob(o->outdir, name, code, g->dataSize, manifest);
            }
            if (o->epicsh) {
                snprintf(name, sizeof name, "%s.epicshf", stem);
                write_epicshf(o->outdir, name, code, g->dataSize,
                              ctrl, g->controlSize, manifest);
            }
            if (manifest)
                fprintf(manifest, "    stage %s  controlOffset %u controlSize %u"
                        " dataOffset %u dataSize %u scratchPerWarp %u\n",
                        stage_name(g->stage), g->controlOffset, g->controlSize,
                        g->dataOffset, g->dataSize, g->scratchMemBytesPerWarp);
            break;
        }
        case GLSLC_SECTION_TYPE_ASM_DUMP:
            snprintf(name, sizeof name, "%s.asdm", stem);
            if (o->epicsh != 2) write_blob(o->outdir, name, data, c->size, manifest);
            break;
        case GLSLC_SECTION_TYPE_PERF_STATS:
            snprintf(name, sizeof name, "%s.perf", stem);
            if (o->epicsh != 2) write_blob(o->outdir, name, data, c->size, manifest);
            break;
        case GLSLC_SECTION_TYPE_REFLECTION:
            snprintf(name, sizeof name, "%s.refl", stem);
            if (o->epicsh != 2) write_blob(o->outdir, name, data, c->size, manifest);
            break;
        case GLSLC_SECTION_TYPE_DEBUG_INFO:
            snprintf(name, sizeof name, "%s.dbgi", stem);
            if (o->epicsh != 2) write_blob(o->outdir, name, data, c->size, manifest);
            break;
        default:
            snprintf(name, sizeof name, "%s.type%d.sec", stem, (int)c->type);
            if (o->epicsh != 2) write_blob(o->outdir, name, data, c->size, manifest);
            break;
        }
    }
    if (manifest) fclose(manifest);

    glslcFinalize(&obj);
    for (unsigned i = 0; i < n_inputs; ++i) { free(inputs[i].text); inputs[i].text = NULL; }
    return 0;
}

int main(int argc, char **argv) {
    /* Line-buffered: when stdout is a file and the run aborts, block buffering
     * throws away everything since the last flush -- including which shader
     * was being compiled, which is the one thing worth knowing. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Before anything else, including argument parsing: a bad command line
     * still tells you which library it was talking to. */
    glslcSetAllocator(cli_alloc, cli_free, cli_realloc, NULL);
    GLSLCversion ver = glslcGetVersion();
    printf("glslc %u.%u  gpu %u.%u  package %u\n",
           ver.apiMajor, ver.apiMinor,
           ver.gpuCodeVersionMajor, ver.gpuCodeVersionMinor, ver.package);
    fflush(stdout);

    input_t *inputs = NULL;
    unsigned n_inputs = 0, cap_inputs = 0;
    const char *outdir = NULL;
    int print_log = 0;
    int link_inputs = 0;        /* --enable-linking: one program, not N */
    unsigned mt_jobs = 0;       /* --enable-multithread-compilation=N cap, 0 = all cores */
    unsigned mt_worker = 0, mt_workers = 0; /* --mt-shard w/n: this is a worker */
    unsigned n_from_folder = 0; /* how many inputs came from -I */
    int epicsh = 0;             /* 0 off, 1 alongside, 2 only .epicshf */

    const char *include_paths[64]; unsigned n_includes = 0;
    const char *xfb_varyings[64];  unsigned n_xfb = 0;
    const char *force_include = NULL;
    const char *spirv_entry = NULL;
    unsigned char opt_reserved[32];
    int opt_reserved_set = 0;
    memset(opt_reserved, 0, sizeof opt_reserved);

    /* Overrides are recorded, not applied, until after glslcInitialize() has
     * filled in the library's own defaults -- which are NOT all zero
     * (outputGpuBinaries is on and enableFastMathMask is 2).  Assigning a
     * zero-initialised GLSLCoptionFlags over the top silently discarded them.
     * `set` marks the fields the command line actually named. */
    GLSLCoptionFlags flags;
    memset(&flags, 0, sizeof flags);
    set_flags_t set;
    memset(&set, 0, sizeof set);

    /* An option may be written --name=value or --name value; `val` is the part
     * after '=' when present, and NULL otherwise. */
    for (int i = 1; i < argc; ++i) {
        char *a = argv[i];
        char *val = strchr(a, '=');
        char namebuf[128];
        if (val && a[0] == '-') {
            size_t n = (size_t)(val - a);
            if (n >= sizeof namebuf) die("option too long: %s", a);
            memcpy(namebuf, a, n); namebuf[n] = '\0';
            a = namebuf; ++val;
        } else {
            val = NULL;
        }

#define NEXT() (val ? val : (++i < argc ? argv[i] : (die("%s needs a value", a), (char *)0)))
#define IS(s)  (!strcmp(a, (s)))

        if (IS("-h") || IS("--help")) { usage(argv[0]); print_defaults(); return 0; }
        else if (IS("-i") || IS("--input")) {
            char *spec = NEXT();
            NVNshaderStage st;
            /* The stage is what follows the last ':' -- but only if it really
             * is a stage.  A Windows path ('C:\\shaders\\a.frag') has a colon
             * that is not a separator, so anything that does not parse as a
             * stage leaves the whole string as the path and the extension
             * decides. */
            char *colon = strrchr(spec, ':');
            if (colon && parse_stage(colon + 1, &st)) {
                *colon = '\0';
            } else if (!stage_from_path(spec, &st)) {
                if (colon)
                    die("'%s': '%s' is not a stage and the file name does not "
                        "imply one -- use <file>:<stage>", spec, colon + 1);
                die("'%s': no stage given and the extension does not imply one "
                    "-- use <file>:<stage>, or name it .vert/.frag/.geom/"
                    ".tesc/.tese/.comp", spec);
            }
            add_input(&inputs, &n_inputs, &cap_inputs, spec, st);
        }
        else if (IS("-I") || IS("--input-folder")) {
            /* Every file in the folder whose name implies a stage.  Anything
             * else -- headers, notes, a stray .md -- is skipped rather than
             * treated as an error, so a shader folder can hold includes. */
            const char *dir = NEXT();
            DIR *d = opendir(dir);
            if (!d) die("cannot open folder %s: %s", dir, strerror(errno));
            unsigned first = n_inputs, skipped = 0;
            struct dirent *de;
            while ((de = readdir(d))) {
                if (de->d_name[0] == '.') continue;
                char full[4096];
                snprintf(full, sizeof full, "%s/%s", dir, de->d_name);
                struct stat st;
                if (stat(full, &st) || !S_ISREG(st.st_mode)) continue;
                NVNshaderStage sg;
                if (!stage_from_path(de->d_name, &sg)) { ++skipped; continue; }
                /* Not strdup(): it needs a feature-test macro on some hosts
                   and is absent on others, and this is two lines. */
                char *keep = malloc(strlen(full) + 1);
                if (!keep) die("out of memory reading %s", dir);
                strcpy(keep, full);
                add_input(&inputs, &n_inputs, &cap_inputs, keep, sg);
            }
            closedir(d);
            if (n_inputs == first)
                die("%s: no file there has an extension that names a stage "
                    "(%u skipped)", dir, skipped);
            unsigned found = n_inputs - first;
            printf("  -I %s: %u shader%s detected", dir, found,
                   found == 1 ? "" : "s");
            if (skipped)
                printf(", %u other file%s ignored", skipped,
                       skipped == 1 ? "" : "s");
            printf("\n");

            /* readdir order is the filesystem's; sort this folder's slice so a
             * run is repeatable. */
            for (unsigned x = first + 1; x < n_inputs; ++x)
                for (unsigned y = x;
                     y > first && strcmp(inputs[y - 1].path, inputs[y].path) > 0;
                     --y) {
                    input_t t = inputs[y - 1]; inputs[y - 1] = inputs[y]; inputs[y] = t;
                }
            n_from_folder += n_inputs - first;
        }
        else if (IS("-o") || IS("--output"))      outdir = NEXT();
        else if (IS("--print-log"))               print_log = 1;
        else if (IS("--generate-epicsh")) {
            const char *v = NEXT();
            char *end;
            long m = strtol(v, &end, 0);
            if (*v == '\0' || *end || m < 0 || m > 2)
                die("--generate-epicsh takes 0, 1 or 2 (got '%s')", v);
            epicsh = (int)m;
        }
        else if (IS("--force-include-std-header")) force_include = NEXT();
        else if (IS("--spirv-entry")) spirv_entry = NEXT();
        else if (IS("--include-path")) {
            if (n_includes == 64) die("too many --include-path");
            include_paths[n_includes++] = NEXT();
        }
        else if (IS("--xfb-varying")) {
            if (n_xfb == 64) die("too many --xfb-varying");
            xfb_varyings[n_xfb++] = NEXT();
        }
        else if (IS("--options-reserved")) {
            char *s = NEXT(), *eq = strchr(s, '=');
            if (!eq) die("--options-reserved wants <index>=<byte>");
            *eq = '\0';
            unsigned idx = (unsigned)strtoul(s, NULL, 0);
            unsigned by  = (unsigned)strtoul(eq + 1, NULL, 0);
            if (idx >= sizeof opt_reserved) die("--options-reserved index 0..31");
            opt_reserved[idx] = (unsigned char)by;
            opt_reserved_set = 1;
        }
        else if (IS("--flags-word")) {
            uint32_t w = (uint32_t)strtoul(NEXT(), NULL, 0);
            memcpy(&flags, &w, sizeof w);
            set.wholeWord = 1;
        }
        else if (IS("--enable-linking")) {
            /* Linking several stages into one program is the opposite of
               separable compilation, so this clears glslSeparable. */
            link_inputs = bool_arg(val);
            flags.glslSeparable = !link_inputs;
            set.glslSeparable = 1;
        }
        /* Each of these MUST also set its bit in `set`: the OVR block above
         * copies a field only when the command line named it, so a flag that
         * updates `flags` alone is parsed, accepted, and then silently
         * dropped. */
        else if (IS("--output-assembly"))
            flags.outputAssembly = bool_arg(val), set.outputAssembly = 1;
        else if (IS("--output-gpu-binaries"))
            flags.outputGpuBinaries = bool_arg(val), set.outputGpuBinaries = 1;
        else if (IS("--output-perf-stats"))
            flags.outputPerfStats = bool_arg(val), set.outputPerfStats = 1;
        else if (IS("--output-shader-reflection")) flags.outputShaderReflection = bool_arg(val), set.outputShaderReflection = 1;
        else if (IS("--output-thin-gpu-binaries")) flags.outputThinGpuBinaries = bool_arg(val), set.outputThinGpuBinaries = 1;
        else if (IS("--tessellation-and-passthrough-gs"))
            flags.tessellationAndPassthroughGS = bool_arg(val), set.tessGS = 1;
        else if (IS("--prioritize-consecutive-texture-instructions"))
            flags.prioritizeConsecutiveTextureInstructions = bool_arg(val), set.prioritizeTex = 1;
        else if (IS("--error-on-scratch-mem-usage"))
            flags.errorOnScratchMemUsage = bool_arg(val), set.errorOnScratch = 1;
        else if (IS("--enable-cbf-optimization")) flags.enableCBFOptimization = bool_arg(val), set.cbf = 1;
        else if (IS("--enable-warp-culling"))     flags.enableWarpCulling = bool_arg(val), set.warpCulling = 1;
        else if (IS("--enable-multithread-compilation")) {
            /* The library's field is a single bit, so a number above 1 cannot
             * mean anything to it -- here it caps how many files the CLI
             * compiles at once (still never more than there are cores). */
            char *end = NULL;
            unsigned long n = (val && *val) ? strtoul(val, &end, 0) : 1;
            if (val && *val && end && !*end && n > 1) {
                mt_jobs = (unsigned)(n > 4096 ? 4096 : n);
                flags.enableMultithreadCompilation = 1;
            } else {
                flags.enableMultithreadCompilation = bool_arg(val);
            }
            set.multithread = 1;
        }
        else if (IS("--language"))
            flags.language = (GLSLClanguageTypeEnum)enum_arg(a, NEXT(), LANGUAGES, 3), set.language = 1;
        else if (IS("--debug-info"))
            flags.outputDebugInfo = (GLSLCdebugInfoLevelEnum)enum_arg(a, NEXT(), DEBUGLEVEL, 4), set.debugInfo = 1;
        else if (IS("--spill-control"))
            flags.spillControl = (SpillControlEnum)enum_arg(a, NEXT(), SPILL, 2), set.spillControl = 1;
        else if (IS("--opt-level"))
            flags.optLevel = (GLSLCoptLevelEnum)enum_arg(a, NEXT(), OPTLEVEL, 2), set.optLevel = 1;
        else if (IS("--unroll-control"))
            flags.unrollControl = (GLSLCunrollControlEnum)enum_arg(a, NEXT(), UNROLL, 3), set.unrollControl = 1;
        else if (IS("--warn-uninit"))
            flags.warnUninitControl = (GLSLCwarnUninitControlEnum)enum_arg(a, NEXT(), WARNUNINIT, 3), set.warnUninit = 1;
        else if (IS("--fast-math-mask")) {
            flags.enableFastMathMask = parse_stage_mask(a, NEXT());
            set.fastMathMask = 1;
        }
        else if (IS("--mt-shard")) {
            /* Not documented in --help: the parent sets this on the workers it
             * starts when the platform has no fork().  "w/n" means "compile
             * every nth file starting at w, and start no workers of your
             * own". */
            const char *v = val ? val : NEXT();
            char *end = NULL;
            unsigned long w = strtoul(v, &end, 10);
            if (!end || *end != '/') die("--mt-shard: expected w/n, got '%s'", v);
            unsigned long n = strtoul(end + 1, &end, 10);
            if (!n || w >= n || (end && *end))
                die("--mt-shard: bad shard '%s'", v);
            mt_worker = (unsigned)w; mt_workers = (unsigned)n;
        }
        else die("unknown option '%s' (try --help)", a);
#undef NEXT
#undef IS
    }

    if (!n_inputs) die("no -i given (try --help)");
    if (!outdir)   die("no -o given (try --help)");

    /* Windows' mkdir takes no mode: the directory inherits the parent's ACL,
     * which is what 0777-minus-umask amounts to there. */
#ifdef _WIN32
    if (_mkdir(outdir) && errno != EEXIST)
#else
    if (mkdir(outdir, 0777) && errno != EEXIST)
#endif
        die("cannot create %s: %s", outdir, strerror(errno));

    opts_t o;
    memset(&o, 0, sizeof o);
    o.outdir = outdir;
    o.epicsh = epicsh;
    o.print_log = print_log;
    o.flags = flags;
    o.set = set;
    o.force_include = force_include;
    o.spirv_entry = spirv_entry;
    o.include_paths = include_paths; o.n_includes = n_includes;
    o.xfb_varyings = xfb_varyings;   o.n_xfb = n_xfb;
    o.opt_reserved = opt_reserved;   o.opt_reserved_set = opt_reserved_set;

    /* --enable-linking makes one program of everything; otherwise a folder
     * given with -I is compiled one file at a time (see the -I handling). */
    if (link_inputs) {
        /* A linked program is the five GRAPHICS stages at most, one shader of
         * each.  Compute is never part of one -- it is a program on its own --
         * so it is refused however it got here. */
        if (n_inputs > 5)
            die("--enable-linking takes at most 5 shaders, got %u", n_inputs);
        for (unsigned i = 0; i < n_inputs; ++i) {
            if (inputs[i].stage == NVN_SHADER_STAGE_COMPUTE)
                die("--enable-linking: %s is a compute shader, which cannot be "
                    "linked with other stages", inputs[i].path);
            for (unsigned j = i + 1; j < n_inputs; ++j)
                if (inputs[i].stage == inputs[j].stage)
                    die("--enable-linking: %s and %s are both %s",
                        inputs[i].path, inputs[j].path,
                        stage_name(inputs[i].stage));
        }
        return compile_and_dump(&o, inputs, n_inputs);
    }

    /* Not linking.  Files named one at a time with -i keep their old meaning
     * (one program, count > 1); a folder is compiled file by file. */
    if (!n_from_folder)
        return compile_and_dump(&o, inputs, n_inputs);
    if (n_from_folder != n_inputs)
        die("-i and -I cannot be mixed without --enable-linking: -i builds one "
            "program, -I compiles each file on its own");

    /* --enable-multithread-compilation is a no-op inside the library: the
     * compilers it runs are single-threaded and the flag only ends up as a bit
     * in the output header.  So when a folder is compiled file by file, honour
     * the flag HERE and run the per-file compilations concurrently.  The guest
     * image is one shared mutable array, so this forks processes rather than
     * spawning threads; each child takes every Nth file and the parent
     * collects the exit statuses.  The flag is still passed to the library, so
     * the bit in each output is exactly what a serial run would produce. */
    int rc = 0;

    /* A worker started by the parent below: just this shard, serially. */
    if (mt_workers) {
        for (unsigned i = mt_worker; i < n_inputs; i += mt_workers)
            if (compile_and_dump(&o, &inputs[i], 1) != 0)
                rc = 1;
        return rc;
    }

    unsigned ncpu = perf_cores();
    unsigned nworkers = 1;
    if (flags.enableMultithreadCompilation && ncpu > 1) {
        nworkers = ncpu;
        /* =N caps the job count; the core count is still the ceiling. */
        if (mt_jobs && mt_jobs < nworkers) nworkers = mt_jobs;
        if (nworkers > n_inputs) nworkers = n_inputs;
    }

    if (nworkers <= 1) {
        for (unsigned i = 0; i < n_inputs; ++i)
            if (compile_and_dump(&o, &inputs[i], 1) != 0)
                rc = 1;
        return rc;
    }

    fprintf(stderr, "  --enable-multithread-compilation: %u parallel workers\n",
            nworkers);

#ifdef _WIN32
    /* No fork() here, so each worker is a fresh copy of this program with
     * --mt-shard added.  The command line is reused verbatim rather than
     * rebuilt from argv, so quoting survives exactly as the shell wrote it. */
    const char *cmd = GetCommandLineA();
    size_t base = strlen(cmd);
    HANDLE *kids = (HANDLE *)calloc(nworkers, sizeof *kids);
    if (!kids) die("out of memory");
    unsigned started = 0;
    for (unsigned w = 0; w < nworkers; ++w) {
        char *line = (char *)malloc(base + 64);
        if (!line) die("out of memory");
        snprintf(line, base + 64, "%s --mt-shard %u/%u", cmd, w, nworkers);
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof si); si.cb = sizeof si;
        memset(&pi, 0, sizeof pi);
        BOOL ok = CreateProcessA(NULL, line, NULL, NULL, TRUE, 0, NULL, NULL,
                                 &si, &pi);
        free(line);
        if (!ok) {
            fprintf(stderr, "glslc_cli: cannot start worker %u (error %lu)\n",
                    w, (unsigned long)GetLastError());
            rc = 1;
            break;
        }
        CloseHandle(pi.hThread);
        kids[started++] = pi.hProcess;
    }
    for (unsigned w = 0; w < started; ++w) {
        DWORD st = 1;
        WaitForSingleObject(kids[w], INFINITE);
        if (!GetExitCodeProcess(kids[w], &st) || st != 0) rc = 1;
        CloseHandle(kids[w]);
    }
    /* Whatever the workers did not get to, because one failed to start. */
    for (unsigned w = started; w < nworkers; ++w)
        for (unsigned i = w; i < n_inputs; i += nworkers)
            if (compile_and_dump(&o, &inputs[i], 1) != 0)
                rc = 1;
    free(kids);
    return rc;
#else
    pid_t *kids = calloc(nworkers, sizeof *kids);
    if (!kids) die("out of memory");
    for (unsigned w = 0; w < nworkers; ++w) {
        pid_t pid = fork();
        if (pid < 0) die("fork: %s", strerror(errno));
        if (pid == 0) {
            int crc = 0;
            for (unsigned i = w; i < n_inputs; i += nworkers)
                if (compile_and_dump(&o, &inputs[i], 1) != 0)
                    crc = 1;
            _exit(crc);
        }
        kids[w] = pid;
    }
    for (unsigned w = 0; w < nworkers; ++w) {
        int st = 0;
        if (waitpid(kids[w], &st, 0) < 0) { rc = 1; continue; }
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            if (WIFSIGNALED(st))
                fprintf(stderr, "glslc_cli: worker %u killed by signal %d\n",
                        w, WTERMSIG(st));
            rc = 1;
        }
    }
    free(kids);
    return rc;
#endif
}
