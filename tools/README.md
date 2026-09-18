# `glslc_cli` — command-line front end

Compiles GLSL through the translated `glslc` library and writes the compiler's
output, whole and section by section, into a folder.

    glslc_cli -i <file>:<stage> [-i <file>:<stage> ...] -o <folder> [options]

Every field of `GLSLCoptions` can be set from the command line.  The same
source also builds against the **original** AArch64 library under QEMU, which
is how the two are compared byte for byte (see [Comparing](#comparing-against-the-original-library)).

---

## Building

    gcc -Iout/include -O1 -std=c11 -mavx2 -c tools/glslc_cli.c -o glslc_cli.o
    gcc -O1 -no-pie -rdynamic -o glslc_cli glslc_cli.o out/build/libguest.a \
        -lpthread -lm

`-no-pie` is for size, not correctness (HANDOVER.md §18).  No `-lstdc++`: the
C++ allocation operators go through C shims (§15).

---

## Inputs

    -i, --input <file>[:<stage>]

Repeatable — give it once per shader stage and they are linked into one
program, exactly as `glslcCompile` does with `input.count > 1`.  Up to 8.

The part after the last `:` is the stage, if it names one:

| stage | aliases | `NVNshaderStage` |
|---|---|---|
| `vertex` | `vert` | 0 |
| `fragment` | `frag`, `pixel` | 1 |
| `geometry` | `geom` | 2 |
| `tess_control` | `tesc` | 3 |
| `tess_evaluation` | `tese` | 4 |
| `compute` | `comp` | 5 |

A bare number `0`–`5` also works.

    -i "shaders/example.vert:vertex" -i "shaders/example.frag:fragment"

### `-I` — a whole folder

    -I, --input-folder <folder>

Takes every file in `<folder>` whose extension names a stage (see below), in
name order.  Anything else — headers, notes — is skipped, so a shader folder
can hold includes.  A folder with no shader in it is an error rather than a
silent no-op.  There is no limit on how many files a folder may hold when they
are compiled separately; the limits below apply to a *linked* program only.

What happens next depends on `--enable-linking`:

| | behaviour |
|---|---|
| **with** `--enable-linking` | the files become **one program**, exactly as if each had been given with `-i`.  At most **5**, and **one shader per stage** — a sixth file or two of the same stage is an error.  **Compute is refused**: it is a program on its own and cannot be linked with other stages, however it was named. |
| **without** | each file is compiled as a **separate invocation**, and each writes its own set of output files |

Because those two are different jobs, `-i` and `-I` cannot be combined unless
`--enable-linking` is given.

    ./glslc_cli -I shaders -o dump --enable-linking     # one linked program
    ./glslc_cli -I shaders -o dump                      # one compile per file

### Inferring the stage from the file name

Leave the `:<stage>` off and the extension decides:

| stage | extensions |
|---|---|
| vertex | `.vert` `.vs` `.vsh` |
| fragment | `.frag` `.fs` `.fsh` `.pix` |
| geometry | `.geom` `.geo` `.gs` `.gsh` |
| tess_control | `.tesc` `.tcs` |
| tess_evaluation | `.tese` `.tes` |
| compute | `.comp` `.cs` `.csh` |

Matching is case-insensitive, and a trailing extension that says nothing about
the stage — `.glsl` `.glslv` `.txt` `.shader` `.sh` `.spv` `.spirv` `.in`
`.inc` — is skipped, so `example.frag.glsl` is a fragment shader.

    -i shaders/example.vert -i shaders/example.frag

An explicit stage always wins.  If the name implies nothing, the tool says so
rather than guessing.

Because the stage is only taken from after the last `:` when it actually names
a stage, a path that merely contains one still works: `-i C:\shaders\a.frag`
is the file `C:\shaders\a.frag`, not a stage called `\shaders\a.frag`.

---

## Output

    -o, --output <folder>

Created if missing.  Written into it:

| file | contents |
|---|---|
| `<input>.nvn` | the entire `GLSLCoutput` blob, `output->size` bytes |
| `<input>.ctrl` | GPU-code section, control words (magic `0x98761234`) |
| `<input>.code` | GPU-code section, the shader itself (`0x12345678`, or `0x12345679` for compute) |
| `<input>.asdm` | assembly dump |
| `<input>.perf` | performance statistics |
| `<input>.refl` | program reflection |
| `<input>.dbgi` | debug info (magic `0x65040891`) |
| `<input>.type<N>.sec` | any section type this tool does not know |
| `<input>.epicshf` | code and control merged into one file — only with `--generate-epicsh` |
| `manifest.txt` | every section's index, type, offset and size, and the GPU-code header fields |

**Naming.**  Each file is named after the input it came from.  A GPU-code
header carries its stage and also points at its own perf-stats and asm-dump
sections (`perfStatsSectionNdx`, `asmDumpSectionIdx`), so those inherit the
same name.  Program-wide sections — reflection, debug info — and the `.nvn`
blob take the first input's name.

Both indices read `0` when the section does not exist, and 0 is a valid section
number, so the tool follows one only when the section it points at really is of
that type.

**Checked as it writes.**  The control and code magics are verified against the
values above; a mismatch is reported on stderr rather than silently dumping the
wrong bytes.

The `.nvn` blob is exactly what `shaderDumpInfo.py` parses.

> The library will not currently emit an assembly-dump section, so `.asdm`
> normally does not appear.  `--output-assembly` is still accepted and is
> recorded in the control block's flags word.

---

## Options

Values may be written `--opt value` or `--opt=value`.

### Overriding vs. replacing

Options are applied **on top of the library's defaults**, which are not all
zero.  `--help` prints them, read from `glslcGetDefaultOptions()` at run time
rather than from a list in this file:

    output-gpu-binaries   1
    fast-math-mask        fragment (0x2)
    everything else       0

So `--output-shader-reflection` adds reflection to the default GPU binaries; it
does not turn the rest off.  Only the fields you name change.  `--flags-word`
is the exception: it replaces the whole word, so nothing else survives.

**One deliberate difference from the library.**  This tool sets
`glslSeparable = 1`, because compiling one stage at a time is what it is for.
Separable programs carry their own source-level requirements; whatever they are
for a given shader, the compiler says so in the info log.

Pass **`--enable-linking`** to link the given stages into one program instead —
it clears `glslSeparable`, which is the library's own default.

Boolean flags take an optional `=0`/`=1` (`=true`/`=yes` also work), which is
how a default-on field is turned **off**:

    --output-gpu-binaries=0

### `GLSLCoptions`

| option | field |
|---|---|
| `--force-include-std-header <s>` | `forceIncludeStdHeader` — a header prepended to every source; pass a header, not a shader |
| `--include-path <p>` | appended to `includeInfo.paths` (max 64) |
| `--xfb-varying <name>` | appended to `xfbVaryingInfo.varyings` (max 64) — needs a stage that produces varyings, so a fragment-only program is rejected by the compiler |
| `--options-reserved <i>=<byte>` | `reserved[i]`, `i` = 0..31 |

### `GLSLCoptionFlags` — booleans

| option | field |
|---|---|
| `--enable-linking` | link the stages into one program.  `glslSeparable` is set by default; this clears it |
| `--output-assembly[=B]` | `outputAssembly` |
| `--output-gpu-binaries[=B]` | `outputGpuBinaries` *(default 1)* |
| `--output-perf-stats[=B]` | `outputPerfStats` |
| `--output-shader-reflection[=B]` | `outputShaderReflection` |
| `--output-thin-gpu-binaries[=B]` | `outputThinGpuBinaries` |
| `--tessellation-and-passthrough-gs[=B]` | `tessellationAndPassthroughGS` |
| `--prioritize-consecutive-texture-instructions[=B]` | `prioritizeConsecutiveTextureInstructions` |
| `--error-on-scratch-mem-usage[=B]` | `errorOnScratchMemUsage` |
| `--enable-cbf-optimization[=B]` | `enableCBFOptimization` |
| `--enable-warp-culling[=B]` | `enableWarpCulling` |
| `--enable-multithread-compilation[=B\|N]` | `enableMultithreadCompilation` |

### `GLSLCoptionFlags` — enumerations

| option | values | field |
|---|---|---|
| `--language` | `glsl`, `gles`, `spirv` | `language` |
| `--debug-info` | `none`, `g0`, `g1`, `g2` | `outputDebugInfo` |
| `--spill-control` | `default`, `no-spill` | `spillControl` |
| `--opt-level` | `default`, `none` | `optLevel` |
| `--unroll-control` | `default`, `none`, `all` | `unrollControl` |
| `--warn-uninit` | `default`, `none`, `all` | `warnUninitControl` |
| `--fast-math-mask` | see below | `enableFastMathMask` *(default `fragment`)* |

Each enumeration also accepts its numeric value.

### `--fast-math-mask` — a mask of shader stages

Not an opaque number: bit *N* is `1 << N` of `NVNshaderStage`, so `0x2` is the
fragment stage.  Give it either stage names joined by `+` or `|`, or a number
in decimal or `0x` hex:

    --fast-math-mask fragment              # 0x2, the default
    --fast-math-mask vertex|fragment       # 0x3
    --fast-math-mask tesc+tese             # 0x18
    --fast-math-mask 0x1f                  # all graphics stages
    --fast-math-mask 0                     # none

| stage | bit |
|---|---|
| vertex | 0x01 |
| fragment | 0x02 |
| geometry | 0x04 |
| tess_control | 0x08 |
| tess_evaluation | 0x10 |
| ~~compute~~ | 0x20 — **rejected**, unsupported |

Both `--fast-math-mask compute` and `--fast-math-mask 0x20` are refused, as is
anything above `0x3f`.

### Whole word, and other

| option | meaning |
|---|---|
| `--flags-word <u32>` | replace all 32 bits of `optionFlags` at once |
| `--generate-epicsh <0\|1\|2>` | write `<input>.epicshf` — see below.  `0` off (default), `1` alongside the other files, `2` only the `.epicshf` files |
| `--print-log` | print the info log even when compilation succeeds |
| `-h`, `--help` | usage summary, followed by the live defaults from `glslcGetDefaultOptions()` |

`--opt-level default` disables `g2` debugging — the compiler says so in the
info log and falls back to `g1`.

---

## `.epicshf`

`--generate-epicsh` merges each GPU-code section's two halves into one file per
stage, `<input>.epicshf`:

    u64 codeSize          little-endian
    u8  code[codeSize]    the .code half, magic 0x12345678 (0x12345679 compute)
    u64 controlSize       little-endian
    u8  control[controlSize]   the .ctrl half, magic 0x98761234

Code first, then control, no header and no padding — the file is exactly
`16 + codeSize + controlSize` bytes.  The two halves are byte-for-byte what
`.code` and `.ctrl` contain, so either form can be checked against the other.

| mode | effect |
|---|---|
| `0` | off — the default; output is exactly as if the option were absent |
| `1` | write `.epicshf` **as well as** everything else |
| `2` | write **only** the `.epicshf` files — no `.nvn`, no other sections, no manifest |

The file is identical in modes 1 and 2.

    ./glslc_cli -i shaders/example.vert -i shaders/example.frag \
                -o dump --generate-epicsh 2
    # -> dump/example.vert.epicshf, dump/example.frag.epicshf

---

## Output on stdout

The first line is always the library version, printed before the command line
is even parsed — so a run that fails on a bad argument still says which library
it was talking to:

    glslc 17.21  gpu 1.16  package 88

`-I` then reports what it found in the folder before compiling anything:

    -I shaders: 2 shaders detected, 2 other files ignored

followed by one line per input, and one per file written.

## Exit status

| code | meaning |
|---|---|
| 0 | compiled; output written |
| 1 | compilation failed — the info log is printed on stderr |
| 2 | bad usage, or a file could not be read or written |

---

## Examples

Vertex + fragment linked, with everything turned on:

    ./glslc_cli -i shaders/example.vert -i shaders/example.frag \
                -o dump \
                --output-shader-reflection --output-perf-stats --debug-info g1

(the stages come from the extensions; `:vertex` / `:fragment` would be
equivalent)

Compute shader, no optimisation, unroll everything:

    ./glslc_cli -i s.comp:compute -o dump --opt-level none --unroll-control all

SPIR-V input, no register spilling, GPU binaries off:

    ./glslc_cli -i s.frag:fragment -o dump --language spirv \
                --spill-control no-spill --output-gpu-binaries=0

Include paths, transform-feedback varyings and a forced header:

    ./glslc_cli -i s.vert:vertex -o dump \
                --include-path inc --include-path shared/inc \
                --xfb-varying vPosition --xfb-varying vNormal \
                --force-include-std-header prelude.h \
                --fast-math-mask vertex|geometry

Linked rather than separable:

    ./glslc_cli -i s.vert:vertex -i s.frag:fragment -o dump --enable-linking

---

## Comparing against the original library

The same source builds against the real AArch64 `glslc` under QEMU, so any
option can be checked byte for byte.  Needs `qemu-user` and the aarch64 cross
compiler (REFERENCE-DIFFING.md §1):

    ./qemu-ref.sh tools/glslc_cli.c        # -> /tmp/ref_bin

    ./out/glslc_cli -i s.frag:fragment -o dump --debug-info g1

    LD_LIBRARY_PATH=/tmp/run qemu-aarch64 -L /usr/aarch64-linux-gnu \
        -E LD_LIBRARY_PATH=/tmp/run /tmp/ref_bin \
        -i s.frag:fragment -o refdump --debug-info g1

    diff -r dump refdump

This is how the `%d`-printed-as-unsigned bug in the debug-info path was found
(HANDOVER.md §13): nothing in the test suite reached it, and the difference was
a single `-1` rendered as `4294967295`.


## Parallel folder compilation

The library's `enableMultithreadCompilation` is a no-op inside the compiler:
the compilers it drives are single-threaded, and the flag only ends up as a
bit in the output header.  The CLI therefore acts on it itself.

With `-I <folder>` and **no** `--enable-linking` -- the mode where each file is
its own independent compilation -- `--enable-multithread-compilation` runs
those per-file compilations concurrently.  They run as separate processes, not
threads: the guest image is one shared mutable array, so a process per worker
is what keeps the compilations independent.  Each worker takes every Nth file
and the parent reports failure if any worker fails.  On POSIX a worker is a
`fork()`; on Windows, which has no `fork`, it is a fresh copy of the program
started from the same command line with a hidden `--mt-shard w/n` appended.

    --enable-multithread-compilation        one worker per core
    --enable-multithread-compilation=4      at most 4 workers
    --enable-multithread-compilation=0      off (serial)

`=N` is a cap, never a request for more than the machine has: the worker count
is `min(N, performance cores, files)`.

"Performance cores" is meant literally.  A static every-Nth split hands every
worker the same number of files, so the run ends when the slowest worker ends;
counting efficiency cores would just make the whole run as slow as they are.
Detection, in order:

  * the CPUs this process may actually run on — its affinity mask on Linux,
    `GetProcessAffinityMask` on Windows — so a container or a `taskset`/
    affinity-limited run sees only what it was given;
  * Linux, Intel hybrid: the P-core list the kernel publishes at
    `/sys/devices/cpu_core/cpus`;
  * Linux, otherwise (big.LITTLE and friends): the cores whose
    `cpufreq/cpuinfo_max_freq` equals the highest ceiling present;
  * Windows: the cores with the highest `EfficiencyClass` reported by
    `GetLogicalProcessorInformationEx(RelationProcessorCore)` — every core
    reports 0 on a uniform machine, so all of them count;
  * anything unreadable, or a uniform CPU: the plain online-CPU count.  The flag is still passed to the library unchanged,
so each output is byte-for-byte what a serial run produces.

It has no effect with `--enable-linking` or with plain `-i`, where all the
inputs are one program and there is only one compilation to run.
