#!/bin/sh
# Reproduce the current state end to end.
#
#     ./QUICKSTART.sh [-j N] /path/to/glslc.elf
#
set -e

# JOBS IS NOT TAKEN FROM THE CORE COUNT.  `nproc` reports the MACHINE, not what
# this process may use: a container quota, a cpuset or a scheduler share all
# make it read high, and the build then runs more compilers than there is CPU
# for -- or more than the memory allows, the oversized translation units being
# the ones that hurt.  So the default is 2, which is safe anywhere, and the
# operator raises it with -j when they know what the machine really has.
JOBS=2
while [ $# -gt 0 ]; do
    case $1 in
        -j)   JOBS=${2:?usage: -j N}; shift 2 ;;
        -j*)  JOBS=${1#-j}; shift ;;
        --)   shift; break ;;
        -*)   echo "unknown option $1 (only -j N)" >&2; exit 1 ;;
        *)    break ;;
    esac
done
case $JOBS in
    ''|*[!0-9]*|0) echo "-j takes a positive number, got '$JOBS'" >&2; exit 1 ;;
esac

BIN=${1:?usage: QUICKSTART.sh [-j N] /path/to/glslc.elf}
HERE=$(cd "$(dirname "$0")" && pwd)
BASE=0x7100000000        # map the image above 4 GB -- HANDOVER.md section 8.3

# Said BEFORE the first command runs, so that a run left going overnight at the
# default is a choice rather than a discovery.
echo "using -j$JOBS (the default is 2; pass -j N to change it)"

echo "== dependencies =="
# Pinned: angr/pyvex/cle/archinfo/claripy must be a matched set, and the tool
# depends on details of theirs that are not a stable API.  See requirements.txt.
# angr >= 9.3.3 needs Python 3.12 or newer.
pip install -r "$HERE/requirements.txt" --break-system-packages -q

echo "== 1. CFG recovery (skipped if cache/funcs.json exists) =="
[ -f "$HERE/cache/funcs.json" ] || \
    python3 "$HERE/analyze.py" "$BIN" "$HERE/cache" "$BASE"

echo "== 2. generate the C tree =="
# The base is taken from the cache, so it cannot disagree with step 1.
python3 "$HERE/elf2c.py" "$BIN" -o "$HERE/out" --cache "$HERE/cache" \
    --closure --rw-pointers --all --no-comments -j"$JOBS"

# THE COMPILER MUST HAVE C23 `#embed`: GCC 15+ or clang 19+.  src/data_ro.c
# pulls the 3.2 MB read-only image in with it and with nothing else -- there is
# no C-array and no assembler `.incbin` spelling of the same bytes to fall back
# to.  Checked here so an old compiler says so now rather than after 56,452
# objects.  Override with CC= if the default one is too old.
CC=${CC:-cc}
if ! echo '#if !defined(__has_embed)
#error no
#endif' | "$CC" -E -xc - >/dev/null 2>&1; then
    echo "$CC has no #embed: src/data_ro.c needs GCC 15+ or clang 19+" >&2
    "$CC" --version | head -1 >&2
    exit 1
fi

echo "== 3. build (resumable -- just rerun make) =="
# glslcinterface.h and tools/glslc_cli.c are copied into the tree by elf2c.py
# when they sit beside this script, which they do; the copies below are the
# belt-and-braces version for a tree generated from somewhere else.
cp "$HERE/glslcinterface.h" "$HERE/out/include/"
mkdir -p "$HERE/out/tools" && cp "$HERE/tools/glslc_cli.c" "$HERE/out/tools/"
# The package's own test programs are the PACKAGE's, not part of a generated
# tree, so they are copied in here rather than by the generator.
cp "$HERE/tests/test_compile.c" "$HERE/tests/test_entry.c" \
   "$HERE/tests/t_suite.c" "$HERE/out/"
cd "$HERE/out"
make -r -j"$JOBS" CC="$CC"

echo "== 4. the command-line tool =="
make cli CC="$CC"              # -> build/glslc

echo "== 5. the package's test programs =="
for t in test_compile test_entry t_suite; do
    gcc -Iinclude -O1 -std=c11 -mavx2 -c $t.c -o $t.o
done
# See HANDOVER.md section 3.4 for what these link flags do and do not buy.
link() { gcc -O1 -no-pie -rdynamic \
             -o "$1" "$2" build/libguest.a -lpthread -lm; }
link testcompile test_compile.o
link testentry   test_entry.o
link tsuite      t_suite.o

echo "== 6. run =="
./testentry
./testcompile
./tsuite
./build/glslc --help | head -8

echo
echo "Expected: testentry and testcompile pass every case (vertex, fragment,"
echo "vertex+fragment, and a correct syntax error on broken input)."
echo
echo "Compile a shader with it:"
echo "    ./out/build/glslc -i shader.vert:vertex -i shader.frag:fragment \\"
echo "                    -o dump --output-gpu-binaries --debug-info g1"
echo "  -> dump/shader.vert.nvn plus .ctrl/.code/.perf/.refl/.dbgi per section."
echo "  Every GLSLCoptions field has a flag; ./out/build/glslc --help lists them."
echo
echo "To check tsuite against the ORIGINAL library byte for byte:"
echo "    cd $HERE && sh qemu-ref.sh tests/t_suite.c"
echo "    qemu-aarch64 -L /usr/aarch64-linux-gnu -E LD_LIBRARY_PATH=/tmp/run /tmp/ref_bin > /tmp/ref.txt"
echo "    diff /tmp/ref.txt <($HERE/out/tsuite)"
echo "All 10 lines must match exactly -- see HANDOVER.md section 9."
echo
echo "The two differential tests of the runtime helpers, both quick:"
echo "    gcc -Iruntime -Iout/include -O1 -std=c11 -mavx2 \\"
echo "        -o /tmp/cctest runtime/cctest.c runtime/guest_rt.c -lm"
echo "    python3 ccref.py /tmp/cctest        # 74,880 cases, 0 mismatches"
echo "    python3 vscan.py $BIN /tmp/vforms.pkl"
echo "    python3 vecref.py $BIN out /tmp/vforms.pkl 256   # 261 forms, 0"
echo
echo "For subsdk0.elf (API 17.24), the same three steps with its own cache dir:"
echo "    python3 analyze.py subsdk0.elf cache-subsdk0 0x7100000000   # ~22 min"
echo "    python3 elf2c.py  subsdk0.elf -o out-subsdk0 --cache cache-subsdk0 \\"
echo "                      --closure --rw-pointers --all --no-comments"
echo "    make -C out-subsdk0 -r -j2                 # ~55 min on two cores"
echo "    sh mkcli.sh                                # -> /tmp/glslc_new"
echo
echo "Score it against an expected hash list (ONE PROCESS PER SHADER -- a"
echo "batched run scores zero, and score.sh's header says why):"
echo "    sh score.sh 200 expected-g1.txt \\"
echo "        --output-shader-reflection --debug-info g1 --output-perf-stats \\"
echo "        --enable-warp-culling            # expect 200 / 200"
