#!/bin/sh
# CROSSBUILD-win.sh -- build a Windows binary FROM LINUX, with MinGW-w64.
#
# THIS IS NOT THE WINDOWS QUICKSTART.  It is a shell script and Windows has no
# shell to run it: building ON Windows is QUICKSTART-win.ps1, which is
# PowerShell and needs no MSYS2 bash.  This one exists because cross-building
# is what can be run and tested on a Linux machine, and because nothing about
# the generated tree is host-specific -- the generator is the same Python, the
# sources are the same C, so only the toolchain changes.
#
# Usage:
#     ./CROSSBUILD-win.sh [-j N] [/path/to/binary.elf]
#
# With no argument it builds a tree that already exists ($HERE/out).  With one,
# it generates that tree first, exactly as QUICKSTART.sh does -- generation is
# host-independent, so a tree generated on Linux is the tree Windows builds.
set -e

# JOBS IS NOT TAKEN FROM THE CORE COUNT -- see QUICKSTART.sh for why `nproc`
# is the wrong number to trust.  Default 2, raised with -j.
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

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$HERE/out}
BASE=0x7100000000

# Said BEFORE the first command runs, so a long build at the default is a
# choice rather than a discovery.
echo "using -j$JOBS (the default is 2; pass -j N to change it)"

# The toolchain: mingw-w64's GCC, version 15 OR NEWER.
#
# 15 is not a preference, it is where `#embed` landed, and src/data_ro.c pulls
# the 3.2 MB read-only image in with `#embed` and nothing else -- no C array,
# no assembler `.incbin`.  Debian/Ubuntu's mingw-w64 is still GCC 13 as of
# 24.04, so this needs a newer distribution, a backport, or a self-built cross
# compiler; point CC_WIN/AR_WIN at it.
#
# NOT clang.  It was tried, because clang has had #embed since 19 and building
# the whole tree with it works -- 56,452 objects, libguest.a and glslc.exe all
# link.  The result then CRASHES on the first long double, and the cause is
# neither this port nor #embed: clang emits the binary128 helper calls
# (__eqtf2, __addtf3, ...) with the arguments in xmm registers, while the
# libgcc that mingw-w64 supplies defines those same helpers taking POINTERS,
# so the callee dereferences whatever was in %rdx.  Five lines reproduce it
# with no part of this tree involved:
#
#     __float128 a = 1, b = 2;
#     int main(void) { return a == b; }
#
# built with `clang --target=x86_64-w64-mingw32` -- page fault; built with
# x86_64-w64-mingw32-gcc -- exit 0.  clang would need its own compiler-rt
# builtins for this target, which Debian/Ubuntu does not package.  musl's
# ld128 float conversion (runtime/musl/gf128.c, floatscan.c) is binary128
# arithmetic from end to end, so this is not avoidable by using it carefully.
CC_WIN=${CC_WIN:-x86_64-w64-mingw32-gcc}
AR_WIN=${AR_WIN:-x86_64-w64-mingw32-ar}
# A separate object directory, so a Linux build in the same tree is not thrown
# away.  Both can coexist: build/ and build-win/.
BUILD_WIN=${BUILD_WIN:-build-win}

command -v "$CC_WIN" >/dev/null || {
    echo "no $CC_WIN -- install mingw-w64 (GCC 15 or newer)" >&2
    exit 1
}
command -v "$AR_WIN" >/dev/null || {
    echo "no $AR_WIN -- install mingw-w64" >&2
    exit 1
}
# The version is checked HERE rather than left to fail 56,452 objects later on
# a `#embed` the compiler has never heard of.
if ! echo '#if !defined(__has_embed)
#error no
#endif' | "$CC_WIN" -E -xc - >/dev/null 2>&1; then
    echo "$CC_WIN has no #embed: src/data_ro.c needs GCC 15 or newer" >&2
    "$CC_WIN" --version | head -1 >&2
    exit 1
fi

if [ $# -gt 0 ]; then
    BIN=$1
    echo "== 0. dependencies =="
    pip install -r "$HERE/requirements.txt" --break-system-packages -q
    echo "== 1. CFG recovery (~6 min; skipped if cache/funcs.json exists) =="
    [ -f "$HERE/cache/funcs.json" ] || \
        python3 "$HERE/analyze.py" "$BIN" "$HERE/cache" "$BASE"
    echo "== 2. generate the C tree (~7 min) -- host-independent =="
    python3 "$HERE/elf2c.py" "$BIN" -o "$OUT" --cache "$HERE/cache" \
        --closure --rw-pointers --all --no-comments -j"$JOBS"
fi

[ -d "$OUT/src" ] || { echo "no generated tree at $OUT (pass the ELF to make one)" >&2; exit 1; }

# glslcinterface.h and tools/glslc_cli.c are copied in by elf2c.py when they sit
# beside this script; do it here too so a tree from elsewhere still builds.
cp "$HERE/glslcinterface.h" "$OUT/include/" 2>/dev/null || true
mkdir -p "$OUT/tools" && cp "$HERE/tools/glslc_cli.c" "$OUT/tools/" 2>/dev/null || true

cd "$OUT"

echo "== 3. the library, for Windows (~1 h on two cores; resumable) =="
# CC/AR are the cross toolchain; BUILD_DIR keeps the objects apart from a Linux
# build of the same tree.  Everything else -- the flags, -march=x86-64-v3, the
# oversized-file rule -- is the Makefile's own and needs no change.
make -r -j"$JOBS" CC="$CC_WIN" AR="$AR_WIN" BUILD_DIR="$BUILD_WIN"

echo "== 4. the command-line tool =="
# -ldbghelp is added by the Makefile when it sees a mingw compiler: guest_rt.c's
# backtrace helper asks for it with a #pragma that GCC ignores.
make -r cli CC="$CC_WIN" AR="$AR_WIN" BUILD_DIR="$BUILD_WIN"

echo "== 5. the runtime tests =="
# These need no generated code, so they are the fast check that the Windows
# side of the runtime is sane -- the wide-character and printf work of
# HANDOVER.md section 30 is what they cover.
for t in t_printf t_scanf t_wide; do
    case $t in
        t_wide)  src=runtime/guest_wide.c ;;
        t_scanf) src=runtime/guest_scanf.c ;;
        *)       src=runtime/guest_printf.c ;;
    esac
    $CC_WIN -Iinclude -Iruntime -std=c11 -O1 "$HERE/tests/$t.c" "$src" \
        -o "$BUILD_WIN/$t.exe"
done

echo "== 6. run what can be run here =="
if command -v wine >/dev/null 2>&1; then
    for t in t_printf t_scanf t_wide; do
        printf '%-9s ' "$t"
        WINEDEBUG=-all wine "$BUILD_WIN/$t.exe" 2>/dev/null | tail -1
    done
    echo "glslc:    $(WINEDEBUG=-all wine "$BUILD_WIN/glslc.exe" --help 2>/dev/null | head -1)"
else
    echo "no wine here; copy $OUT/$BUILD_WIN/glslc.exe and the .exe tests to a"
    echo "Windows machine and run them there."
fi

cat <<'NOTE'

== done ==
  the compiler:  OUT/BUILD_WIN/glslc.exe        (build-win/glslc.exe by default)
  the tests:     OUT/BUILD_WIN/t_printf.exe, t_scanf.exe, t_wide.exe

BUILDING ON WINDOWS itself: use QUICKSTART-win.ps1 from a normal PowerShell
prompt, with a MinGW-w64 GCC 15+ on PATH.  It runs the same Makefile with the
same variables; the Makefile already has a native-Windows branch for its file
operations, selected on OS=Windows_NT, so no MSYS2 bash is involved.

  * -ldbghelp is added automatically when the compiler's name contains "mingw"
    (the cross case) or when OS=Windows_NT (the native case).
  * MSVC is NOT supported: the generated code uses GCC statement expressions and
    __attribute__, and guest_eh.c is built around the Itanium C++ ABI.
NOTE
