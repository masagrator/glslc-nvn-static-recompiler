<#
.SYNOPSIS
    Build the port ON WINDOWS, from a normal PowerShell prompt.

.DESCRIPTION
    Run this in PowerShell (5.1 or 7+) with a MinGW-w64 toolchain on PATH.  NOT
    in an MSYS2 bash shell: the Makefile has a native-Windows branch that uses
    cmd built-ins (mkdir/del/move) for its file operations, and it selects that
    branch on the OS environment variable, which is "Windows_NT" here.  A
    normal prompt is therefore the supported way, and it needs no sh.exe.

    With no argument it builds a generated tree that already exists (out\ beside
    this script, or -Out).  With -Elf it generates that tree first.  Generation
    is host-independent -- same Python, same C -- so a tree generated on Linux
    is the tree Windows builds, and copying one over is the faster route.

.PARAMETER Elf
    The AArch64 binary to translate.  Omit if the tree already exists.

.PARAMETER Out
    The generated tree.  Default: out\ beside this script.

.PARAMETER BuildDir
    Object directory, relative to the tree.  Default: build.  A tree carried
    over from Linux already has build\ full of ELF objects; either pass
    something else or delete it, because .o files do not announce their format
    and the link is where you would find out.

.PARAMETER Cc
    The C compiler.  Default: gcc.  MUST BE GCC 15 OR NEWER -- see below.

.PARAMETER Ar
    The archiver.  Default: ar.

.PARAMETER Make
    Default: mingw32-make if present, else make.

.PARAMETER Jobs
    Parallel compiles.  Default 2, and DELIBERATELY not the processor count:
    $env:NUMBER_OF_PROCESSORS reports the machine rather than what this process
    may use, and it is missing or wrong often enough (a job object, a container,
    a VM with a CPU limit) that a build sized from it can run more compilers
    than there is CPU or memory for.  Raise it with -j once you know what the
    machine really has.  -j is accepted as an alias.

.EXAMPLE
    .\QUICKSTART-win.ps1
    .\QUICKSTART-win.ps1 -Elf C:\work\subsdk0.elf -j 8

.NOTES
    THE COMPILER MUST BE GCC 15 OR NEWER.  15 is not a preference, it is where
    C23 `#embed` landed, and src\data_ro.c pulls the 3.2 MB read-only image in
    with `#embed` and nothing else -- there is no C-array and no assembler
    `.incbin` spelling of the same bytes to fall back to.  MSYS2 tracks GCC
    closely (`pacman -S mingw-w64-x86_64-gcc make`), so this is easy to meet
    there; a winlibs or w64devkit build works the same way.

    NOT clang, and this was measured rather than assumed.  clang has had
    `#embed` since 19 and the whole tree builds with it -- 56,452 objects,
    libguest.a, glslc.exe and the tests all link -- and then the result crashes
    on the first long double.  The cause is neither this port nor `#embed`:
    clang emits the binary128 helper calls (__eqtf2, __addtf3, ...) with the
    operands in xmm registers, while the libgcc mingw-w64 ships defines those
    same helpers taking POINTERS, so the callee dereferences whatever was in
    %rdx.  Five lines reproduce it with none of this tree involved:

        __float128 a = 1, b = 2;
        int main(void) { return a == b; }

    musl's ld128 conversion (runtime\musl\gf128.c, floatscan.c) is binary128
    from end to end, so it cannot be avoided by using it carefully.

    MSVC is not supported either: the generated code uses GCC statement
    expressions and __attribute__, and guest_eh.c is built around the Itanium
    C++ ABI.
#>

[CmdletBinding()]
param(
    [string] $Elf,
    [string] $Out,
    [string] $BuildDir = 'build',
    [string] $Cc       = 'gcc',
    [string] $Ar       = 'ar',
    [string] $Make,
    [Alias('j')]
    [int]    $Jobs = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Here = $PSScriptRoot
if (-not $Out) { $Out = Join-Path $Here 'out' }
$Base = '0x7100000000'
if ($Jobs -lt 1) { throw "-Jobs takes a positive number, got $Jobs" }

# Said BEFORE the first command runs, so a long build at the default is a
# choice rather than a discovery.
Write-Host "using -j$Jobs (the default is 2; pass -j N to change it)"

# $ErrorActionPreference does NOT apply to native programs -- they report
# failure through the exit code, and a build that keeps going after a failed
# step is worse than one that stops.  So every native call goes through this.
function Invoke-Native {
    param([Parameter(Mandatory)][string] $Exe,
          [string[]] $Arguments = @())
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Find-Tool {
    param([Parameter(Mandatory)][string] $Name, [string] $Hint)
    # -First 1: Get-Command returns EVERY match on PATH, and passing that
    # array where a path is expected produces "the term 'a b' is not
    # recognized" -- the two paths joined by a space.
    $c = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
         Select-Object -First 1
    if (-not $c) {
        if ($Hint) { throw "$Name is not on PATH -- $Hint" }
        throw "$Name is not on PATH"
    }
    return $c.Source
}

Write-Host '== 0. the toolchain =='
$ccPath = Find-Tool $Cc 'install MinGW-w64 GCC 15 or newer and put it on PATH'
$null   = Find-Tool $Ar 'it comes with the same MinGW-w64 toolchain'
if (-not $Make) {
    $Make = if (Get-Command mingw32-make -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1) {
        'mingw32-make'
    } else { 'make' }
}
$null = Find-Tool $Make 'MSYS2: pacman -S make; w64devkit ships mingw32-make'

# The #embed check is done HERE rather than left to fail on data_ro.c after
# 56,452 objects.  -E on a probe that #errors out is the whole test.
$probe = Join-Path ([System.IO.Path]::GetTempPath()) ("embedprobe-" + [guid]::NewGuid() + ".c")
Set-Content -LiteralPath $probe -Encoding ASCII -Value @'
#if !defined(__has_embed)
#error no embed
#endif
int main(void) { return 0; }
'@
try {
    & $ccPath -E $probe > $null 2>&1
    $hasEmbed = ($LASTEXITCODE -eq 0)
} finally {
    Remove-Item -LiteralPath $probe -ErrorAction SilentlyContinue
}
if (-not $hasEmbed) {
    & $ccPath --version | Select-Object -First 1 | Write-Host
    throw "$Cc has no #embed: src\data_ro.c needs GCC 15 or newer (see -? for why)"
}
Write-Host "   $ccPath"
Write-Host "   $((& $ccPath --version | Select-Object -First 1))"

if ($Elf) {
    if (-not (Test-Path -LiteralPath $Elf)) { throw "no such file: $Elf" }
    $py = Find-Tool 'python' 'install Python 3.12 or newer'

    Write-Host '== 0b. dependencies =='
    Invoke-Native $py @('-m', 'pip', 'install', '-r',
                        (Join-Path $Here 'requirements.txt'), '-q')

    Write-Host '== 1. CFG recovery (skipped if cache\funcs.json exists) =='
    $cache = Join-Path $Here 'cache'
    if (-not (Test-Path -LiteralPath (Join-Path $cache 'funcs.json'))) {
        Invoke-Native $py @((Join-Path $Here 'analyze.py'), $Elf, $cache, $Base)
    } else {
        Write-Host '   cache\funcs.json exists, skipping'
    }

    Write-Host '== 2. generate the C tree -- host-independent =='
    Invoke-Native $py @((Join-Path $Here 'elf2c.py'), $Elf, '-o', $Out,
                        '--cache', $cache, '--closure', '--rw-pointers',
                        '--all', '--no-comments', "-j$Jobs")
}

if (-not (Test-Path -LiteralPath (Join-Path $Out 'src'))) {
    throw "no generated tree at $Out (pass -Elf to make one)"
}

# glslcinterface.h and tools\glslc_cli.c are copied in by elf2c.py when they sit
# beside this script; done here too so a tree from elsewhere still builds.
$hdr = Join-Path $Here 'glslcinterface.h'
if (Test-Path -LiteralPath $hdr) {
    Copy-Item -LiteralPath $hdr -Destination (Join-Path $Out 'include') -Force
}
$cli = Join-Path $Here 'tools\glslc_cli.c'
if (Test-Path -LiteralPath $cli) {
    $dst = Join-Path $Out 'tools'
    if (-not (Test-Path -LiteralPath $dst)) { $null = New-Item -ItemType Directory $dst }
    Copy-Item -LiteralPath $cli -Destination $dst -Force
}

Push-Location $Out
try {
    # make wants forward slashes in a variable it will paste into commands.
    $mk = @("CC=$Cc", "AR=$Ar", "BUILD_DIR=$($BuildDir -replace '\\','/')")

    Write-Host "== 3. the library ($Jobs jobs; resumable -- just rerun this) =="
    # -r kills the built-in suffix rules: with 56,452 objects they cost real
    # time and match nothing here.
    Invoke-Native $Make (@('-r', "-j$Jobs") + $mk)

    Write-Host '== 4. the command-line tool =='
    # -ldbghelp is added by the Makefile when OS=Windows_NT (it is, here):
    # guest_rt.c's backtrace helper asks for it with a #pragma that GCC ignores.
    Invoke-Native $Make (@('-r', 'cli') + $mk)

    Write-Host '== 5. the runtime tests =='
    # These need no generated code, so they are the fast check that the Windows
    # side of the runtime is sane -- the wide-character and printf work of
    # HANDOVER.md section 30 is what they cover.
    $tests = @{
        't_printf' = 'runtime/guest_printf.c'
        't_scanf'  = 'runtime/guest_scanf.c'
        't_wide'   = 'runtime/guest_wide.c'
    }
    foreach ($t in $tests.Keys) {
        $src = Join-Path $Here "tests\$t.c"
        if (-not (Test-Path -LiteralPath $src)) {
            Write-Host "   $t.c is not in this package, skipping"
            continue
        }
        # Join-Path, not "$BuildDir\$t.exe": the separator belongs to the
        # platform, and step 6 below looks the file up the same way.
        Invoke-Native $ccPath @('-Iinclude', '-Iruntime', '-std=c11', '-O1',
                                $src, $tests[$t], '-o', (Join-Path $BuildDir "$t.exe"))
    }

    Write-Host '== 6. run them =='
    foreach ($t in $tests.Keys) {
        $exe = Join-Path $BuildDir "$t.exe"
        if (-not (Test-Path -LiteralPath $exe)) { continue }
        $last = (& $exe | Select-Object -Last 1)
        # The tests report "N checks, N failures" and exit non-zero on any
        # failure.  Both are shown: the line says what ran, the code is what a
        # script should test.
        '{0,-9} {1}  (exit {2})' -f $t, $last, $LASTEXITCODE | Write-Host
    }
    $glslc = Join-Path $BuildDir 'glslc.exe'
    if (Test-Path -LiteralPath $glslc) {
        Write-Host "glslc:    $((& $glslc --help | Select-Object -First 1))"
    }
} finally {
    Pop-Location
}

Write-Host @"

== done ==
  the compiler:  $Out\$BuildDir\glslc.exe
  the tests:     $Out\$BuildDir\t_printf.exe, t_scanf.exe, t_wide.exe

  A first compile, to check it against the reference:

      $Out\$BuildDir\glslc.exe -i shader.vert -o outdir --output-shader-reflection

  There is nothing to tell the build about data_ro.bin: #embed resolves its
  path against data_ro.c, not against the working directory, so the path
  question an assembler .incbin would have raised does not arise.
"@
