# GLSLC NVN Static Recompiler

Naive static recompiler of glslc included with some Nintendo Switch games. It was done for reverse engineering purposes, it works with every glslc listed here:

 GLSLC version | Package version | NVN version | Included with game | exefs filename |
| --- | --- | --- | --- | --- |
| 17.10 | 30 | 1.9 | Cave Story+ 1.0 | subsdk1 |
| 17.16 | 51 | 1.14 | シークレットゲーム KILLER QUEEN 1.0.0-1.0.1 | subsdk1 |
| 17.17 | 57 | 1.15 | Civilization VI 1.0.0<br>Assassin's Creed III 1.0.0-1.0.3 | subsdk0<br>subsdk1 |
| 17.20 | 62 | 1.15 | A Hat in Time 1.0.0-1.0.4 | subsdk0 |
| 17.20 | 68 | 1.15 | The Legend of Zelda: Link's Awakening 1.0.0-1.1.0<br>Civilization VI 1.2.19 | subsdk0 |
| 17.21 | 88 | 1.16 | Cave Story+ 1.3 | subsdk0 |
| 17.22 | 94 | 1.16 | Nobunaga's Ambition: Awakening 1.0.0-1.1.1 | subsdk0 |
| 17.22 | 97 | 1.16 | Metal Gear Solid 2: Sons of Liberty 2.1.0<br>Metal Gear Solid 3: Snake Eater 3.0.0 | subsdk1 |
| 17.24 | 102 | 1.16 | The Legend of Zelda: Echoes of Wisdom 1.0.0<br>Beyond Good & Evil 1.0.0-1.0.1 | subsdk0 |
| 17.24 | 113 | 1.16 | Tomb Raider Definitive Edition 1.0.3 | subsdk0 |

Naive in the sense that it generates tons of false functions that are never used which can generate executable size even 6x bigger than ELF. But it's still faster than running their ELFs through Unicorn via Python.

Code was generated with Claude.

GCC 15+ is a must. Clang will generate output incompatible with how musl functions work, older GCCs don't support `#embed`.<br>
Python 3 is also required.

# How to recompile glslc

1. Convert NSO to ELF with f.e. nx2elf
2. Run:
 - via Windows: 
 ```pwsh
 ./QUICKSTART-win.ps1 file.elf 0x7100000000 [-j n]
 ```
 - via Linux:
 ```bash
 ./QUICKSTART.sh file.elf 0x7100000000 [-jn]
 ```
`-j n`/`-jn` - amount of threads to use in parts that allow it, by default `n` is `2`.<br>
Depending on size of ELF and amount of threads this can take even an hour to finish.

Result of this work is a folder with source code ready to compile via make with additional file `glslc_cli.c` for CLI interface added on top of library.
