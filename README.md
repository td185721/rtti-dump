# rtti-dump

A command-line extractor for MSVC-emitted Run-Time Type Information from
x64 Windows binaries. Reads a `.exe` or `.dll` from disk, locates the
on-disk RTTI structures that the Visual C++ compiler emits for classes
with virtual functions, and prints each class along with its base class
list.

Written as a learning tool for anyone studying how MSVC lays out RTTI on
disk, or needing a quick way to recover class hierarchies from a stripped
binary without spinning up a full RE suite.

## What it extracts

For each class with RTTI, the tool prints:

- The mangled class name (as stored in the `TypeDescriptor`)
- The list of base classes, each with:
  - The base class's mangled name
  - The `PMD` triple (`mdisp`, `pdisp`, `vdisp`) describing where the base
    sub-object lives relative to the derived object

## How it works

MSVC emits several on-disk structures for each class with a vtable:

1. **TypeDescriptor** — contains the mangled class name, prefixed with
   `.?A` (interface class), `.?AV` (regular class), or `.?AU` (struct).
2. **BaseClassDescriptor** — one per base class in the inheritance tree,
   references its own `TypeDescriptor` and holds the `PMD` offset triple.
3. **ClassHierarchyDescriptor** — references an array of
   `BaseClassDescriptor` RVAs.
4. **CompleteObjectLocator** — one per vtable, references the class's
   `TypeDescriptor` and `ClassHierarchyDescriptor`. On x64 it also
   contains a self-RVA which is used here to validate candidates.

The tool scans `.data` and `.rdata` for candidate `TypeDescriptor`
structures (anything prefixed with `.?A`), then scans `.rdata` for valid
Complete Object Locators that reference them, then walks each COL's
Class Hierarchy Descriptor and Base Class Array.

## Build

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Usage

```powershell
rtti-dump.exe path\to\binary.exe
rtti-dump.exe --demangle path\to\binary.exe
```

### Flags

| flag             | effect |
|------------------|--------|
| `--demangle`, `-d` | run a simple MSVC type_info demangler on class names (e.g. `.?AVWidget@ui@@` → `ui::Widget`). Template names, which have a non-trivial parameter grammar, are left in their mangled form. |

## Example output

```
[*] scanning for type descriptors in .data / .rdata ...
    found 42 candidate type descriptor(s)
[*] scanning for Complete Object Locators ...
    found 38 COL(s)

class .?AVWidget@ui@@
    base classes (3):
      [0] .?AVWidget@ui@@  (mdisp=0 pdisp=-1 vdisp=0)
      [1] .?AVPaintable@gfx@@  (mdisp=0 pdisp=-1 vdisp=0)
      [2] .?AVObject@@  (mdisp=0 pdisp=-1 vdisp=0)

class .?AVButton@ui@@
    base classes (4):
      [0] .?AVButton@ui@@  (mdisp=0 pdisp=-1 vdisp=0)
      [1] .?AVWidget@ui@@  (mdisp=0 pdisp=-1 vdisp=0)
      ...
```

## Demangling

The `--demangle` / `-d` flag enables a small built-in demangler for the
common type_info name form (`.?A[VU]Name@ns@...@@` → `ns::Name`).
Template names are detected via the `?$` sequence and returned in their
mangled form; a full MSVC name demangler would need to parse the
parameter grammar, which is non-trivial.

For template demangling, pipe output through `undname.exe` from the
Visual Studio tools, or call `__unDName` / `UnDecorateSymbolName` from
the DbgHelp API in your own code.

## Scope and limits

- **x64 PE only.** The 32-bit RTTI layout uses absolute pointers rather
  than RVAs and is not handled here.
- **MSVC convention only.** MinGW / Clang on Windows emit Itanium ABI
  RTTI with a different structure.
- **No vtable discovery.** The tool finds class metadata, not where
  vtables live or which objects use them.
- **Heuristic scanning.** Candidate `TypeDescriptor` detection is
  prefix-based (`.?A`), which can occasionally match a non-RTTI string.
  The COL validation step (self-RVA check + referenced type-RVA
  membership) filters most false positives.

## References

- Igor Skochinsky, *Reversing Microsoft Visual C++ Part II: Classes,
  Methods and RTTI*
- Quarkslab, *Visual C++ RTTI Inspection*
- Microsoft docs: `type_info` class, `__RTtypeid`, `__RTDynamicCast`

## License

MIT — see [LICENSE](LICENSE).
