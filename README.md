# Remapping ntdll.dll

[![Website](https://img.shields.io/badge/Website-virtualspacesec.com-2b59ff)](https://virtualspacesec.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small, self-contained C++ tool that performs a **read-only integrity check** of the loaded `ntdll.dll` against a freshly-mapped clean copy from disk, and reports which exported function (if any) each divergence falls inside.

This is one of the public repositories that accompany [**VirtualSpace AppSec**](https://virtualspacesec.com), a secure code review tool for Windows by [Verse](https://virtualspacesec.com/pages/about-us) (a Netherlands-registered business, KVK 88114171) that runs entirely on the user's own machine.

## How it works

1. **Resolve a small set of native section APIs** (`NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtClose`) from the already-loaded `ntdll.dll`.
2. **Map a clean on-disk copy of `ntdll.dll` privately** into the current process via `SEC_IMAGE` + `SECTION_MAP_READ` + `PAGE_READONLY`. The PE is laid out exactly as the loader would lay it out, but in a copy that is independent of the loader's own.
3. **Walk the PE headers of both copies** to locate the `.text` section bounds.
4. **Compare the `.text` section page-by-page** (4 KiB pages) between the loaded image and the clean copy.
5. **For each diverging page**, walk the export directory of the clean copy and report the largest-RVA named export not exceeding the divergence - i.e. the named function the divergence most likely falls inside.
6. **Print a structured summary** of pages checked, pages diverging, and per-page export attribution. Exit code is `0` when the loaded `.text` matches the clean copy and `2` when divergences are present.

## Sample output

```
[i] Loaded ntdll.dll image base: 00007FF8C4F70000
[i] Clean on-disk copy mapped at:  0000023A41C00000
[i] Comparing 1572864 bytes of .text

[+] Loaded ntdll .text matches the clean on-disk copy.

[=] Pages checked:    384
[=] Pages diverging:  0
```

## What it is - and what it is not

This is a **defensive, read-only** reference. Concretely:

- The loaded `ntdll.dll` image is **never written to**.
- The clean copy is mapped **`PAGE_READONLY`** under **`SECTION_MAP_READ`**.
- No other process is opened, inspected, or modified - the tool runs entirely against its own process.
- No network connection is made.
- No payload is shipped or executed.

It is published as an educational integrity-checking pattern that runs entirely on the developer's own machine, useful for software that needs to verify the integrity of a trusted system library before relying on it.

## Build and run

1. Compile `Source.cpp` with any modern C++ compiler that targets Windows (MSVC and clang-cl both work).
2. Run the resulting executable on Windows 10 or 11.
3. Read the printed report. A divergence does not by itself indicate something malicious - legitimate compatibility shims and instrumentation also patch in-memory code - but it gives you a precise per-page, per-export view of where the in-memory copy stops matching the on-disk one.

## License

MIT - see [LICENSE](LICENSE).
