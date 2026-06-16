// SPDX-License-Identifier: MIT
//
// ntdll.dll in-memory integrity scanner (defensive, read-only).
//
// This program loads the on-disk copy of ntdll.dll into a private SEC_IMAGE
// mapping using the native section APIs, then walks the .text section of the
// already-loaded ntdll and compares every page with the freshly-mapped clean
// copy. When a divergence is found, it identifies which exported function the
// divergence falls inside (via the export directory of the on-disk copy) and
// prints a structured report.
//
// It is strictly read-only:
//   - the loaded ntdll image is never written to,
//   - no other process is opened or inspected,
//   - no network calls are made,
//   - the clean copy is mapped PAGE_READONLY via SECTION_MAP_READ.
//
// Reference: https://virtualspacesec.com

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif

#define VS_PAGE_SIZE 0x1000

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);

struct NtdllApi {
    NtCreateSection_t      NtCreateSection;
    NtMapViewOfSection_t   NtMapViewOfSection;
    NtUnmapViewOfSection_t NtUnmapViewOfSection;
    NtClose_t              NtClose;
};

static bool ResolveNtdll(NtdllApi& api) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return false;
    api.NtCreateSection      = (NtCreateSection_t)     GetProcAddress(h, "NtCreateSection");
    api.NtMapViewOfSection   = (NtMapViewOfSection_t)  GetProcAddress(h, "NtMapViewOfSection");
    api.NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(h, "NtUnmapViewOfSection");
    api.NtClose              = (NtClose_t)             GetProcAddress(h, "NtClose");
    return api.NtCreateSection && api.NtMapViewOfSection
        && api.NtUnmapViewOfSection && api.NtClose;
}

// Loads ntdll.dll from disk into a private SEC_IMAGE mapping, so the PE is
// laid out in memory exactly as the loader would lay it out - but in a copy
// independent of the loader's. The caller owns the returned base and must
// NtUnmapViewOfSection it.
static PVOID MapCleanNtdllFromDisk(const NtdllApi& api) {
    WCHAR path[MAX_PATH];
    UINT n = GetSystemDirectoryW(path, MAX_PATH);
    if (n == 0 || n > MAX_PATH - 12) return nullptr;
    wcscat_s(path, MAX_PATH, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return nullptr;

    HANDLE hSection = nullptr;
    NTSTATUS st = api.NtCreateSection(
        &hSection, SECTION_MAP_READ | SECTION_QUERY,
        nullptr, nullptr,
        PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    if (!NT_SUCCESS(st)) return nullptr;

    PVOID base = nullptr;
    SIZE_T viewSize = 0;
    st = api.NtMapViewOfSection(
        hSection, GetCurrentProcess(), &base,
        0, 0, nullptr, &viewSize,
        2 /* ViewUnmap */, 0, PAGE_READONLY);
    api.NtClose(hSection);
    if (!NT_SUCCESS(st)) return nullptr;
    return base;
}

// Locates a .text section within a PE loaded at `base`. Returns true on
// success and fills the section base + virtual size in bytes.
static bool FindTextSection(PVOID base, PVOID& textBase, SIZE_T& textSize) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sec[i].Name, ".text", 6) == 0) {
            textBase = (BYTE*)base + sec[i].VirtualAddress;
            textSize = sec[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// Walks the export directory of the on-disk copy at `cleanBase` and returns
// the name of the export whose start RVA is the largest one not greater than
// `rva` - i.e. the named export the divergence most likely falls inside. The
// export table does not carry function sizes, so this is a best-effort
// containing-export lookup; for ntdll.dll, where named exports are densely
// packed, it is accurate in practice.
static const char* ExportNameForRva(PVOID cleanBase, DWORD rva) {
    auto dos = (PIMAGE_DOS_HEADER)cleanBase;
    auto nt  = (PIMAGE_NT_HEADERS)((BYTE*)cleanBase + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return nullptr;

    auto exp      = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)cleanBase + dir.VirtualAddress);
    auto funcs    = (DWORD*)((BYTE*)cleanBase + exp->AddressOfFunctions);
    auto names    = (DWORD*)((BYTE*)cleanBase + exp->AddressOfNames);
    auto ordinals = (WORD*) ((BYTE*)cleanBase + exp->AddressOfNameOrdinals);

    const char* best = nullptr;
    DWORD bestStart = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        WORD ord = ordinals[i];
        DWORD fnRva = funcs[ord];
        if (fnRva <= rva && fnRva > bestStart) {
            bestStart = fnRva;
            best = (const char*)((BYTE*)cleanBase + names[i]);
        }
    }
    return best;
}

int main() {
    NtdllApi api{};
    if (!ResolveNtdll(api)) {
        fprintf(stderr, "[-] Failed to resolve required ntdll exports.\n");
        return 1;
    }

    HMODULE loaded = GetModuleHandleW(L"ntdll.dll");
    if (!loaded) {
        fprintf(stderr, "[-] Loaded ntdll.dll handle unavailable.\n");
        return 1;
    }
    printf("[i] Loaded ntdll.dll image base: %p\n", (void*)loaded);

    PVOID clean = MapCleanNtdllFromDisk(api);
    if (!clean) {
        fprintf(stderr, "[-] Failed to map clean on-disk copy of ntdll.dll.\n");
        return 1;
    }
    printf("[i] Clean on-disk copy mapped at:  %p\n", clean);

    PVOID loadedText = nullptr;
    PVOID cleanText  = nullptr;
    SIZE_T loadedSize = 0;
    SIZE_T cleanSize  = 0;
    if (!FindTextSection(loaded, loadedText, loadedSize) ||
        !FindTextSection(clean,  cleanText,  cleanSize)) {
        fprintf(stderr, "[-] Could not locate .text in one of the copies.\n");
        api.NtUnmapViewOfSection(GetCurrentProcess(), clean);
        return 1;
    }
    SIZE_T cmpSize = (loadedSize < cleanSize) ? loadedSize : cleanSize;
    printf("[i] Comparing %zu bytes of .text\n\n", cmpSize);

    SIZE_T mismatchPages = 0;
    SIZE_T totalPages    = (cmpSize + VS_PAGE_SIZE - 1) / VS_PAGE_SIZE;

    for (SIZE_T page = 0; page < totalPages; ++page) {
        SIZE_T offset = page * VS_PAGE_SIZE;
        SIZE_T n = (cmpSize - offset < VS_PAGE_SIZE) ? (cmpSize - offset) : VS_PAGE_SIZE;
        BYTE* a = (BYTE*)loadedText + offset;
        BYTE* b = (BYTE*)cleanText  + offset;
        if (memcmp(a, b, n) == 0) continue;

        ++mismatchPages;

        // Locate the first differing byte for reporting.
        SIZE_T firstDelta = 0;
        for (; firstDelta < n; ++firstDelta) {
            if (a[firstDelta] != b[firstDelta]) break;
        }

        // RVA of the divergence inside the loaded image.
        DWORD rva = (DWORD)((BYTE*)loadedText - (BYTE*)loaded)
                  + (DWORD)offset + (DWORD)firstDelta;

        const char* name = ExportNameForRva(clean, rva);
        printf("[!] Divergence at page %zu (RVA 0x%08lx) inside %s\n",
               page, (unsigned long)rva,
               name ? name : "<unresolved>");
    }

    printf("\n[=] Pages checked:    %zu\n", totalPages);
    printf("[=] Pages diverging:  %zu\n", mismatchPages);
    if (mismatchPages == 0) {
        printf("[+] Loaded ntdll .text matches the clean on-disk copy.\n");
    } else {
        printf("[!] Loaded ntdll .text diverges from the clean on-disk copy.\n");
    }

    api.NtUnmapViewOfSection(GetCurrentProcess(), clean);
    return mismatchPages == 0 ? 0 : 2;
}
