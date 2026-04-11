#include <Windows.h>
#include <iostream>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE Handle);

void PrintSectionInfo(void* baseAddress, SIZE_T viewSize) {
    std::cout << "[*] Section mapped at " << baseAddress << " with size " << std::hex << viewSize << std::endl;
}

int main() {
    HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[-] Failed to load ntdll.dll" << std::endl;
        return -1;
    }

    // Resolve necessary functions from ntdll
    auto NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
    auto NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
    auto NtClose = (NtClose_t)GetProcAddress(hNtdll, "NtClose");

    if (!NtCreateSection || !NtMapViewOfSection || !NtClose) {
        std::cerr << "[-] Failed to resolve functions from ntdll.dll" << std::endl;
        return -1;
    }

    std::cout << "[+] Successfully loaded and resolved functions from ntdll.dll" << std::endl;

    // Get the base address of the original ntdll.dll
    HMODULE hOriginalNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hOriginalNtdll) {
        std::cerr << "[-] Failed to get handle to original ntdll.dll" << std::endl;
        return -1;
    }
    std::cout << "[+] Original ntdll.dll loaded at: " << hOriginalNtdll << std::endl;

    HANDLE sectionHandle = nullptr;
    LARGE_INTEGER sectionSize = { 0 };
    sectionSize.QuadPart = 0x800000;  // 8MB section size

    // Create a section
    NTSTATUS status = NtCreateSection(
        &sectionHandle,
        SECTION_ALL_ACCESS,
        nullptr,
        &sectionSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        std::cerr << "[-] Failed to create section" << std::endl;
        return -1;
    }

    std::cout << "[+] NtCreateSection successful, handle: " << sectionHandle << std::endl;

    // Map the section into memory
    PVOID baseAddress = nullptr;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(
        sectionHandle,
        GetCurrentProcess(),
        &baseAddress,
        0,
        0,
        nullptr,
        &viewSize,
        2,  // View share
        0,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        std::cerr << "[-] Failed to map section into memory" << std::endl;
        NtClose(sectionHandle);
        return -1;
    }

    PrintSectionInfo(baseAddress, viewSize);

    // Compare the first 0x1000 bytes of the original and newly mapped ntdll.dll
    bool pagesMatch = memcmp(hOriginalNtdll, baseAddress, 0x1000) == 0;
    if (pagesMatch) {
        std::cout << "[+] The first page of the original and newly mapped ntdll.dll are identical." << std::endl;
    }
    else {
        std::cout << "[-] The first page of the original and newly mapped ntdll.dll are different." << std::endl;
    }

    // Perform modifications (for demonstration purposes, we'll zero out the first part of the mapped section)
    memset(baseAddress, 0, 0x1000);  // Clear first page of the section
    std::cout << "[+] Modified the section's first page in memory." << std::endl;

    // Unmap and close the section
    NtClose(sectionHandle);

    std::cout << "[+] Section handle closed." << std::endl;

    Sleep(30000);

    return 0;
}