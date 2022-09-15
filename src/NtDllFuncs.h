// https://www.codeproject.com/Articles/19685/Get-Process-Info-with-NtQueryInformationProcess

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength    OPTIONAL
    );

typedef NTSTATUS (NTAPI *pfNtUnmapViewOfSection)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
    );

pfnNtQueryInformationProcess gNtQueryInformationProcess;
pfNtUnmapViewOfSection gNtUnmapViewOfSection;


HMODULE sm_LoadNTDLLFunctions()
{
    // Load NTDLL Library and get entry address

    // for NtQueryInformationProcess

    HMODULE hNtDll = LoadLibrary("ntdll.dll");
    if(hNtDll == NULL) return NULL;

    gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll,
                                                        "NtQueryInformationProcess");
    if(gNtQueryInformationProcess == NULL) {
        FreeLibrary(hNtDll);
        return NULL;
    }

    gNtUnmapViewOfSection = (pfNtUnmapViewOfSection)GetProcAddress(hNtDll, "NtUnmapViewOfSection");
    if(gNtUnmapViewOfSection == NULL) {
        FreeLibrary(hNtDll);
        return NULL;
    }

    return hNtDll;
}