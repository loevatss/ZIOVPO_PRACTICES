#include "ProcessProtection.h"

#include <aclapi.h>

#include <array>
#include <cwchar>
#include <memory>

namespace antivirus::protection
{
namespace
{
constexpr DWORD kProcessHardeningAccess =
    READ_CONTROL | WRITE_DAC | PROCESS_QUERY_LIMITED_INFORMATION;

struct LocalMemoryDeleter
{
    void operator()(void* pointer) const noexcept
    {
        if (pointer != nullptr)
        {
            LocalFree(pointer);
        }
    }
};

using LocalAclPtr = std::unique_ptr<ACL, LocalMemoryDeleter>;
using LocalSecurityDescriptorPtr = std::unique_ptr<void, LocalMemoryDeleter>;

// Пишет диагностическое сообщение в OutputDebugStringW с кодом Win32.
void DebugLogWin32(const wchar_t* operation, DWORD error)
{
    wchar_t message[256]{};
    swprintf_s(
        message,
        L"[ProcessProtection] %ls failed. Win32 error: %lu\r\n",
        operation,
        error);
    OutputDebugStringW(message);
}

// Пишет успешное диагностическое сообщение в OutputDebugStringW.
void DebugLogSuccess(const wchar_t* operation)
{
    wchar_t message[256]{};
    swprintf_s(message, L"[ProcessProtection] %ls succeeded.\r\n", operation);
    OutputDebugStringW(message);
}

// Пишет информационное диагностическое сообщение в OutputDebugStringW.
void DebugLogInfo(const wchar_t* operation)
{
    wchar_t message[256]{};
    swprintf_s(message, L"[ProcessProtection] %ls\r\n", operation);
    OutputDebugStringW(message);
}

// Создаёт SID стандартной Windows-группы или учётной записи.
bool CreateKnownSid(WELL_KNOWN_SID_TYPE sidType, PSID sid, DWORD sidCapacity)
{
    DWORD sidSize = sidCapacity;
    if (!CreateWellKnownSid(sidType, nullptr, sid, &sidSize))
    {
        DebugLogWin32(L"CreateWellKnownSid", GetLastError());
        return false;
    }

    return true;
}

// Заполняет EXPLICIT_ACCESSW для ACE, привязанной к SID.
void BuildSidAccessEntry(
    EXPLICIT_ACCESSW& entry,
    ACCESS_MODE mode,
    ACCESS_MASK permissions,
    PSID sid)
{
    ZeroMemory(&entry, sizeof(entry));
    entry.grfAccessPermissions = permissions;
    entry.grfAccessMode = mode;
    entry.grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&entry.Trustee, sid);
}

// Проверяет, что ACE явно даёт указанному SID полный доступ.
bool IsFullAllowAceForSid(PACE_HEADER aceHeader, PSID sid, ACCESS_MASK fullAccessMask)
{
    if (aceHeader == nullptr || sid == nullptr || aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
    {
        return false;
    }

    auto* allowedAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(aceHeader);
    return (allowedAce->Mask & fullAccessMask) == fullAccessMask
        && EqualSid(static_cast<PSID>(&allowedAce->SidStart), sid);
}

// Копирует ACE в новый ACL без изменения содержимого ACE.
bool AddExistingAce(PACL targetAcl, PACE_HEADER aceHeader)
{
    if (!AddAce(targetAcl, ACL_REVISION, MAXDWORD, aceHeader, aceHeader->AceSize))
    {
        DebugLogWin32(L"AddAce", GetLastError());
        return false;
    }

    return true;
}

// Переносит allow ACE для SYSTEM в начало DACL, чтобы deny Administrators не затрагивал SYSTEM.
bool BuildDaclWithSystemAllowFirst(
    PACL sourceDacl,
    PSID systemSid,
    ACCESS_MASK fullAccessMask,
    PACL* reorderedDacl)
{
    if (sourceDacl == nullptr || systemSid == nullptr || reorderedDacl == nullptr)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        DebugLogWin32(L"BuildDaclWithSystemAllowFirst validation", ERROR_INVALID_PARAMETER);
        return false;
    }

    ACL_SIZE_INFORMATION aclSizeInfo{};
    if (!GetAclInformation(sourceDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation))
    {
        DebugLogWin32(L"GetAclInformation", GetLastError());
        return false;
    }

    const DWORD aclSize = aclSizeInfo.AclBytesInUse;
    auto* newAcl = static_cast<PACL>(LocalAlloc(LMEM_FIXED, aclSize));
    if (newAcl == nullptr)
    {
        DebugLogWin32(L"LocalAlloc", GetLastError());
        return false;
    }

    if (!InitializeAcl(newAcl, aclSize, ACL_REVISION))
    {
        const DWORD initError = GetLastError();
        LocalFree(newAcl);
        DebugLogWin32(L"InitializeAcl", initError);
        return false;
    }

    for (DWORD i = 0; i < aclSizeInfo.AceCount; ++i)
    {
        void* ace = nullptr;
        if (!GetAce(sourceDacl, i, &ace))
        {
            const DWORD aceError = GetLastError();
            LocalFree(newAcl);
            DebugLogWin32(L"GetAce", aceError);
            return false;
        }

        auto* aceHeader = static_cast<PACE_HEADER>(ace);
        if (IsFullAllowAceForSid(aceHeader, systemSid, fullAccessMask)
            && !AddExistingAce(newAcl, aceHeader))
        {
            LocalFree(newAcl);
            return false;
        }
    }

    for (DWORD i = 0; i < aclSizeInfo.AceCount; ++i)
    {
        void* ace = nullptr;
        if (!GetAce(sourceDacl, i, &ace))
        {
            const DWORD aceError = GetLastError();
            LocalFree(newAcl);
            DebugLogWin32(L"GetAce", aceError);
            return false;
        }

        auto* aceHeader = static_cast<PACE_HEADER>(ace);
        if (!IsFullAllowAceForSid(aceHeader, systemSid, fullAccessMask)
            && !AddExistingAce(newAcl, aceHeader))
        {
            LocalFree(newAcl);
            return false;
        }
    }

    *reorderedDacl = newAcl;
    DebugLogSuccess(L"SYSTEM allow ACE ordering");
    return true;
}

// Применяет DACL, запрещающую PROCESS_TERMINATE выбранным группам.
bool ApplyProcessDacl(
    HANDLE processHandle,
    DWORD processId,
    const ProcessProtectionPolicy& policy)
{
    if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        DebugLogWin32(L"process handle validation", ERROR_INVALID_HANDLE);
        return false;
    }

    wchar_t startMessage[256]{};
    swprintf_s(
        startMessage,
        L"[ProcessProtection] hardening process handle for PID %lu.\r\n",
        processId);
    OutputDebugStringW(startMessage);

    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR rawSecurityDescriptor = nullptr;
    const DWORD getSecurityError = GetSecurityInfo(
        processHandle,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &oldDacl,
        nullptr,
        &rawSecurityDescriptor);
    if (getSecurityError != ERROR_SUCCESS)
    {
        DebugLogWin32(L"GetSecurityInfo", getSecurityError);
        return false;
    }

    LocalSecurityDescriptorPtr securityDescriptor(rawSecurityDescriptor);
    DebugLogSuccess(L"GetSecurityInfo");

    std::array<BYTE, SECURITY_MAX_SID_SIZE> usersSidBuffer{};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSidBuffer{};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSidBuffer{};

    PSID usersSid = static_cast<PSID>(usersSidBuffer.data());
    PSID administratorsSid = static_cast<PSID>(administratorsSidBuffer.data());
    PSID systemSid = static_cast<PSID>(systemSidBuffer.data());

    if (!CreateKnownSid(WinBuiltinUsersSid, usersSid, static_cast<DWORD>(usersSidBuffer.size()))
        || !CreateKnownSid(WinBuiltinAdministratorsSid, administratorsSid, static_cast<DWORD>(administratorsSidBuffer.size()))
        || !CreateKnownSid(WinLocalSystemSid, systemSid, static_cast<DWORD>(systemSidBuffer.size())))
    {
        return false;
    }

    EXPLICIT_ACCESSW entries[3]{};
    ULONG entryCount = 0;

    BuildSidAccessEntry(entries[entryCount++], DENY_ACCESS, PROCESS_TERMINATE, usersSid);

    if (policy.denyBuiltinAdministratorsTerminate)
    {
        BuildSidAccessEntry(entries[entryCount++], DENY_ACCESS, PROCESS_TERMINATE, administratorsSid);
    }

    BuildSidAccessEntry(entries[entryCount++], GRANT_ACCESS, PROCESS_ALL_ACCESS, systemSid);

    PACL rawNewDacl = nullptr;
    const DWORD aclError = SetEntriesInAclW(entryCount, entries, oldDacl, &rawNewDacl);
    if (aclError != ERROR_SUCCESS)
    {
        DebugLogWin32(L"SetEntriesInAclW", aclError);
        return false;
    }

    LocalAclPtr newDacl(rawNewDacl);
    DebugLogSuccess(L"SetEntriesInAclW");

    PACL rawOrderedDacl = nullptr;
    if (!BuildDaclWithSystemAllowFirst(
        newDacl.get(),
        systemSid,
        PROCESS_ALL_ACCESS,
        &rawOrderedDacl))
    {
        return false;
    }

    LocalAclPtr orderedDacl(rawOrderedDacl);

    const DWORD setSecurityError = SetSecurityInfo(
        processHandle,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        orderedDacl.get(),
        nullptr);
    if (setSecurityError != ERROR_SUCCESS)
    {
        DebugLogWin32(L"SetSecurityInfo", setSecurityError);
        return false;
    }

    DebugLogSuccess(L"SetSecurityInfo");
    return true;
}
}

bool HardenCurrentProcess(const ProcessProtectionPolicy& policy)
{
    const DWORD processId = GetCurrentProcessId();
    HANDLE processHandle = OpenProcess(kProcessHardeningAccess, FALSE, processId);
    if (processHandle == nullptr)
    {
        DebugLogWin32(L"OpenProcess", GetLastError());
        return false;
    }

    DebugLogSuccess(L"OpenProcess");
    const bool hardened = ApplyProcessDacl(processHandle, processId, policy);
    CloseHandle(processHandle);
    return hardened;
}

bool HardenProcessHandle(
    HANDLE processHandle,
    DWORD processId,
    const ProcessProtectionPolicy& policy)
{
    DebugLogInfo(L"OpenProcess skipped: using existing process HANDLE");
    return ApplyProcessDacl(processHandle, processId, policy);
}
}
