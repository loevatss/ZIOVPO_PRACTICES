#include "ServiceProtection.h"

#include <aclapi.h>

#include <array>
#include <cwchar>
#include <memory>
#include <vector>

namespace antivirus::protection
{
namespace
{
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

// Пишет диагностическое сообщение service hardening с кодом Win32.
void DebugLogWin32(const wchar_t* operation, DWORD error)
{
    wchar_t message[256]{};
    swprintf_s(
        message,
        L"[ServiceProtection] %ls failed. Win32 error: %lu\r\n",
        operation,
        error);
    OutputDebugStringW(message);
}

// Пишет успешное диагностическое сообщение service hardening.
void DebugLogSuccess(const wchar_t* operation)
{
    wchar_t message[256]{};
    swprintf_s(message, L"[ServiceProtection] %ls succeeded.\r\n", operation);
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

// Читает SECURITY_DESCRIPTOR service object через QueryServiceObjectSecurity.
bool QueryServiceDacl(SC_HANDLE serviceHandle, std::vector<BYTE>& securityDescriptor)
{
    DWORD bytesNeeded = 0;
    QueryServiceObjectSecurity(
        serviceHandle,
        DACL_SECURITY_INFORMATION,
        nullptr,
        0,
        &bytesNeeded);

    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || bytesNeeded == 0)
    {
        DebugLogWin32(L"QueryServiceObjectSecurity(size)", sizeError);
        return false;
    }

    securityDescriptor.resize(bytesNeeded);
    if (!QueryServiceObjectSecurity(
        serviceHandle,
        DACL_SECURITY_INFORMATION,
        reinterpret_cast<PSECURITY_DESCRIPTOR>(securityDescriptor.data()),
        static_cast<DWORD>(securityDescriptor.size()),
        &bytesNeeded))
    {
        DebugLogWin32(L"QueryServiceObjectSecurity", GetLastError());
        return false;
    }

    DebugLogSuccess(L"QueryServiceObjectSecurity");
    return true;
}

// Применяет DACL, запрещающую SERVICE_STOP выбранным группам.
bool ApplyServiceDacl(SC_HANDLE serviceHandle, const ServiceProtectionPolicy& policy)
{
    std::vector<BYTE> securityDescriptorBuffer;
    if (!QueryServiceDacl(serviceHandle, securityDescriptorBuffer))
    {
        return false;
    }

    auto* securityDescriptor =
        reinterpret_cast<PSECURITY_DESCRIPTOR>(securityDescriptorBuffer.data());

    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL oldDacl = nullptr;
    if (!GetSecurityDescriptorDacl(
        securityDescriptor,
        &daclPresent,
        &oldDacl,
        &daclDefaulted))
    {
        DebugLogWin32(L"GetSecurityDescriptorDacl", GetLastError());
        return false;
    }

    UNREFERENCED_PARAMETER(daclDefaulted);

    if (!daclPresent)
    {
        oldDacl = nullptr;
    }

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

    BuildSidAccessEntry(entries[entryCount++], DENY_ACCESS, SERVICE_STOP, usersSid);

    if (policy.denyBuiltinAdministratorsStop)
    {
        BuildSidAccessEntry(entries[entryCount++], DENY_ACCESS, SERVICE_STOP, administratorsSid);
    }

    BuildSidAccessEntry(entries[entryCount++], GRANT_ACCESS, SERVICE_ALL_ACCESS, systemSid);

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
        SERVICE_ALL_ACCESS,
        &rawOrderedDacl))
    {
        return false;
    }

    LocalAclPtr orderedDacl(rawOrderedDacl);

    SECURITY_DESCRIPTOR absoluteSecurityDescriptor{};
    if (!InitializeSecurityDescriptor(
        &absoluteSecurityDescriptor,
        SECURITY_DESCRIPTOR_REVISION))
    {
        DebugLogWin32(L"InitializeSecurityDescriptor", GetLastError());
        return false;
    }

    if (!SetSecurityDescriptorDacl(
        &absoluteSecurityDescriptor,
        TRUE,
        orderedDacl.get(),
        FALSE))
    {
        DebugLogWin32(L"SetSecurityDescriptorDacl", GetLastError());
        return false;
    }

    if (!SetServiceObjectSecurity(
        serviceHandle,
        DACL_SECURITY_INFORMATION,
        &absoluteSecurityDescriptor))
    {
        DebugLogWin32(L"SetServiceObjectSecurity", GetLastError());
        return false;
    }

    DebugLogSuccess(L"SetServiceObjectSecurity");
    return true;
}
}

bool HardenServiceObject(
    const wchar_t* serviceName,
    const ServiceProtectionPolicy& policy)
{
    if (serviceName == nullptr || *serviceName == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        DebugLogWin32(L"service name validation", ERROR_INVALID_PARAMETER);
        return false;
    }

    SC_HANDLE scmHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scmHandle == nullptr)
    {
        DebugLogWin32(L"OpenSCManagerW", GetLastError());
        return false;
    }

    DebugLogSuccess(L"OpenSCManagerW");

    SC_HANDLE serviceHandle = OpenServiceW(
        scmHandle,
        serviceName,
        READ_CONTROL | WRITE_DAC);
    if (serviceHandle == nullptr)
    {
        const DWORD openError = GetLastError();
        CloseServiceHandle(scmHandle);
        DebugLogWin32(L"OpenServiceW", openError);
        return false;
    }

    DebugLogSuccess(L"OpenServiceW");

    const bool hardened = ApplyServiceDacl(serviceHandle, policy);
    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return hardened;
}
}
