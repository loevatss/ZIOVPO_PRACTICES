// Antivirus.cpp : Defines the entry point for the application.
//

#include "pch.h"
#include "framework.h"
#include "Antivirus.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <shellapi.h>
#include <tlhelp32.h>
#include <rpc.h>

#include "AntivirusRpcControl.h"
#include "ServiceCommon.h"

#pragma comment(lib, "Iphlpapi.lib")

#define MAX_LOADSTRING 100

constexpr UINT WMAPP_TRAYICON = WM_APP + 1;
constexpr UINT TRAY_ICON_UID = 1;
constexpr DWORD SERVICE_START_TIMEOUT_MS = 30000;
constexpr DWORD SERVICE_STATUS_POLL_INTERVAL_MS = 250;
constexpr UINT_PTR LICENSE_POLL_TIMER_ID = 100;
constexpr UINT LICENSE_POLL_INTERVAL_MS = 5000;
constexpr int IDC_LABEL_AUTH = 2001;
constexpr int IDC_LABEL_LICENSE = 2002;
constexpr int IDC_EDIT_USERNAME = 2003;
constexpr int IDC_EDIT_PASSWORD = 2004;
constexpr int IDC_BUTTON_LOGIN = 2005;
constexpr int IDC_LABEL_AUTH_ERROR = 2006;
constexpr int IDC_EDIT_ACTIVATION = 2007;
constexpr int IDC_EDIT_PRODUCT_ID = 2008;
constexpr int IDC_BUTTON_ACTIVATE = 2009;
constexpr int IDC_LABEL_LICENSE_ERROR = 2010;
constexpr int IDC_BUTTON_LOGOUT = 2011;
constexpr int IDC_BUTTON_AV_ACTION = 2012;
constexpr int IDC_LABEL_AV_STATUS = 2013;
constexpr int IDC_LABEL_HEADER = 2014;

HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];
UINT g_taskbarCreatedMessage = 0;
HANDLE g_singleInstanceMutex = nullptr;
bool g_isExitRequested = false;
bool g_startHidden = false;
handle_t AntivirusRpcControlBinding = nullptr;
HWND g_hLabelAuth = nullptr;
HWND g_hLabelLicense = nullptr;
HWND g_hLabelHeader = nullptr;
HWND g_hLabelUsernameCaption = nullptr;
HWND g_hLabelPasswordCaption = nullptr;
HWND g_hEditUsername = nullptr;
HWND g_hEditPassword = nullptr;
HWND g_hButtonLogin = nullptr;
HWND g_hLabelAuthError = nullptr;
HWND g_hLabelActivationCaption = nullptr;
HWND g_hLabelProductIdCaption = nullptr;
HWND g_hEditActivation = nullptr;
HWND g_hEditProductId = nullptr;
HWND g_hButtonActivate = nullptr;
HWND g_hLabelLicenseError = nullptr;
HWND g_hButtonLogout = nullptr;
HWND g_hButtonAvAction = nullptr;
HWND g_hLabelAvStatus = nullptr;
bool g_isAuthenticated = false;
bool g_hasLicense = false;
bool g_antivirusUnlocked = false;
RpcResultCode g_lastLicenseCode = RPC_RESULT_NO_LICENSE;
std::wstring g_currentUsername;
std::wstring g_currentLicenseExpirationDate;
std::wstring g_currentLicenseError;
std::wstring g_defaultDeviceName;
std::wstring g_defaultDeviceMac;
HBRUSH g_hBackgroundBrush = nullptr;
HFONT g_hFontHeader = nullptr;
HFONT g_hFontText = nullptr;
HFONT g_hFontButton = nullptr;
bool g_licenseRefreshInProgress = false;

enum class ServiceRuntimeState
{
    Running,
    NotRunning,
    Unknown
};

ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK About(HWND, UINT, WPARAM, LPARAM);
bool AddTrayIcon(HWND hWnd);
void RemoveTrayIcon(HWND hWnd);
LRESULT HandleTrayIconMessage(HWND hWnd, LPARAM lParam);
void ShowMainWindow(HWND hWnd);
void HideMainWindowToTray(HWND hWnd);
void ShowTrayMenu(HWND hWnd);
bool ShouldStartHidden(LPCWSTR commandLine);
bool EnsureSingleInstance();
void ReleaseSingleInstance();
ServiceRuntimeState GetServiceRuntimeState();
bool StartServiceAndWaitUntilRunning();
bool IsParentProcessService();
DWORD GetParentProcessId(DWORD processId);
bool TryGetProcessBaseName(DWORD processId, std::wstring& baseName);
bool QueryServiceStatusProcess(SC_HANDLE serviceHandle, SERVICE_STATUS_PROCESS& status);
bool IsServiceLaunchArgumentPresent(LPCWSTR commandLine);
bool ShouldContinueGuiStartup(LPCWSTR commandLine);
bool RequestServiceStopViaRpc();
bool EnsureRpcBinding();
void ReleaseRpcBinding();
bool QueryCurrentAuthInfo(RpcAuthInfo& authInfo);
bool QueryActiveLicenseInfo(LONGLONG productId, const std::wstring& deviceMac, RpcLicenseInfo& licenseInfo);
bool LoginViaRpc(const std::wstring& username, const std::wstring& password, RpcAuthInfo& authInfo);
bool LogoutViaRpc(RpcAuthInfo& authInfo, RpcLicenseInfo& licenseInfo);
bool ActivateProductViaRpc(
    const std::wstring& activationKey,
    const std::wstring& deviceName,
    const std::wstring& deviceMac,
    LONGLONG productId,
    RpcLicenseInfo& licenseInfo);
void CreateSecurityControls(HWND hWnd);
void UpdateSecurityUi(HWND hWnd);
void RefreshAuthState(HWND hWnd);
void RefreshLicenseState(HWND hWnd);
void HandleLoginAction(HWND hWnd);
void HandleActivationAction(HWND hWnd);
void HandleLogoutAction(HWND hWnd);
void HandleAntivirusAction(HWND hWnd);
std::wstring GetControlText(HWND hWnd);
std::wstring TrimCopy(const std::wstring& text);
std::wstring GetDefaultDeviceName();
std::wstring GetDefaultDeviceMac();
std::wstring BuildFallbackDeviceMac();
std::wstring FormatMacAddress(const BYTE* bytes, ULONG length);
LONGLONG ParseProductIdOrDefault(const std::wstring& text);
HMENU MenuIdFromInt(int id);
void InitializeFriendlyUiTheme();
void DestroyFriendlyUiTheme();
void ApplyControlFont(HWND control, HFONT font);
void SetAuthErrorText(const std::wstring& text);
void SetLicenseErrorText(const std::wstring& text);
void ApplyAuthInfo(const RpcAuthInfo& authInfo);
void ApplyLicenseInfo(const RpcLicenseInfo& licenseInfo);
std::wstring RpcCodeToText(RpcResultCode code);

namespace
{
std::wstring GetModuleDirectoryPathInternal()
{
    WCHAR modulePath[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
    {
        return {};
    }

    const WCHAR* separator = wcsrchr(modulePath, L'\\');
    if (separator == nullptr)
    {
        return {};
    }

    return std::wstring(modulePath, static_cast<size_t>(separator - modulePath));
}

std::wstring ResolveSiblingServiceExecutablePathInternal()
{
    const std::wstring directoryPath = GetModuleDirectoryPathInternal();
    if (directoryPath.empty())
    {
        return {};
    }

    return directoryPath + L"\\" + antivirus::common::kServiceBinaryName;
}

bool FileExistsInternal(const std::wstring& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES
        && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring QuotePathForScmInternal(const std::wstring& path)
{
    return L"\"" + path + L"\"";
}

std::wstring NormalizeServiceBinaryPathInternal(std::wstring path)
{
    while (!path.empty() && iswspace(path.front()))
    {
        path.erase(path.begin());
    }

    while (!path.empty() && iswspace(path.back()))
    {
        path.pop_back();
    }

    if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
    {
        path = path.substr(1, path.size() - 2);
    }

    std::replace(path.begin(), path.end(), L'/', L'\\');
    return path;
}

bool ArePathsEqualInsensitiveInternal(const std::wstring& left, const std::wstring& right)
{
    const std::wstring normalizedLeft = NormalizeServiceBinaryPathInternal(left);
    const std::wstring normalizedRight = NormalizeServiceBinaryPathInternal(right);
    if (normalizedLeft.empty() || normalizedRight.empty())
    {
        return false;
    }

    return _wcsicmp(normalizedLeft.c_str(), normalizedRight.c_str()) == 0;
}

bool QueryServiceBinaryPathInternal(SC_HANDLE serviceHandle, std::wstring& binaryPath)
{
    DWORD bytesNeeded = 0;
    QueryServiceConfigW(serviceHandle, nullptr, 0, &bytesNeeded);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytesNeeded == 0)
    {
        return false;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    auto* queryConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (!QueryServiceConfigW(serviceHandle, queryConfig, bytesNeeded, &bytesNeeded))
    {
        return false;
    }

    binaryPath = queryConfig->lpBinaryPathName != nullptr
        ? queryConfig->lpBinaryPathName
        : L"";
    return true;
}

bool EnsureServiceInstalledAndConfiguredInternal(SC_HANDLE scmHandle, SC_HANDLE& serviceHandle)
{
    const std::wstring serviceExecutablePath = ResolveSiblingServiceExecutablePathInternal();
    if (serviceExecutablePath.empty() || !FileExistsInternal(serviceExecutablePath))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return false;
    }

    const std::wstring quotedServicePath = QuotePathForScmInternal(serviceExecutablePath);
    constexpr DWORD desiredAccess =
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG;

    serviceHandle = OpenServiceW(scmHandle, antivirus::common::kServiceName, desiredAccess);
    if (serviceHandle == nullptr)
    {
        const DWORD openError = GetLastError();
        if (openError != ERROR_SERVICE_DOES_NOT_EXIST)
        {
            SetLastError(openError);
            return false;
        }

        serviceHandle = CreateServiceW(
            scmHandle,
            antivirus::common::kServiceName,
            antivirus::common::kServiceName,
            desiredAccess,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            quotedServicePath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);
        return serviceHandle != nullptr;
    }

    std::wstring configuredBinaryPath;
    if (!QueryServiceBinaryPathInternal(serviceHandle, configuredBinaryPath))
    {
        return false;
    }

    if (!ArePathsEqualInsensitiveInternal(configuredBinaryPath, serviceExecutablePath))
    {
        if (!ChangeServiceConfigW(
            serviceHandle,
            SERVICE_NO_CHANGE,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            quotedServicePath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr))
        {
            return false;
        }
    }

    return true;
}
} // namespace

// Gets current service runtime state.
ServiceRuntimeState GetServiceRuntimeState()
{
    SC_HANDLE scmHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scmHandle == nullptr)
    {
        return ServiceRuntimeState::Unknown;
    }

    SC_HANDLE serviceHandle =
        OpenServiceW(scmHandle, antivirus::common::kServiceName, SERVICE_QUERY_STATUS);
    if (serviceHandle == nullptr)
    {
        CloseServiceHandle(scmHandle);
        return ServiceRuntimeState::Unknown;
    }

    SERVICE_STATUS_PROCESS serviceStatus{};
    const bool isStatusQueried = QueryServiceStatusProcess(serviceHandle, serviceStatus);

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    if (!isStatusQueried)
    {
        return ServiceRuntimeState::Unknown;
    }

    return serviceStatus.dwCurrentState == SERVICE_RUNNING
        ? ServiceRuntimeState::Running
        : ServiceRuntimeState::NotRunning;
}

// Starts service and waits until RUNNING state.
bool StartServiceAndWaitUntilRunning()
{
    SC_HANDLE scmHandle = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (scmHandle == nullptr)
    {
        return false;
    }

    SC_HANDLE serviceHandle = nullptr;
    if (!EnsureServiceInstalledAndConfiguredInternal(scmHandle, serviceHandle))
    {
        CloseServiceHandle(scmHandle);
        return false;
    }

    SERVICE_STATUS_PROCESS serviceStatus{};
    if (!QueryServiceStatusProcess(serviceHandle, serviceStatus))
    {
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
        return false;
    }

    if (serviceStatus.dwCurrentState != SERVICE_RUNNING
        && serviceStatus.dwCurrentState != SERVICE_START_PENDING)
    {
        if (!StartServiceW(serviceHandle, 0, nullptr)
            && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        {
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }
    }

    const ULONGLONG deadline = GetTickCount64() + SERVICE_START_TIMEOUT_MS;
    while (GetTickCount64() < deadline)
    {
        if (!QueryServiceStatusProcess(serviceHandle, serviceStatus))
        {
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }

        if (serviceStatus.dwCurrentState == SERVICE_RUNNING)
        {
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return true;
        }

        if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
        {
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }

        Sleep(SERVICE_STATUS_POLL_INTERVAL_MS);
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return false;
}

// Checks whether parent process is the service process.
bool IsParentProcessService()
{
    const DWORD parentProcessId = GetParentProcessId(GetCurrentProcessId());
    if (parentProcessId == 0)
    {
        return false;
    }

    std::wstring parentProcessName;
    if (!TryGetProcessBaseName(parentProcessId, parentProcessName))
    {
        return false;
    }

    return _wcsicmp(parentProcessName.c_str(), antivirus::common::kServiceBinaryName) == 0;
}

// Gets parent process id for a process.
DWORD GetParentProcessId(DWORD processId)
{
    DWORD parentProcessId = 0;
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshotHandle == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32W processEntry{};
    processEntry.dwSize = sizeof(processEntry);
    if (Process32FirstW(snapshotHandle, &processEntry))
    {
        do
        {
            if (processEntry.th32ProcessID == processId)
            {
                parentProcessId = processEntry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshotHandle, &processEntry));
    }

    CloseHandle(snapshotHandle);
    return parentProcessId;
}

// Resolves base executable name by process id.
bool TryGetProcessBaseName(DWORD processId, std::wstring& baseName)
{
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (processHandle == nullptr)
    {
        return false;
    }

    WCHAR processPath[MAX_PATH]{};
    DWORD processPathLength = MAX_PATH;
    const bool isQueried =
        QueryFullProcessImageNameW(processHandle, 0, processPath, &processPathLength) != FALSE;

    CloseHandle(processHandle);
    if (!isQueried)
    {
        return false;
    }

    const WCHAR* fileNameStart = wcsrchr(processPath, L'\\');
    baseName = (fileNameStart != nullptr) ? (fileNameStart + 1) : processPath;
    return true;
}

// Queries extended service status.
bool QueryServiceStatusProcess(SC_HANDLE serviceHandle, SERVICE_STATUS_PROCESS& status)
{
    DWORD bytesNeeded = 0;
    return QueryServiceStatusEx(
        serviceHandle,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytesNeeded) != FALSE;
}

// Checks if service launch argument exists.
bool IsServiceLaunchArgumentPresent(LPCWSTR commandLine)
{
    if (commandLine == nullptr)
    {
        return false;
    }

    return wcsstr(commandLine, L"--service-launch") != nullptr;
}

// Controls standalone GUI startup policy.
bool ShouldContinueGuiStartup(LPCWSTR commandLine)
{
    const ServiceRuntimeState runtimeState = GetServiceRuntimeState();

    if (runtimeState != ServiceRuntimeState::Running)
    {
        StartServiceAndWaitUntilRunning();
        return false;
    }

    if (IsParentProcessService())
    {
        return true;
    }

    return IsServiceLaunchArgumentPresent(commandLine);
}

// Requests service stop through RPC.
bool RequestServiceStopViaRpc()
{
    if (!EnsureRpcBinding())
    {
        return false;
    }

    bool rpcCallSucceeded = true;
    RpcTryExcept
    {
        StopService();
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        rpcCallSucceeded = false;
    }
    RpcEndExcept;

    ReleaseRpcBinding();
    return rpcCallSucceeded;
}

// Creates RPC binding to service endpoint.
bool EnsureRpcBinding()
{
    if (AntivirusRpcControlBinding != nullptr)
    {
        return true;
    }

    RPC_WSTR stringBinding = nullptr;
    const RPC_STATUS composeStatus = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(antivirus::common::kRpcProtseq)),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(antivirus::common::kRpcEndpoint)),
        nullptr,
        &stringBinding);
    if (composeStatus != RPC_S_OK)
    {
        return false;
    }

    const RPC_STATUS bindingStatus = RpcBindingFromStringBindingW(stringBinding, &AntivirusRpcControlBinding);
    RpcStringFreeW(&stringBinding);
    if (bindingStatus != RPC_S_OK)
    {
        AntivirusRpcControlBinding = nullptr;
        return false;
    }

    return true;
}

// Releases active RPC binding.
void ReleaseRpcBinding()
{
    if (AntivirusRpcControlBinding != nullptr)
    {
        RpcBindingFree(&AntivirusRpcControlBinding);
        AntivirusRpcControlBinding = nullptr;
    }
}

// Gets safe auth info from service.
bool QueryCurrentAuthInfo(RpcAuthInfo& authInfo)
{
    std::memset(&authInfo, 0, sizeof(authInfo));
    if (!EnsureRpcBinding())
    {
        return false;
    }

    bool rpcCallSucceeded = true;
    RpcTryExcept
    {
        const RpcResultCode result = GetCurrentAuthInfo(&authInfo);
        rpcCallSucceeded = (result == RPC_RESULT_OK);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        rpcCallSucceeded = false;
    }
    RpcEndExcept;

    ReleaseRpcBinding();
    return rpcCallSucceeded;
}

// Gets safe active license info from service.
bool QueryActiveLicenseInfo(LONGLONG productId, const std::wstring& deviceMac, RpcLicenseInfo& licenseInfo)
{
    std::memset(&licenseInfo, 0, sizeof(licenseInfo));
    if (!EnsureRpcBinding())
    {
        return false;
    }

    bool rpcCallSucceeded = true;
    RpcTryExcept
    {
        const RpcResultCode result = GetActiveLicenseInfo(productId, deviceMac.c_str(), &licenseInfo);
        rpcCallSucceeded = (result == RPC_RESULT_OK
            || result == RPC_RESULT_NO_LICENSE
            || result == RPC_RESULT_LICENSE_EXPIRED
            || result == RPC_RESULT_LICENSE_BLOCKED);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        rpcCallSucceeded = false;
    }
    RpcEndExcept;

    ReleaseRpcBinding();
    return rpcCallSucceeded;
}

// Calls RPC login and reads safe auth result.
bool LoginViaRpc(const std::wstring& username, const std::wstring& password, RpcAuthInfo& authInfo)
{
    std::memset(&authInfo, 0, sizeof(authInfo));
    if (!EnsureRpcBinding())
    {
        return false;
    }

    bool rpcCallSucceeded = true;
    RpcTryExcept
    {
        const RpcResultCode result = LoginUser(username.c_str(), password.c_str(), &authInfo);
        rpcCallSucceeded = (result == RPC_RESULT_OK);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        rpcCallSucceeded = false;
    }
    RpcEndExcept;

    ReleaseRpcBinding();
    return rpcCallSucceeded;
}

// Calls RPC logout and reads safe auth/license result.
bool LogoutViaRpc(RpcAuthInfo& authInfo, RpcLicenseInfo& licenseInfo)
{
    std::memset(&authInfo, 0, sizeof(authInfo));
    std::memset(&licenseInfo, 0, sizeof(licenseInfo));
    if (!EnsureRpcBinding())
    {
        return false;
    }

    bool rpcCallSucceeded = true;
    RpcTryExcept
    {
        const RpcResultCode result = LogoutUser(&authInfo, &licenseInfo);
        rpcCallSucceeded = (result == RPC_RESULT_OK);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        rpcCallSucceeded = false;
    }
    RpcEndExcept;

    ReleaseRpcBinding();
    return rpcCallSucceeded;
}

// Calls RPC activation and returns safe license result.
bool ActivateProductViaRpc(
    const std::wstring& activationKey,
    const std::wstring& deviceName,
    const std::wstring& deviceMac,
    LONGLONG productId,
    RpcLicenseInfo& licenseInfo)
{
    std::memset(&licenseInfo, 0, sizeof(licenseInfo));
    if (!EnsureRpcBinding())
    {
        return false;
    }

    bool rpcCallSucceeded = true;
    RpcTryExcept
    {
        const RpcResultCode result = ActivateProduct(
            activationKey.c_str(),
            deviceName.c_str(),
            deviceMac.c_str(),
            productId,
            &licenseInfo);
        rpcCallSucceeded = (result == RPC_RESULT_OK
            || result == RPC_RESULT_NO_LICENSE
            || result == RPC_RESULT_LICENSE_EXPIRED
            || result == RPC_RESULT_LICENSE_BLOCKED);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        rpcCallSucceeded = false;
    }
    RpcEndExcept;

    ReleaseRpcBinding();
    return rpcCallSucceeded;
}

// Reads text from a control.
std::wstring GetControlText(HWND hWnd)
{
    if (hWnd == nullptr)
    {
        return {};
    }

    const int length = GetWindowTextLengthW(hWnd);
    if (length <= 0)
    {
        return {};
    }

    std::wstring text(static_cast<size_t>(length + 1), L'\0');
    GetWindowTextW(hWnd, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
    return text;
}

// Returns a trimmed copy of text.
std::wstring TrimCopy(const std::wstring& text)
{
    size_t begin = 0;
    while (begin < text.size() && iswspace(text[begin]))
    {
        ++begin;
    }

    size_t end = text.size();
    while (end > begin && iswspace(text[end - 1]))
    {
        --end;
    }

    return text.substr(begin, end - begin);
}

// Gets host name to use as default device name.
std::wstring GetDefaultDeviceName()
{
    WCHAR buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD bufferSize = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(buffer, &bufferSize) || bufferSize == 0)
    {
        return L"Windows-PC";
    }

    return buffer;
}

// Builds deterministic fallback MAC when no hardware address is available.
std::wstring BuildFallbackDeviceMac()
{
    const std::wstring deviceName = GetDefaultDeviceName();
    uint32_t hash = 2166136261u;
    for (wchar_t ch : deviceName)
    {
        hash ^= static_cast<uint32_t>(towupper(ch));
        hash *= 16777619u;
    }

    const unsigned int b3 = static_cast<unsigned int>((hash >> 0) & 0xFFu);
    const unsigned int b4 = static_cast<unsigned int>((hash >> 8) & 0xFFu);
    const unsigned int b5 = static_cast<unsigned int>((hash >> 16) & 0xFFu);

    WCHAR macBuffer[18]{};
    swprintf_s(macBuffer, _countof(macBuffer), L"AA:BB:CC:%02X:%02X:%02X", b3, b4, b5);
    return macBuffer;
}

// Formats six MAC bytes into XX:XX:XX:XX:XX:XX text.
std::wstring FormatMacAddress(const BYTE* bytes, ULONG length)
{
    if (bytes == nullptr || length < 6)
    {
        return {};
    }

    WCHAR macBuffer[18]{};
    swprintf_s(
        macBuffer,
        _countof(macBuffer),
        L"%02X:%02X:%02X:%02X:%02X:%02X",
        static_cast<unsigned int>(bytes[0]),
        static_cast<unsigned int>(bytes[1]),
        static_cast<unsigned int>(bytes[2]),
        static_cast<unsigned int>(bytes[3]),
        static_cast<unsigned int>(bytes[4]),
        static_cast<unsigned int>(bytes[5]));
    return macBuffer;
}

// Gets real adapter MAC for license requests.
std::wstring GetDefaultDeviceMac()
{
    ULONG bufferSize = 0;
    constexpr ULONG flags =
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER;

    DWORD status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &bufferSize);
    if (status != ERROR_BUFFER_OVERFLOW || bufferSize == 0)
    {
        return BuildFallbackDeviceMac();
    }

    std::vector<BYTE> rawBuffer(bufferSize);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(rawBuffer.data());
    status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &bufferSize);
    if (status != NO_ERROR)
    {
        return BuildFallbackDeviceMac();
    }

    const IP_ADAPTER_ADDRESSES* firstCandidate = nullptr;
    const IP_ADAPTER_ADDRESSES* upCandidate = nullptr;
    for (const IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr; adapter = adapter->Next)
    {
        if (adapter->PhysicalAddressLength < 6)
        {
            continue;
        }

        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL)
        {
            continue;
        }

        if (firstCandidate == nullptr)
        {
            firstCandidate = adapter;
        }

        if (adapter->OperStatus == IfOperStatusUp)
        {
            upCandidate = adapter;
            break;
        }
    }

    const IP_ADAPTER_ADDRESSES* selected = upCandidate != nullptr ? upCandidate : firstCandidate;
    if (selected == nullptr)
    {
        return BuildFallbackDeviceMac();
    }

    const std::wstring mac = FormatMacAddress(selected->PhysicalAddress, selected->PhysicalAddressLength);
    return mac.empty() ? BuildFallbackDeviceMac() : mac;
}

// Parses product id from UI, returns default when invalid.
LONGLONG ParseProductIdOrDefault(const std::wstring& text)
{
    const std::wstring trimmed = TrimCopy(text);
    if (trimmed.empty())
    {
        return 1;
    }

    const LONGLONG value = _wtoll(trimmed.c_str());
    return value > 0 ? value : 1;
}

// Converts integer control ID into child HMENU handle.
HMENU MenuIdFromInt(int id)
{
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

// Initializes brushes and fonts for friendly UI.
void InitializeFriendlyUiTheme()
{
    if (g_hBackgroundBrush == nullptr)
    {
        g_hBackgroundBrush = CreateSolidBrush(RGB(244, 248, 252));
    }

    if (g_hFontHeader == nullptr)
    {
        g_hFontHeader = CreateFontW(
            -24, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }

    if (g_hFontText == nullptr)
    {
        g_hFontText = CreateFontW(
            -16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }

    if (g_hFontButton == nullptr)
    {
        g_hFontButton = CreateFontW(
            -16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }
}

// Releases brushes and fonts allocated for UI.
void DestroyFriendlyUiTheme()
{
    if (g_hBackgroundBrush != nullptr)
    {
        DeleteObject(g_hBackgroundBrush);
        g_hBackgroundBrush = nullptr;
    }

    if (g_hFontHeader != nullptr)
    {
        DeleteObject(g_hFontHeader);
        g_hFontHeader = nullptr;
    }

    if (g_hFontText != nullptr)
    {
        DeleteObject(g_hFontText);
        g_hFontText = nullptr;
    }

    if (g_hFontButton != nullptr)
    {
        DeleteObject(g_hFontButton);
        g_hFontButton = nullptr;
    }
}

// Applies a font to a control.
void ApplyControlFont(HWND control, HFONT font)
{
    if (control != nullptr && font != nullptr)
    {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
}

// Sets auth error text label.
void SetAuthErrorText(const std::wstring& text)
{
    if (g_hLabelAuthError != nullptr)
    {
        SetWindowTextW(g_hLabelAuthError, text.c_str());
    }
}

// Sets license error text label.
void SetLicenseErrorText(const std::wstring& text)
{
    if (g_hLabelLicenseError != nullptr)
    {
        SetWindowTextW(g_hLabelLicenseError, text.c_str());
    }
}

// Applies auth info into local GUI state.
void ApplyAuthInfo(const RpcAuthInfo& authInfo)
{
    g_isAuthenticated = authInfo.authenticated != 0;
    g_currentUsername = g_isAuthenticated ? authInfo.username : L"";
    if (!g_isAuthenticated)
    {
        g_hasLicense = false;
        g_antivirusUnlocked = false;
        g_currentLicenseExpirationDate.clear();
        g_currentLicenseError.clear();
        g_lastLicenseCode = RPC_RESULT_NO_LICENSE;
    }
}

// Applies license info into local GUI state.
void ApplyLicenseInfo(const RpcLicenseInfo& licenseInfo)
{
    g_hasLicense = licenseInfo.hasLicense != 0;
    g_currentLicenseExpirationDate = g_hasLicense ? licenseInfo.expirationDate : L"";
    g_currentLicenseError = licenseInfo.error;
    g_lastLicenseCode = static_cast<RpcResultCode>(licenseInfo.errorCode);
    g_antivirusUnlocked =
        g_isAuthenticated &&
        g_hasLicense &&
        g_lastLicenseCode == RPC_RESULT_OK &&
        licenseInfo.blocked == 0;
}

// Converts RPC code into readable safe text.
std::wstring RpcCodeToText(RpcResultCode code)
{
    switch (code)
    {
    case RPC_RESULT_OK:
        return L"OK";
    case RPC_RESULT_INVALID_ARGUMENT:
        return L"INVALID_ARGUMENT";
    case RPC_RESULT_AUTH_FAILED:
        return L"AUTH_FAILED";
    case RPC_RESULT_NOT_AUTHENTICATED:
        return L"NOT_AUTHENTICATED";
    case RPC_RESULT_NETWORK_ERROR:
        return L"NETWORK_ERROR";
    case RPC_RESULT_NO_LICENSE:
        return L"NO_LICENSE";
    case RPC_RESULT_LICENSE_EXPIRED:
        return L"LICENSE_EXPIRED";
    case RPC_RESULT_LICENSE_BLOCKED:
        return L"LICENSE_BLOCKED";
    default:
        return L"INTERNAL_ERROR";
    }
}

// Creates all runtime controls for auth/license UX.
void CreateSecurityControls(HWND hWnd)
{
    InitializeFriendlyUiTheme();

    g_hLabelHeader = CreateWindowExW(0, L"STATIC", L"Antivirus Security Center",
        WS_CHILD | WS_VISIBLE, 24, 16, 700, 34, hWnd, MenuIdFromInt(IDC_LABEL_HEADER), hInst, nullptr);
    g_hLabelAuth = CreateWindowExW(0, L"STATIC", L"User: -",
        WS_CHILD | WS_VISIBLE, 24, 62, 700, 24, hWnd, MenuIdFromInt(IDC_LABEL_AUTH), hInst, nullptr);
    g_hLabelLicense = CreateWindowExW(0, L"STATIC", L"License: -",
        WS_CHILD | WS_VISIBLE, 24, 90, 700, 24, hWnd, MenuIdFromInt(IDC_LABEL_LICENSE), hInst, nullptr);
    g_hLabelAvStatus = CreateWindowExW(0, L"STATIC", L"Antivirus: blocked",
        WS_CHILD | WS_VISIBLE, 24, 118, 700, 24, hWnd, MenuIdFromInt(IDC_LABEL_AV_STATUS), hInst, nullptr);

    g_hLabelUsernameCaption = CreateWindowExW(0, L"STATIC", L"Username",
        WS_CHILD | WS_VISIBLE, 36, 164, 120, 20, hWnd, nullptr, hInst, nullptr);
    g_hEditUsername = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 36, 186, 250, 28, hWnd,
        MenuIdFromInt(IDC_EDIT_USERNAME), hInst, nullptr);
    g_hLabelPasswordCaption = CreateWindowExW(0, L"STATIC", L"Password",
        WS_CHILD | WS_VISIBLE, 36, 224, 120, 20, hWnd, nullptr, hInst, nullptr);
    g_hEditPassword = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_PASSWORD, 36, 246, 250, 28, hWnd,
        MenuIdFromInt(IDC_EDIT_PASSWORD), hInst, nullptr);
    g_hButtonLogin = CreateWindowExW(0, L"BUTTON", L"Sign in",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 304, 186, 140, 88, hWnd,
        MenuIdFromInt(IDC_BUTTON_LOGIN), hInst, nullptr);
    g_hLabelAuthError = CreateWindowExW(0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE, 36, 282, 408, 36, hWnd,
        MenuIdFromInt(IDC_LABEL_AUTH_ERROR), hInst, nullptr);

    g_hLabelActivationCaption = CreateWindowExW(0, L"STATIC", L"Activation code",
        WS_CHILD | WS_VISIBLE, 468, 164, 220, 20, hWnd, nullptr, hInst, nullptr);
    g_hEditActivation = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 468, 186, 248, 28, hWnd,
        MenuIdFromInt(IDC_EDIT_ACTIVATION), hInst, nullptr);
    g_hLabelProductIdCaption = CreateWindowExW(0, L"STATIC", L"Product ID",
        WS_CHILD | WS_VISIBLE, 468, 224, 220, 20, hWnd, nullptr, hInst, nullptr);
    g_hEditProductId = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"1",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 468, 246, 128, 28, hWnd,
        MenuIdFromInt(IDC_EDIT_PRODUCT_ID), hInst, nullptr);
    g_hButtonActivate = CreateWindowExW(0, L"BUTTON", L"Activate",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 604, 246, 112, 28, hWnd,
        MenuIdFromInt(IDC_BUTTON_ACTIVATE), hInst, nullptr);
    g_hLabelLicenseError = CreateWindowExW(0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE, 468, 282, 248, 36, hWnd,
        MenuIdFromInt(IDC_LABEL_LICENSE_ERROR), hInst, nullptr);

    g_hButtonLogout = CreateWindowExW(0, L"BUTTON", L"Logout",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 468, 332, 120, 32, hWnd,
        MenuIdFromInt(IDC_BUTTON_LOGOUT), hInst, nullptr);
    g_hButtonAvAction = CreateWindowExW(0, L"BUTTON", L"Start scan",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 596, 332, 120, 32, hWnd,
        MenuIdFromInt(IDC_BUTTON_AV_ACTION), hInst, nullptr);

    ApplyControlFont(g_hLabelHeader, g_hFontHeader);
    ApplyControlFont(g_hLabelAuth, g_hFontText);
    ApplyControlFont(g_hLabelLicense, g_hFontText);
    ApplyControlFont(g_hLabelAvStatus, g_hFontText);
    ApplyControlFont(g_hLabelUsernameCaption, g_hFontText);
    ApplyControlFont(g_hLabelPasswordCaption, g_hFontText);
    ApplyControlFont(g_hEditUsername, g_hFontText);
    ApplyControlFont(g_hEditPassword, g_hFontText);
    ApplyControlFont(g_hButtonLogin, g_hFontButton);
    ApplyControlFont(g_hLabelAuthError, g_hFontText);
    ApplyControlFont(g_hLabelActivationCaption, g_hFontText);
    ApplyControlFont(g_hLabelProductIdCaption, g_hFontText);
    ApplyControlFont(g_hEditActivation, g_hFontText);
    ApplyControlFont(g_hEditProductId, g_hFontText);
    ApplyControlFont(g_hButtonActivate, g_hFontButton);
    ApplyControlFont(g_hLabelLicenseError, g_hFontText);
    ApplyControlFont(g_hButtonLogout, g_hFontButton);
    ApplyControlFont(g_hButtonAvAction, g_hFontButton);
}

// Updates UI from current auth/license state.
void UpdateSecurityUi(HWND hWnd)
{
    UNREFERENCED_PARAMETER(hWnd);

    std::wstring authText = L"User: ";
    authText += g_isAuthenticated ? g_currentUsername : L"not authenticated";
    SetWindowTextW(g_hLabelAuth, authText.c_str());

    std::wstring licenseText = L"License: ";
    if (!g_isAuthenticated)
    {
        licenseText += L"sign in required";
    }
    else if (g_antivirusUnlocked)
    {
        licenseText += L"active until ";
        licenseText += g_currentLicenseExpirationDate.empty() ? L"-" : g_currentLicenseExpirationDate;
    }
    else
    {
        licenseText += RpcCodeToText(g_lastLicenseCode);
    }
    SetWindowTextW(g_hLabelLicense, licenseText.c_str());

    const std::wstring avText = g_antivirusUnlocked
        ? L"Antivirus: functionality unlocked"
        : L"Antivirus: functionality blocked";
    SetWindowTextW(g_hLabelAvStatus, avText.c_str());

    const BOOL showAuthForm = g_isAuthenticated ? FALSE : TRUE;
    ShowWindow(g_hLabelUsernameCaption, showAuthForm);
    ShowWindow(g_hLabelPasswordCaption, showAuthForm);
    ShowWindow(g_hEditUsername, showAuthForm);
    ShowWindow(g_hEditPassword, showAuthForm);
    ShowWindow(g_hButtonLogin, showAuthForm);
    ShowWindow(g_hLabelAuthError, showAuthForm);

    const BOOL showLicenseForm = (g_isAuthenticated && !g_antivirusUnlocked) ? TRUE : FALSE;
    ShowWindow(g_hLabelActivationCaption, showLicenseForm);
    ShowWindow(g_hLabelProductIdCaption, showLicenseForm);
    ShowWindow(g_hEditActivation, showLicenseForm);
    ShowWindow(g_hEditProductId, showLicenseForm);
    ShowWindow(g_hButtonActivate, showLicenseForm);
    ShowWindow(g_hLabelLicenseError, showLicenseForm);

    ShowWindow(g_hButtonLogout, g_isAuthenticated ? TRUE : FALSE);
    const BOOL enableAntivirusButton = (g_isAuthenticated && g_antivirusUnlocked) ? TRUE : FALSE;
    EnableWindow(g_hButtonAvAction, enableAntivirusButton);
    RedrawWindow(g_hButtonAvAction, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE);
}

// Pulls auth state from service and refreshes view.
void RefreshAuthState(HWND hWnd)
{
    RpcAuthInfo authInfo{};
    if (!QueryCurrentAuthInfo(authInfo))
    {
        g_isAuthenticated = false;
        g_currentUsername.clear();
        g_hasLicense = false;
        g_antivirusUnlocked = false;
        g_lastLicenseCode = RPC_RESULT_NOT_AUTHENTICATED;
        SetAuthErrorText(L"RPC error while reading authentication state.");
        UpdateSecurityUi(hWnd);
        return;
    }

    ApplyAuthInfo(authInfo);
    SetAuthErrorText(L"");
    if (g_isAuthenticated)
    {
        RefreshLicenseState(hWnd);
    }
    else
    {
        g_hasLicense = false;
        g_antivirusUnlocked = false;
        g_lastLicenseCode = RPC_RESULT_NO_LICENSE;
        SetLicenseErrorText(L"");
        UpdateSecurityUi(hWnd);
    }
}

// Pulls license state from service and refreshes view.
void RefreshLicenseState(HWND hWnd)
{
    if (g_licenseRefreshInProgress)
    {
        return;
    }

    g_licenseRefreshInProgress = true;
    auto finishRefresh = []() { g_licenseRefreshInProgress = false; };

    if (!g_isAuthenticated)
    {
        g_hasLicense = false;
        g_antivirusUnlocked = false;
        g_lastLicenseCode = RPC_RESULT_NOT_AUTHENTICATED;
        UpdateSecurityUi(hWnd);
        finishRefresh();
        return;
    }

    g_antivirusUnlocked = false;
    UpdateSecurityUi(hWnd);

    const LONGLONG productId = ParseProductIdOrDefault(GetControlText(g_hEditProductId));
    RpcLicenseInfo licenseInfo{};
    if (!QueryActiveLicenseInfo(productId, g_defaultDeviceMac, licenseInfo))
    {
        g_hasLicense = false;
        g_antivirusUnlocked = false;
        g_lastLicenseCode = RPC_RESULT_NETWORK_ERROR;
        SetLicenseErrorText(L"RPC error while requesting license state.");
        UpdateSecurityUi(hWnd);
        finishRefresh();
        return;
    }

    ApplyLicenseInfo(licenseInfo);
    SetLicenseErrorText(g_currentLicenseError);
    UpdateSecurityUi(hWnd);
    finishRefresh();
}

// Handles login action in UI.
void HandleLoginAction(HWND hWnd)
{
    const std::wstring username = TrimCopy(GetControlText(g_hEditUsername));
    const std::wstring password = GetControlText(g_hEditPassword);
    if (username.empty() || password.empty())
    {
        SetAuthErrorText(L"Enter username and password.");
        g_antivirusUnlocked = false;
        UpdateSecurityUi(hWnd);
        return;
    }

    RpcAuthInfo authInfo{};
    if (!LoginViaRpc(username, password, authInfo))
    {
        g_isAuthenticated = false;
        g_antivirusUnlocked = false;
        SetAuthErrorText(L"Authentication failed.");
        UpdateSecurityUi(hWnd);
        return;
    }

    ApplyAuthInfo(authInfo);
    SetAuthErrorText(L"");
    SetWindowTextW(g_hEditPassword, L"");
    RefreshLicenseState(hWnd);
}

// Handles license activation action in UI.
void HandleActivationAction(HWND hWnd)
{
    const std::wstring activationCode = TrimCopy(GetControlText(g_hEditActivation));
    if (activationCode.empty())
    {
        SetLicenseErrorText(L"Enter activation code.");
        g_antivirusUnlocked = false;
        UpdateSecurityUi(hWnd);
        return;
    }

    const LONGLONG productId = ParseProductIdOrDefault(GetControlText(g_hEditProductId));
    RpcLicenseInfo licenseInfo{};
    if (!ActivateProductViaRpc(
        activationCode,
        g_defaultDeviceName,
        g_defaultDeviceMac,
        productId,
        licenseInfo))
    {
        g_hasLicense = false;
        g_antivirusUnlocked = false;
        g_lastLicenseCode = RPC_RESULT_INTERNAL_ERROR;
        SetLicenseErrorText(L"Activation failed.");
        UpdateSecurityUi(hWnd);
        return;
    }

    ApplyLicenseInfo(licenseInfo);
    SetLicenseErrorText(g_currentLicenseError);
    if (g_antivirusUnlocked)
    {
        SetWindowTextW(g_hEditActivation, L"");
    }
    UpdateSecurityUi(hWnd);
}

// Handles logout action in UI.
void HandleLogoutAction(HWND hWnd)
{
    RpcAuthInfo authInfo{};
    RpcLicenseInfo licenseInfo{};
    LogoutViaRpc(authInfo, licenseInfo);

    g_isAuthenticated = false;
    g_hasLicense = false;
    g_antivirusUnlocked = false;
    g_lastLicenseCode = RPC_RESULT_NOT_AUTHENTICATED;
    g_currentUsername.clear();
    g_currentLicenseExpirationDate.clear();
    g_currentLicenseError.clear();
    SetWindowTextW(g_hEditPassword, L"");
    SetWindowTextW(g_hEditActivation, L"");
    SetAuthErrorText(L"");
    SetLicenseErrorText(L"");
    UpdateSecurityUi(hWnd);
}

// Handles antivirus action and blocks when license is invalid.
void HandleAntivirusAction(HWND hWnd)
{
    RefreshLicenseState(hWnd);
    if (!g_antivirusUnlocked)
    {
        MessageBoxW(
            hWnd,
            L"Antivirus functionality is blocked. Check authentication and license state.",
            L"Antivirus",
            MB_OK | MB_ICONWARNING);
        return;
    }

    MessageBoxW(hWnd, L"Antivirus task started.", L"Antivirus", MB_OK | MB_ICONINFORMATION);
}

void RequestServiceStopAndExit(HWND hWnd)
{
    if (!RequestServiceStopViaRpc())
    {
        MessageBoxW(
            hWnd,
            L"Failed to stop the service via RPC.",
            L"Antivirus",
            MB_OK | MB_ICONERROR);
        return;
    }

    g_isExitRequested = true;
    DestroyWindow(hWnd);
}

// Starts application and message loop.
extern "C" void* __RPC_USER MIDL_user_allocate(size_t size)
{
    return std::malloc(size);
}

extern "C" void __RPC_USER MIDL_user_free(void* pointer)
{
    std::free(pointer);
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

    if (!ShouldContinueGuiStartup(lpCmdLine))
    {
        return FALSE;
    }

    if (!EnsureSingleInstance())
    {
        return FALSE;
    }

    g_startHidden = ShouldStartHidden(lpCmdLine);
    g_taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_ANTIVIRUS, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    if (!InitInstance(hInstance, nCmdShow))
    {
        ReleaseSingleInstance();
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_ANTIVIRUS));
    MSG msg;

    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return static_cast<int>(msg.wParam);
}

// Ð ÐµÐ³Ð¸ÑÑ‚Ñ€Ð¸Ñ€ÑƒÐµÑ‚ ÐºÐ»Ð°ÑÑ Ð³Ð»Ð°Ð²Ð½Ð¾Ð³Ð¾ Ð¾ÐºÐ½Ð°.
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex{};

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ANTIVIRUS));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_ANTIVIRUS);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

// Ð¡Ð¾Ð·Ð´Ð°ÐµÑ‚ Ð³Ð»Ð°Ð²Ð½Ð¾Ðµ Ð¾ÐºÐ½Ð¾ Ð¸ Ð´Ð¾Ð±Ð°Ð²Ð»ÑÐµÑ‚ Ð¸ÐºÐ¾Ð½ÐºÑƒ Ð² Ñ‚Ñ€ÐµÐ¹.
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    hInst = hInstance;

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, 760, 440, nullptr, nullptr, hInstance, nullptr);

    if (hWnd == nullptr)
    {
        return FALSE;
    }

    if (!AddTrayIcon(hWnd))
    {
        DestroyWindow(hWnd);
        return FALSE;
    }

    g_defaultDeviceName = GetDefaultDeviceName();
    g_defaultDeviceMac = GetDefaultDeviceMac();
    CreateSecurityControls(hWnd);
    RefreshAuthState(hWnd);
    SetTimer(hWnd, LICENSE_POLL_TIMER_ID, LICENSE_POLL_INTERVAL_MS, nullptr);

    if (!g_startHidden)
    {
        ShowWindow(hWnd, nCmdShow);
        UpdateWindow(hWnd);
    }

    return TRUE;
}

// ÐžÐ±Ñ€Ð°Ð±Ð°Ñ‚Ñ‹Ð²Ð°ÐµÑ‚ ÑÐ¾Ð¾Ð±Ñ‰ÐµÐ½Ð¸Ñ Ð³Ð»Ð°Ð²Ð½Ð¾Ð³Ð¾ Ð¾ÐºÐ½Ð°.
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (g_taskbarCreatedMessage != 0 && message == g_taskbarCreatedMessage)
    {
        AddTrayIcon(hWnd);
        return 0;
    }

    if (message == WMAPP_TRAYICON)
    {
        return HandleTrayIconMessage(hWnd, lParam);
    }

    switch (message)
    {
    case WM_COMMAND:
    {
        const int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            return 0;
        case IDC_BUTTON_LOGIN:
            HandleLoginAction(hWnd);
            return 0;
        case IDC_BUTTON_ACTIVATE:
            HandleActivationAction(hWnd);
            return 0;
        case IDC_BUTTON_LOGOUT:
            HandleLogoutAction(hWnd);
            return 0;
        case IDC_BUTTON_AV_ACTION:
            HandleAntivirusAction(hWnd);
            return 0;
        case IDM_TRAY_OPEN:
            ShowMainWindow(hWnd);
            return 0;
        case IDM_TRAY_EXIT:
        case IDM_EXIT:
            RequestServiceStopAndExit(hWnd);
            return 0;
        default:
            break;
        }
        break;
    }
    case WM_TIMER:
        if (wParam == LICENSE_POLL_TIMER_ID)
        {
            if (g_isAuthenticated)
            {
                RefreshLicenseState(hWnd);
            }
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        HWND control = reinterpret_cast<HWND>(lParam);
        SetBkMode(hdc, TRANSPARENT);

        if (control == g_hLabelAuthError || control == g_hLabelLicenseError)
        {
            SetTextColor(hdc, RGB(182, 49, 49));
        }
        else if (control == g_hLabelHeader)
        {
            SetTextColor(hdc, RGB(26, 48, 76));
        }
        else
        {
            SetTextColor(hdc, RGB(53, 66, 84));
        }

        return reinterpret_cast<LRESULT>(
            g_hBackgroundBrush != nullptr ? g_hBackgroundBrush : GetStockObject(WHITE_BRUSH));
    }
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        SetBkColor(hdc, RGB(255, 255, 255));
        SetTextColor(hdc, RGB(31, 43, 58));
        return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
    }
    case WM_CLOSE:
        if (!g_isExitRequested)
        {
            HideMainWindowToTray(hWnd);
            return 0;
        }
        break;
    case WM_ERASEBKGND:
    {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        RECT clientRect{};
        GetClientRect(hWnd, &clientRect);
        FillRect(hdc, &clientRect, g_hBackgroundBrush != nullptr
            ? g_hBackgroundBrush
            : reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1));
        return 1;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT clientRect{};
        GetClientRect(hWnd, &clientRect);

        FillRect(hdc, &clientRect, g_hBackgroundBrush != nullptr
            ? g_hBackgroundBrush
            : reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1));

        HBRUSH cardBrush = CreateSolidBrush(RGB(255, 255, 255));
        HPEN cardPen = CreatePen(PS_SOLID, 1, RGB(216, 225, 236));
        const HGDIOBJ oldBrush = SelectObject(hdc, cardBrush);
        const HGDIOBJ oldPen = SelectObject(hdc, cardPen);
        RoundRect(hdc, 18, 150, 456, 332, 14, 14);
        RoundRect(hdc, 450, 150, 732, 396, 14, 14);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(cardPen);
        DeleteObject(cardBrush);

        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        KillTimer(hWnd, LICENSE_POLL_TIMER_ID);
        DestroyFriendlyUiTheme();
        RemoveTrayIcon(hWnd);
        ReleaseSingleInstance();
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return DefWindowProc(hWnd, message, wParam, lParam);
}

// ÐžÐ±Ñ€Ð°Ð±Ð°Ñ‚Ñ‹Ð²Ð°ÐµÑ‚ Ð´Ð¸Ð°Ð»Ð¾Ð³ "Ðž Ð¿Ñ€Ð¾Ð³Ñ€Ð°Ð¼Ð¼Ðµ".
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (message)
    {
    case WM_INITDIALOG:
        return static_cast<INT_PTR>(TRUE);
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return static_cast<INT_PTR>(TRUE);
        }
        break;
    default:
        break;
    }

    return static_cast<INT_PTR>(FALSE);
}

// Ð”Ð¾Ð±Ð°Ð²Ð»ÑÐµÑ‚ Ð¸ÐºÐ¾Ð½ÐºÑƒ Ð¿Ñ€Ð¸Ð»Ð¾Ð¶ÐµÐ½Ð¸Ñ Ð² Ñ‚Ñ€ÐµÐ¹.
bool AddTrayIcon(HWND hWnd)
{
    NOTIFYICONDATAW notifyIconData{};
    notifyIconData.cbSize = sizeof(notifyIconData);
    notifyIconData.hWnd = hWnd;
    notifyIconData.uID = TRAY_ICON_UID;
    notifyIconData.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    notifyIconData.uCallbackMessage = WMAPP_TRAYICON;
    notifyIconData.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_ANTIVIRUS));
    wcscpy_s(notifyIconData.szTip, szTitle);

    if (!Shell_NotifyIconW(NIM_ADD, &notifyIconData))
    {
        return false;
    }

    notifyIconData.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &notifyIconData);

    return true;
}

// Ð£Ð´Ð°Ð»ÑÐµÑ‚ Ð¸ÐºÐ¾Ð½ÐºÑƒ Ð¿Ñ€Ð¸Ð»Ð¾Ð¶ÐµÐ½Ð¸Ñ Ð¸Ð· Ñ‚Ñ€ÐµÑ.
void RemoveTrayIcon(HWND hWnd)
{
    NOTIFYICONDATAW notifyIconData{};
    notifyIconData.cbSize = sizeof(notifyIconData);
    notifyIconData.hWnd = hWnd;
    notifyIconData.uID = TRAY_ICON_UID;

    Shell_NotifyIconW(NIM_DELETE, &notifyIconData);
}

// ÐžÐ±Ñ€Ð°Ð±Ð°Ñ‚Ñ‹Ð²Ð°ÐµÑ‚ ÑÐ¾Ð¾Ð±Ñ‰ÐµÐ½Ð¸Ñ Ð¾Ñ‚ Ð¸ÐºÐ¾Ð½ÐºÐ¸ Ð² ÑÐ¸ÑÑ‚ÐµÐ¼Ð½Ð¾Ð¼ Ñ‚Ñ€ÐµÐµ.
LRESULT HandleTrayIconMessage(HWND hWnd, LPARAM lParam)
{
    const UINT trayEventCode = LOWORD(static_cast<DWORD_PTR>(lParam));

    switch (trayEventCode)
    {
    case NIN_SELECT:
    case NIN_KEYSELECT:
    case WM_LBUTTONUP:
    case WM_LBUTTONDBLCLK:
        ShowMainWindow(hWnd);
        return 0;
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
    case WM_CONTEXTMENU:
        ShowTrayMenu(hWnd);
        return 0;
    default:
        return 0;
    }
}

// ÐŸÐ¾ÐºÐ°Ð·Ñ‹Ð²Ð°ÐµÑ‚ Ð³Ð»Ð°Ð²Ð½Ð¾Ðµ Ð¾ÐºÐ½Ð¾ Ð¿Ð¾Ð²ÐµÑ€Ñ… Ð¾ÑÑ‚Ð°Ð»ÑŒÐ½Ñ‹Ñ… Ð¾ÐºÐ¾Ð½.
void ShowMainWindow(HWND hWnd)
{
    ShowWindow(hWnd, SW_SHOW);
    ShowWindow(hWnd, SW_RESTORE);
    SetForegroundWindow(hWnd);
}

// Ð¡ÐºÑ€Ñ‹Ð²Ð°ÐµÑ‚ Ð³Ð»Ð°Ð²Ð½Ð¾Ðµ Ð¾ÐºÐ½Ð¾, Ð¾ÑÑ‚Ð°Ð²Ð»ÑÑ Ð¿Ñ€Ð¸Ð»Ð¾Ð¶ÐµÐ½Ð¸Ðµ Ñ€Ð°Ð±Ð¾Ñ‚Ð°Ñ‚ÑŒ Ð² Ñ„Ð¾Ð½Ðµ.
void HideMainWindowToTray(HWND hWnd)
{
    ShowWindow(hWnd, SW_HIDE);
}

// ÐŸÐ¾ÐºÐ°Ð·Ñ‹Ð²Ð°ÐµÑ‚ ÐºÐ¾Ð½Ñ‚ÐµÐºÑÑ‚Ð½Ð¾Ðµ Ð¼ÐµÐ½ÑŽ Ñ‚Ñ€ÐµÑ.
void ShowTrayMenu(HWND hWnd)
{
    HMENU hMenu = CreatePopupMenu();
    if (hMenu == nullptr)
    {
        return;
    }

    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_OPEN, L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C");
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT, L"\x0412\x044B\x0445\x043E\x0434");

    POINT pt{};
    GetCursorPos(&pt);

    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, nullptr);
    PostMessageW(hWnd, WM_NULL, 0, 0);
    DestroyMenu(hMenu);
}

// ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÑ‚, Ð½ÑƒÐ¶Ð½Ð¾ Ð»Ð¸ Ð·Ð°Ð¿ÑƒÑÐºÐ°Ñ‚ÑŒ Ð¿Ñ€Ð¸Ð»Ð¾Ð¶ÐµÐ½Ð¸Ðµ ÑÐºÑ€Ñ‹Ñ‚Ð¾.
bool ShouldStartHidden(LPCWSTR commandLine)
{
    if (commandLine == nullptr)
    {
        return false;
    }

    return wcsstr(commandLine, L"--hidden") != nullptr
        || wcsstr(commandLine, L"/hidden") != nullptr
        || wcsstr(commandLine, L"-background") != nullptr
        || wcsstr(commandLine, L"/background") != nullptr
        || wcsstr(commandLine, L"-tray") != nullptr
        || wcsstr(commandLine, L"/tray") != nullptr;
}

// ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÑ‚, Ñ‡Ñ‚Ð¾ Ð¿Ñ€Ð¸Ð»Ð¾Ð¶ÐµÐ½Ð¸Ðµ Ð·Ð°Ð¿ÑƒÑ‰ÐµÐ½Ð¾ Ð² ÐµÐ´Ð¸Ð½ÑÑ‚Ð²ÐµÐ½Ð½Ð¾Ð¼ ÑÐºÐ·ÐµÐ¼Ð¿Ð»ÑÑ€Ðµ.
bool EnsureSingleInstance()
{
    g_singleInstanceMutex = CreateMutexW(nullptr, FALSE, L"Local\\AntivirusTrayAppSingleInstanceMutex");
    if (g_singleInstanceMutex == nullptr)
    {
        return false;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(g_singleInstanceMutex);
        g_singleInstanceMutex = nullptr;
        return false;
    }

    return true;
}

// ÐžÑÐ²Ð¾Ð±Ð¾Ð¶Ð´Ð°ÐµÑ‚ Ñ€ÐµÑÑƒÑ€ÑÑ‹ Ð¾Ð´Ð¸Ð½Ð¾Ñ‡Ð½Ð¾Ð³Ð¾ Ð·Ð°Ð¿ÑƒÑÐºÐ°.
void ReleaseSingleInstance()
{
    if (g_singleInstanceMutex != nullptr)
    {
        CloseHandle(g_singleInstanceMutex);
        g_singleInstanceMutex = nullptr;
    }
}





