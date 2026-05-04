#include <windows.h>
#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cwctype>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "AntivirusRpcControl.h"
#include "ServiceCommon.h"
#include "WebApiIntegration.h"

namespace
{
struct GuiProcessInfo
{
    DWORD processId = 0;
    HANDLE processHandle = nullptr;
};

SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
SERVICE_STATUS g_serviceStatus{};
volatile LONG g_rpcStopRequested = 0;
constexpr DWORD kServiceStartTimeoutMs = 30000;
constexpr DWORD kServiceStatusPollIntervalMs = 250;

std::mutex g_guiProcessesMutex;
std::unordered_map<DWORD, GuiProcessInfo> g_guiProcessesBySession;
std::wstring g_guiExecutablePath;
antivirus::web::InMemorySession g_webSession;
antivirus::web::ApiClient g_webApiClient(L"https://192.168.1.56:8443/");
std::mutex g_webStateMutex;
std::thread g_webWorkerThread;
std::atomic<bool> g_webWorkerStopRequested = false;
bool g_antivirusBackgroundTasksRunning = false;
std::string g_authenticatedUsername;

struct LicenseRequestContext
{
    bool hasContext = false;
    long long productId = 0;
    std::string deviceMac;
};

LicenseRequestContext g_licenseRequestContext;
constexpr DWORD kWebWorkerPollIntervalMs = 1000;

// Converts UTF-16 text to UTF-8 for HTTP API calls.
std::string ToUtf8(const wchar_t* text)
{
    if (text == nullptr || *text == L'\0')
    {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1)
    {
        return {};
    }

    std::string utf8(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8.data(), size, nullptr, nullptr);
    utf8.resize(static_cast<size_t>(size - 1));
    return utf8;
}

// Converts UTF-8 text to UTF-16 for RPC output fields.
std::wstring ToWide(const std::string& text)
{
    if (text.empty())
    {
        return {};
    }

    const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (size <= 1)
    {
        return {};
    }

    std::wstring wide(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wide.data(), size);
    wide.resize(static_cast<size_t>(size - 1));
    return wide;
}

// Copies UTF-8 text into a fixed RPC wide-char buffer.
template <size_t BufferSize>
void CopyUtf8ToRpcBuffer(const std::string& source, wchar_t (&target)[BufferSize])
{
    static_assert(BufferSize > 0);
    std::fill(std::begin(target), std::end(target), L'\0');

    const std::wstring wide = ToWide(source);
    if (wide.empty())
    {
        return;
    }

    const size_t count = std::min(static_cast<size_t>(BufferSize - 1), wide.size());
    std::wmemcpy(target, wide.c_str(), count);
    target[count] = L'\0';
}

// Parses Java OffsetDateTime string into system_clock time point.
bool TryParseIsoDateTimeUtc(
    const std::string& isoDateTime,
    std::chrono::system_clock::time_point* outTimePoint)
{
    if (outTimePoint == nullptr || isoDateTime.size() < 19)
    {
        return false;
    }

    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    if (::sscanf_s(
        isoDateTime.c_str(),
        "%4d-%2d-%2dT%2d:%2d:%2d",
        &year,
        &month,
        &day,
        &hour,
        &minute,
        &second) != 6)
    {
        return false;
    }

    std::tm tmUtc{};
    tmUtc.tm_year = year - 1900;
    tmUtc.tm_mon = month - 1;
    tmUtc.tm_mday = day;
    tmUtc.tm_hour = hour;
    tmUtc.tm_min = minute;
    tmUtc.tm_sec = second;

    time_t baseUnixTime = _mkgmtime(&tmUtc);
    if (baseUnixTime == static_cast<time_t>(-1))
    {
        return false;
    }

    int offsetSign = 0;
    int offsetHour = 0;
    int offsetMinute = 0;
    const size_t tzPosition = isoDateTime.find_first_of("Z+-", 19);
    if (tzPosition != std::string::npos)
    {
        const char tzMarker = isoDateTime[tzPosition];
        if (tzMarker == '+')
        {
            offsetSign = 1;
        }
        else if (tzMarker == '-')
        {
            offsetSign = -1;
        }

        if (offsetSign != 0 && tzPosition + 5 < isoDateTime.size())
        {
            const std::string hourText = isoDateTime.substr(tzPosition + 1, 2);
            const std::string minuteText = isoDateTime.substr(tzPosition + 4, 2);
            offsetHour = std::atoi(hourText.c_str());
            offsetMinute = std::atoi(minuteText.c_str());
        }
    }

    const int totalOffsetSeconds = offsetSign * ((offsetHour * 60 * 60) + (offsetMinute * 60));
    const time_t utcUnixTime = baseUnixTime - totalOffsetSeconds;
    *outTimePoint = std::chrono::system_clock::from_time_t(utcUnixTime);
    return true;
}

// Maps authentication API error to RPC result code.
RpcResultCode MapAuthErrorToRpcCode(const antivirus::web::AuthError& error)
{
    if (error.httpStatus == 401)
    {
        return RPC_RESULT_AUTH_FAILED;
    }

    if (error.httpStatus == 400)
    {
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    if (error.httpStatus == 0)
    {
        return RPC_RESULT_NETWORK_ERROR;
    }

    return RPC_RESULT_INTERNAL_ERROR;
}

// Maps license API error to RPC result code.
RpcResultCode MapLicenseErrorToRpcCode(const antivirus::web::LicenseError& error)
{
    if (error.httpStatus == 401)
    {
        return RPC_RESULT_NOT_AUTHENTICATED;
    }

    if (error.httpStatus == 400)
    {
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    if (error.httpStatus == 404)
    {
        return RPC_RESULT_NO_LICENSE;
    }

    if (error.httpStatus == 0)
    {
        return RPC_RESULT_NETWORK_ERROR;
    }

    return RPC_RESULT_INTERNAL_ERROR;
}

// Clears all auth and license state that must exist only in memory.
void ClearAuthAndLicenseState()
{
    std::lock_guard<std::mutex> guard(g_webStateMutex);
    g_webSession.Clear();
    g_licenseRequestContext = LicenseRequestContext{};
    g_authenticatedUsername.clear();
    g_antivirusBackgroundTasksRunning = false;
}

// Returns current centralized license state for antivirus operations.
RpcResultCode EvaluateLicenseState()
{
    if (!g_webSession.HasLicenseTicket())
    {
        return RPC_RESULT_NO_LICENSE;
    }

    const antivirus::web::LicenseState licenseState = g_webSession.GetLicenseState();
    if (!licenseState.hasLicense)
    {
        return RPC_RESULT_NO_LICENSE;
    }

    if (licenseState.ticket.licenseBlocked)
    {
        return RPC_RESULT_LICENSE_BLOCKED;
    }

    std::chrono::system_clock::time_point expirationTime{};
    if (!TryParseIsoDateTimeUtc(licenseState.ticket.licenseExpirationDate, &expirationTime))
    {
        return RPC_RESULT_LICENSE_EXPIRED;
    }

    if (expirationTime <= std::chrono::system_clock::now())
    {
        return RPC_RESULT_LICENSE_EXPIRED;
    }

    return RPC_RESULT_OK;
}

// Applies centralized license check and starts/stops antivirus tasks.
RpcResultCode EnsureValidLicenseForAntivirus()
{
    const RpcResultCode licenseCode = EvaluateLicenseState();
    std::lock_guard<std::mutex> guard(g_webStateMutex);
    g_antivirusBackgroundTasksRunning = (licenseCode == RPC_RESULT_OK);
    return licenseCode;
}

// Converts RPC license code to a readable safe error string.
std::string LicenseCodeToText(RpcResultCode code)
{
    switch (code)
    {
    case RPC_RESULT_NO_LICENSE:
        return "NO_LICENSE";
    case RPC_RESULT_LICENSE_EXPIRED:
        return "LICENSE_EXPIRED";
    case RPC_RESULT_LICENSE_BLOCKED:
        return "LICENSE_BLOCKED";
    default:
        return {};
    }
}

// Fills RPC auth info with safe data only.
void FillRpcAuthInfo(RpcAuthInfo* authInfo)
{
    if (authInfo == nullptr)
    {
        return;
    }

    authInfo->authenticated = 0;
    authInfo->hasUserId = 0;
    authInfo->userId = 0;
    std::fill(std::begin(authInfo->username), std::end(authInfo->username), L'\0');

    if (!g_webSession.HasAuthTokens())
    {
        return;
    }

    authInfo->authenticated = 1;

    antivirus::web::AuthUserInfo userInfo = g_webSession.GetAuthUserInfo();
    std::string username = userInfo.username;
    if (username.empty())
    {
        std::lock_guard<std::mutex> guard(g_webStateMutex);
        username = g_authenticatedUsername;
    }

    CopyUtf8ToRpcBuffer(username, authInfo->username);
    if (userInfo.id > 0)
    {
        authInfo->hasUserId = 1;
        authInfo->userId = userInfo.id;
    }
}

// Fills RPC license info with safe data only.
void FillRpcLicenseInfo(RpcLicenseInfo* licenseInfo, RpcResultCode errorCode, const std::string& errorText)
{
    if (licenseInfo == nullptr)
    {
        return;
    }

    licenseInfo->hasLicense = 0;
    licenseInfo->blocked = 0;
    licenseInfo->errorCode = static_cast<long>(errorCode);
    std::fill(std::begin(licenseInfo->expirationDate), std::end(licenseInfo->expirationDate), L'\0');
    std::fill(std::begin(licenseInfo->error), std::end(licenseInfo->error), L'\0');

    if (g_webSession.HasLicenseTicket())
    {
        const antivirus::web::LicenseState licenseState = g_webSession.GetLicenseState();
        if (licenseState.hasLicense)
        {
            licenseInfo->hasLicense = 1;
            licenseInfo->blocked = licenseState.ticket.licenseBlocked ? 1 : 0;
            CopyUtf8ToRpcBuffer(licenseState.ticket.licenseExpirationDate, licenseInfo->expirationDate);
        }
    }

    if (!errorText.empty())
    {
        CopyUtf8ToRpcBuffer(errorText, licenseInfo->error);
    }
}

// Periodically refreshes tokens and license ticket in memory.
void WebSessionWorkerLoop()
{
    while (!g_webWorkerStopRequested.load())
    {
        bool didWork = false;
        const auto now = std::chrono::system_clock::now();

        if (g_webSession.HasAuthTokens())
        {
            const antivirus::web::AuthTokens currentTokens = g_webSession.GetAuthTokens();
            if (now >= currentTokens.nextRefreshAt)
            {
                didWork = true;
                antivirus::web::AuthTokens refreshedTokens;
                antivirus::web::AuthError refreshError;
                if (g_webApiClient.RefreshTokens(currentTokens.refreshToken, &refreshedTokens, &refreshError))
                {
                    g_webSession.SetAuthTokens(std::move(refreshedTokens));
                }
                else
                {
                    ClearAuthAndLicenseState();
                }
            }
        }

        if (g_webSession.HasAuthTokens() && g_webSession.HasLicenseTicket())
        {
            const antivirus::web::LicenseState licenseState = g_webSession.GetLicenseState();
            if (now >= licenseState.nextRefreshAt)
            {
                didWork = true;
                antivirus::web::AuthTokens authTokens = g_webSession.GetAuthTokens();

                LicenseRequestContext context;
                {
                    std::lock_guard<std::mutex> guard(g_webStateMutex);
                    context = g_licenseRequestContext;
                }

                if (!context.hasContext)
                {
                    g_webSession.SetLicenseState(antivirus::web::LicenseState{});
                }
                else
                {
                    antivirus::web::LicenseState refreshedLicense;
                    antivirus::web::LicenseError licenseError;
                    if (g_webApiClient.CheckLicense(
                        authTokens.accessToken,
                        context.productId,
                        context.deviceMac,
                        &refreshedLicense,
                        &licenseError))
                    {
                        g_webSession.SetLicenseState(std::move(refreshedLicense));
                    }
                    else
                    {
                        g_webSession.SetLicenseState(antivirus::web::LicenseState{});
                    }
                }

                EnsureValidLicenseForAntivirus();
            }
        }
        else if (!g_webSession.HasLicenseTicket())
        {
            std::lock_guard<std::mutex> guard(g_webStateMutex);
            g_antivirusBackgroundTasksRunning = false;
        }

        if (!didWork)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(kWebWorkerPollIntervalMs));
        }
    }
}

// Clears API session state in memory before service work starts.
void InitializeWebApiLayer()
{
    ClearAuthAndLicenseState();
    g_webWorkerStopRequested.store(false);
    if (!g_webWorkerThread.joinable())
    {
        g_webWorkerThread = std::thread(WebSessionWorkerLoop);
    }
}

// Clears API session state in memory before service exits.
void ShutdownWebApiLayer()
{
    g_webWorkerStopRequested.store(true);
    if (g_webWorkerThread.joinable())
    {
        g_webWorkerThread.join();
    }

    ClearAuthAndLicenseState();
}

DWORD RpcStatusToWin32(RPC_STATUS status)
{
    return status == RPC_S_OK ? NO_ERROR : static_cast<DWORD>(status);
}

void ReportServiceStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint)
{
    static DWORD checkpoint = 1;

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = currentState;
    g_serviceStatus.dwWin32ExitCode = win32ExitCode;
    g_serviceStatus.dwServiceSpecificExitCode = 0;
    g_serviceStatus.dwWaitHint = waitHint;
    g_serviceStatus.dwControlsAccepted =
        currentState == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE : 0;

    if (currentState == SERVICE_START_PENDING)
    {
        g_serviceStatus.dwCheckPoint = checkpoint++;
    }
    else
    {
        g_serviceStatus.dwCheckPoint = 0;
        checkpoint = 1;
    }

    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
}

std::wstring ExtractDirectory(const std::wstring& fullPath)
{
    const size_t separatorIndex = fullPath.find_last_of(L"\\/");
    if (separatorIndex == std::wstring::npos)
    {
        return L".";
    }

    return fullPath.substr(0, separatorIndex);
}

std::wstring ResolveGuiExecutablePath()
{
    WCHAR modulePath[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
    {
        return {};
    }

    std::wstring directoryPath = ExtractDirectory(modulePath);
    return directoryPath + L"\\Antivirus.exe";
}

bool FileExists(const std::wstring& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES
        && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring QuotePathForScm(const std::wstring& path)
{
    return L"\"" + path + L"\"";
}

std::wstring NormalizeServiceBinaryPath(std::wstring path)
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

bool ArePathsEqualInsensitive(const std::wstring& left, const std::wstring& right)
{
    const std::wstring normalizedLeft = NormalizeServiceBinaryPath(left);
    const std::wstring normalizedRight = NormalizeServiceBinaryPath(right);

    if (normalizedLeft.empty() || normalizedRight.empty())
    {
        return false;
    }

    return _wcsicmp(normalizedLeft.c_str(), normalizedRight.c_str()) == 0;
}

bool QueryServiceBinaryPath(SC_HANDLE serviceHandle, std::wstring& binaryPath)
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

std::wstring ResolveSelfExecutablePath()
{
    WCHAR modulePath[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
    {
        return {};
    }

    return modulePath;
}

bool EnsureServiceInstalledAndConfigured(SC_HANDLE scmHandle, SC_HANDLE& serviceHandle)
{
    const std::wstring serviceExecutablePath = ResolveSelfExecutablePath();
    if (serviceExecutablePath.empty() || !FileExists(serviceExecutablePath))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return false;
    }

    const std::wstring quotedServicePath = QuotePathForScm(serviceExecutablePath);
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
        if (serviceHandle == nullptr)
        {
            return false;
        }

        return true;
    }

    std::wstring configuredBinaryPath;
    if (!QueryServiceBinaryPath(serviceHandle, configuredBinaryPath))
    {
        return false;
    }

    if (!ArePathsEqualInsensitive(configuredBinaryPath, serviceExecutablePath))
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

bool StartServiceAndWaitUntilRunningFromConsole()
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
    if (!EnsureServiceInstalledAndConfigured(scmHandle, serviceHandle))
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
        if (!StartServiceW(serviceHandle, 0, nullptr))
        {
            const DWORD startError = GetLastError();
            if (startError == ERROR_FILE_NOT_FOUND || startError == ERROR_PATH_NOT_FOUND)
            {
                CloseServiceHandle(serviceHandle);
                serviceHandle = nullptr;

                if (!EnsureServiceInstalledAndConfigured(scmHandle, serviceHandle))
                {
                    CloseServiceHandle(scmHandle);
                    return false;
                }

                if (!StartServiceW(serviceHandle, 0, nullptr)
                    && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
                {
                    CloseServiceHandle(serviceHandle);
                    CloseServiceHandle(scmHandle);
                    return false;
                }
            }
            else if (startError != ERROR_SERVICE_ALREADY_RUNNING)
            {
                CloseServiceHandle(serviceHandle);
                CloseServiceHandle(scmHandle);
                return false;
            }
        }
    }

    const ULONGLONG deadline = GetTickCount64() + kServiceStartTimeoutMs;
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

        Sleep(kServiceStatusPollIntervalMs);
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    SetLastError(ERROR_TIMEOUT);
    return false;
}

int RunInteractiveBootstrap()
{
    if (!StartServiceAndWaitUntilRunningFromConsole())
    {
        const DWORD error = GetLastError();
        std::fwprintf(
            stderr,
            L"Failed to install/start %ls. Win32 error: %lu\n",
            antivirus::common::kServiceName,
            error);
        return static_cast<int>(error == NO_ERROR ? ERROR_GEN_FAILURE : error);
    }

    std::wprintf(L"%ls is running.\n", antivirus::common::kServiceName);
    return 0;
}

void CleanupExitedGuiProcessesLocked()
{
    for (auto it = g_guiProcessesBySession.begin(); it != g_guiProcessesBySession.end();)
    {
        const DWORD waitResult = WaitForSingleObject(it->second.processHandle, 0);
        if (waitResult == WAIT_TIMEOUT)
        {
            ++it;
            continue;
        }

        CloseHandle(it->second.processHandle);
        it = g_guiProcessesBySession.erase(it);
    }
}

bool IsGuiRunningInSessionLocked(DWORD sessionId)
{
    auto it = g_guiProcessesBySession.find(sessionId);
    if (it == g_guiProcessesBySession.end())
    {
        return false;
    }

    const DWORD waitResult = WaitForSingleObject(it->second.processHandle, 0);
    if (waitResult == WAIT_TIMEOUT)
    {
        return true;
    }

    CloseHandle(it->second.processHandle);
    g_guiProcessesBySession.erase(it);
    return false;
}

bool IsGuiRunningInSession(DWORD sessionId)
{
    std::lock_guard<std::mutex> guard(g_guiProcessesMutex);
    CleanupExitedGuiProcessesLocked();
    return IsGuiRunningInSessionLocked(sessionId);
}

bool TrackGuiProcess(DWORD sessionId, DWORD processId, HANDLE processHandle)
{
    std::lock_guard<std::mutex> guard(g_guiProcessesMutex);
    CleanupExitedGuiProcessesLocked();

    if (IsGuiRunningInSessionLocked(sessionId))
    {
        return false;
    }

    g_guiProcessesBySession[sessionId] = { processId, processHandle };
    return true;
}

std::wstring BuildGuiCommandLine(const std::wstring& executablePath)
{
    return L"\"" + executablePath + L"\" --hidden --service-launch";
}

bool LaunchGuiInSession(DWORD sessionId)
{
    if (sessionId == 0)
    {
        return false;
    }

    if (InterlockedCompareExchange(&g_rpcStopRequested, 0, 0) != 0)
    {
        return false;
    }

    if (g_guiExecutablePath.empty() || !FileExists(g_guiExecutablePath))
    {
        return false;
    }

    if (IsGuiRunningInSession(sessionId))
    {
        return true;
    }

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken))
    {
        return false;
    }

    HANDLE primaryToken = nullptr;
    const bool tokenDuplicated = DuplicateTokenEx(
        userToken,
        MAXIMUM_ALLOWED,
        nullptr,
        SecurityImpersonation,
        TokenPrimary,
        &primaryToken) != FALSE;
    CloseHandle(userToken);

    if (!tokenDuplicated)
    {
        return false;
    }

    LPVOID environmentBlock = nullptr;
    const bool envCreated = CreateEnvironmentBlock(&environmentBlock, primaryToken, FALSE) != FALSE;

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInfo{};
    std::wstring commandLine = BuildGuiCommandLine(g_guiExecutablePath);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    const std::wstring workingDirectory = ExtractDirectory(g_guiExecutablePath);

    DWORD creationFlags = CREATE_UNICODE_ENVIRONMENT;
    const bool processCreated = CreateProcessAsUserW(
        primaryToken,
        g_guiExecutablePath.c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        creationFlags,
        envCreated ? environmentBlock : nullptr,
        workingDirectory.c_str(),
        &startupInfo,
        &processInfo) != FALSE;

    if (envCreated)
    {
        DestroyEnvironmentBlock(environmentBlock);
    }

    CloseHandle(primaryToken);

    if (!processCreated)
    {
        return false;
    }

    CloseHandle(processInfo.hThread);

    if (!TrackGuiProcess(sessionId, processInfo.dwProcessId, processInfo.hProcess))
    {
        TerminateProcess(processInfo.hProcess, 0);
        WaitForSingleObject(processInfo.hProcess, 5000);
        CloseHandle(processInfo.hProcess);
    }

    return true;
}

void LaunchGuiInAllUserSessions()
{
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD sessionCount = 0;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount))
    {
        return;
    }

    for (DWORD i = 0; i < sessionCount; ++i)
    {
        const DWORD sessionId = sessions[i].SessionId;
        if (sessionId == 0)
        {
            continue;
        }

        LaunchGuiInSession(sessionId);
    }

    WTSFreeMemory(sessions);
}

void StopTrackedGuiProcesses()
{
    std::vector<GuiProcessInfo> trackedProcesses;

    {
        std::lock_guard<std::mutex> guard(g_guiProcessesMutex);
        CleanupExitedGuiProcessesLocked();
        trackedProcesses.reserve(g_guiProcessesBySession.size());
        for (const auto& [sessionId, processInfo] : g_guiProcessesBySession)
        {
            UNREFERENCED_PARAMETER(sessionId);
            trackedProcesses.push_back(processInfo);
        }
        g_guiProcessesBySession.clear();
    }

    for (const GuiProcessInfo& processInfo : trackedProcesses)
    {
        if (WaitForSingleObject(processInfo.processHandle, 0) == WAIT_TIMEOUT)
        {
            TerminateProcess(processInfo.processHandle, 0);
            WaitForSingleObject(processInfo.processHandle, 5000);
        }

        CloseHandle(processInfo.processHandle);
    }
}

DWORD StartRpcServer()
{
    const RPC_WSTR protseq =
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(antivirus::common::kRpcProtseq));
    const RPC_WSTR endpoint =
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(antivirus::common::kRpcEndpoint));

    RPC_STATUS rpcStatus = RpcServerUseProtseqEpW(
        protseq,
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        endpoint,
        nullptr);
    if (rpcStatus != RPC_S_OK && rpcStatus != RPC_S_DUPLICATE_ENDPOINT)
    {
        return RpcStatusToWin32(rpcStatus);
    }

    rpcStatus = RpcServerRegisterIf(AntivirusRpcControl_v1_0_s_ifspec, nullptr, nullptr);
    if (rpcStatus != RPC_S_OK && rpcStatus != RPC_S_TYPE_ALREADY_REGISTERED)
    {
        return RpcStatusToWin32(rpcStatus);
    }

    rpcStatus = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (rpcStatus != RPC_S_OK && rpcStatus != RPC_S_ALREADY_LISTENING)
    {
        return RpcStatusToWin32(rpcStatus);
    }

    return NO_ERROR;
}

DWORD WINAPI ServiceControlHandlerEx(
    DWORD controlCode,
    DWORD eventType,
    LPVOID eventData,
    LPVOID context)
{
    UNREFERENCED_PARAMETER(context);

    switch (controlCode)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        return ERROR_CALL_NOT_IMPLEMENTED;
    case SERVICE_CONTROL_INTERROGATE:
        ReportServiceStatus(g_serviceStatus.dwCurrentState, g_serviceStatus.dwWin32ExitCode, 0);
        return NO_ERROR;
    case SERVICE_CONTROL_SESSIONCHANGE:
    {
        if (eventType == WTS_SESSION_LOGON && eventData != nullptr)
        {
            const auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);
            LaunchGuiInSession(notification->dwSessionId);
        }

        return NO_ERROR;
    }
    default:
        return NO_ERROR;
    }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_serviceStatusHandle = RegisterServiceCtrlHandlerExW(
        antivirus::common::kServiceName,
        ServiceControlHandlerEx,
        nullptr);
    if (g_serviceStatusHandle == nullptr)
    {
        return;
    }

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 5000);
    InitializeWebApiLayer();

    g_guiExecutablePath = ResolveGuiExecutablePath();
    if (g_guiExecutablePath.empty() || !FileExists(g_guiExecutablePath))
    {
        ShutdownWebApiLayer();
        ReportServiceStatus(SERVICE_STOPPED, ERROR_FILE_NOT_FOUND, 0);
        return;
    }

    const DWORD rpcStartError = StartRpcServer();
    if (rpcStartError != NO_ERROR)
    {
        ShutdownWebApiLayer();
        ReportServiceStatus(SERVICE_STOPPED, rpcStartError, 0);
        return;
    }

    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    LaunchGuiInAllUserSessions();

    RPC_STATUS waitStatus = RpcMgmtWaitServerListen();
    if (waitStatus != RPC_S_OK && waitStatus != RPC_S_NOT_LISTENING)
    {
        ShutdownWebApiLayer();
        ReportServiceStatus(SERVICE_STOPPED, RpcStatusToWin32(waitStatus), 0);
        return;
    }

    StopTrackedGuiProcesses();
    ShutdownWebApiLayer();
    RpcServerUnregisterIf(AntivirusRpcControl_v1_0_s_ifspec, nullptr, FALSE);
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}
} // namespace

extern "C" void StopService(void)
{
    if (InterlockedExchange(&g_rpcStopRequested, 1) != 0)
    {
        return;
    }

    RpcMgmtStopServerListening(nullptr);
}

// Returns safe information about the current authenticated user.
extern "C" RpcResultCode GetCurrentAuthInfo(RpcAuthInfo* authInfo)
{
    if (authInfo == nullptr)
    {
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    FillRpcAuthInfo(authInfo);
    return RPC_RESULT_OK;
}

// Performs login and stores JWT tokens only in service memory.
extern "C" RpcResultCode LoginUser(
    const wchar_t* username,
    const wchar_t* password,
    RpcAuthInfo* authInfo)
{
    if (authInfo == nullptr || username == nullptr || password == nullptr)
    {
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    if (*username == L'\0' || *password == L'\0')
    {
        FillRpcAuthInfo(authInfo);
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    const std::string usernameUtf8 = ToUtf8(username);
    const std::string passwordUtf8 = ToUtf8(password);
    if (usernameUtf8.empty() || passwordUtf8.empty())
    {
        FillRpcAuthInfo(authInfo);
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    antivirus::web::AuthTokens tokens;
    antivirus::web::AuthError loginError;
    if (!g_webApiClient.Login(usernameUtf8, passwordUtf8, &tokens, &loginError))
    {
        ClearAuthAndLicenseState();
        FillRpcAuthInfo(authInfo);
        return MapAuthErrorToRpcCode(loginError);
    }

    g_webSession.SetAuthTokens(std::move(tokens));
    {
        std::lock_guard<std::mutex> guard(g_webStateMutex);
        g_authenticatedUsername = usernameUtf8;
    }

    antivirus::web::AuthUserInfo userInfo;
    antivirus::web::AuthError userError;
    const antivirus::web::AuthTokens currentTokens = g_webSession.GetAuthTokens();
    if (g_webApiClient.GetCurrentUser(currentTokens.accessToken, &userInfo, &userError))
    {
        g_webSession.SetAuthUserInfo(userInfo);
    }

    FillRpcAuthInfo(authInfo);
    return RPC_RESULT_OK;
}

// Performs logout and clears auth/license state from memory.
extern "C" RpcResultCode LogoutUser(RpcAuthInfo* authInfo, RpcLicenseInfo* licenseInfo)
{
    ClearAuthAndLicenseState();

    if (authInfo != nullptr)
    {
        FillRpcAuthInfo(authInfo);
    }

    if (licenseInfo != nullptr)
    {
        FillRpcLicenseInfo(licenseInfo, RPC_RESULT_NO_LICENSE, "NO_LICENSE");
    }

    return RPC_RESULT_OK;
}

// Requests current license status and stores ticket only in memory.
extern "C" RpcResultCode GetActiveLicenseInfo(
    hyper productId,
    const wchar_t* deviceMac,
    RpcLicenseInfo* licenseInfo)
{
    if (licenseInfo == nullptr)
    {
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    if (!g_webSession.HasAuthTokens())
    {
        FillRpcLicenseInfo(licenseInfo, RPC_RESULT_NOT_AUTHENTICATED, "NOT_AUTHENTICATED");
        return RPC_RESULT_NOT_AUTHENTICATED;
    }

    const std::string deviceMacUtf8 = ToUtf8(deviceMac);
    if (productId <= 0 || deviceMacUtf8.empty())
    {
        FillRpcLicenseInfo(licenseInfo, RPC_RESULT_INVALID_ARGUMENT, "INVALID_ARGUMENT");
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    const antivirus::web::AuthTokens tokens = g_webSession.GetAuthTokens();
    antivirus::web::LicenseState licenseState;
    antivirus::web::LicenseError licenseError;
    if (!g_webApiClient.CheckLicense(tokens.accessToken, static_cast<long long>(productId), deviceMacUtf8, &licenseState, &licenseError))
    {
        const RpcResultCode errorCode = MapLicenseErrorToRpcCode(licenseError);
        if (errorCode == RPC_RESULT_NO_LICENSE)
        {
            g_webSession.SetLicenseState(antivirus::web::LicenseState{});
            EnsureValidLicenseForAntivirus();
        }

        FillRpcLicenseInfo(licenseInfo, errorCode, licenseError.message);
        return errorCode;
    }

    g_webSession.SetLicenseState(std::move(licenseState));
    {
        std::lock_guard<std::mutex> guard(g_webStateMutex);
        g_licenseRequestContext.hasContext = true;
        g_licenseRequestContext.productId = static_cast<long long>(productId);
        g_licenseRequestContext.deviceMac = deviceMacUtf8;
    }

    const RpcResultCode licenseCode = EnsureValidLicenseForAntivirus();
    FillRpcLicenseInfo(licenseInfo, licenseCode, LicenseCodeToText(licenseCode));
    return licenseCode;
}

// Activates product and updates in-memory license state.
extern "C" RpcResultCode ActivateProduct(
    const wchar_t* activationKey,
    const wchar_t* deviceName,
    const wchar_t* deviceMac,
    hyper productId,
    RpcLicenseInfo* licenseInfo)
{
    if (licenseInfo == nullptr || activationKey == nullptr || deviceName == nullptr || deviceMac == nullptr)
    {
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    if (!g_webSession.HasAuthTokens())
    {
        FillRpcLicenseInfo(licenseInfo, RPC_RESULT_NOT_AUTHENTICATED, "NOT_AUTHENTICATED");
        return RPC_RESULT_NOT_AUTHENTICATED;
    }

    const std::string activationKeyUtf8 = ToUtf8(activationKey);
    const std::string deviceNameUtf8 = ToUtf8(deviceName);
    const std::string deviceMacUtf8 = ToUtf8(deviceMac);
    if (activationKeyUtf8.empty() || deviceNameUtf8.empty() || deviceMacUtf8.empty())
    {
        FillRpcLicenseInfo(licenseInfo, RPC_RESULT_INVALID_ARGUMENT, "INVALID_ARGUMENT");
        return RPC_RESULT_INVALID_ARGUMENT;
    }

    const antivirus::web::AuthTokens tokens = g_webSession.GetAuthTokens();
    antivirus::web::LicenseState licenseState;
    antivirus::web::LicenseError activateError;
    if (!g_webApiClient.ActivateLicense(
        tokens.accessToken,
        activationKeyUtf8,
        deviceNameUtf8,
        deviceMacUtf8,
        &licenseState,
        &activateError))
    {
        const RpcResultCode errorCode = MapLicenseErrorToRpcCode(activateError);
        FillRpcLicenseInfo(licenseInfo, errorCode, activateError.message);
        return errorCode;
    }

    if (!licenseState.hasLicense)
    {
        if (productId <= 0)
        {
            g_webSession.SetLicenseState(antivirus::web::LicenseState{});
            EnsureValidLicenseForAntivirus();
            FillRpcLicenseInfo(licenseInfo, RPC_RESULT_NO_LICENSE, "NO_LICENSE");
            return RPC_RESULT_NO_LICENSE;
        }

        antivirus::web::LicenseError checkError;
        if (!g_webApiClient.CheckLicense(
            tokens.accessToken,
            static_cast<long long>(productId),
            deviceMacUtf8,
            &licenseState,
            &checkError))
        {
            const RpcResultCode errorCode = MapLicenseErrorToRpcCode(checkError);
            FillRpcLicenseInfo(licenseInfo, errorCode, checkError.message);
            return errorCode;
        }
    }

    g_webSession.SetLicenseState(std::move(licenseState));
    {
        std::lock_guard<std::mutex> guard(g_webStateMutex);
        g_licenseRequestContext.hasContext = true;
        g_licenseRequestContext.productId = static_cast<long long>(productId);
        g_licenseRequestContext.deviceMac = deviceMacUtf8;
    }

    const RpcResultCode licenseCode = EnsureValidLicenseForAntivirus();
    FillRpcLicenseInfo(licenseInfo, licenseCode, LicenseCodeToText(licenseCode));
    return licenseCode;
}

extern "C" void* __RPC_USER MIDL_user_allocate(size_t size)
{
    return std::malloc(size);
}

extern "C" void __RPC_USER MIDL_user_free(void* pointer)
{
    std::free(pointer);
}

int wmain()
{
    SERVICE_TABLE_ENTRYW dispatchTable[] = {
        { const_cast<LPWSTR>(antivirus::common::kServiceName), ServiceMain },
        { nullptr, nullptr },
    };

    if (!StartServiceCtrlDispatcherW(dispatchTable))
    {
        const DWORD dispatcherError = GetLastError();
        if (dispatcherError == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            return RunInteractiveBootstrap();
        }

        return static_cast<int>(dispatcherError);
    }

    return 0;
}
