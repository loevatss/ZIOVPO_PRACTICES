#include <windows.h>
#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cwctype>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "AntivirusRpcControl.h"
#include "ServiceCommon.h"

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

    g_guiExecutablePath = ResolveGuiExecutablePath();
    if (g_guiExecutablePath.empty() || !FileExists(g_guiExecutablePath))
    {
        ReportServiceStatus(SERVICE_STOPPED, ERROR_FILE_NOT_FOUND, 0);
        return;
    }

    const DWORD rpcStartError = StartRpcServer();
    if (rpcStartError != NO_ERROR)
    {
        ReportServiceStatus(SERVICE_STOPPED, rpcStartError, 0);
        return;
    }

    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    LaunchGuiInAllUserSessions();

    RPC_STATUS waitStatus = RpcMgmtWaitServerListen();
    if (waitStatus != RPC_S_OK && waitStatus != RPC_S_NOT_LISTENING)
    {
        ReportServiceStatus(SERVICE_STOPPED, RpcStatusToWin32(waitStatus), 0);
        return;
    }

    StopTrackedGuiProcesses();
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
