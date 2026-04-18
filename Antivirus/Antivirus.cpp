// Antivirus.cpp : Defines the entry point for the application.
//

#include "pch.h"
#include "framework.h"
#include "Antivirus.h"

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <cstdlib>
#include <string>
#include <vector>
#include <shellapi.h>
#include <tlhelp32.h>
#include <rpc.h>

#include "AntivirusRpcControl.h"
#include "ServiceCommon.h"

#define MAX_LOADSTRING 100

constexpr UINT WMAPP_TRAYICON = WM_APP + 1;
constexpr UINT TRAY_ICON_UID = 1;
constexpr DWORD SERVICE_START_TIMEOUT_MS = 30000;
constexpr DWORD SERVICE_STATUS_POLL_INTERVAL_MS = 250;

HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];
UINT g_taskbarCreatedMessage = 0;
HANDLE g_singleInstanceMutex = nullptr;
bool g_isExitRequested = false;
bool g_startHidden = false;
handle_t AntivirusRpcControlBinding = nullptr;

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
void RequestServiceStopAndExit(HWND hWnd);
std::wstring GetModuleDirectoryPath();
std::wstring ResolveSiblingServiceExecutablePath();
bool FileExists(const std::wstring& path);
std::wstring QuotePathForScm(const std::wstring& path);
std::wstring NormalizeServiceBinaryPath(std::wstring path);
bool ArePathsEqualInsensitive(const std::wstring& left, const std::wstring& right);
bool QueryServiceBinaryPath(SC_HANDLE serviceHandle, std::wstring& binaryPath);
bool EnsureServiceInstalledAndConfigured(SC_HANDLE scmHandle, SC_HANDLE& serviceHandle);

std::wstring GetModuleDirectoryPath()
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

std::wstring ResolveSiblingServiceExecutablePath()
{
    const std::wstring directoryPath = GetModuleDirectoryPath();
    if (directoryPath.empty())
    {
        return {};
    }

    return directoryPath + L"\\" + antivirus::common::kServiceBinaryName;
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

bool EnsureServiceInstalledAndConfigured(SC_HANDLE scmHandle, SC_HANDLE& serviceHandle)
{
    const std::wstring serviceExecutablePath = ResolveSiblingServiceExecutablePath();
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

bool IsServiceLaunchArgumentPresent(LPCWSTR commandLine)
{
    if (commandLine == nullptr)
    {
        return false;
    }

    return wcsstr(commandLine, L"--service-launch") != nullptr;
}

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

    if (!IsServiceLaunchArgumentPresent(commandLine))
    {
        return false;
    }

    return true;
}

bool RequestServiceStopViaRpc()
{
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

    RpcBindingFree(&AntivirusRpcControlBinding);
    AntivirusRpcControlBinding = nullptr;
    return rpcCallSucceeded;
}

void RequestServiceStopAndExit(HWND hWnd)
{
    if (!RequestServiceStopViaRpc())
    {
        MessageBoxW(
            hWnd,
            L"Не удалось остановить службу через RPC.",
            L"Antivirus",
            MB_OK | MB_ICONERROR);
        return;
    }

    g_isExitRequested = true;
    DestroyWindow(hWnd);
}

// Запускает приложение и основной цикл сообщений.
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

// Регистрирует класс главного окна.
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

// Создает главное окно и добавляет иконку в трей.
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    hInst = hInstance;

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (hWnd == nullptr)
    {
        return FALSE;
    }

    if (!AddTrayIcon(hWnd))
    {
        DestroyWindow(hWnd);
        return FALSE;
    }

    if (!g_startHidden)
    {
        ShowWindow(hWnd, nCmdShow);
        UpdateWindow(hWnd);
    }

    return TRUE;
}

// Обрабатывает сообщения главного окна.
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
    case WM_CLOSE:
        if (!g_isExitRequested)
        {
            HideMainWindowToTray(hWnd);
            return 0;
        }
        break;
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hWnd, &ps);
        EndPaint(hWnd, &ps);
        UNREFERENCED_PARAMETER(hdc);
        return 0;
    }
    case WM_DESTROY:
        RemoveTrayIcon(hWnd);
        ReleaseSingleInstance();
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return DefWindowProc(hWnd, message, wParam, lParam);
}

// Обрабатывает диалог "О программе".
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

// Добавляет иконку приложения в трей.
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

// Удаляет иконку приложения из трея.
void RemoveTrayIcon(HWND hWnd)
{
    NOTIFYICONDATAW notifyIconData{};
    notifyIconData.cbSize = sizeof(notifyIconData);
    notifyIconData.hWnd = hWnd;
    notifyIconData.uID = TRAY_ICON_UID;

    Shell_NotifyIconW(NIM_DELETE, &notifyIconData);
}

// Обрабатывает сообщения от иконки в системном трее.
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

// Показывает главное окно поверх остальных окон.
void ShowMainWindow(HWND hWnd)
{
    ShowWindow(hWnd, SW_SHOW);
    ShowWindow(hWnd, SW_RESTORE);
    SetForegroundWindow(hWnd);
}

// Скрывает главное окно, оставляя приложение работать в фоне.
void HideMainWindowToTray(HWND hWnd)
{
    ShowWindow(hWnd, SW_HIDE);
}

// Показывает контекстное меню трея.
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

// Проверяет, нужно ли запускать приложение скрыто.
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

// Проверяет, что приложение запущено в единственном экземпляре.
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

// Освобождает ресурсы одиночного запуска.
void ReleaseSingleInstance()
{
    if (g_singleInstanceMutex != nullptr)
    {
        CloseHandle(g_singleInstanceMutex);
        g_singleInstanceMutex = nullptr;
    }
}
