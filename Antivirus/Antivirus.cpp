// Antivirus.cpp : Defines the entry point for the application.
//

#include "pch.h"
#include "framework.h"
#include "Antivirus.h"

#include <cwchar>
#include <shellapi.h>

#define MAX_LOADSTRING 100

constexpr UINT WMAPP_TRAYICON = WM_APP + 1;
constexpr UINT TRAY_ICON_UID = 1;

HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];
UINT g_taskbarCreatedMessage = 0;
HANDLE g_singleInstanceMutex = nullptr;
bool g_isExitRequested = false;
bool g_startHidden = false;

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

// Запускает приложение и основной цикл сообщений.
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

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
            g_isExitRequested = true;
            DestroyWindow(hWnd);
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
