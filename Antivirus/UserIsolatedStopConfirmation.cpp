#include "UserIsolatedStopConfirmation.h"

#include "UserDesktopSession.h"

#include <windows.h>

#include <cwchar>

namespace antivirus::ui
{
namespace
{
constexpr DWORD kWindowReadyTimeoutMs = 5000;
constexpr DWORD kUserDecisionTimeoutMs = 60000;
constexpr int kWindowWidth = 600;
constexpr int kWindowHeight = 260;
constexpr int kConfirmButtonId = 20001;
constexpr int kCancelButtonId = 20002;
constexpr UINT_PTR kDecisionTimerId = 21001;
constexpr UINT kForceCancelMessage = WM_APP + 101;
volatile LONG g_confirmationActive = 0;

struct ConfirmationContext
{
    HDESK isolatedDesktop = nullptr;
    HANDLE startupEvent = nullptr;
    HINSTANCE instance = nullptr;
    HWND window = nullptr;
    DWORD uiThreadId = 0;
    volatile LONG completed = 0;
    bool windowReady = false;
    StopConfirmationResult result = StopConfirmationResult::Failed;
};

// Пишет диагностическое сообщение confirmation flow с кодом Win32.
void DebugLogWin32(const wchar_t* operation, DWORD error)
{
    wchar_t message[256]{};
    swprintf_s(
        message,
        L"[StopConfirmation] %ls failed. Win32 error: %lu\r\n",
        operation,
        error);
    OutputDebugStringW(message);
}

// Пишет обычное диагностическое сообщение confirmation flow.
void DebugLogInfo(const wchar_t* message)
{
    wchar_t buffer[256]{};
    swprintf_s(buffer, L"[StopConfirmation] %ls\r\n", message);
    OutputDebugStringW(buffer);
}

class ConfirmationActiveGuard
{
public:
    // Не даёт открыть второе подтверждение поверх уже активного flow.
    bool TryAcquire()
    {
        acquired_ = InterlockedCompareExchange(&g_confirmationActive, 1, 0) == 0;
        if (!acquired_)
        {
            DebugLogInfo(L"confirmation already active");
        }

        return acquired_;
    }

    ~ConfirmationActiveGuard()
    {
        if (acquired_)
        {
            InterlockedExchange(&g_confirmationActive, 0);
        }
    }

private:
    bool acquired_ = false;
};

// Пишет HWND confirmation window в OutputDebugStringW.
void DebugLogHwnd(HWND window)
{
    wchar_t message[256]{};
    swprintf_s(
        message,
        L"[StopConfirmation] CreateWindowExW HWND value: 0x%p\r\n",
        window);
    OutputDebugStringW(message);
}

// Возвращает имя desktop для указанного desktop handle.
std::wstring QueryDesktopName(HDESK desktop)
{
    if (desktop == nullptr)
    {
        return {};
    }

    DWORD bytesNeeded = 0;
    GetUserObjectInformationW(desktop, UOI_NAME, nullptr, 0, &bytesNeeded);
    if (bytesNeeded == 0)
    {
        return {};
    }

    std::wstring name(bytesNeeded / sizeof(wchar_t), L'\0');
    if (!GetUserObjectInformationW(
        desktop,
        UOI_NAME,
        name.data(),
        bytesNeeded,
        &bytesNeeded))
    {
        DebugLogWin32(L"GetUserObjectInformationW(UOI_NAME)", GetLastError());
        return {};
    }

    while (!name.empty() && name.back() == L'\0')
    {
        name.pop_back();
    }

    return name;
}

// Логирует desktop, к которому сейчас привязан UI thread.
void LogCurrentThreadDesktop(const wchar_t* stage)
{
    HDESK threadDesktop = GetThreadDesktop(GetCurrentThreadId());
    const std::wstring desktopName = QueryDesktopName(threadDesktop);
    wchar_t message[256]{};
    swprintf_s(
        message,
        L"[StopConfirmation] %ls thread desktop: %ls\r\n",
        stage,
        desktopName.empty() ? L"<unknown>" : desktopName.c_str());
    OutputDebugStringW(message);
}

// Центрирует окно подтверждения на текущем экране.
void CenterWindow(HWND window)
{
    const int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    const int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    const int x = max(0, (screenWidth - kWindowWidth) / 2);
    const int y = max(0, (screenHeight - kWindowHeight) / 2);
    SetWindowPos(window, HWND_TOPMOST, x, y, kWindowWidth, kWindowHeight, SWP_SHOWWINDOW);
}

// Завершает confirmation window с выбранным результатом.
void CompleteConfirmation(
    ConfirmationContext* context,
    StopConfirmationResult result,
    const wchar_t* logMessage)
{
    if (context == nullptr)
    {
        return;
    }

    if (InterlockedExchange(&context->completed, 1) != 0)
    {
        return;
    }

    context->result = result;
    DebugLogInfo(logMessage);

    if (context->window != nullptr)
    {
        DestroyWindow(context->window);
    }
    else
    {
        PostQuitMessage(0);
    }
}

// Обрабатывает сообщения confirmation window.
LRESULT CALLBACK ConfirmationWndProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    ConfirmationContext* context =
        reinterpret_cast<ConfirmationContext*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    if (message == WM_NCCREATE)
    {
        const auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
        context = static_cast<ConfirmationContext*>(createStruct->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(context));
    }

    switch (message)
    {
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case kConfirmButtonId:
            CompleteConfirmation(context, StopConfirmationResult::Confirmed, L"Confirm clicked");
            return 0;
        case kCancelButtonId:
            CompleteConfirmation(context, StopConfirmationResult::Rejected, L"Cancel clicked");
            return 0;
        default:
            break;
        }
        break;
    case WM_CLOSE:
        DebugLogInfo(L"WM_CLOSE");
        CompleteConfirmation(context, StopConfirmationResult::Rejected, L"Cancel clicked");
        return 0;
    case WM_TIMER:
        if (wParam == kDecisionTimerId)
        {
            DebugLogInfo(L"timeout");
            CompleteConfirmation(context, StopConfirmationResult::Rejected, L"Cancel clicked");
            return 0;
        }
        break;
    case kForceCancelMessage:
        DebugLogInfo(L"timeout");
        CompleteConfirmation(context, StopConfirmationResult::Rejected, L"Cancel clicked");
        return 0;
    case WM_DESTROY:
        KillTimer(window, kDecisionTimerId);
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return DefWindowProcW(window, message, wParam, lParam);
}

// Назначает DEFAULT_GUI_FONT дочернему контролу.
void ApplyDefaultGuiFont(HWND control)
{
    HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    if (control != nullptr && font != nullptr)
    {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
}

// Создаёт текст и кнопки внутри confirmation window.
bool CreateConfirmationControls(HWND window)
{
    HWND label = CreateWindowExW(
        0,
        L"STATIC",
        L"Confirm service stop?",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        40,
        44,
        520,
        36,
        window,
        nullptr,
        nullptr,
        nullptr);
    HWND confirmButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Stop Service",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        160,
        140,
        130,
        34,
        window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kConfirmButtonId)),
        nullptr,
        nullptr);
    HWND cancelButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Cancel",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        310,
        140,
        130,
        34,
        window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCancelButtonId)),
        nullptr,
        nullptr);

    if (label == nullptr || confirmButton == nullptr || cancelButton == nullptr)
    {
        DebugLogWin32(L"CreateWindowExW(child controls)", GetLastError());
        return false;
    }

    ApplyDefaultGuiFont(label);
    ApplyDefaultGuiFont(confirmButton);
    ApplyDefaultGuiFont(cancelButton);
    SetFocus(cancelButton);
    DebugLogInfo(L"controls created");
    return true;
}

// Регистрирует класс окна подтверждения на isolated desktop.
bool RegisterConfirmationWindowClass(HINSTANCE instance, const wchar_t* className)
{
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = ConfirmationWndProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = className;

    if (RegisterClassExW(&windowClass) == 0)
    {
        DebugLogWin32(L"RegisterClassExW", GetLastError());
        return false;
    }

    DebugLogInfo(L"RegisterClassExW succeeded");
    return true;
}

// Создаёт top-level confirmation window после SetThreadDesktop.
HWND CreateConfirmationWindow(
    ConfirmationContext* context,
    HINSTANCE instance,
    const wchar_t* className)
{
    HWND window = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_APPWINDOW,
        className,
        L"Antivirus",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        kWindowWidth,
        kWindowHeight,
        nullptr,
        nullptr,
        instance,
        context);
    if (window == nullptr)
    {
        DebugLogWin32(L"CreateWindowExW", GetLastError());
        return nullptr;
    }

    DebugLogHwnd(window);
    CenterWindow(window);
    return window;
}

// Обрабатывает hotkeys Enter/Esc до DispatchMessageW.
bool HandleConfirmationHotkey(ConfirmationContext* context, const MSG& message)
{
    if (message.message != WM_KEYDOWN && message.message != WM_SYSKEYDOWN)
    {
        return false;
    }

    if (message.wParam == VK_RETURN)
    {
        CompleteConfirmation(context, StopConfirmationResult::Confirmed, L"Confirm clicked");
        return true;
    }

    if (message.wParam == VK_ESCAPE)
    {
        CompleteConfirmation(context, StopConfirmationResult::Rejected, L"Cancel clicked");
        return true;
    }

    return false;
}

// Выполняет обычный GetMessageW loop confirmation thread.
void RunConfirmationMessageLoop(ConfirmationContext* context)
{
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0)
    {
        if (message.message == kForceCancelMessage)
        {
            DebugLogInfo(L"timeout");
            CompleteConfirmation(context, StopConfirmationResult::Rejected, L"Cancel clicked");
            continue;
        }

        if (HandleConfirmationHotkey(context, message))
        {
            continue;
        }

        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

// Просит UI thread закрыть окно и ждёт полного выхода потока.
void RequestUiThreadExitAndWait(
    ConfirmationContext& context,
    HANDLE uiThread,
    const wchar_t* reason)
{
    DebugLogInfo(reason);

    if (context.window != nullptr)
    {
        PostMessageW(context.window, kForceCancelMessage, 0, 0);
    }

    if (context.uiThreadId != 0)
    {
        PostThreadMessageW(context.uiThreadId, kForceCancelMessage, 0, 0);
    }

    const DWORD waitResult = WaitForSingleObject(uiThread, INFINITE);
    if (waitResult == WAIT_OBJECT_0)
    {
        DebugLogInfo(L"UI thread joined");
    }
    else
    {
        DebugLogWin32(L"WaitForSingleObject(UI thread)", GetLastError());
    }
}

// UI thread: привязывается к isolated desktop до любых UI операций.
DWORD WINAPI ConfirmationThreadProc(LPVOID parameter)
{
    auto* context = static_cast<ConfirmationContext*>(parameter);
    context->uiThreadId = GetCurrentThreadId();

    LogCurrentThreadDesktop(L"before SetThreadDesktop");
    if (!SetThreadDesktop(context->isolatedDesktop))
    {
        DebugLogWin32(L"SetThreadDesktop", GetLastError());
        SetEvent(context->startupEvent);
        DebugLogInfo(L"UI thread exited");
        return 1;
    }

    DebugLogInfo(L"SetThreadDesktop succeeded");
    LogCurrentThreadDesktop(L"after SetThreadDesktop");
    MSG bootstrapMessage{};
    PeekMessageW(&bootstrapMessage, nullptr, WM_USER, WM_USER, PM_NOREMOVE);

    context->instance = GetModuleHandleW(nullptr);
    wchar_t className[128]{};
    swprintf_s(
        className,
        L"AntivirusStopConfirmationWindow_%lu",
        GetCurrentThreadId());

    if (!RegisterConfirmationWindowClass(context->instance, className))
    {
        SetEvent(context->startupEvent);
        DebugLogInfo(L"UI thread exited");
        return 1;
    }

    HWND window = CreateConfirmationWindow(context, context->instance, className);
    if (window == nullptr)
    {
        SetEvent(context->startupEvent);
        DebugLogInfo(L"UI thread exited");
        return 1;
    }

    context->window = window;
    if (!CreateConfirmationControls(window))
    {
        DestroyWindow(window);
        SetEvent(context->startupEvent);
        DebugLogInfo(L"UI thread exited");
        return 1;
    }

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    SetTimer(window, kDecisionTimerId, kUserDecisionTimeoutMs, nullptr);
    context->windowReady = true;
    SetEvent(context->startupEvent);
    DebugLogInfo(L"window ready");

    RunConfirmationMessageLoop(context);
    UnregisterClassW(className, context->instance);
    DebugLogInfo(L"UI thread exited");
    return 0;
}
}

StopConfirmationResult ShowIsolatedStopConfirmation()
{
    ConfirmationActiveGuard activeGuard;
    if (!activeGuard.TryAcquire())
    {
        return StopConfirmationResult::Rejected;
    }

    UserDesktopSession desktopSession;
    if (!desktopSession.Initialize())
    {
        return StopConfirmationResult::Failed;
    }

    HANDLE startupEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (startupEvent == nullptr)
    {
        DebugLogWin32(L"CreateEventW", GetLastError());
        desktopSession.RestoreDefault();
        return StopConfirmationResult::Failed;
    }

    ConfirmationContext context{};
    context.isolatedDesktop = desktopSession.IsolatedDesktop();
    context.startupEvent = startupEvent;

    HANDLE uiThread = CreateThread(
        nullptr,
        0,
        ConfirmationThreadProc,
        &context,
        0,
        nullptr);
    if (uiThread == nullptr)
    {
        DebugLogWin32(L"CreateThread", GetLastError());
        CloseHandle(startupEvent);
        desktopSession.RestoreDefault();
        return StopConfirmationResult::Failed;
    }

    const DWORD startupWait = WaitForSingleObject(startupEvent, kWindowReadyTimeoutMs);
    if (startupWait != WAIT_OBJECT_0 || !context.windowReady)
    {
        desktopSession.RestoreDefault();
        RequestUiThreadExitAndWait(context, uiThread, L"window creation timeout");
        CloseHandle(uiThread);
        CloseHandle(startupEvent);
        return StopConfirmationResult::Failed;
    }

    if (!desktopSession.SwitchToIsolated())
    {
        desktopSession.RestoreDefault();
        RequestUiThreadExitAndWait(context, uiThread, L"SwitchDesktop failed cleanup");
        CloseHandle(uiThread);
        CloseHandle(startupEvent);
        return StopConfirmationResult::Failed;
    }

    const DWORD decisionWait = WaitForSingleObject(uiThread, kUserDecisionTimeoutMs);
    if (decisionWait != WAIT_OBJECT_0)
    {
        desktopSession.RestoreDefault();
        RequestUiThreadExitAndWait(context, uiThread, L"user decision timeout");
        CloseHandle(uiThread);
        CloseHandle(startupEvent);
        return StopConfirmationResult::Rejected;
    }

    desktopSession.RestoreDefault();
    const StopConfirmationResult result = context.result;
    CloseHandle(uiThread);
    CloseHandle(startupEvent);
    return result;
}
}
