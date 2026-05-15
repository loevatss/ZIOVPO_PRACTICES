#include "UserDesktopSession.h"

#include <cwchar>

namespace antivirus::ui
{
namespace
{
// Пишет диагностическое сообщение desktop flow с кодом Win32.
void DebugLogWin32(const wchar_t* operation, DWORD error)
{
    wchar_t message[256]{};
    swprintf_s(
        message,
        L"[UserDesktopSession] %ls failed. Win32 error: %lu\r\n",
        operation,
        error);
    OutputDebugStringW(message);
}

// Пишет успешное диагностическое сообщение desktop flow.
void DebugLogSuccess(const wchar_t* operation)
{
    wchar_t message[256]{};
    swprintf_s(message, L"[UserDesktopSession] %ls succeeded.\r\n", operation);
    OutputDebugStringW(message);
}

// Создаёт уникальное имя desktop внутри текущей window station.
std::wstring BuildIsolatedDesktopName()
{
    wchar_t name[128]{};
    swprintf_s(
        name,
        L"AntivirusStopConfirmation_%lu_%llu",
        GetCurrentProcessId(),
        static_cast<unsigned long long>(GetTickCount64()));
    return name;
}
}

UserDesktopSession::~UserDesktopSession()
{
    Close();
}

bool UserDesktopSession::Initialize()
{
    if (defaultDesktop_ != nullptr || isolatedDesktop_ != nullptr)
    {
        return true;
    }

    defaultDesktop_ = OpenDesktopW(
        L"Default",
        0,
        FALSE,
        DESKTOP_SWITCHDESKTOP | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
    if (defaultDesktop_ == nullptr)
    {
        DebugLogWin32(L"OpenDesktopW(Default)", GetLastError());
        return false;
    }

    DebugLogSuccess(L"OpenDesktopW(Default)");

    isolatedDesktopName_ = BuildIsolatedDesktopName();
    constexpr DWORD isolatedDesktopAccess =
        DESKTOP_CREATEWINDOW |
        DESKTOP_CREATEMENU |
        DESKTOP_ENUMERATE |
        DESKTOP_READOBJECTS |
        DESKTOP_WRITEOBJECTS |
        DESKTOP_SWITCHDESKTOP;

    isolatedDesktop_ = CreateDesktopW(
        isolatedDesktopName_.c_str(),
        nullptr,
        nullptr,
        0,
        isolatedDesktopAccess,
        nullptr);
    if (isolatedDesktop_ == nullptr)
    {
        const DWORD createError = GetLastError();
        CloseDesktop(defaultDesktop_);
        defaultDesktop_ = nullptr;
        DebugLogWin32(L"CreateDesktopW", createError);
        return false;
    }

    DebugLogSuccess(L"CreateDesktopW");
    return true;
}

bool UserDesktopSession::SwitchToIsolated()
{
    if (isolatedDesktop_ == nullptr)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        DebugLogWin32(L"SwitchDesktop(isolated) validation", ERROR_INVALID_HANDLE);
        return false;
    }

    if (!SwitchDesktop(isolatedDesktop_))
    {
        DebugLogWin32(L"SwitchDesktop(isolated)", GetLastError());
        return false;
    }

    DebugLogSuccess(L"SwitchDesktop(isolated)");
    return true;
}

bool UserDesktopSession::RestoreDefault()
{
    if (defaultDesktop_ == nullptr)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        DebugLogWin32(L"SwitchDesktop(Default) validation", ERROR_INVALID_HANDLE);
        return false;
    }

    if (!SwitchDesktop(defaultDesktop_))
    {
        DebugLogWin32(L"SwitchDesktop(Default)", GetLastError());
        return false;
    }

    DebugLogSuccess(L"desktop restored");
    return true;
}

void UserDesktopSession::Close()
{
    if (defaultDesktop_ != nullptr)
    {
        RestoreDefault();
    }

    if (isolatedDesktop_ != nullptr)
    {
        CloseDesktop(isolatedDesktop_);
        isolatedDesktop_ = nullptr;
        DebugLogSuccess(L"CloseDesktop(isolated)");
    }

    if (defaultDesktop_ != nullptr)
    {
        CloseDesktop(defaultDesktop_);
        defaultDesktop_ = nullptr;
        DebugLogSuccess(L"CloseDesktop(Default)");
    }
}
}
