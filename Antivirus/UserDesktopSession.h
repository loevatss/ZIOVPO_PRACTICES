#pragma once

#include <windows.h>

#include <string>

namespace antivirus::ui
{
class UserDesktopSession
{
public:
    UserDesktopSession() = default;
    ~UserDesktopSession();

    UserDesktopSession(const UserDesktopSession&) = delete;
    UserDesktopSession& operator=(const UserDesktopSession&) = delete;

    // Открывает Default desktop и создаёт отдельный desktop для подтверждения.
    bool Initialize();

    // Переключает пользовательскую session на isolated desktop.
    bool SwitchToIsolated();

    // Возвращает пользовательскую session на Default desktop.
    bool RestoreDefault();

    // Закрывает desktop handle'ы после возврата на Default.
    void Close();

    HDESK DefaultDesktop() const { return defaultDesktop_; }
    HDESK IsolatedDesktop() const { return isolatedDesktop_; }
    const std::wstring& IsolatedDesktopName() const { return isolatedDesktopName_; }

private:
    HDESK defaultDesktop_ = nullptr;
    HDESK isolatedDesktop_ = nullptr;
    std::wstring isolatedDesktopName_;
};
}
