#pragma once

#include <windows.h>

namespace antivirus::protection
{
struct ServiceProtectionPolicy
{
    bool denyBuiltinUsersStop = false;
    bool denyBuiltinAdministratorsStop = false;
};

// Ужесточает DACL service object, не запрещая управление службой целиком.
bool HardenServiceObject(
    const wchar_t* serviceName,
    const ServiceProtectionPolicy& policy = ServiceProtectionPolicy{});
}
