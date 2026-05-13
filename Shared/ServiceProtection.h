#pragma once

#include <windows.h>

namespace antivirus::protection
{
struct ServiceProtectionPolicy
{
    bool denyBuiltinAdministratorsStop = true;
};

// Ужесточает DACL service object, не запрещая управление службой целиком.
bool HardenServiceObject(
    const wchar_t* serviceName,
    const ServiceProtectionPolicy& policy = ServiceProtectionPolicy{});
}
