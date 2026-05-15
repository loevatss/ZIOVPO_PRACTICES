#pragma once

#include <windows.h>

namespace antivirus::protection
{
struct ProcessProtectionPolicy
{
    bool denyBuiltinAdministratorsTerminate = true;
};

// Ужесточает DACL текущего процесса через обычный process HANDLE.
bool HardenCurrentProcess(const ProcessProtectionPolicy& policy = ProcessProtectionPolicy{});

// Ужесточает DACL процесса по уже открытому HANDLE, например из CreateProcessAsUserW.
bool HardenProcessHandle(
    HANDLE processHandle,
    DWORD processId,
    const ProcessProtectionPolicy& policy = ProcessProtectionPolicy{});
}
