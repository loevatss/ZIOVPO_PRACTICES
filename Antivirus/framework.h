#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Networking headers used for adapter/MAC discovery.
#include <winsock2.h>
#include <ws2tcpip.h>
// Windows Header Files
#include <windows.h>
#include <iphlpapi.h>
// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
