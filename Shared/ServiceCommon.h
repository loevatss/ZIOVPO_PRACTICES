#pragma once

namespace antivirus::common
{
inline constexpr wchar_t kServiceName[] = L"AntivirusService";
inline constexpr wchar_t kServiceDisplayName[] = L"ZIOVPO Antivirus Service";
inline constexpr wchar_t kGuiBinaryName[] = L"TrayApp.exe";
inline constexpr wchar_t kServiceBinaryName[] = L"TrayService.exe";
inline constexpr wchar_t kRpcProtseq[] = L"ncalrpc";
inline constexpr wchar_t kRpcEndpoint[] = L"AntivirusServiceRpcControl";
}
