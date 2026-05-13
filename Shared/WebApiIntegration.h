#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winhttp.h>

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace antivirus::web
{
struct ApiError
{
    int httpStatus = 0;
    std::string timestamp;
    std::string error;
    std::string message;
    std::string rawBody;
};

using AuthError = ApiError;
using LicenseError = ApiError;

struct AuthTokens
{
    std::string accessToken;
    std::string refreshToken;
    std::string accessExpiresAt;
    std::string refreshExpiresAt;
    long long sessionId = 0;
    std::chrono::system_clock::time_point nextRefreshAt{};
};

struct AuthUserInfo
{
    long long id = 0;
    std::string username;
    std::string role;
};

struct LicenseTicket
{
    std::string serverDate;
    long long ticketTtlSeconds = 0;
    std::string licenseActivationDate;
    std::string licenseExpirationDate;
    long long userId = 0;
    long long deviceId = 0;
    bool hasUserId = false;
    bool hasDeviceId = false;
    bool licenseBlocked = false;
};

struct LicenseState
{
    bool hasLicense = false;
    LicenseTicket ticket;
    std::string signature;
    std::chrono::system_clock::time_point nextRefreshAt{};
};

namespace detail
{
// Skips JSON whitespace.
inline size_t SkipWs(const std::string& s, size_t i)
{
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])) != 0)
    {
        ++i;
    }
    return i;
}

// Finds JSON value range by key.
inline bool FindValueRange(const std::string& json, const std::string& key, size_t* begin, size_t* end)
{
    if (begin == nullptr || end == nullptr)
    {
        return false;
    }

    const std::string token = "\"" + key + "\"";
    size_t pos = 0;
    while ((pos = json.find(token, pos)) != std::string::npos)
    {
        size_t colon = SkipWs(json, pos + token.size());
        if (colon >= json.size() || json[colon] != ':')
        {
            ++pos;
            continue;
        }

        size_t valueBegin = SkipWs(json, colon + 1);
        if (valueBegin >= json.size())
        {
            return false;
        }

        const char first = json[valueBegin];
        size_t valueEnd = valueBegin;
        if (first == '"')
        {
            bool esc = false;
            ++valueEnd;
            for (; valueEnd < json.size(); ++valueEnd)
            {
                const char c = json[valueEnd];
                if (esc)
                {
                    esc = false;
                    continue;
                }
                if (c == '\\')
                {
                    esc = true;
                    continue;
                }
                if (c == '"')
                {
                    ++valueEnd;
                    break;
                }
            }
        }
        else if (first == '{')
        {
            int depth = 0;
            bool inString = false;
            bool esc = false;
            for (; valueEnd < json.size(); ++valueEnd)
            {
                const char c = json[valueEnd];
                if (inString)
                {
                    if (esc)
                    {
                        esc = false;
                        continue;
                    }
                    if (c == '\\')
                    {
                        esc = true;
                        continue;
                    }
                    if (c == '"')
                    {
                        inString = false;
                    }
                    continue;
                }
                if (c == '"')
                {
                    inString = true;
                    continue;
                }
                if (c == '{')
                {
                    ++depth;
                }
                if (c == '}')
                {
                    --depth;
                    if (depth == 0)
                    {
                        ++valueEnd;
                        break;
                    }
                }
            }
        }
        else
        {
            while (valueEnd < json.size() && json[valueEnd] != ',' && json[valueEnd] != '}' && json[valueEnd] != ']')
            {
                ++valueEnd;
            }
        }

        *begin = valueBegin;
        *end = valueEnd;
        return true;
    }

    return false;
}

// Reads JSON string field.
inline bool GetString(const std::string& json, const std::string& key, std::string* value)
{
    if (value == nullptr)
    {
        return false;
    }

    size_t b = 0;
    size_t e = 0;
    if (!FindValueRange(json, key, &b, &e) || b >= e || json[b] != '"' || json[e - 1] != '"')
    {
        return false;
    }

    std::string out;
    out.reserve(e - b - 2);
    bool esc = false;
    for (size_t i = b + 1; i + 1 < e; ++i)
    {
        char c = json[i];
        if (esc)
        {
            esc = false;
            switch (c)
            {
            case '"':
            case '\\':
            case '/':
                out.push_back(c);
                break;
            case 'n':
                out.push_back('\n');
                break;
            case 'r':
                out.push_back('\r');
                break;
            case 't':
                out.push_back('\t');
                break;
            default:
                out.push_back('?');
                break;
            }
            continue;
        }
        if (c == '\\')
        {
            esc = true;
            continue;
        }
        out.push_back(c);
    }

    *value = std::move(out);
    return true;
}

// Reads JSON int64 field.
inline bool GetInt64(const std::string& json, const std::string& key, long long* value)
{
    if (value == nullptr)
    {
        return false;
    }

    size_t b = 0;
    size_t e = 0;
    if (!FindValueRange(json, key, &b, &e) || b >= e)
    {
        return false;
    }

    const std::string t = json.substr(b, e - b);
    char* p = nullptr;
    errno = 0;
    const long long v = std::strtoll(t.c_str(), &p, 10);
    if (p == t.c_str() || errno != 0)
    {
        return false;
    }

    *value = v;
    return true;
}

// Reads JSON bool field.
inline bool GetBool(const std::string& json, const std::string& key, bool* value)
{
    if (value == nullptr)
    {
        return false;
    }

    size_t b = 0;
    size_t e = 0;
    if (!FindValueRange(json, key, &b, &e))
    {
        return false;
    }

    const std::string t = json.substr(b, e - b);
    if (t == "true")
    {
        *value = true;
        return true;
    }
    if (t == "false")
    {
        *value = false;
        return true;
    }
    return false;
}

// Reads nested JSON object field.
inline bool GetObject(const std::string& json, const std::string& key, std::string* value)
{
    if (value == nullptr)
    {
        return false;
    }

    size_t b = 0;
    size_t e = 0;
    if (!FindValueRange(json, key, &b, &e) || b >= e || json[b] != '{')
    {
        return false;
    }

    *value = json.substr(b, e - b);
    return true;
}

// Escapes string for JSON request.
inline std::string Escape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for (char c : value)
    {
        if (c == '"' || c == '\\')
        {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    return out;
}

// Decodes base64url payload.
inline bool Base64UrlDecode(const std::string& in, std::string* out)
{
    if (out == nullptr)
    {
        return false;
    }

    std::string s = in;
    std::replace(s.begin(), s.end(), '-', '+');
    std::replace(s.begin(), s.end(), '_', '/');
    while (s.size() % 4 != 0)
    {
        s.push_back('=');
    }

    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int table[256];
    std::fill(std::begin(table), std::end(table), -1);
    for (int i = 0; alphabet[i] != '\0'; ++i)
    {
        table[static_cast<unsigned char>(alphabet[i])] = i;
    }

    std::string decoded;
    decoded.reserve((s.size() / 4) * 3);
    for (size_t i = 0; i < s.size(); i += 4)
    {
        int v[4];
        for (int j = 0; j < 4; ++j)
        {
            const char c = s[i + j];
            v[j] = (c == '=') ? -2 : table[static_cast<unsigned char>(c)];
            if (v[j] == -1)
            {
                return false;
            }
        }
        if (v[0] < 0 || v[1] < 0)
        {
            return false;
        }
        decoded.push_back(static_cast<char>((v[0] << 2) | (v[1] >> 4)));
        if (v[2] >= 0)
        {
            decoded.push_back(static_cast<char>(((v[1] & 0x0F) << 4) | (v[2] >> 2)));
            if (v[3] >= 0)
            {
                decoded.push_back(static_cast<char>(((v[2] & 0x03) << 6) | v[3]));
            }
        }
    }

    *out = std::move(decoded);
    return true;
}

// Extracts JWT exp claim.
inline bool GetJwtExp(const std::string& token, long long* exp)
{
    if (exp == nullptr)
    {
        return false;
    }
    const size_t d1 = token.find('.');
    const size_t d2 = (d1 == std::string::npos) ? std::string::npos : token.find('.', d1 + 1);
    if (d1 == std::string::npos || d2 == std::string::npos || d2 <= d1 + 1)
    {
        return false;
    }
    std::string payload;
    if (!Base64UrlDecode(token.substr(d1 + 1, d2 - d1 - 1), &payload))
    {
        return false;
    }
    return GetInt64(payload, "exp", exp);
}

// Calculates next JWT refresh time.
inline std::chrono::system_clock::time_point CalcJwtRefresh(const std::string& accessToken)
{
    const auto now = std::chrono::system_clock::now();
    long long exp = 0;
    if (!GetJwtExp(accessToken, &exp) || exp <= 0)
    {
        return now + std::chrono::minutes(5);
    }
    const auto expiration = std::chrono::system_clock::time_point(std::chrono::seconds(exp));
    const auto preferred = expiration - std::chrono::seconds(60);
    return preferred > now ? preferred : (now + std::chrono::seconds(15));
}

// Calculates next ticket refresh time.
inline std::chrono::system_clock::time_point CalcTicketRefresh(const LicenseTicket& ticket)
{
    const auto now = std::chrono::system_clock::now();
    if (ticket.ticketTtlSeconds <= 0)
    {
        return now + std::chrono::minutes(2);
    }
    const long long margin = std::clamp(ticket.ticketTtlSeconds / 10, 5LL, 60LL);
    const long long sec = std::max(15LL, ticket.ticketTtlSeconds - margin);
    return now + std::chrono::seconds(sec);
}
} // namespace detail

class InMemorySession
{
public:
    // Clears all auth/license secrets from RAM.
    void Clear();
    // Stores auth tokens and computes next refresh time.
    void SetAuthTokens(AuthTokens tokens);
    // Stores current user info in RAM.
    void SetAuthUserInfo(const AuthUserInfo& userInfo);
    // Stores license ticket/signature and computes next refresh time.
    void SetLicenseState(LicenseState state);
    // Returns true when auth tokens are present.
    bool HasAuthTokens() const;
    // Returns true when license ticket is present.
    bool HasLicenseTicket() const;
    // Returns a copy of auth tokens.
    AuthTokens GetAuthTokens() const;
    // Returns a copy of user info.
    AuthUserInfo GetAuthUserInfo() const;
    // Returns a copy of license state.
    LicenseState GetLicenseState() const;

private:
    mutable std::mutex mutex_;
    AuthTokens tokens_{};
    AuthUserInfo userInfo_{};
    LicenseState licenseState_{};
    bool hasTokens_ = false;
    bool hasLicense_ = false;
};

class ApiClient
{
public:
    // Creates HTTPS client for Java API base URL.
    explicit ApiClient(std::wstring baseUrl);
    // Returns normalized base URL.
    const std::wstring& GetBaseUrl() const;
    // Calls /api/auth/login.
    bool Login(const std::string& username, const std::string& password, AuthTokens* tokens, AuthError* error) const;
    // Calls /api/auth/refresh.
    bool RefreshTokens(const std::string& refreshToken, AuthTokens* tokens, AuthError* error) const;
    // Calls /api/users/me.
    bool GetCurrentUser(const std::string& accessToken, AuthUserInfo* userInfo, AuthError* error) const;
    // Calls /api/licenses/activate.
    bool ActivateLicense(const std::string& accessToken, const std::string& activationKey, const std::string& deviceName, const std::string& deviceMac, LicenseState* state, LicenseError* error) const;
    // Calls /api/licenses/check.
    bool CheckLicense(const std::string& accessToken, long long productId, const std::string& deviceMac, LicenseState* state, LicenseError* error) const;
    // Calls /api/licenses/renew.
    bool RenewLicense(const std::string& accessToken, const std::string& activationKey, const std::string& deviceMac, LicenseState* state, LicenseError* error) const;

private:
    struct HttpResponse
    {
        int statusCode = 0;
        std::string body;
    };
    struct WinHttpCloser
    {
        void operator()(HINTERNET h) const
        {
            if (h != nullptr)
            {
                WinHttpCloseHandle(h);
            }
        }
    };
    using WinHttpHandle = std::unique_ptr<std::remove_pointer_t<HINTERNET>, WinHttpCloser>;

    // Parses host/port/path from base URL.
    void ParseBaseUrl();
    // Builds full request path from root and endpoint.
    std::wstring BuildPath(const std::wstring& endpoint) const;
    // Sends JSON over HTTPS and returns status/body.
    bool SendJson(const std::wstring& method, const std::wstring& endpoint, const std::string& body, const std::string& bearerToken, HttpResponse* response, ApiError* transportError) const;
    // Parses AuthTokens response model.
    static bool ParseAuthTokens(const std::string& json, AuthTokens* tokens);
    // Parses AuthUserInfo response model.
    static bool ParseUserInfo(const std::string& json, AuthUserInfo* userInfo);
    // Parses LicenseState response model.
    static bool ParseLicenseState(const std::string& json, LicenseState* state);
    // Builds API error from non-2xx response JSON.
    static ApiError BuildApiError(int statusCode, const std::string& responseBody);
    // Builds transport error for WinHTTP failures.
    static ApiError BuildTransportError(DWORD win32Error, const char* prefix);
    // Returns true for successful HTTP status code.
    static bool IsSuccess(int statusCode);

    std::wstring baseUrl_;
    std::wstring host_;
    std::wstring rootPath_ = L"/";
    INTERNET_PORT port_ = INTERNET_DEFAULT_HTTPS_PORT;
    bool secure_ = true;
};

// Clears all auth/license secrets from RAM.
inline void InMemorySession::Clear()
{
    std::lock_guard<std::mutex> guard(mutex_);
    tokens_ = AuthTokens{};
    userInfo_ = AuthUserInfo{};
    licenseState_ = LicenseState{};
    hasTokens_ = false;
    hasLicense_ = false;
}

// Stores auth tokens and computes next refresh time.
inline void InMemorySession::SetAuthTokens(AuthTokens tokens)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (tokens.nextRefreshAt == std::chrono::system_clock::time_point{})
    {
        tokens.nextRefreshAt = detail::CalcJwtRefresh(tokens.accessToken);
    }
    tokens_ = std::move(tokens);
    hasTokens_ = !tokens_.accessToken.empty() && !tokens_.refreshToken.empty();
}

// Stores current user info in RAM.
inline void InMemorySession::SetAuthUserInfo(const AuthUserInfo& userInfo)
{
    std::lock_guard<std::mutex> guard(mutex_);
    userInfo_ = userInfo;
}

// Stores license ticket/signature and computes next refresh time.
inline void InMemorySession::SetLicenseState(LicenseState state)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (state.hasLicense && state.nextRefreshAt == std::chrono::system_clock::time_point{})
    {
        state.nextRefreshAt = detail::CalcTicketRefresh(state.ticket);
    }
    licenseState_ = std::move(state);
    hasLicense_ = licenseState_.hasLicense;
}

// Returns true when auth tokens are present.
inline bool InMemorySession::HasAuthTokens() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return hasTokens_;
}

// Returns true when license ticket is present.
inline bool InMemorySession::HasLicenseTicket() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return hasLicense_;
}

// Returns a copy of auth tokens.
inline AuthTokens InMemorySession::GetAuthTokens() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return tokens_;
}

// Returns a copy of user info.
inline AuthUserInfo InMemorySession::GetAuthUserInfo() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return userInfo_;
}

// Returns a copy of license state.
inline LicenseState InMemorySession::GetLicenseState() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return licenseState_;
}

// Creates HTTPS client for Java API base URL.
inline ApiClient::ApiClient(std::wstring baseUrl) : baseUrl_(std::move(baseUrl))
{
    ParseBaseUrl();
}

// Returns normalized base URL.
inline const std::wstring& ApiClient::GetBaseUrl() const
{
    return baseUrl_;
}

// Calls /api/auth/login.
inline bool ApiClient::Login(
    const std::string& username,
    const std::string& password,
    AuthTokens* tokens,
    AuthError* error) const
{
    const std::string body = std::string("{\"username\":\"")
        + detail::Escape(username)
        + "\",\"password\":\""
        + detail::Escape(password)
        + "\"}";

    HttpResponse response;
    ApiError transportError;
    if (!SendJson(L"POST", L"/api/auth/login", body, "", &response, &transportError))
    {
        if (error != nullptr)
        {
            *error = std::move(transportError);
        }
        return false;
    }

    if (!IsSuccess(response.statusCode))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
        }
        return false;
    }

    if (!ParseAuthTokens(response.body, tokens))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
            error->error = "Parse Error";
            error->message = "Cannot parse TokenPairResponse";
        }
        return false;
    }

    return true;
}

// Calls /api/auth/refresh.
inline bool ApiClient::RefreshTokens(
    const std::string& refreshToken,
    AuthTokens* tokens,
    AuthError* error) const
{
    const std::string body =
        std::string("{\"refreshToken\":\"") + detail::Escape(refreshToken) + "\"}";

    HttpResponse response;
    ApiError transportError;
    if (!SendJson(L"POST", L"/api/auth/refresh", body, "", &response, &transportError))
    {
        if (error != nullptr)
        {
            *error = std::move(transportError);
        }
        return false;
    }

    if (!IsSuccess(response.statusCode))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
        }
        return false;
    }

    if (!ParseAuthTokens(response.body, tokens))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
            error->error = "Parse Error";
            error->message = "Cannot parse TokenPairResponse";
        }
        return false;
    }

    return true;
}

// Calls /api/users/me.
inline bool ApiClient::GetCurrentUser(
    const std::string& accessToken,
    AuthUserInfo* userInfo,
    AuthError* error) const
{
    HttpResponse response;
    ApiError transportError;
    if (!SendJson(L"GET", L"/api/users/me", "", accessToken, &response, &transportError))
    {
        if (error != nullptr)
        {
            *error = std::move(transportError);
        }
        return false;
    }

    if (!IsSuccess(response.statusCode))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
        }
        return false;
    }

    if (!ParseUserInfo(response.body, userInfo))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
            error->error = "Parse Error";
            error->message = "Cannot parse UserResponse";
        }
        return false;
    }

    return true;
}

// Calls /api/licenses/activate.
inline bool ApiClient::ActivateLicense(
    const std::string& accessToken,
    const std::string& activationKey,
    const std::string& deviceName,
    const std::string& deviceMac,
    LicenseState* state,
    LicenseError* error) const
{
    const std::string body = std::string("{\"activationKey\":\"")
        + detail::Escape(activationKey)
        + "\",\"deviceName\":\""
        + detail::Escape(deviceName)
        + "\",\"deviceMac\":\""
        + detail::Escape(deviceMac)
        + "\"}";

    HttpResponse response;
    ApiError transportError;
    if (!SendJson(L"POST", L"/api/licenses/activate", body, accessToken, &response, &transportError))
    {
        if (error != nullptr)
        {
            *error = std::move(transportError);
        }
        return false;
    }

    if (!IsSuccess(response.statusCode))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
        }
        return false;
    }

    if (!ParseLicenseState(response.body, state))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
            error->error = "Parse Error";
            error->message = "Cannot parse TicketResponse";
        }
        return false;
    }

    return true;
}

// Calls /api/licenses/check.
inline bool ApiClient::CheckLicense(
    const std::string& accessToken,
    long long productId,
    const std::string& deviceMac,
    LicenseState* state,
    LicenseError* error) const
{
    const std::string body = std::string("{\"productId\":")
        + std::to_string(productId)
        + ",\"deviceMac\":\""
        + detail::Escape(deviceMac)
        + "\"}";

    HttpResponse response;
    ApiError transportError;
    if (!SendJson(L"POST", L"/api/licenses/check", body, accessToken, &response, &transportError))
    {
        if (error != nullptr)
        {
            *error = std::move(transportError);
        }
        return false;
    }

    if (!IsSuccess(response.statusCode))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
        }
        return false;
    }

    if (!ParseLicenseState(response.body, state))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
            error->error = "Parse Error";
            error->message = "Cannot parse TicketResponse";
        }
        return false;
    }

    return true;
}

// Calls /api/licenses/renew.
inline bool ApiClient::RenewLicense(
    const std::string& accessToken,
    const std::string& activationKey,
    const std::string& deviceMac,
    LicenseState* state,
    LicenseError* error) const
{
    const std::string body = std::string("{\"activationKey\":\"")
        + detail::Escape(activationKey)
        + "\",\"deviceMac\":\""
        + detail::Escape(deviceMac)
        + "\"}";

    HttpResponse response;
    ApiError transportError;
    if (!SendJson(L"POST", L"/api/licenses/renew", body, accessToken, &response, &transportError))
    {
        if (error != nullptr)
        {
            *error = std::move(transportError);
        }
        return false;
    }

    if (!IsSuccess(response.statusCode))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
        }
        return false;
    }

    if (!ParseLicenseState(response.body, state))
    {
        if (error != nullptr)
        {
            *error = BuildApiError(response.statusCode, response.body);
            error->error = "Parse Error";
            error->message = "Cannot parse TicketResponse";
        }
        return false;
    }

    return true;
}

// Parses host/port/path from base URL.
inline void ApiClient::ParseBaseUrl()
{
    URL_COMPONENTSW parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (!WinHttpCrackUrl(baseUrl_.c_str(), 0, 0, &parts))
    {
        return;
    }

    if (parts.lpszHostName != nullptr && parts.dwHostNameLength > 0)
    {
        host_.assign(parts.lpszHostName, parts.dwHostNameLength);
    }

    rootPath_ = L"/";
    if (parts.lpszUrlPath != nullptr && parts.dwUrlPathLength > 0)
    {
        rootPath_.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    }
    if (parts.lpszExtraInfo != nullptr && parts.dwExtraInfoLength > 0)
    {
        rootPath_.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    }

    port_ = parts.nPort;
    secure_ = (parts.nScheme == INTERNET_SCHEME_HTTPS);
}

// Builds full request path from root and endpoint.
inline std::wstring ApiClient::BuildPath(const std::wstring& endpoint) const
{
    std::wstring base = rootPath_.empty() ? L"/" : rootPath_;
    if (!endpoint.empty() && endpoint.front() == L'/' && !base.empty() && base.back() == L'/')
    {
        base.pop_back();
    }
    else if (!endpoint.empty() && endpoint.front() != L'/' && !base.empty() && base.back() != L'/')
    {
        base.push_back(L'/');
    }
    return base + endpoint;
}

// Sends JSON over HTTPS and returns status/body.
inline bool ApiClient::SendJson(
    const std::wstring& method,
    const std::wstring& endpoint,
    const std::string& body,
    const std::string& bearerToken,
    HttpResponse* response,
    ApiError* transportError) const
{
    if (response == nullptr)
    {
        if (transportError != nullptr)
        {
            *transportError = BuildTransportError(ERROR_INVALID_PARAMETER, "SendJson");
        }
        return false;
    }

    const std::wstring path = BuildPath(endpoint);
    WinHttpHandle session(
        WinHttpOpen(L"AntivirusService/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session)
    {
        if (transportError != nullptr)
        {
            *transportError = BuildTransportError(GetLastError(), "WinHttpOpen");
        }
        return false;
    }

    WinHttpHandle connection(WinHttpConnect(session.get(), host_.c_str(), port_, 0));
    if (!connection)
    {
        if (transportError != nullptr)
        {
            *transportError = BuildTransportError(GetLastError(), "WinHttpConnect");
        }
        return false;
    }

    const DWORD flags = secure_ ? WINHTTP_FLAG_SECURE : 0;
    WinHttpHandle request(WinHttpOpenRequest(
        connection.get(),
        method.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags));
    if (!request)
    {
        if (transportError != nullptr)
        {
            *transportError = BuildTransportError(GetLastError(), "WinHttpOpenRequest");
        }
        return false;
    }

    if (secure_)
    {
        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));
    }

    std::wstring headers = L"Accept: application/json\r\nContent-Type: application/json\r\n";
    if (!bearerToken.empty())
    {
        headers += L"Authorization: Bearer ";
        headers.append(bearerToken.begin(), bearerToken.end());
        headers += L"\r\n";
    }

    void* bodyPtr = WINHTTP_NO_REQUEST_DATA;
    DWORD bodySize = 0;
    if (!body.empty())
    {
        bodyPtr = const_cast<char*>(body.data());
        bodySize = static_cast<DWORD>(body.size());
    }

    if (!WinHttpSendRequest(request.get(), headers.c_str(), static_cast<DWORD>(headers.size()), bodyPtr, bodySize, bodySize, 0))
    {
        if (transportError != nullptr)
        {
            *transportError = BuildTransportError(GetLastError(), "WinHttpSendRequest");
        }
        return false;
    }

    if (!WinHttpReceiveResponse(request.get(), nullptr))
    {
        if (transportError != nullptr)
        {
            *transportError = BuildTransportError(GetLastError(), "WinHttpReceiveResponse");
        }
        return false;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(
        request.get(),
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusSize,
        WINHTTP_NO_HEADER_INDEX))
    {
        if (transportError != nullptr)
        {
            *transportError = BuildTransportError(GetLastError(), "WinHttpQueryHeaders");
        }
        return false;
    }

    std::string responseBody;
    for (;;)
    {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &available))
        {
            if (transportError != nullptr)
            {
                *transportError = BuildTransportError(GetLastError(), "WinHttpQueryDataAvailable");
            }
            return false;
        }
        if (available == 0)
        {
            break;
        }

        std::vector<char> chunk(available);
        DWORD read = 0;
        if (!WinHttpReadData(request.get(), chunk.data(), available, &read))
        {
            if (transportError != nullptr)
            {
                *transportError = BuildTransportError(GetLastError(), "WinHttpReadData");
            }
            return false;
        }
        responseBody.append(chunk.data(), read);
    }

    response->statusCode = static_cast<int>(statusCode);
    response->body = std::move(responseBody);
    return true;
}

// Parses AuthTokens response model.
inline bool ApiClient::ParseAuthTokens(const std::string& json, AuthTokens* tokens)
{
    if (tokens == nullptr)
    {
        return false;
    }

    AuthTokens t;
    if (!detail::GetString(json, "accessToken", &t.accessToken))
    {
        return false;
    }
    if (!detail::GetString(json, "refreshToken", &t.refreshToken))
    {
        return false;
    }
    detail::GetString(json, "accessExpiresAt", &t.accessExpiresAt);
    detail::GetString(json, "refreshExpiresAt", &t.refreshExpiresAt);
    detail::GetInt64(json, "sessionId", &t.sessionId);
    t.nextRefreshAt = detail::CalcJwtRefresh(t.accessToken);
    *tokens = std::move(t);
    return true;
}

// Parses AuthUserInfo response model.
inline bool ApiClient::ParseUserInfo(const std::string& json, AuthUserInfo* userInfo)
{
    if (userInfo == nullptr)
    {
        return false;
    }
    AuthUserInfo u;
    if (!detail::GetInt64(json, "id", &u.id))
    {
        return false;
    }
    if (!detail::GetString(json, "username", &u.username))
    {
        return false;
    }
    if (!detail::GetString(json, "role", &u.role))
    {
        return false;
    }
    *userInfo = std::move(u);
    return true;
}

// Parses LicenseState response model.
inline bool ApiClient::ParseLicenseState(const std::string& json, LicenseState* state)
{
    if (state == nullptr)
    {
        return false;
    }

    std::string ticketJson;
    if (!detail::GetObject(json, "ticket", &ticketJson))
    {
        *state = LicenseState{};
        return true;
    }

    LicenseState s;
    s.hasLicense = true;
    detail::GetString(ticketJson, "serverDate", &s.ticket.serverDate);
    detail::GetInt64(ticketJson, "ticketTtlSeconds", &s.ticket.ticketTtlSeconds);
    detail::GetString(ticketJson, "licenseActivationDate", &s.ticket.licenseActivationDate);
    if (!detail::GetString(ticketJson, "licenseExpirationDate", &s.ticket.licenseExpirationDate))
    {
        detail::GetString(ticketJson, "endingDate", &s.ticket.licenseExpirationDate);
    }
    detail::GetBool(ticketJson, "licenseBlocked", &s.ticket.licenseBlocked);
    long long userId = 0;
    if (detail::GetInt64(ticketJson, "userId", &userId))
    {
        s.ticket.hasUserId = true;
        s.ticket.userId = userId;
    }
    long long deviceId = 0;
    if (detail::GetInt64(ticketJson, "deviceId", &deviceId))
    {
        s.ticket.hasDeviceId = true;
        s.ticket.deviceId = deviceId;
    }
    detail::GetString(json, "signature", &s.signature);
    s.nextRefreshAt = detail::CalcTicketRefresh(s.ticket);
    *state = std::move(s);
    return true;
}

// Builds API error from non-2xx response JSON.
inline ApiError ApiClient::BuildApiError(int statusCode, const std::string& responseBody)
{
    ApiError e;
    e.httpStatus = statusCode;
    e.rawBody = responseBody;
    detail::GetString(responseBody, "timestamp", &e.timestamp);
    detail::GetString(responseBody, "error", &e.error);
    detail::GetString(responseBody, "message", &e.message);
    if (e.message.empty())
    {
        e.message = "HTTP error " + std::to_string(statusCode);
    }
    return e;
}

// Builds transport error for WinHTTP failures.
inline ApiError ApiClient::BuildTransportError(DWORD win32Error, const char* prefix)
{
    ApiError e;
    e.httpStatus = 0;
    e.error = "Transport Error";
    e.message = std::string(prefix == nullptr ? "WinHTTP" : prefix)
        + " failed with Win32="
        + std::to_string(win32Error);
    return e;
}

// Returns true for successful HTTP status code.
inline bool ApiClient::IsSuccess(int statusCode)
{
    return statusCode >= 200 && statusCode < 300;
}
} // namespace antivirus::web
