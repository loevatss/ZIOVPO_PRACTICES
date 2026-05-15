#include "AntivirusDatabaseUpdater.h"

#include "AntivirusScanService.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <system_error>
#include <utility>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Winhttp.lib")

namespace antivirus::service
{
namespace
{
constexpr wchar_t kHttpUserAgent[] = L"AntivirusService/1.0";
constexpr wchar_t kFullEndpoint[] = L"/api/binary/signatures/full";
constexpr wchar_t kIncrementEndpointPrefix[] = L"/api/binary/signatures/increment?since=";
constexpr wchar_t kByIdsEndpoint[] = L"/api/binary/signatures/by-ids";
constexpr uint8_t kManifestStatusActual = 1;
constexpr uint8_t kManifestStatusDeleted = 2;

struct HttpResponse
{
    int statusCode = 0;
    std::wstring contentType;
    std::vector<uint8_t> body;
    std::string error;
};

struct ParsedMultipartPart
{
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;
};

struct BinaryDataRecord
{
    uint64_t payloadOffset = 0;
    std::string threatName;
    std::vector<uint8_t> firstBytes;
    std::vector<uint8_t> remainderHash;
    uint64_t remainderLength = 0;
    uint8_t fileTypeCode = 0;
    uint64_t offsetStart = 0;
    uint64_t offsetEnd = 0;
    uint32_t rawLength = 0;
};

struct BinaryManifestEntry
{
    std::array<uint8_t, 16> recordId{};
    uint8_t statusCode = 0;
    uint64_t updatedAtEpochMillis = 0;
    uint64_t dataOffset = 0;
    uint32_t dataLength = 0;
    std::vector<uint8_t> recordSignatureBytes;
};

struct BinaryManifest
{
    uint16_t version = 0;
    uint8_t exportType = 0;
    uint64_t generatedAtEpochMillis = 0;
    int64_t sinceEpochMillis = -1;
    std::vector<uint8_t> dataSha256;
    std::vector<BinaryManifestEntry> entries;
    std::vector<uint8_t> unsignedBytes;
    std::vector<uint8_t> manifestSignatureBytes;
};

struct ImportedPackage
{
    engine::AvSignatureDatabase database;
    std::set<std::array<uint8_t, 16>> deletedRecordIds;
    size_t skippedRecordCount = 0;
};

class BinaryReader
{
public:
    explicit BinaryReader(const std::vector<uint8_t>& bytes) : bytes_(bytes)
    {
    }

    size_t Position() const
    {
        return position_;
    }

    bool ReadUInt8(uint8_t* value)
    {
        if (value == nullptr || position_ >= bytes_.size())
        {
            return false;
        }

        *value = bytes_[position_++];
        return true;
    }

    bool ReadUInt16(uint16_t* value)
    {
        if (value == nullptr || position_ + 2 > bytes_.size())
        {
            return false;
        }

        *value = static_cast<uint16_t>((bytes_[position_] << 8) | bytes_[position_ + 1]);
        position_ += 2;
        return true;
    }

    bool ReadUInt32(uint32_t* value)
    {
        if (value == nullptr || position_ + 4 > bytes_.size())
        {
            return false;
        }

        uint32_t result = 0;
        for (size_t i = 0; i < 4; ++i)
        {
            result = (result << 8) | bytes_[position_ + i];
        }

        position_ += 4;
        *value = result;
        return true;
    }

    bool ReadUInt64(uint64_t* value)
    {
        if (value == nullptr || position_ + 8 > bytes_.size())
        {
            return false;
        }

        uint64_t result = 0;
        for (size_t i = 0; i < 8; ++i)
        {
            result = (result << 8) | bytes_[position_ + i];
        }

        position_ += 8;
        *value = result;
        return true;
    }

    bool ReadInt64(int64_t* value)
    {
        uint64_t raw = 0;
        if (!ReadUInt64(&raw) || value == nullptr)
        {
            return false;
        }

        *value = static_cast<int64_t>(raw);
        return true;
    }

    bool ReadRaw(size_t byteCount, std::vector<uint8_t>* value)
    {
        if (value == nullptr || position_ + byteCount > bytes_.size())
        {
            return false;
        }

        value->assign(
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_ + byteCount));
        position_ += byteCount;
        return true;
    }

    bool ReadUtf8(std::string* value)
    {
        if (value == nullptr)
        {
            return false;
        }

        uint32_t length = 0;
        std::vector<uint8_t> bytes;
        if (!ReadUInt32(&length) || !ReadRaw(length, &bytes))
        {
            return false;
        }

        value->assign(bytes.begin(), bytes.end());
        return true;
    }

    bool ReadByteArray(std::vector<uint8_t>* value)
    {
        if (value == nullptr)
        {
            return false;
        }

        uint32_t length = 0;
        return ReadUInt32(&length) && ReadRaw(length, value);
    }

private:
    const std::vector<uint8_t>& bytes_;
    size_t position_ = 0;
};

class JsonBuilder
{
public:
    void AddString(const std::string& key, const std::string& value)
    {
        fields_.emplace_back(key, "\"" + Escape(value) + "\"");
    }

    void AddNumber(const std::string& key, uint64_t value)
    {
        fields_.emplace_back(key, std::to_string(value));
    }

    std::vector<uint8_t> BuildCanonicalUtf8() const
    {
        std::vector<std::pair<std::string, std::string>> fields = fields_;
        std::sort(fields.begin(), fields.end(), [](const auto& left, const auto& right) {
            return left.first < right.first;
        });

        std::ostringstream output;
        output << "{";
        for (size_t i = 0; i < fields.size(); ++i)
        {
            if (i != 0)
            {
                output << ",";
            }

            output << "\"" << Escape(fields[i].first) << "\":" << fields[i].second;
        }
        output << "}";

        const std::string json = output.str();
        return std::vector<uint8_t>(json.begin(), json.end());
    }

private:
    static std::string Escape(const std::string& input)
    {
        std::ostringstream output;
        for (const unsigned char ch : input)
        {
            switch (ch)
            {
            case '\"':
                output << "\\\"";
                break;
            case '\\':
                output << "\\\\";
                break;
            case '\b':
                output << "\\b";
                break;
            case '\f':
                output << "\\f";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                if (ch < 0x20)
                {
                    output << "\\u";
                    output << std::hex << std::uppercase;
                    output.width(4);
                    output.fill('0');
                    output << static_cast<int>(ch);
                    output << std::dec << std::nouppercase;
                }
                else
                {
                    output << static_cast<char>(ch);
                }
                break;
            }
        }
        return output.str();
    }

    std::vector<std::pair<std::string, std::string>> fields_;
};

struct WinHttpHandleCloser
{
    void operator()(HINTERNET handle) const
    {
        if (handle != nullptr)
        {
            WinHttpCloseHandle(handle);
        }
    }
};

struct BCryptKeyHandleCloser
{
    void operator()(BCRYPT_KEY_HANDLE handle) const
    {
        if (handle != nullptr)
        {
            BCryptDestroyKey(handle);
        }
    }
};

using UniqueWinHttpHandle = std::unique_ptr<std::remove_pointer_t<HINTERNET>, WinHttpHandleCloser>;
using UniqueBcryptKeyHandle = std::unique_ptr<void, BCryptKeyHandleCloser>;

std::wstring ToWide(const std::string& text)
{
    if (text.empty())
    {
        return {};
    }

    const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (size <= 1)
    {
        return {};
    }

    std::wstring wide(static_cast<size_t>(size - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wide.data(), size);
    return wide;
}

std::string ToNarrow(const std::wstring& text)
{
    if (text.empty())
    {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1)
    {
        return {};
    }

    std::string narrow(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, narrow.data(), size, nullptr, nullptr);
    return narrow;
}

std::string ToHexUpper(const std::vector<uint8_t>& bytes)
{
    std::ostringstream output;
    output << std::hex << std::uppercase;
    for (const uint8_t byte : bytes)
    {
        output.width(2);
        output.fill('0');
        output << static_cast<unsigned int>(byte);
    }
    return output.str();
}

std::string BuildUtcDateFromEpochMillis(uint64_t epochMillis)
{
    const time_t unixTime = static_cast<time_t>(epochMillis / 1000ull);
    std::tm utcTime{};
    gmtime_s(&utcTime, &unixTime);
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utcTime);
    return buffer;
}

std::wstring BuildUtcDateTimeQueryFromEpochMillis(uint64_t epochMillis)
{
    return ToWide(BuildUtcDateFromEpochMillis(epochMillis));
}

std::vector<uint8_t> Sha256(const uint8_t* bytes, size_t byteCount)
{
    BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    DWORD hashLength = 0;
    DWORD copied = 0;
    std::vector<uint8_t> hash;

    if (BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
    {
        return {};
    }

    if (BCryptGetProperty(
            algorithmHandle,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashLength),
            sizeof(hashLength),
            &copied,
            0) < 0)
    {
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return {};
    }

    hash.resize(hashLength);
    const bool success =
        BCryptCreateHash(algorithmHandle, &hashHandle, nullptr, 0, nullptr, 0, 0) >= 0
        && BCryptHashData(hashHandle, const_cast<PUCHAR>(bytes), static_cast<ULONG>(byteCount), 0) >= 0
        && BCryptFinishHash(hashHandle, hash.data(), static_cast<ULONG>(hash.size()), 0) >= 0;

    if (hashHandle != nullptr)
    {
        BCryptDestroyHash(hashHandle);
    }
    BCryptCloseAlgorithmProvider(algorithmHandle, 0);
    return success ? hash : std::vector<uint8_t>{};
}

bool DecodeBase64(const std::string& text, std::vector<uint8_t>* bytes)
{
    if (bytes == nullptr)
    {
        return false;
    }

    DWORD length = 0;
    if (!CryptStringToBinaryA(
            text.c_str(),
            static_cast<DWORD>(text.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &length,
            nullptr,
            nullptr))
    {
        return false;
    }

    bytes->resize(length);
    return CryptStringToBinaryA(
        text.c_str(),
        static_cast<DWORD>(text.size()),
        CRYPT_STRING_BASE64,
        bytes->data(),
        &length,
        nullptr,
        nullptr) != FALSE;
}

UniqueBcryptKeyHandle ImportRsaPublicKey(const std::string& publicKeyBase64)
{
    std::vector<uint8_t> publicKeyDer;
    if (!DecodeBase64(publicKeyBase64, &publicKeyDer))
    {
        return UniqueBcryptKeyHandle(nullptr);
    }

    CERT_PUBLIC_KEY_INFO* publicKeyInfo = nullptr;
    DWORD decodedSize = 0;
    if (!CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            publicKeyDer.data(),
            static_cast<DWORD>(publicKeyDer.size()),
            CRYPT_DECODE_ALLOC_FLAG,
            nullptr,
            &publicKeyInfo,
            &decodedSize))
    {
        return UniqueBcryptKeyHandle(nullptr);
    }

    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    const BOOL imported = CryptImportPublicKeyInfoEx2(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        publicKeyInfo,
        0,
        nullptr,
        &keyHandle);
    LocalFree(publicKeyInfo);
    return imported ? UniqueBcryptKeyHandle(keyHandle) : UniqueBcryptKeyHandle(nullptr);
}

bool VerifyRsaSha256Signature(
    BCRYPT_KEY_HANDLE publicKey,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature)
{
    if (publicKey == nullptr || signature.empty())
    {
        return false;
    }

    const std::vector<uint8_t> digest = Sha256(payload.data(), payload.size());
    if (digest.size() != 32)
    {
        return false;
    }

    BCRYPT_PKCS1_PADDING_INFO paddingInfo{};
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    return BCryptVerifySignature(
        publicKey,
        &paddingInfo,
        const_cast<PUCHAR>(digest.data()),
        static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(signature.data()),
        static_cast<ULONG>(signature.size()),
        BCRYPT_PAD_PKCS1) >= 0;
}

bool SendRequest(
    const std::wstring& baseUrl,
    const std::wstring& method,
    const std::wstring& endpoint,
    const std::string& accessToken,
    const std::string& body,
    HttpResponse* response)
{
    if (response == nullptr)
    {
        return false;
    }

    URL_COMPONENTSW parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(baseUrl.c_str(), 0, 0, &parts))
    {
        response->error = "WinHttpCrackUrl failed";
        return false;
    }

    std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    std::wstring root = L"/";
    if (parts.lpszUrlPath != nullptr && parts.dwUrlPathLength > 0)
    {
        root.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    }
    if (parts.lpszExtraInfo != nullptr && parts.dwExtraInfoLength > 0)
    {
        root.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    }

    std::wstring path = root;
    if (!path.empty() && path.back() == L'/' && !endpoint.empty() && endpoint.front() == L'/')
    {
        path.pop_back();
    }
    path += endpoint;

    UniqueWinHttpHandle session(
        WinHttpOpen(kHttpUserAgent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session)
    {
        response->error = "WinHttpOpen failed";
        return false;
    }

    UniqueWinHttpHandle connection(WinHttpConnect(session.get(), host.c_str(), parts.nPort, 0));
    if (!connection)
    {
        response->error = "WinHttpConnect failed";
        return false;
    }

    const DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    UniqueWinHttpHandle request(WinHttpOpenRequest(
        connection.get(),
        method.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags));
    if (!request)
    {
        response->error = "WinHttpOpenRequest failed";
        return false;
    }

    if (flags != 0)
    {
        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));
    }

    std::wstring headers = L"Accept: multipart/mixed, application/json\r\n";
    if (!accessToken.empty())
    {
        headers += L"Authorization: Bearer ";
        headers += ToWide(accessToken);
        headers += L"\r\n";
    }
    if (!body.empty())
    {
        headers += L"Content-Type: application/json\r\n";
    }

    void* bodyPointer = WINHTTP_NO_REQUEST_DATA;
    DWORD bodyLength = 0;
    if (!body.empty())
    {
        bodyPointer = const_cast<char*>(body.data());
        bodyLength = static_cast<DWORD>(body.size());
    }

    if (!WinHttpSendRequest(
            request.get(),
            headers.c_str(),
            static_cast<DWORD>(headers.size()),
            bodyPointer,
            bodyLength,
            bodyLength,
            0))
    {
        response->error = "WinHttpSendRequest failed";
        return false;
    }

    if (!WinHttpReceiveResponse(request.get(), nullptr))
    {
        response->error = "WinHttpReceiveResponse failed";
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
        response->error = "WinHttpQueryHeaders(status) failed";
        return false;
    }
    response->statusCode = static_cast<int>(statusCode);

    WCHAR contentType[256]{};
    DWORD contentTypeLength = sizeof(contentType);
    if (WinHttpQueryHeaders(
            request.get(),
            WINHTTP_QUERY_CONTENT_TYPE,
            WINHTTP_HEADER_NAME_BY_INDEX,
            contentType,
            &contentTypeLength,
            WINHTTP_NO_HEADER_INDEX))
    {
        response->contentType = contentType;
    }

    for (;;)
    {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &available))
        {
            response->error = "WinHttpQueryDataAvailable failed";
            return false;
        }

        if (available == 0)
        {
            break;
        }

        const size_t start = response->body.size();
        response->body.resize(start + available);
        DWORD read = 0;
        if (!WinHttpReadData(request.get(), response->body.data() + start, available, &read))
        {
            response->error = "WinHttpReadData failed";
            return false;
        }
        response->body.resize(start + read);
    }

    return true;
}

bool ParseBoundary(const std::wstring& contentType, std::string* boundary)
{
    if (boundary == nullptr)
    {
        return false;
    }

    const std::string contentTypeUtf8 = ToNarrow(contentType);
    std::stringstream stream(contentTypeUtf8);
    std::string item;
    while (std::getline(stream, item, ';'))
    {
        item.erase(item.begin(), std::find_if(item.begin(), item.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        if (item.rfind("boundary=", 0) == 0)
        {
            *boundary = item.substr(std::string("boundary=").size());
            return !boundary->empty();
        }
    }

    return false;
}

bool ParseMultipartMixed(const HttpResponse& response, std::vector<ParsedMultipartPart>* parts)
{
    if (parts == nullptr)
    {
        return false;
    }

    std::string boundary;
    if (!ParseBoundary(response.contentType, &boundary))
    {
        return false;
    }

    const std::string marker = "--" + boundary;
    const std::string raw(response.body.begin(), response.body.end());

    size_t searchFrom = 0;
    while (true)
    {
        const size_t markerPos = raw.find(marker, searchFrom);
        if (markerPos == std::string::npos)
        {
            break;
        }

        size_t chunkStart = markerPos + marker.size();
        if (chunkStart + 1 < raw.size() && raw[chunkStart] == '-' && raw[chunkStart + 1] == '-')
        {
            break;
        }
        if (chunkStart + 1 < raw.size() && raw[chunkStart] == '\r' && raw[chunkStart + 1] == '\n')
        {
            chunkStart += 2;
        }

        const size_t nextMarker = raw.find(marker, chunkStart);
        if (nextMarker == std::string::npos)
        {
            break;
        }

        std::string chunk = raw.substr(chunkStart, nextMarker - chunkStart);
        if (chunk.size() >= 2 && chunk.ends_with("\r\n"))
        {
            chunk.resize(chunk.size() - 2);
        }

        const size_t headerEnd = chunk.find("\r\n\r\n");
        if (headerEnd != std::string::npos)
        {
            ParsedMultipartPart part;
            std::stringstream headerStream(chunk.substr(0, headerEnd));
            std::string line;
            while (std::getline(headerStream, line))
            {
                if (line.ends_with("\r"))
                {
                    line.pop_back();
                }

                const size_t separator = line.find(':');
                if (separator == std::string::npos)
                {
                    continue;
                }

                std::string name = line.substr(0, separator);
                std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
                    return static_cast<char>(std::tolower(ch));
                });
                std::string value = line.substr(separator + 1);
                value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
                    return !std::isspace(ch);
                }));
                part.headers.emplace(std::move(name), std::move(value));
            }

            const std::string body = chunk.substr(headerEnd + 4);
            part.body.assign(body.begin(), body.end());
            parts->push_back(std::move(part));
        }

        searchFrom = nextMarker;
    }

    return parts->size() == 2;
}

bool ParseDataFile(const std::vector<uint8_t>& dataBytes, std::vector<BinaryDataRecord>* records)
{
    if (records == nullptr)
    {
        return false;
    }

    BinaryReader reader(dataBytes);
    std::string magic;
    uint16_t version = 0;
    uint32_t recordCount = 0;
    if (!reader.ReadUtf8(&magic)
        || magic != "DB-DMITRIY"
        || !reader.ReadUInt16(&version)
        || version != 1
        || !reader.ReadUInt32(&recordCount))
    {
        return false;
    }

    const size_t payloadStart = reader.Position();
    for (uint32_t i = 0; i < recordCount; ++i)
    {
        const size_t recordStart = reader.Position();
        BinaryDataRecord record;
        record.payloadOffset = static_cast<uint64_t>(recordStart - payloadStart);
        if (!reader.ReadUtf8(&record.threatName)
            || !reader.ReadByteArray(&record.firstBytes)
            || !reader.ReadByteArray(&record.remainderHash)
            || !reader.ReadUInt64(&record.remainderLength)
            || !reader.ReadUInt8(&record.fileTypeCode)
            || !reader.ReadUInt64(&record.offsetStart)
            || !reader.ReadUInt64(&record.offsetEnd))
        {
            return false;
        }

        record.rawLength = static_cast<uint32_t>(reader.Position() - recordStart);
        records->push_back(std::move(record));
    }

    return reader.Position() == dataBytes.size();
}

bool ParseManifest(const std::vector<uint8_t>& manifestBytes, BinaryManifest* manifest)
{
    if (manifest == nullptr)
    {
        return false;
    }

    BinaryReader reader(manifestBytes);
    std::string magic;
    uint32_t recordCount = 0;
    if (!reader.ReadUtf8(&magic)
        || magic != "MF-DMITRIY"
        || !reader.ReadUInt16(&manifest->version)
        || manifest->version != 1
        || !reader.ReadUInt8(&manifest->exportType)
        || !reader.ReadUInt64(&manifest->generatedAtEpochMillis)
        || !reader.ReadInt64(&manifest->sinceEpochMillis)
        || !reader.ReadUInt32(&recordCount)
        || !reader.ReadRaw(32, &manifest->dataSha256))
    {
        return false;
    }

    for (uint32_t i = 0; i < recordCount; ++i)
    {
        BinaryManifestEntry entry;
        std::vector<uint8_t> uuidBytes;
        if (!reader.ReadRaw(entry.recordId.size(), &uuidBytes)
            || uuidBytes.size() != entry.recordId.size()
            || !reader.ReadUInt8(&entry.statusCode)
            || !reader.ReadUInt64(&entry.updatedAtEpochMillis)
            || !reader.ReadUInt64(&entry.dataOffset)
            || !reader.ReadUInt32(&entry.dataLength))
        {
            return false;
        }

        std::copy(uuidBytes.begin(), uuidBytes.end(), entry.recordId.begin());

        uint32_t signatureLength = 0;
        if (!reader.ReadUInt32(&signatureLength)
            || !reader.ReadRaw(signatureLength, &entry.recordSignatureBytes))
        {
            return false;
        }

        manifest->entries.push_back(std::move(entry));
    }

    manifest->unsignedBytes.assign(
        manifestBytes.begin(),
        manifestBytes.begin() + static_cast<std::ptrdiff_t>(reader.Position()));

    uint32_t manifestSignatureLength = 0;
    if (!reader.ReadUInt32(&manifestSignatureLength)
        || !reader.ReadRaw(manifestSignatureLength, &manifest->manifestSignatureBytes))
    {
        return false;
    }

    return reader.Position() == manifestBytes.size();
}

std::string StatusCodeToText(uint8_t statusCode)
{
    switch (statusCode)
    {
    case kManifestStatusActual:
        return "ACTUAL";
    case kManifestStatusDeleted:
        return "DELETED";
    default:
        return "UNKNOWN";
    }
}

std::optional<std::string> FileTypeCodeToBackendName(uint8_t fileTypeCode)
{
    switch (fileTypeCode)
    {
    case 1:
        return "exe";
    case 2:
        return "dll";
    case 3:
        return "sys";
    case 4:
        return "bin";
    case 5:
        return "elf";
    case 6:
        return "macho";
    case 7:
        return "apk";
    case 8:
        return "jar";
    case 9:
        return "doc";
    case 10:
        return "pdf";
    case 11:
        return "script";
    default:
        return std::nullopt;
    }
}

engine::AvObjectType FileTypeCodeToEngineType(uint8_t fileTypeCode)
{
    switch (fileTypeCode)
    {
    case 1:
    case 2:
    case 3:
        return engine::AvObjectType::PE;
    case 11:
        return engine::AvObjectType::ScriptText;
    default:
        return engine::AvObjectType::Unknown;
    }
}

std::vector<uint8_t> BuildRecordSigningPayload(
    const BinaryDataRecord& dataRecord,
    uint8_t statusCode)
{
    JsonBuilder builder;
    builder.AddString("fileType", FileTypeCodeToBackendName(dataRecord.fileTypeCode).value_or("unknown"));
    builder.AddString("firstBytesHex", ToHexUpper(dataRecord.firstBytes));
    builder.AddNumber("offsetEnd", dataRecord.offsetEnd);
    builder.AddNumber("offsetStart", dataRecord.offsetStart);
    builder.AddString("remainderHashHex", ToHexUpper(dataRecord.remainderHash));
    builder.AddNumber("remainderLength", dataRecord.remainderLength);
    builder.AddString("status", StatusCodeToText(statusCode));
    builder.AddString("threatName", dataRecord.threatName);
    return builder.BuildCanonicalUtf8();
}

bool CopyFileIfExists(const std::filesystem::path& source, const std::filesystem::path& target)
{
    std::error_code error;
    if (!std::filesystem::exists(source, error) || error)
    {
        return false;
    }

    std::filesystem::create_directories(target.parent_path(), error);
    if (error)
    {
        return false;
    }

    std::filesystem::copy_file(source, target, std::filesystem::copy_options::overwrite_existing, error);
    return !error;
}

ImportedPackage BuildImportedPackage(
    const std::vector<BinaryDataRecord>& dataRecords,
    const BinaryManifest& manifest,
    const storage::ISignatureVerifier& signatureVerifier,
    std::string* errorMessage)
{
    ImportedPackage imported;
    imported.database = engine::AvSignatureDatabase(BuildUtcDateFromEpochMillis(manifest.generatedAtEpochMillis));

    std::map<uint64_t, const BinaryDataRecord*> recordsByOffset;
    for (const BinaryDataRecord& record : dataRecords)
    {
        recordsByOffset.emplace(record.payloadOffset, &record);
    }

    for (const BinaryManifestEntry& entry : manifest.entries)
    {
        const auto recordIt = recordsByOffset.find(entry.dataOffset);
        if (recordIt == recordsByOffset.end() || recordIt->second->rawLength != entry.dataLength)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Manifest/data offsets do not match";
            }
            imported.database.Clear();
            return imported;
        }

        const BinaryDataRecord& dataRecord = *recordIt->second;
        const std::vector<uint8_t> recordPayload = BuildRecordSigningPayload(dataRecord, entry.statusCode);
        if (!signatureVerifier.Verify(recordPayload, entry.recordSignatureBytes))
        {
            ++imported.skippedRecordCount;
            continue;
        }

        if (entry.statusCode == kManifestStatusDeleted)
        {
            imported.deletedRecordIds.insert(entry.recordId);
            continue;
        }

        const engine::AvObjectType objectType = FileTypeCodeToEngineType(dataRecord.fileTypeCode);
        if (objectType == engine::AvObjectType::Unknown)
        {
            ++imported.skippedRecordCount;
            continue;
        }

        engine::AvSignatureRecord record;
        record.PrefixBytes = dataRecord.firstBytes;
        record.ObjectSignaturePrefix =
            engine::PackSignaturePrefix(record.PrefixBytes.data(), std::min(record.PrefixBytes.size(), engine::kSignaturePrefixLength));
        record.ObjectSignatureLength = static_cast<uint32_t>(record.PrefixBytes.size() + dataRecord.remainderLength);
        record.ObjectSignature = dataRecord.remainderHash;
        record.RemainderLength = dataRecord.remainderLength;
        record.OffsetBegin = dataRecord.offsetStart;
        record.OffsetEnd = dataRecord.offsetEnd;
        record.ObjectType = objectType;
        record.MatchMode = engine::AvSignatureMatchMode::PrefixAndRemainderHash;
        record.HasRecordId = true;
        record.RecordId = entry.recordId;
        record.UpdatedAtEpochMillis = entry.updatedAtEpochMillis;
        record.AvRecordSignature = entry.recordSignatureBytes;
        if (!imported.database.AddRecord(std::move(record)))
        {
            ++imported.skippedRecordCount;
        }
    }

    return imported;
}

uint64_t GetLatestUpdatedAtEpochMillis(const engine::AvSignatureDatabase& database)
{
    uint64_t latest = 0;
    for (const engine::AvSignatureRecord& record : database.GetAllRecords())
    {
        latest = std::max(latest, record.UpdatedAtEpochMillis);
    }
    return latest;
}

std::wstring BuildIncrementEndpoint(const engine::AvSignatureDatabase& database)
{
    const uint64_t latestUpdatedAt = GetLatestUpdatedAtEpochMillis(database);
    if (latestUpdatedAt == 0)
    {
        return kFullEndpoint;
    }

    return std::wstring(kIncrementEndpointPrefix) + BuildUtcDateTimeQueryFromEpochMillis(latestUpdatedAt);
}

bool DownloadAndImportPackage(
    const AvDatabaseUpdaterContext& context,
    const std::wstring& endpoint,
    const std::string& body,
    ImportedPackage* imported,
    std::string* errorMessage)
{
    if (imported == nullptr)
    {
        if (errorMessage != nullptr)
        {
            *errorMessage = "Internal updater error";
        }
        return false;
    }

    HttpResponse response;
    if (!SendRequest(context.apiBaseUrl, body.empty() ? L"GET" : L"POST", endpoint, context.accessToken, body, &response))
    {
        if (errorMessage != nullptr)
        {
            *errorMessage = response.error.empty() ? "Network request failed" : response.error;
        }
        return false;
    }

    if (response.statusCode < 200 || response.statusCode >= 300)
    {
        if (errorMessage != nullptr)
        {
            *errorMessage = "HTTP " + std::to_string(response.statusCode);
        }
        return false;
    }

    std::vector<ParsedMultipartPart> parts;
    if (!ParseMultipartMixed(response, &parts))
    {
        if (errorMessage != nullptr)
        {
            *errorMessage = "Cannot parse multipart/mixed response";
        }
        return false;
    }

    std::vector<BinaryDataRecord> dataRecords;
    BinaryManifest manifest;
    if (!ParseManifest(parts[0].body, &manifest) || !ParseDataFile(parts[1].body, &dataRecords))
    {
        if (errorMessage != nullptr)
        {
            *errorMessage = "Binary package format is invalid";
        }
        return false;
    }

    const std::vector<uint8_t> dataSha256 = Sha256(parts[1].body.data(), parts[1].body.size());
    if (dataSha256 != manifest.dataSha256)
    {
        if (errorMessage != nullptr)
        {
            *errorMessage = "Binary package checksum is invalid";
        }
        return false;
    }

    const storage::RsaSha256SignatureVerifier signatureVerifier;
    if (!signatureVerifier.IsConfigured())
    {
        if (errorMessage != nullptr)
        {
            *errorMessage = "Backend RSA public key is not configured";
        }
        return false;
    }

    if (!signatureVerifier.Verify(manifest.unsignedBytes, manifest.manifestSignatureBytes))
    {
        if (errorMessage != nullptr)
        {
            *errorMessage = "Manifest signature is invalid";
        }
        return false;
    }

    *imported = BuildImportedPackage(dataRecords, manifest, signatureVerifier, errorMessage);
    return !imported->database.GetAllRecords().empty() || !imported->deletedRecordIds.empty();
}

engine::AvSignatureDatabase MergeDatabaseRecords(
    const engine::AvSignatureDatabase& currentDatabase,
    const ImportedPackage& imported)
{
    const engine::AvDatabaseInfo currentInfo = currentDatabase.GetInfo();
    engine::AvSignatureDatabase merged(currentInfo.releaseDateUtc);
    const std::vector<engine::AvSignatureRecord> currentRecords = currentDatabase.GetAllRecords();

    std::set<std::array<uint8_t, 16>> replacementIds = imported.deletedRecordIds;
    for (const engine::AvSignatureRecord& record : imported.database.GetAllRecords())
    {
        if (record.HasRecordId)
        {
            replacementIds.insert(record.RecordId);
        }
    }

    for (const engine::AvSignatureRecord& record : currentRecords)
    {
        if (record.HasRecordId && replacementIds.contains(record.RecordId))
        {
            continue;
        }

        merged.AddRecord(record);
    }

    for (const engine::AvSignatureRecord& record : imported.database.GetAllRecords())
    {
        merged.AddRecord(record);
    }

    return merged;
}

bool RestoreFromBackupOrDefault(
    const storage::AvDatabasePaths& paths,
    engine::AvSignatureDatabase& database,
    AvDatabaseUpdateResult* updateResult)
{
    const storage::DemoHmacSha256SignatureVerifier verifier;
    std::error_code error;
    if (std::filesystem::exists(paths.backupDatabasePath, error) && !error)
    {
        std::filesystem::copy_file(
            paths.backupDatabasePath,
            paths.mainDatabasePath,
            std::filesystem::copy_options::overwrite_existing,
            error);
        error.clear();
    }

    storage::AvDatabaseLoadResult loadResult;
    const bool loaded = LoadServiceAntivirusDatabase(database, paths, &loadResult);
    if (updateResult != nullptr)
    {
        updateResult->loadResult = loadResult;
        updateResult->rolledBack = true;
    }
    return loaded;
}

bool PersistAndReloadDatabase(
    const AvDatabaseUpdaterContext& context,
    const engine::AvSignatureDatabase& candidateDatabase,
    engine::AvSignatureDatabase& database,
    AvDatabaseUpdateResult* updateResult)
{
    const storage::DemoHmacSha256SignatureVerifier verifier;
    if (!storage::SaveDatabaseFileAtomically(
            candidateDatabase,
            context.paths.incomingDatabasePath,
            context.paths.temporaryDatabasePath,
            verifier))
    {
        if (updateResult != nullptr)
        {
            updateResult->message = "Cannot save downloaded database into incoming.avdb";
        }
        return false;
    }

    CopyFileIfExists(context.paths.mainDatabasePath, context.paths.backupDatabasePath);

    std::error_code copyError;
    std::filesystem::copy_file(
        context.paths.incomingDatabasePath,
        context.paths.mainDatabasePath,
        std::filesystem::copy_options::overwrite_existing,
        copyError);
    if (copyError)
    {
        if (updateResult != nullptr)
        {
            updateResult->message = "Cannot promote incoming.avdb to main.avdb";
        }
        return false;
    }

    storage::AvDatabaseLoadResult loadResult;
    const bool loaded = LoadServiceAntivirusDatabase(database, context.paths, &loadResult);
    if (updateResult != nullptr)
    {
        updateResult->loadResult = loadResult;
    }

    if (!loaded || loadResult.source != storage::AvDatabaseLoadSource::Main)
    {
        RestoreFromBackupOrDefault(context.paths, database, updateResult);
        return false;
    }

    return true;
}

std::string BuildIdsRequestBody(const std::vector<std::array<uint8_t, 16>>& recordIds)
{
    std::ostringstream output;
    output << "{\"ids\":[";
    for (size_t i = 0; i < recordIds.size(); ++i)
    {
        if (i != 0)
        {
            output << ",";
        }

        const std::array<uint8_t, 16>& id = recordIds[i];
        char buffer[37]{};
        std::snprintf(
            buffer,
            sizeof(buffer),
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            id[0], id[1], id[2], id[3],
            id[4], id[5],
            id[6], id[7],
            id[8], id[9],
            id[10], id[11], id[12], id[13], id[14], id[15]);
        output << "\"" << buffer << "\"";
    }
    output << "]}";
    return output.str();
}

bool IsNetworkAvailableInternal(const AvDatabaseUpdaterContext& context, std::string* reason)
{
    if (context.apiBaseUrl.empty())
    {
        if (reason != nullptr)
        {
            *reason = "Updater skipped: API base URL is missing";
        }
        return false;
    }

    if (context.accessToken.empty())
    {
        if (reason != nullptr)
        {
            *reason = "Updater skipped: access token is missing";
        }
        return false;
    }

    const storage::RsaSha256SignatureVerifier verifier;
    if (!verifier.IsConfigured())
    {
        if (reason != nullptr)
        {
            *reason = "Updater skipped: backend public key is missing";
        }
        return false;
    }

    return true;
}
} // namespace

bool IsNetworkAvailable(const AvDatabaseUpdaterContext& context, std::string* reason)
{
    return IsNetworkAvailableInternal(context, reason);
}

// Downloads the full binary signature export, saves it as the main compact DB and reloads it.
bool UpdateDatabaseFromServer(
    const AvDatabaseUpdaterContext& context,
    bool forceFullDownload,
    engine::AvSignatureDatabase& database,
    AvDatabaseUpdateResult* updateResult)
{
    AvDatabaseUpdateResult localResult;
    localResult.attempted = true;

    std::string reason;
    if (!IsNetworkAvailableInternal(context, &reason))
    {
        localResult.message = reason;
        if (updateResult != nullptr)
        {
            *updateResult = localResult;
        }
        return false;
    }

    ImportedPackage imported;
    const std::wstring endpoint = forceFullDownload ? std::wstring(kFullEndpoint) : BuildIncrementEndpoint(database);
    if (!DownloadAndImportPackage(context, endpoint, "", &imported, &localResult.message))
    {
        if (updateResult != nullptr)
        {
            *updateResult = localResult;
        }
        return false;
    }

    localResult.downloaded = true;
    localResult.importedRecordCount = imported.database.GetInfo().recordCount;
    localResult.skippedRecordCount = imported.skippedRecordCount;
    const engine::AvSignatureDatabase candidateDatabase =
        (forceFullDownload || endpoint == kFullEndpoint)
        ? imported.database
        : MergeDatabaseRecords(database, imported);
    if (!PersistAndReloadDatabase(context, candidateDatabase, database, &localResult))
    {
        if (localResult.message.empty())
        {
            localResult.message = "Update written, but reload failed and rollback was applied";
        }
        if (updateResult != nullptr)
        {
            *updateResult = localResult;
        }
        return false;
    }

    localResult.updated = true;
    localResult.message = endpoint == kFullEndpoint
        ? "Full database update loaded successfully"
        : "Incremental database update loaded successfully";
    if (updateResult != nullptr)
    {
        *updateResult = localResult;
    }
    return true;
}

// Attempts to repair skipped compact DB records by UUID through /api/binary/signatures/by-ids.
bool RepairDamagedRecordsFromServer(
    const AvDatabaseUpdaterContext& context,
    const std::vector<std::array<uint8_t, 16>>& recordIds,
    engine::AvSignatureDatabase& database,
    AvDatabaseUpdateResult* updateResult)
{
    AvDatabaseUpdateResult localResult;
    localResult.attempted = true;

    if (recordIds.empty())
    {
        localResult.message = "Repair skipped: no damaged record ids";
        if (updateResult != nullptr)
        {
            *updateResult = localResult;
        }
        return false;
    }

    std::string reason;
    if (!IsNetworkAvailableInternal(context, &reason))
    {
        localResult.message = reason;
        if (updateResult != nullptr)
        {
            *updateResult = localResult;
        }
        return false;
    }

    ImportedPackage imported;
    if (!DownloadAndImportPackage(context, kByIdsEndpoint, BuildIdsRequestBody(recordIds), &imported, &localResult.message))
    {
        if (updateResult != nullptr)
        {
            *updateResult = localResult;
        }
        return false;
    }

    localResult.downloaded = true;
    localResult.importedRecordCount = imported.database.GetInfo().recordCount;
    localResult.skippedRecordCount = imported.skippedRecordCount;
    const engine::AvSignatureDatabase mergedDatabase = MergeDatabaseRecords(database, imported);
    if (!PersistAndReloadDatabase(context, mergedDatabase, database, &localResult))
    {
        if (localResult.message.empty())
        {
            localResult.message = "Record repair written, but reload failed and rollback was applied";
        }
        if (updateResult != nullptr)
        {
            *updateResult = localResult;
        }
        return false;
    }

    localResult.updated = true;
    localResult.message = "Damaged records were repaired from server";
    if (updateResult != nullptr)
    {
        *updateResult = localResult;
    }
    return true;
}
} // namespace antivirus::service
