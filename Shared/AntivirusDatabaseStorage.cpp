#include "AntivirusDatabaseStorage.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <sstream>
#include <system_error>
#include <utility>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

namespace antivirus::storage
{
namespace
{
constexpr std::array<uint8_t, 4> kDatabaseMagic = { 'A', 'V', 'D', 'B' };
constexpr uint16_t kDatabaseVersionLegacy = 1;
constexpr uint16_t kDatabaseVersionCurrent = 2;
constexpr uint8_t kHashAlgorithmSha256 = 1;
constexpr uint8_t kSignatureAlgorithmDemoHmacSha256 = 1;
constexpr size_t kSha256Length = 32;
constexpr size_t kUnsignedManifestLength = 56;
constexpr uint32_t kMaxRecordSignatureLength = 4096;
constexpr uint32_t kMaxRecordCount = 1000000;
constexpr uint32_t kMaxRecordPrefixLength = 4096;
constexpr uint32_t kMaxRecordHashLength = 4096;

// Training-only demo key; replace the verifier for a real ЭЦП/public-key implementation.
const std::array<uint8_t, 38> kDemoHmacKey = {
    'A', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', '-',
    'D', 'E', 'M', 'O', '-', 'H', 'M', 'A', 'C', '-',
    'S', 'H', 'A', '2', '5', '6', '-', 'T', 'R', 'A',
    'I', 'N', 'I', 'N', 'G', '-', 'V', '1'
};

const char kEmbeddedBackendPublicKeyBase64[] =
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxgtL+gG4dRzyn4QYqT0+wBozMHYMzKtzDcInf9d2HvQlWv3spIUYhlMR1rhvd8LeVJYIXxt1GE/TrJwTw/16PVnXEyT6bAL4P0atPRpppS2KDyMcCXWEj3qOR5MfO0K1yu35kJeilYvmQi5DyBChvn2E6Rh4ilrw8LVxGaqZyNphSvETZz/4pct/WbYn5KxKWhkq87JcqvXJAjLhWQ2/gUXUBz8pL2oWQph3qH2hW/JQ+ApC6VgUg+N5rw7Lh2ApPtoUo1XWLfHIGfnMdd0R730kyxZg/Y3CZ+6JupruQK355f5CVg1o3u55bVSGQGexQiFiFqehFFqr1BFPieodRwIDAQAB";

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

class BinaryWriter
{
public:
    // Appends one raw byte to the output buffer.
    void WriteUInt8(uint8_t value)
    {
        bytes_.push_back(value);
    }

    // Appends a 16-bit value in the Java service BigEndian order.
    void WriteUInt16(uint16_t value)
    {
        bytes_.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
        bytes_.push_back(static_cast<uint8_t>(value & 0xFFu));
    }

    // Appends a 32-bit value in the Java service BigEndian order.
    void WriteUInt32(uint32_t value)
    {
        for (int shift = 24; shift >= 0; shift -= 8)
        {
            bytes_.push_back(static_cast<uint8_t>((value >> shift) & 0xFFu));
        }
    }

    // Appends a 64-bit value in the Java service BigEndian order.
    void WriteUInt64(uint64_t value)
    {
        for (int shift = 56; shift >= 0; shift -= 8)
        {
            bytes_.push_back(static_cast<uint8_t>((value >> shift) & 0xFFu));
        }
    }

    // Appends raw bytes without an additional length prefix.
    void WriteRaw(const std::vector<uint8_t>& bytes)
    {
        bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
    }

    // Appends raw bytes without an additional length prefix.
    void WriteRaw(const uint8_t* bytes, size_t byteCount)
    {
        if (bytes != nullptr && byteCount > 0)
        {
            bytes_.insert(bytes_.end(), bytes, bytes + byteCount);
        }
    }

    // Returns the accumulated output bytes.
    const std::vector<uint8_t>& Bytes() const
    {
        return bytes_;
    }

    // Moves the accumulated output bytes to the caller.
    std::vector<uint8_t> TakeBytes()
    {
        return std::move(bytes_);
    }

private:
    std::vector<uint8_t> bytes_;
};

class BinaryReader
{
public:
    // Creates a cursor over immutable binary input.
    explicit BinaryReader(const std::vector<uint8_t>& bytes) : bytes_(bytes)
    {
    }

    // Returns the current absolute cursor position.
    size_t Position() const
    {
        return position_;
    }

    // Reads a fixed byte sequence and advances the cursor.
    bool ReadRaw(size_t byteCount, std::vector<uint8_t>* outBytes)
    {
        if (outBytes == nullptr || byteCount > Remaining())
        {
            return false;
        }

        outBytes->assign(bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_ + byteCount));
        position_ += byteCount;
        return true;
    }

    // Reads one raw byte from the cursor.
    bool ReadUInt8(uint8_t* value)
    {
        if (value == nullptr || Remaining() < 1)
        {
            return false;
        }

        *value = bytes_[position_++];
        return true;
    }

    // Reads a 16-bit BigEndian value from the cursor.
    bool ReadUInt16(uint16_t* value)
    {
        if (value == nullptr || Remaining() < 2)
        {
            return false;
        }

        *value = static_cast<uint16_t>((bytes_[position_] << 8) | bytes_[position_ + 1]);
        position_ += 2;
        return true;
    }

    // Reads a 32-bit BigEndian value from the cursor.
    bool ReadUInt32(uint32_t* value)
    {
        if (value == nullptr || Remaining() < 4)
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

    // Reads a 64-bit BigEndian value from the cursor.
    bool ReadUInt64(uint64_t* value)
    {
        if (value == nullptr || Remaining() < 8)
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

private:
    // Returns the number of unread bytes.
    size_t Remaining() const
    {
        return bytes_.size() - position_;
    }

    const std::vector<uint8_t>& bytes_;
    size_t position_ = 0;
};

// Converts a Win32 path to a UTF-8-ish diagnostic string for errors.
std::string PathForMessage(const std::filesystem::path& path)
{
    return path.string();
}

// Reads a whole binary file into memory.
bool ReadFileBytes(const std::filesystem::path& path, std::vector<uint8_t>* outBytes)
{
    if (outBytes == nullptr)
    {
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        return false;
    }

    outBytes->assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return file.good() || file.eof();
}

// Reads one UTF-8-ish environment variable from the process.
std::string ReadEnvironmentVariableUtf8(const wchar_t* name)
{
    if (name == nullptr || *name == L'\0')
    {
        return {};
    }

    DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0)
    {
        return {};
    }

    std::vector<wchar_t> wide(required, L'\0');
    if (GetEnvironmentVariableW(name, wide.data(), required) == 0)
    {
        return {};
    }

    const int narrowLength = WideCharToMultiByte(CP_UTF8, 0, wide.data(), -1, nullptr, 0, nullptr, nullptr);
    if (narrowLength <= 1)
    {
        return {};
    }

    std::string utf8(static_cast<size_t>(narrowLength - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), -1, utf8.data(), narrowLength, nullptr, nullptr);
    return utf8;
}

// Writes a whole binary file from memory.
bool WriteFileBytes(const std::filesystem::path& path, const std::vector<uint8_t>& bytes)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open())
    {
        return false;
    }

    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return file.good();
}

// Appends a vector to another vector.
void AppendBytes(std::vector<uint8_t>& target, const std::vector<uint8_t>& source)
{
    target.insert(target.end(), source.begin(), source.end());
}

// Returns a subrange copy from a binary buffer.
std::vector<uint8_t> SliceBytes(const std::vector<uint8_t>& bytes, size_t begin, size_t end)
{
    if (begin > end || end > bytes.size())
    {
        return {};
    }

    return std::vector<uint8_t>(
        bytes.begin() + static_cast<std::ptrdiff_t>(begin),
        bytes.begin() + static_cast<std::ptrdiff_t>(end));
}

// Converts SHA/HMAC failures into an empty byte vector.
std::vector<uint8_t> BCryptDigest(
    const wchar_t* algorithm,
    const std::vector<uint8_t>& data,
    const uint8_t* key,
    size_t keySize,
    ULONG flags)
{
    BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    DWORD hashLength = 0;
    DWORD bytesCopied = 0;
    std::vector<uint8_t> hash;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithmHandle, algorithm, nullptr, flags)))
    {
        return {};
    }

    if (!NT_SUCCESS(BCryptGetProperty(
        algorithmHandle,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashLength),
        sizeof(hashLength),
        &bytesCopied,
        0)))
    {
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return {};
    }

    hash.resize(hashLength);
    if (NT_SUCCESS(BCryptCreateHash(
            algorithmHandle,
            &hashHandle,
            nullptr,
            0,
            const_cast<PUCHAR>(key),
            static_cast<ULONG>(keySize),
            0))
        && NT_SUCCESS(BCryptHashData(
            hashHandle,
            const_cast<PUCHAR>(data.data()),
            static_cast<ULONG>(data.size()),
            0))
        && NT_SUCCESS(BCryptFinishHash(hashHandle, hash.data(), static_cast<ULONG>(hash.size()), 0)))
    {
        if (hashHandle != nullptr)
        {
            BCryptDestroyHash(hashHandle);
        }
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return hash;
    }

    if (hashHandle != nullptr)
    {
        BCryptDestroyHash(hashHandle);
    }
    BCryptCloseAlgorithmProvider(algorithmHandle, 0);
    return {};
}

// Calculates SHA-256 for manifest content checks.
std::vector<uint8_t> Sha256(const std::vector<uint8_t>& data)
{
    return BCryptDigest(BCRYPT_SHA256_ALGORITHM, data, nullptr, 0, 0);
}

// Calculates demo HMAC/SHA-256 signatures for lab databases.
std::vector<uint8_t> DemoHmacSha256(const std::vector<uint8_t>& data)
{
    return BCryptDigest(
        BCRYPT_SHA256_ALGORITHM,
        data,
        kDemoHmacKey.data(),
        kDemoHmacKey.size(),
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
}

// Decodes Base64 DER public key bytes.
bool DecodeBase64(const std::string& text, std::vector<uint8_t>* bytes)
{
    if (bytes == nullptr || text.empty())
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

using UniqueBcryptKeyHandle = std::unique_ptr<void, BCryptKeyHandleCloser>;

// Imports DER SubjectPublicKeyInfo into a CNG key handle.
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

// Verifies RSA/SHA-256 detached signature using CNG.
bool VerifyRsaSha256(
    const std::string& publicKeyBase64,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature)
{
    if (publicKeyBase64.empty() || signature.empty())
    {
        return false;
    }

    UniqueBcryptKeyHandle keyHandle = ImportRsaPublicKey(publicKeyBase64);
    if (!keyHandle)
    {
        return false;
    }

    const std::vector<uint8_t> digest = Sha256(payload);
    if (digest.size() != kSha256Length)
    {
        return false;
    }

    BCRYPT_PKCS1_PADDING_INFO paddingInfo{};
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    return NT_SUCCESS(BCryptVerifySignature(
        static_cast<BCRYPT_KEY_HANDLE>(keyHandle.get()),
        &paddingInfo,
        const_cast<PUCHAR>(digest.data()),
        static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(signature.data()),
        static_cast<ULONG>(signature.size()),
        BCRYPT_PAD_PKCS1));
}

// Converts an ISO-8601 UTC date to epoch milliseconds.
uint64_t ReleaseDateToEpochMillis(const std::string& releaseDateUtc)
{
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    if (::sscanf_s(
            releaseDateUtc.c_str(),
            "%4d-%2d-%2dT%2d:%2d:%2dZ",
            &year,
            &month,
            &day,
            &hour,
            &minute,
            &second) != 6)
    {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }

    std::tm utcTime{};
    utcTime.tm_year = year - 1900;
    utcTime.tm_mon = month - 1;
    utcTime.tm_mday = day;
    utcTime.tm_hour = hour;
    utcTime.tm_min = minute;
    utcTime.tm_sec = second;

    const time_t unixTime = _mkgmtime(&utcTime);
    if (unixTime == static_cast<time_t>(-1))
    {
        return 0;
    }

    return static_cast<uint64_t>(unixTime) * 1000ull;
}

// Converts epoch milliseconds from the manifest into an ISO-8601 UTC date.
std::string EpochMillisToReleaseDate(uint64_t epochMillis)
{
    const time_t unixTime = static_cast<time_t>(epochMillis / 1000ull);
    std::tm utcTime{};
    gmtime_s(&utcTime, &unixTime);

    char output[32]{};
    std::strftime(output, sizeof(output), "%Y-%m-%dT%H:%M:%SZ", &utcTime);
    return output;
}

// Converts a service object type into the compact database type code.
uint8_t ObjectTypeToCode(engine::AvObjectType objectType)
{
    switch (objectType)
    {
    case engine::AvObjectType::PE:
        return 1;
    case engine::AvObjectType::ScriptText:
        return 11;
    default:
        return 255;
    }
}

// Converts a compact database type code into a service object type.
engine::AvObjectType ObjectTypeFromCode(uint8_t code)
{
    switch (code)
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

// Converts the in-memory match mode into a compact database code.
uint8_t MatchModeToCode(engine::AvSignatureMatchMode matchMode)
{
    switch (matchMode)
    {
    case engine::AvSignatureMatchMode::LegacyFullFragmentHash:
        return 1;
    case engine::AvSignatureMatchMode::PrefixAndRemainderHash:
        return 2;
    default:
        return 0;
    }
}

// Converts a compact database match-mode code into an in-memory enum.
engine::AvSignatureMatchMode MatchModeFromCode(uint8_t code)
{
    switch (code)
    {
    case 1:
        return engine::AvSignatureMatchMode::LegacyFullFragmentHash;
    case 2:
        return engine::AvSignatureMatchMode::PrefixAndRemainderHash;
    default:
        return engine::AvSignatureMatchMode::LegacyFullFragmentHash;
    }
}

// Extracts legacy 8-byte prefix bytes from the packed key.
std::vector<uint8_t> PrefixBytesFromKey(uint64_t prefix)
{
    std::vector<uint8_t> bytes(engine::kSignaturePrefixLength);
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        bytes[i] = static_cast<uint8_t>((prefix >> (i * 8)) & 0xFFu);
    }
    return bytes;
}

// Builds the unsigned bytes that are signed for one record.
std::vector<uint8_t> BuildUnsignedRecordPayload(const engine::AvSignatureRecord& record)
{
    BinaryWriter writer;
    writer.WriteUInt8(MatchModeToCode(record.MatchMode));
    writer.WriteUInt32(static_cast<uint32_t>(record.PrefixBytes.size()));
    writer.WriteRaw(record.PrefixBytes);
    writer.WriteUInt32(record.ObjectSignatureLength);
    writer.WriteUInt32(static_cast<uint32_t>(record.ObjectSignature.size()));
    writer.WriteRaw(record.ObjectSignature);
    writer.WriteUInt64(record.RemainderLength);

    writer.WriteUInt64(record.OffsetBegin);
    writer.WriteUInt64(record.OffsetEnd);
    writer.WriteUInt8(ObjectTypeToCode(record.ObjectType));
    writer.WriteUInt8(record.HasRecordId ? 1 : 0);
    if (record.HasRecordId)
    {
        writer.WriteRaw(record.RecordId.data(), record.RecordId.size());
    }
    writer.WriteUInt64(record.UpdatedAtEpochMillis);
    return writer.TakeBytes();
}

// Builds the signed record bytes that are persisted after the manifest.
std::vector<uint8_t> BuildStoredRecord(
    const engine::AvSignatureRecord& record,
    const ISignatureVerifier& signatureVerifier,
    std::vector<uint8_t>* unsignedRecordBytes)
{
    std::vector<uint8_t> payload = BuildUnsignedRecordPayload(record);
    const std::vector<uint8_t> signature = signatureVerifier.CreateSignatureForDemo(payload);
    if (unsignedRecordBytes != nullptr)
    {
        AppendBytes(*unsignedRecordBytes, payload);
    }

    BinaryWriter writer;
    writer.WriteRaw(payload);
    writer.WriteUInt32(static_cast<uint32_t>(signature.size()));
    writer.WriteRaw(signature);
    return writer.TakeBytes();
}

// Builds the manifest bytes without the detached manifest signature.
std::vector<uint8_t> BuildUnsignedManifest(
    uint64_t releaseEpochMillis,
    uint32_t recordCount,
    uint32_t unsignedContentLength,
    const std::vector<uint8_t>& contentSha256)
{
    BinaryWriter writer;
    writer.WriteRaw(kDatabaseMagic.data(), kDatabaseMagic.size());
    writer.WriteUInt16(kDatabaseVersionCurrent);
    writer.WriteUInt64(releaseEpochMillis);
    writer.WriteUInt32(recordCount);
    writer.WriteUInt8(kHashAlgorithmSha256);
    writer.WriteUInt8(kSignatureAlgorithmDemoHmacSha256);
    writer.WriteUInt32(unsignedContentLength);
    writer.WriteRaw(contentSha256);
    return writer.TakeBytes();
}

// Creates a failed load result with a compact diagnostic message.
AvDatabaseLoadResult FailedLoad(std::string message)
{
    AvDatabaseLoadResult result;
    result.loaded = false;
    result.message = std::move(message);
    return result;
}

// Creates a successful load result with the selected fallback source.
AvDatabaseLoadResult SuccessfulLoad(
    AvDatabaseLoadSource source,
    const engine::AvSignatureDatabase& database,
    size_t skippedRecords,
    std::string message)
{
    AvDatabaseLoadResult result;
    result.loaded = true;
    result.source = source;
    result.databaseInfo = database.GetInfo();
    result.skippedRecordCount = skippedRecords;
    result.message = std::move(message);
    return result;
}
} // namespace

// Returns the demo HMAC/SHA-256 signature algorithm identifier.
std::string DemoHmacSha256SignatureVerifier::AlgorithmName() const
{
    return "DEMO-HMAC-SHA256";
}

// Verifies the demo HMAC/SHA-256 signature using the built-in training key.
bool DemoHmacSha256SignatureVerifier::Verify(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature) const
{
    const std::vector<uint8_t> expectedSignature = CreateSignatureForDemo(payload);
    return !expectedSignature.empty() && expectedSignature == signature;
}

// Creates a demo HMAC/SHA-256 signature using the built-in training key.
std::vector<uint8_t> DemoHmacSha256SignatureVerifier::CreateSignatureForDemo(
    const std::vector<uint8_t>& payload) const
{
    return DemoHmacSha256(payload);
}

RsaSha256SignatureVerifier::RsaSha256SignatureVerifier(std::string publicKeyBase64)
    : publicKeyBase64_(publicKeyBase64.empty() ? ResolveBackendPublicKeyBase64() : std::move(publicKeyBase64))
{
}

std::string RsaSha256SignatureVerifier::AlgorithmName() const
{
    return "SHA256withRSA";
}

bool RsaSha256SignatureVerifier::Verify(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature) const
{
    return VerifyRsaSha256(publicKeyBase64_, payload, signature);
}

std::vector<uint8_t> RsaSha256SignatureVerifier::CreateSignatureForDemo(
    const std::vector<uint8_t>& payload) const
{
    (void)payload;
    return {};
}

bool RsaSha256SignatureVerifier::IsConfigured() const
{
    return !publicKeyBase64_.empty();
}

const std::string& RsaSha256SignatureVerifier::PublicKeyBase64() const
{
    return publicKeyBase64_;
}

std::string ResolveBackendPublicKeyBase64()
{
    const std::string overrideValue = ReadEnvironmentVariableUtf8(L"SIGNATURE_PUBLIC_KEY_BASE64");
    return !overrideValue.empty() ? overrideValue : std::string(kEmbeddedBackendPublicKeyBase64);
}

// Returns the service database file layout under ProgramData.
AvDatabasePaths ResolveDefaultDatabasePaths()
{
    std::filesystem::path programDataRoot;
    char* programData = nullptr;
    size_t programDataLength = 0;
    if (_dupenv_s(&programData, &programDataLength, "ProgramData") == 0
        && programData != nullptr
        && *programData != '\0')
    {
        programDataRoot = std::filesystem::path(programData);
        std::free(programData);
    }
    else
    {
        if (programData != nullptr)
        {
            std::free(programData);
        }
        programDataRoot = std::filesystem::temp_directory_path();
    }

    const std::filesystem::path databaseRoot = programDataRoot / "Antivirus" / "Databases";
    AvDatabasePaths paths;
    paths.mainDatabasePath = databaseRoot / "main.avdb";
    paths.backupDatabasePath = databaseRoot / "backup.avdb";
    paths.defaultDatabasePath = databaseRoot / "default.avdb";
    paths.incomingDatabasePath = databaseRoot / "incoming.avdb";
    paths.temporaryDatabasePath = databaseRoot / "database.tmp";
    return paths;
}

// Writes a database using a temporary file and then replaces the target file.
bool SaveDatabaseFileAtomically(
    const engine::AvSignatureDatabase& database,
    const std::filesystem::path& targetPath,
    const std::filesystem::path& temporaryPath,
    const ISignatureVerifier& signatureVerifier)
{
    const std::vector<engine::AvSignatureRecord> records = database.GetAllRecords();
    if (records.size() > kMaxRecordCount)
    {
        return false;
    }

    std::vector<uint8_t> unsignedRecords;
    std::vector<uint8_t> storedRecords;
    for (const engine::AvSignatureRecord& record : records)
    {
        if (record.PrefixBytes.empty()
            || record.PrefixBytes.size() > kMaxRecordPrefixLength
            || record.ObjectSignature.size() > kMaxRecordHashLength)
        {
            return false;
        }

        const std::vector<uint8_t> storedRecord = BuildStoredRecord(record, signatureVerifier, &unsignedRecords);
        AppendBytes(storedRecords, storedRecord);
    }

    const std::vector<uint8_t> contentSha256 = Sha256(unsignedRecords);
    if (contentSha256.size() != kSha256Length || unsignedRecords.size() > std::numeric_limits<uint32_t>::max())
    {
        return false;
    }

    const engine::AvDatabaseInfo info = database.GetInfo();
    const std::vector<uint8_t> unsignedManifest = BuildUnsignedManifest(
        ReleaseDateToEpochMillis(info.releaseDateUtc),
        static_cast<uint32_t>(records.size()),
        static_cast<uint32_t>(unsignedRecords.size()),
        contentSha256);
    const std::vector<uint8_t> manifestSignature = signatureVerifier.CreateSignatureForDemo(unsignedManifest);
    if (manifestSignature.empty() || manifestSignature.size() > std::numeric_limits<uint32_t>::max())
    {
        return false;
    }

    BinaryWriter fileWriter;
    fileWriter.WriteRaw(unsignedManifest);
    fileWriter.WriteUInt32(static_cast<uint32_t>(manifestSignature.size()));
    fileWriter.WriteRaw(manifestSignature);
    fileWriter.WriteRaw(storedRecords);

    std::error_code fsError;
    std::filesystem::create_directories(targetPath.parent_path(), fsError);
    if (fsError)
    {
        return false;
    }

    std::filesystem::remove(temporaryPath, fsError);
    fsError.clear();
    if (!WriteFileBytes(temporaryPath, fileWriter.Bytes()))
    {
        std::filesystem::remove(temporaryPath, fsError);
        return false;
    }

    std::filesystem::remove(targetPath, fsError);
    fsError.clear();
    std::filesystem::rename(temporaryPath, targetPath, fsError);
    if (fsError)
    {
        std::filesystem::remove(temporaryPath, fsError);
        return false;
    }

    return true;
}

// Creates or repairs the signed default database file.
bool EnsureDefaultDatabaseFile(const AvDatabasePaths& paths, const ISignatureVerifier& signatureVerifier)
{
    engine::AvSignatureDatabase existingDatabase;
    const AvDatabaseLoadResult existing = LoadDatabaseFile(
        paths.defaultDatabasePath,
        signatureVerifier,
        existingDatabase);
    if (existing.loaded && existing.databaseInfo.recordCount > 0)
    {
        return true;
    }

    engine::AvSignatureDatabase defaultDatabase("2026-05-14T00:00:00Z");
    engine::LoadDefaultTestSignatures(defaultDatabase);
    return SaveDatabaseFileAtomically(
        defaultDatabase,
        paths.defaultDatabasePath,
        paths.temporaryDatabasePath,
        signatureVerifier);
}

// Loads one signed binary database file into the in-memory engine database.
AvDatabaseLoadResult LoadDatabaseFile(
    const std::filesystem::path& path,
    const ISignatureVerifier& signatureVerifier,
    engine::AvSignatureDatabase& database)
{
    std::vector<uint8_t> fileBytes;
    if (!ReadFileBytes(path, &fileBytes))
    {
        return FailedLoad("Cannot read database file: " + PathForMessage(path));
    }

    if (fileBytes.size() < kUnsignedManifestLength + sizeof(uint32_t))
    {
        return FailedLoad("Database file is too small: " + PathForMessage(path));
    }

    BinaryReader reader(fileBytes);
    std::vector<uint8_t> magic;
    uint16_t version = 0;
    uint64_t releaseEpochMillis = 0;
    uint32_t recordCount = 0;
    uint8_t hashAlgorithm = 0;
    uint8_t signatureAlgorithm = 0;
    uint32_t unsignedContentLength = 0;
    std::vector<uint8_t> expectedContentSha256;
    uint32_t manifestSignatureLength = 0;
    std::vector<uint8_t> manifestSignature;

    if (!reader.ReadRaw(kDatabaseMagic.size(), &magic)
        || magic != std::vector<uint8_t>(kDatabaseMagic.begin(), kDatabaseMagic.end())
        || !reader.ReadUInt16(&version)
        || !reader.ReadUInt64(&releaseEpochMillis)
        || !reader.ReadUInt32(&recordCount)
        || !reader.ReadUInt8(&hashAlgorithm)
        || !reader.ReadUInt8(&signatureAlgorithm)
        || !reader.ReadUInt32(&unsignedContentLength)
        || !reader.ReadRaw(kSha256Length, &expectedContentSha256))
    {
        return FailedLoad("Database manifest is malformed: " + PathForMessage(path));
    }

    if ((version != kDatabaseVersionLegacy && version != kDatabaseVersionCurrent)
        || hashAlgorithm != kHashAlgorithmSha256
        || signatureAlgorithm != kSignatureAlgorithmDemoHmacSha256
        || recordCount > kMaxRecordCount)
    {
        return FailedLoad("Database manifest uses unsupported format: " + PathForMessage(path));
    }

    const std::vector<uint8_t> unsignedManifest = SliceBytes(fileBytes, 0, reader.Position());
    if (!reader.ReadUInt32(&manifestSignatureLength)
        || manifestSignatureLength == 0
        || manifestSignatureLength > kMaxRecordSignatureLength
        || !reader.ReadRaw(manifestSignatureLength, &manifestSignature))
    {
        return FailedLoad("Database manifest signature is malformed: " + PathForMessage(path));
    }

    if (!signatureVerifier.Verify(unsignedManifest, manifestSignature))
    {
        return FailedLoad("Database manifest signature is invalid: " + PathForMessage(path));
    }

    std::vector<uint8_t> unsignedRecords;
    engine::AvSignatureDatabase loadedDatabase(EpochMillisToReleaseDate(releaseEpochMillis));
    size_t skippedRecords = 0;
    std::vector<std::array<uint8_t, 16>> skippedRecordIds;
    for (uint32_t i = 0; i < recordCount; ++i)
    {
        const size_t payloadStart = reader.Position();
        engine::AvSignatureRecord record;
        uint8_t objectTypeCode = 0;
        if (version == kDatabaseVersionLegacy)
        {
            uint64_t prefix = 0;
            uint32_t signatureLength = 0;
            std::vector<uint8_t> objectSignature;
            if (!reader.ReadUInt64(&prefix)
                || !reader.ReadUInt32(&signatureLength)
                || !reader.ReadRaw(8, &objectSignature)
                || !reader.ReadUInt64(&record.OffsetBegin)
                || !reader.ReadUInt64(&record.OffsetEnd)
                || !reader.ReadUInt8(&objectTypeCode))
            {
                return FailedLoad("Database record is truncated: " + PathForMessage(path));
            }

            record.ObjectSignaturePrefix = prefix;
            record.ObjectSignatureLength = signatureLength;
            record.ObjectSignature = std::move(objectSignature);
            record.PrefixBytes = PrefixBytesFromKey(prefix);
            record.RemainderLength = 0;
            record.MatchMode = engine::AvSignatureMatchMode::LegacyFullFragmentHash;
        }
        else
        {
            uint8_t matchModeCode = 0;
            uint32_t prefixLength = 0;
            uint32_t signatureLength = 0;
            uint32_t hashLength = 0;
            uint8_t hasRecordId = 0;
            if (!reader.ReadUInt8(&matchModeCode)
                || !reader.ReadUInt32(&prefixLength)
                || prefixLength == 0
                || prefixLength > kMaxRecordPrefixLength
                || !reader.ReadRaw(prefixLength, &record.PrefixBytes)
                || !reader.ReadUInt32(&signatureLength)
                || !reader.ReadUInt32(&hashLength)
                || hashLength > kMaxRecordHashLength
                || !reader.ReadRaw(hashLength, &record.ObjectSignature)
                || !reader.ReadUInt64(&record.RemainderLength)
                || !reader.ReadUInt64(&record.OffsetBegin)
                || !reader.ReadUInt64(&record.OffsetEnd)
                || !reader.ReadUInt8(&objectTypeCode)
                || !reader.ReadUInt8(&hasRecordId))
            {
                return FailedLoad("Database record is truncated: " + PathForMessage(path));
            }

            record.MatchMode = MatchModeFromCode(matchModeCode);
            record.ObjectSignaturePrefix =
                engine::PackSignaturePrefix(record.PrefixBytes.data(), std::min(record.PrefixBytes.size(), engine::kSignaturePrefixLength));
            record.ObjectSignatureLength = signatureLength;
            record.HasRecordId = (hasRecordId != 0);
            if (record.HasRecordId)
            {
                std::vector<uint8_t> recordIdBytes;
                if (!reader.ReadRaw(record.RecordId.size(), &recordIdBytes)
                    || recordIdBytes.size() != record.RecordId.size())
                {
                    return FailedLoad("Database record id is truncated: " + PathForMessage(path));
                }

                std::copy(recordIdBytes.begin(), recordIdBytes.end(), record.RecordId.begin());
            }

            if (!reader.ReadUInt64(&record.UpdatedAtEpochMillis))
            {
                return FailedLoad("Database record metadata is truncated: " + PathForMessage(path));
            }
        }

        const size_t payloadEnd = reader.Position();
        const std::vector<uint8_t> recordPayload = SliceBytes(fileBytes, payloadStart, payloadEnd);
        AppendBytes(unsignedRecords, recordPayload);

        uint32_t recordSignatureLength = 0;
        std::vector<uint8_t> recordSignature;
        if (!reader.ReadUInt32(&recordSignatureLength)
            || recordSignatureLength == 0
            || recordSignatureLength > kMaxRecordSignatureLength
            || !reader.ReadRaw(recordSignatureLength, &recordSignature))
        {
            return FailedLoad("Database record signature is malformed: " + PathForMessage(path));
        }

        if (!signatureVerifier.Verify(recordPayload, recordSignature))
        {
            ++skippedRecords;
            if (record.HasRecordId)
            {
                skippedRecordIds.push_back(record.RecordId);
            }
            continue;
        }

        record.ObjectType = ObjectTypeFromCode(objectTypeCode);
        record.AvRecordSignature = std::move(recordSignature);
        if (!loadedDatabase.AddRecord(std::move(record)))
        {
            ++skippedRecords;
        }
    }

    if (reader.Position() != fileBytes.size())
    {
        return FailedLoad("Database has trailing bytes: " + PathForMessage(path));
    }

    if (unsignedRecords.size() != unsignedContentLength)
    {
        return FailedLoad("Database content length is invalid: " + PathForMessage(path));
    }

    const std::vector<uint8_t> actualContentSha256 = Sha256(unsignedRecords);
    if (actualContentSha256 != expectedContentSha256)
    {
        return FailedLoad("Database content checksum is invalid: " + PathForMessage(path));
    }

    database = std::move(loadedDatabase);
    AvDatabaseLoadResult result = SuccessfulLoad(
        AvDatabaseLoadSource::None,
        database,
        skippedRecords,
        "Database loaded: " + PathForMessage(path));
    result.skippedRecordIds = std::move(skippedRecordIds);
    return result;
}

// Loads main, then backup, then default database with manifest and record verification.
AvDatabaseLoadResult LoadDatabaseWithFallback(
    const AvDatabasePaths& paths,
    const ISignatureVerifier& signatureVerifier,
    engine::AvSignatureDatabase& database)
{
    EnsureDefaultDatabaseFile(paths, signatureVerifier);

    engine::AvSignatureDatabase candidateDatabase;
    AvDatabaseLoadResult mainResult = LoadDatabaseFile(paths.mainDatabasePath, signatureVerifier, candidateDatabase);
    if (mainResult.loaded)
    {
        database = std::move(candidateDatabase);
        mainResult.source = AvDatabaseLoadSource::Main;
        mainResult.databaseInfo = database.GetInfo();
        return mainResult;
    }

    candidateDatabase = engine::AvSignatureDatabase();
    AvDatabaseLoadResult backupResult = LoadDatabaseFile(paths.backupDatabasePath, signatureVerifier, candidateDatabase);
    if (backupResult.loaded)
    {
        database = std::move(candidateDatabase);
        backupResult.source = AvDatabaseLoadSource::Backup;
        backupResult.databaseInfo = database.GetInfo();
        backupResult.message = mainResult.message + "; fallback loaded backup";
        return backupResult;
    }

    candidateDatabase = engine::AvSignatureDatabase();
    AvDatabaseLoadResult defaultResult = LoadDatabaseFile(paths.defaultDatabasePath, signatureVerifier, candidateDatabase);
    if (defaultResult.loaded)
    {
        database = std::move(candidateDatabase);
        defaultResult.source = AvDatabaseLoadSource::Default;
        defaultResult.databaseInfo = database.GetInfo();
        defaultResult.message = mainResult.message + "; " + backupResult.message + "; fallback loaded default";
        return defaultResult;
    }

    AvDatabaseLoadResult failed = FailedLoad(
        mainResult.message + "; " + backupResult.message + "; " + defaultResult.message);
    failed.source = AvDatabaseLoadSource::None;
    return failed;
}

// Converts a database load source to a short diagnostic name.
const char* ToString(AvDatabaseLoadSource source)
{
    switch (source)
    {
    case AvDatabaseLoadSource::Main:
        return "main";
    case AvDatabaseLoadSource::Backup:
        return "backup";
    case AvDatabaseLoadSource::Default:
        return "default";
    case AvDatabaseLoadSource::Incoming:
        return "incoming";
    default:
        return "none";
    }
}
} // namespace antivirus::storage
