#include "AntivirusEngine.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <limits>
#include <queue>
#include <sstream>
#include <system_error>
#include <utility>

#pragma comment(lib, "Bcrypt.lib")

namespace antivirus::engine
{
namespace
{
constexpr uint64_t kFnv1a64OffsetBasis = 14695981039346656037ull;
constexpr uint64_t kFnv1a64Prime = 1099511628211ull;
constexpr size_t kSha256Length = 32;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Converts a string literal into bytes for demo records.
std::vector<uint8_t> BytesFromText(const char* text)
{
    std::vector<uint8_t> bytes;
    if (text == nullptr)
    {
        return bytes;
    }

    while (*text != '\0')
    {
        bytes.push_back(static_cast<uint8_t>(*text));
        ++text;
    }
    return bytes;
}

// Converts a 64-bit value to little-endian bytes.
std::vector<uint8_t> UInt64ToLittleEndianBytes(uint64_t value)
{
    std::vector<uint8_t> bytes(sizeof(value));
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
    }
    return bytes;
}

// Returns true when the signature record has internally consistent fields.
bool IsValidRecord(const AvSignatureRecord& record)
{
    const size_t prefixLength = record.PrefixBytes.empty()
        ? kSignaturePrefixLength
        : record.PrefixBytes.size();
    if (prefixLength == 0
        || record.OffsetBegin > record.OffsetEnd
        || record.ObjectType == AvObjectType::Unknown)
    {
        return false;
    }

    if (record.MatchMode == AvSignatureMatchMode::LegacyFullFragmentHash)
    {
        return record.ObjectSignatureLength >= kSignaturePrefixLength
            && !record.ObjectSignature.empty();
    }

    if (record.ObjectSignatureLength < prefixLength)
    {
        return false;
    }

    return record.RemainderLength == static_cast<uint64_t>(record.ObjectSignatureLength - prefixLength)
        && (record.RemainderLength == 0 || !record.ObjectSignature.empty());
}

// Computes SHA-256 over the supplied bytes.
std::vector<uint8_t> Sha256(const uint8_t* bytes, size_t byteCount)
{
    if (bytes == nullptr && byteCount != 0)
    {
        return {};
    }

    BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    DWORD hashLength = 0;
    DWORD bytesCopied = 0;
    std::vector<uint8_t> hash;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
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
    const bool success =
        NT_SUCCESS(BCryptCreateHash(algorithmHandle, &hashHandle, nullptr, 0, nullptr, 0, 0))
        && NT_SUCCESS(BCryptHashData(
            hashHandle,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(bytes)),
            static_cast<ULONG>(byteCount),
            0))
        && NT_SUCCESS(BCryptFinishHash(hashHandle, hash.data(), static_cast<ULONG>(hash.size()), 0));

    if (hashHandle != nullptr)
    {
        BCryptDestroyHash(hashHandle);
    }
    BCryptCloseAlgorithmProvider(algorithmHandle, 0);
    return success ? hash : std::vector<uint8_t>{};
}

// Extracts the first bytes from a legacy 64-bit prefix key.
std::vector<uint8_t> PrefixBytesFromKey(uint64_t prefixKey)
{
    std::vector<uint8_t> bytes(kSignaturePrefixLength);
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        bytes[i] = static_cast<uint8_t>((prefixKey >> (i * 8)) & 0xFFu);
    }
    return bytes;
}
} // namespace

// Creates an in-memory byte stream for tests and synthetic scans.
MemoryByteStream::MemoryByteStream(std::vector<uint8_t> bytes) : bytes_(std::move(bytes))
{
}

// Reads bytes from the current in-memory cursor.
size_t MemoryByteStream::Read(uint8_t* buffer, size_t byteCount)
{
    if (buffer == nullptr || byteCount == 0 || position_ >= bytes_.size())
    {
        return 0;
    }

    const uint64_t available = static_cast<uint64_t>(bytes_.size()) - position_;
    const size_t toRead = static_cast<size_t>(std::min<uint64_t>(available, byteCount));
    std::memcpy(buffer, bytes_.data() + position_, toRead);
    position_ += toRead;
    return toRead;
}

// Moves the in-memory cursor to an absolute byte position.
bool MemoryByteStream::Seek(uint64_t position)
{
    if (position > bytes_.size())
    {
        return false;
    }

    position_ = position;
    return true;
}

// Returns the current in-memory cursor position.
uint64_t MemoryByteStream::Tell()
{
    return position_;
}

// Returns the total number of bytes in memory.
uint64_t MemoryByteStream::Size()
{
    return static_cast<uint64_t>(bytes_.size());
}

// Opens a file as a seekable byte stream.
FileByteStream::FileByteStream(const std::filesystem::path& path)
    : file_(path, std::ios::binary)
{
    std::error_code error;
    const uintmax_t fileSize = std::filesystem::file_size(path, error);
    if (!error && fileSize <= std::numeric_limits<uint64_t>::max())
    {
        size_ = static_cast<uint64_t>(fileSize);
    }
}

// Returns true when the file was opened successfully.
bool FileByteStream::IsOpen() const
{
    return file_.is_open();
}

// Reads bytes from the current file cursor.
size_t FileByteStream::Read(uint8_t* buffer, size_t byteCount)
{
    if (!file_.is_open() || buffer == nullptr || byteCount == 0)
    {
        return 0;
    }

    file_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(byteCount));
    return static_cast<size_t>(file_.gcount());
}

// Moves the file cursor to an absolute byte position.
bool FileByteStream::Seek(uint64_t position)
{
    if (!file_.is_open() || position > size_)
    {
        return false;
    }

    file_.clear();
    file_.seekg(static_cast<std::streamoff>(position), std::ios::beg);
    return file_.good();
}

// Returns the current file cursor position.
uint64_t FileByteStream::Tell()
{
    if (!file_.is_open())
    {
        return 0;
    }

    const std::streampos position = file_.tellg();
    if (position < std::streampos(0))
    {
        return size_;
    }

    return static_cast<uint64_t>(position);
}

// Returns the total file size in bytes.
uint64_t FileByteStream::Size()
{
    return size_;
}

// Creates an in-memory database with the supplied release date.
AvSignatureDatabase::AvSignatureDatabase(std::string releaseDateUtc)
    : releaseDateUtc_(std::move(releaseDateUtc))
{
}

// Removes all records while keeping the database in memory only.
void AvSignatureDatabase::Clear()
{
    recordsByPrefix_.clear();
    recordCount_ = 0;
}

// Adds a prepared signature record under its 8-byte prefix key.
bool AvSignatureDatabase::AddRecord(AvSignatureRecord record)
{
    if (record.PrefixBytes.empty())
    {
        record.PrefixBytes = PrefixBytesFromKey(record.ObjectSignaturePrefix);
    }

    if (!IsValidRecord(record))
    {
        return false;
    }

    recordsByPrefix_[record.ObjectSignaturePrefix].push_back(std::move(record));
    ++recordCount_;
    return true;
}

// Builds a record from raw signature bytes and stores its fragment hash.
bool AvSignatureDatabase::AddSignature(
    const std::vector<uint8_t>& signatureBytes,
    AvObjectType objectType,
    uint64_t offsetBegin,
    uint64_t offsetEnd,
    std::vector<uint8_t> avRecordSignature)
{
    if (signatureBytes.size() < kSignaturePrefixLength
        || signatureBytes.size() > std::numeric_limits<uint32_t>::max()
        || offsetBegin > offsetEnd
        || objectType == AvObjectType::Unknown)
    {
        return false;
    }

    AvSignatureRecord record;
    record.ObjectSignaturePrefix = PackSignaturePrefix(signatureBytes.data(), kSignaturePrefixLength);
    record.ObjectSignatureLength = static_cast<uint32_t>(signatureBytes.size());
    record.PrefixBytes.assign(signatureBytes.begin(), signatureBytes.begin() + static_cast<std::ptrdiff_t>(kSignaturePrefixLength));
    record.RemainderLength = static_cast<uint64_t>(signatureBytes.size() - kSignaturePrefixLength);
    if (record.RemainderLength != 0)
    {
        record.ObjectSignature = HashSignatureRemainderSha256(
            signatureBytes.data() + kSignaturePrefixLength,
            signatureBytes.size() - kSignaturePrefixLength,
            kSha256Length);
    }
    record.OffsetBegin = offsetBegin;
    record.OffsetEnd = offsetEnd;
    record.ObjectType = objectType;
    record.MatchMode = AvSignatureMatchMode::PrefixAndRemainderHash;
    record.AvRecordSignature = std::move(avRecordSignature);
    return AddRecord(std::move(record));
}

// Returns records for a prefix using std::map logarithmic lookup.
const std::vector<AvSignatureRecord>* AvSignatureDatabase::FindRecords(uint64_t prefix) const
{
    const auto it = recordsByPrefix_.find(prefix);
    if (it == recordsByPrefix_.end())
    {
        return nullptr;
    }

    return &it->second;
}

// Returns a flat copy of all records for disk serialization.
std::vector<AvSignatureRecord> AvSignatureDatabase::GetAllRecords() const
{
    std::vector<AvSignatureRecord> records;
    records.reserve(recordCount_);
    for (const auto& [prefix, bucket] : recordsByPrefix_)
    {
        (void)prefix;
        records.insert(records.end(), bucket.begin(), bucket.end());
    }
    return records;
}

// Returns release date and record count for diagnostics.
AvDatabaseInfo AvSignatureDatabase::GetInfo() const
{
    AvDatabaseInfo info;
    info.releaseDateUtc = releaseDateUtc_;
    info.recordCount = recordCount_;
    return info;
}

// Creates a scanner over an immutable in-memory signature database.
AvScanner::AvScanner(const AvSignatureDatabase& database) : database_(database)
{
    BuildAutomaton();
}

void AvScanner::BuildAutomaton()
{
    nodes_.clear();
    nodes_.push_back(AhoNode{});
    records_ = database_.GetAllRecords();

    for (AvSignatureRecord& record : records_)
    {
        if (record.PrefixBytes.empty())
        {
            continue;
        }

        size_t state = 0;
        for (const uint8_t byte : record.PrefixBytes)
        {
            const auto [it, inserted] = nodes_[state].next.emplace(byte, nodes_.size());
            if (inserted)
            {
                nodes_.push_back(AhoNode{});
            }
            state = it->second;
        }

        nodes_[state].outputs.push_back(&record);
    }

    std::queue<size_t> pending;
    for (const auto& [byte, nextState] : nodes_[0].next)
    {
        (void)byte;
        nodes_[nextState].failure = 0;
        pending.push(nextState);
    }

    while (!pending.empty())
    {
        const size_t state = pending.front();
        pending.pop();

        for (const auto& [byte, nextState] : nodes_[state].next)
        {
            size_t failure = nodes_[state].failure;
            while (failure != 0 && !nodes_[failure].next.contains(byte))
            {
                failure = nodes_[failure].failure;
            }

            const auto failureTransition = nodes_[failure].next.find(byte);
            if (failureTransition != nodes_[failure].next.end() && failureTransition->second != nextState)
            {
                nodes_[nextState].failure = failureTransition->second;
            }
            else
            {
                nodes_[nextState].failure = 0;
            }

            const std::vector<const AvSignatureRecord*>& inheritedOutputs =
                nodes_[nodes_[nextState].failure].outputs;
            nodes_[nextState].outputs.insert(
                nodes_[nextState].outputs.end(),
                inheritedOutputs.begin(),
                inheritedOutputs.end());

            pending.push(nextState);
        }
    }
}

bool AvScanner::VerifyMatch(
    const std::vector<uint8_t>& objectBytes,
    uint64_t position,
    AvObjectType objectType,
    const AvSignatureRecord& record) const
{
    if (record.ObjectType != objectType)
    {
        return false;
    }

    if (position < record.OffsetBegin || position > record.OffsetEnd)
    {
        return false;
    }

    if (record.ObjectSignatureLength < record.PrefixBytes.size()
        || record.ObjectSignatureLength > objectBytes.size() - position)
    {
        return false;
    }

    if (!std::equal(
            record.PrefixBytes.begin(),
            record.PrefixBytes.end(),
            objectBytes.begin() + static_cast<std::ptrdiff_t>(position)))
    {
        return false;
    }

    if (record.MatchMode == AvSignatureMatchMode::LegacyFullFragmentHash)
    {
        std::vector<uint8_t> fragment(record.ObjectSignatureLength);
        std::copy_n(
            objectBytes.data() + position,
            static_cast<size_t>(record.ObjectSignatureLength),
            fragment.begin());
        return HashSignatureFragment(fragment) == record.ObjectSignature;
    }

    if (record.RemainderLength == 0)
    {
        return true;
    }

    const uint8_t* remainderBytes = objectBytes.data() + position + record.PrefixBytes.size();
    const std::vector<uint8_t> remainderHash = HashSignatureRemainderSha256(
        remainderBytes,
        static_cast<size_t>(record.RemainderLength),
        record.ObjectSignature.size());
    return !remainderHash.empty() && remainderHash == record.ObjectSignature;
}

// Scans a byte stream for signatures of the supplied object type.
AvScanResult AvScanner::Scan(IByteStream& stream, AvObjectType objectType) const
{
    AvScanResult result;
    result.objectType = objectType;

    const uint64_t streamSize = stream.Size();
    if (streamSize < kSignaturePrefixLength || !stream.Seek(0))
    {
        result.scanCompleted = true;
        return result;
    }

    if (streamSize > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
    {
        result.scanCompleted = false;
        return result;
    }

    std::vector<uint8_t> objectBytes(static_cast<size_t>(streamSize));
    size_t totalRead = 0;
    while (totalRead < objectBytes.size())
    {
        const size_t bytesRead = stream.Read(
            objectBytes.data() + totalRead,
            objectBytes.size() - totalRead);
        if (bytesRead == 0)
        {
            break;
        }

        totalRead += bytesRead;
    }

    if (totalRead < objectBytes.size())
    {
        result.scanCompleted = false;
        return result;
    }

    size_t state = 0;
    for (uint64_t index = 0; index < streamSize; ++index)
    {
        const uint8_t byte = objectBytes[static_cast<size_t>(index)];
        while (state != 0 && !nodes_[state].next.contains(byte))
        {
            state = nodes_[state].failure;
        }

        const auto transition = nodes_[state].next.find(byte);
        state = transition != nodes_[state].next.end() ? transition->second : 0;

        for (const AvSignatureRecord* record : nodes_[state].outputs)
        {
            if (record == nullptr || static_cast<uint64_t>(record->PrefixBytes.size()) > index + 1)
            {
                continue;
            }

            const uint64_t position = index + 1 - static_cast<uint64_t>(record->PrefixBytes.size());
            if (VerifyMatch(objectBytes, position, objectType, *record))
            {
                result.scanCompleted = true;
                result.malicious = true;
                result.detectionOffset = position;
                result.matchedRecord = *record;
                return result;
            }
        }
    }

    result.scanCompleted = true;
    return result;
}

// Packs the first 8 signature bytes into a stable little-endian key.
uint64_t PackSignaturePrefix(const uint8_t* bytes, size_t byteCount)
{
    if (bytes == nullptr || byteCount == 0)
    {
        return 0;
    }

    uint64_t value = 0;
    const size_t prefixLength = std::min(kSignaturePrefixLength, byteCount);
    for (size_t i = 0; i < prefixLength; ++i)
    {
        value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    }
    return value;
}

// Calculates the demo hash stored in ObjectSignature fields.
std::vector<uint8_t> HashSignatureFragment(const std::vector<uint8_t>& bytes)
{
    uint64_t hash = kFnv1a64OffsetBasis;
    for (const uint8_t byte : bytes)
    {
        hash ^= byte;
        hash *= kFnv1a64Prime;
    }

    return UInt64ToLittleEndianBytes(hash);
}

// Calculates a truncated SHA-256 used by imported backend remainder hashes.
std::vector<uint8_t> HashSignatureRemainderSha256(const uint8_t* bytes, size_t byteCount, size_t hashLength)
{
    if (hashLength == 0)
    {
        return {};
    }

    const std::vector<uint8_t> fullHash = Sha256(bytes, byteCount);
    if (fullHash.size() != kSha256Length || hashLength > fullHash.size())
    {
        return {};
    }

    return std::vector<uint8_t>(fullHash.begin(), fullHash.begin() + static_cast<std::ptrdiff_t>(hashLength));
}

// Returns current UTC time as an ISO-8601 database release date.
std::string BuildCurrentUtcReleaseDate()
{
    std::time_t now = std::time(nullptr);
    std::tm utcTime{};
    gmtime_s(&utcTime, &now);

    std::ostringstream output;
    output << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

// Adds deterministic in-memory demo records used when the service starts.
void LoadDefaultTestSignatures(AvSignatureDatabase& database)
{
    const std::vector<uint8_t> demoRecordSignature = BytesFromText("DEMO-AV-RECORD-SIGNATURE-V1");

    database.AddSignature(
        BytesFromText("AVTESTPE\x01\x02\x03\x04"),
        AvObjectType::PE,
        0,
        512,
        demoRecordSignature);

    database.AddSignature(
        BytesFromText("AVSCRIPTalert(1);"),
        AvObjectType::ScriptText,
        0,
        std::numeric_limits<uint64_t>::max(),
        demoRecordSignature);

    database.AddSignature(
        BytesFromText("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
        AvObjectType::ScriptText,
        0,
        std::numeric_limits<uint64_t>::max(),
        demoRecordSignature);

    database.AddSignature(
        BytesFromText("MZDEMOPEpayload"),
        AvObjectType::PE,
        128,
        4096,
        demoRecordSignature);
}

// Converts an object type to a compact diagnostic string.
const char* ToString(AvObjectType objectType)
{
    switch (objectType)
    {
    case AvObjectType::PE:
        return "PE";
    case AvObjectType::ScriptText:
        return "ScriptText";
    default:
        return "Unknown";
    }
}

// Converts a match mode to a compact diagnostic string.
const char* ToString(AvSignatureMatchMode matchMode)
{
    switch (matchMode)
    {
    case AvSignatureMatchMode::LegacyFullFragmentHash:
        return "LegacyFullHash";
    case AvSignatureMatchMode::PrefixAndRemainderHash:
        return "PrefixRemainderHash";
    default:
        return "Unknown";
    }
}
} // namespace antivirus::engine
