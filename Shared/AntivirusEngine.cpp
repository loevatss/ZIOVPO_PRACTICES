#include "AntivirusEngine.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>

namespace antivirus::engine
{
namespace
{
constexpr uint64_t kFnv1a64OffsetBasis = 14695981039346656037ull;
constexpr uint64_t kFnv1a64Prime = 1099511628211ull;

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
    return record.ObjectSignatureLength >= kSignaturePrefixLength
        && !record.ObjectSignature.empty()
        && record.OffsetBegin <= record.OffsetEnd
        && record.ObjectType != AvObjectType::Unknown;
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
    record.ObjectSignaturePrefix = PackSignaturePrefix(signatureBytes.data(), signatureBytes.size());
    record.ObjectSignatureLength = static_cast<uint32_t>(signatureBytes.size());
    record.ObjectSignature = HashSignatureFragment(signatureBytes);
    record.OffsetBegin = offsetBegin;
    record.OffsetEnd = offsetEnd;
    record.ObjectType = objectType;
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

    for (uint64_t position = 0; position + kSignaturePrefixLength <= streamSize; ++position)
    {
        const uint8_t* prefixBytes = objectBytes.data() + position;
        const uint64_t prefix = PackSignaturePrefix(prefixBytes, kSignaturePrefixLength);
        const std::vector<AvSignatureRecord>* records = database_.FindRecords(prefix);
        if (records == nullptr)
        {
            continue;
        }

        bool hasCandidateAfterCheapChecks = false;
        for (const AvSignatureRecord& record : *records)
        {
            if (record.ObjectType != objectType)
            {
                continue;
            }

            if (position < record.OffsetBegin || position > record.OffsetEnd)
            {
                continue;
            }

            if (record.ObjectSignatureLength < kSignaturePrefixLength
                || record.ObjectSignatureLength > streamSize - position)
            {
                continue;
            }

            hasCandidateAfterCheapChecks = true;
            std::vector<uint8_t> fragment(record.ObjectSignatureLength);
            std::copy_n(
                objectBytes.data() + position,
                static_cast<size_t>(record.ObjectSignatureLength),
                fragment.begin());

            const std::vector<uint8_t> fragmentHash = HashSignatureFragment(fragment);
            if (fragmentHash == record.ObjectSignature)
            {
                result.scanCompleted = true;
                result.malicious = true;
                result.detectionOffset = position;
                result.matchedRecord = record;
                return result;
            }
        }

        if (!hasCandidateAfterCheapChecks)
        {
            continue;
        }
    }

    result.scanCompleted = true;
    return result;
}

// Packs the first 8 signature bytes into a stable little-endian key.
uint64_t PackSignaturePrefix(const uint8_t* bytes, size_t byteCount)
{
    if (bytes == nullptr || byteCount < kSignaturePrefixLength)
    {
        return 0;
    }

    uint64_t value = 0;
    for (size_t i = 0; i < kSignaturePrefixLength; ++i)
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
} // namespace antivirus::engine
