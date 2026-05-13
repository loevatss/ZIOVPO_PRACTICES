#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace antivirus::engine
{
inline constexpr size_t kSignaturePrefixLength = 8;

enum class AvObjectType
{
    Unknown = 0,
    PE = 1,
    ScriptText = 2,
};

struct AvSignatureRecord
{
    uint64_t ObjectSignaturePrefix = 0;
    uint32_t ObjectSignatureLength = 0;
    std::vector<uint8_t> ObjectSignature;
    uint64_t OffsetBegin = 0;
    uint64_t OffsetEnd = 0;
    AvObjectType ObjectType = AvObjectType::Unknown;
    std::vector<uint8_t> AvRecordSignature;
};

struct AvDatabaseInfo
{
    std::string releaseDateUtc;
    size_t recordCount = 0;
};

struct AvScanResult
{
    bool scanCompleted = false;
    bool malicious = false;
    uint64_t detectionOffset = 0;
    AvObjectType objectType = AvObjectType::Unknown;
    AvSignatureRecord matchedRecord;
};

// Returns current UTC time as an ISO-8601 database release date.
std::string BuildCurrentUtcReleaseDate();

class IByteStream
{
public:
    virtual ~IByteStream() = default;

    // Reads up to byteCount bytes from the current position.
    virtual size_t Read(uint8_t* buffer, size_t byteCount) = 0;
    // Moves the stream cursor to an absolute byte position.
    virtual bool Seek(uint64_t position) = 0;
    // Returns the current absolute byte position.
    virtual uint64_t Tell() = 0;
    // Returns the total byte length of the stream.
    virtual uint64_t Size() = 0;
};

class MemoryByteStream final : public IByteStream
{
public:
    // Creates an in-memory byte stream for tests and synthetic scans.
    explicit MemoryByteStream(std::vector<uint8_t> bytes);

    // Reads bytes from the current in-memory cursor.
    size_t Read(uint8_t* buffer, size_t byteCount) override;
    // Moves the in-memory cursor to an absolute byte position.
    bool Seek(uint64_t position) override;
    // Returns the current in-memory cursor position.
    uint64_t Tell() override;
    // Returns the total number of bytes in memory.
    uint64_t Size() override;

private:
    std::vector<uint8_t> bytes_;
    uint64_t position_ = 0;
};

class FileByteStream final : public IByteStream
{
public:
    // Opens a file as a seekable byte stream.
    explicit FileByteStream(const std::filesystem::path& path);

    // Returns true when the file was opened successfully.
    bool IsOpen() const;
    // Reads bytes from the current file cursor.
    size_t Read(uint8_t* buffer, size_t byteCount) override;
    // Moves the file cursor to an absolute byte position.
    bool Seek(uint64_t position) override;
    // Returns the current file cursor position.
    uint64_t Tell() override;
    // Returns the total file size in bytes.
    uint64_t Size() override;

private:
    std::ifstream file_;
    uint64_t size_ = 0;
};

class AvSignatureDatabase
{
public:
    // Creates an in-memory database with the supplied release date.
    explicit AvSignatureDatabase(std::string releaseDateUtc = BuildCurrentUtcReleaseDate());

    // Removes all records while keeping the database in memory only.
    void Clear();
    // Adds a prepared signature record under its 8-byte prefix key.
    bool AddRecord(AvSignatureRecord record);
    // Builds a record from raw signature bytes and stores its fragment hash.
    bool AddSignature(
        const std::vector<uint8_t>& signatureBytes,
        AvObjectType objectType,
        uint64_t offsetBegin,
        uint64_t offsetEnd,
        std::vector<uint8_t> avRecordSignature);
    // Returns records for a prefix using std::map logarithmic lookup.
    const std::vector<AvSignatureRecord>* FindRecords(uint64_t prefix) const;
    // Returns release date and record count for diagnostics.
    AvDatabaseInfo GetInfo() const;

private:
    std::string releaseDateUtc_;
    size_t recordCount_ = 0;
    std::map<uint64_t, std::vector<AvSignatureRecord>> recordsByPrefix_;
};

class AvScanner
{
public:
    // Creates a scanner over an immutable in-memory signature database.
    explicit AvScanner(const AvSignatureDatabase& database);

    // Scans a byte stream for signatures of the supplied object type.
    AvScanResult Scan(IByteStream& stream, AvObjectType objectType) const;

private:
    const AvSignatureDatabase& database_;
};

// Packs the first 8 signature bytes into a stable little-endian key.
uint64_t PackSignaturePrefix(const uint8_t* bytes, size_t byteCount);
// Calculates the demo hash stored in ObjectSignature fields.
std::vector<uint8_t> HashSignatureFragment(const std::vector<uint8_t>& bytes);
// Adds deterministic in-memory demo records used when the service starts.
void LoadDefaultTestSignatures(AvSignatureDatabase& database);
// Converts an object type to a compact diagnostic string.
const char* ToString(AvObjectType objectType);
} // namespace antivirus::engine
