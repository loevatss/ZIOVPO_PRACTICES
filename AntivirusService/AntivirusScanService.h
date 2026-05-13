#pragma once

#include "AntivirusEngine.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::service
{
enum class FileScanStatus
{
    Clean = 0,
    Infected = 1,
    Error = 2,
};

struct FileScanResult
{
    FileScanStatus status = FileScanStatus::Clean;
    std::filesystem::path path;
    engine::AvObjectType objectType = engine::AvObjectType::Unknown;
    std::string recordId;
    std::string message;
};

struct DirectoryScanResult
{
    uint64_t totalScanned = 0;
    uint64_t infectedCount = 0;
    uint64_t errorCount = 0;
    std::vector<FileScanResult> results;
};

struct AvDatabaseRuntimeInfo
{
    bool loaded = false;
    engine::AvDatabaseInfo databaseInfo;
};

// Loads the default in-memory antivirus database for service runtime use.
bool LoadServiceAntivirusDatabase(engine::AvSignatureDatabase& database);
// Returns database state in the format used by service RPC.
AvDatabaseRuntimeInfo GetDatabaseRuntimeInfo(const engine::AvSignatureDatabase& database, bool loaded);
// Opens and scans one file through the shared byte-stream antivirus engine.
FileScanResult ScanFilePath(const std::filesystem::path& path, const engine::AvSignatureDatabase& database);
// Recursively scans regular files under a directory and aggregates per-file results.
DirectoryScanResult ScanDirectoryPath(const std::filesystem::path& path, const engine::AvSignatureDatabase& database);
// Detects the scanner object type from file bytes and filename extension.
engine::AvObjectType DetectObjectType(engine::IByteStream& stream, const std::filesystem::path& path);
// Builds a stable diagnostic id for the matched in-memory database record.
std::string BuildRecordId(const engine::AvSignatureRecord& record);
} // namespace antivirus::service
