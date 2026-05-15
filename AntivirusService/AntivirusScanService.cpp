#include "AntivirusScanService.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>

namespace antivirus::service
{
namespace
{
// Converts an extension to lowercase ASCII for object type checks.
std::string ExtensionLower(const std::filesystem::path& path)
{
    std::string extension = path.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return extension;
}

// Returns true when a filename extension is commonly used for PE files.
bool IsPeExtension(const std::string& extension)
{
    return extension == ".exe"
        || extension == ".dll"
        || extension == ".sys"
        || extension == ".scr"
        || extension == ".ocx";
}

// Returns true when a filename extension is commonly used for script/text files.
bool IsScriptTextExtension(const std::string& extension)
{
    return extension == ".txt"
        || extension == ".log"
        || extension == ".js"
        || extension == ".vbs"
        || extension == ".ps1"
        || extension == ".bat"
        || extension == ".cmd"
        || extension == ".html"
        || extension == ".htm";
}

// Returns true when the first bytes look like readable text.
bool LooksLikeText(const std::array<uint8_t, 64>& bytes, size_t byteCount)
{
    if (byteCount == 0)
    {
        return false;
    }

    size_t printable = 0;
    for (size_t i = 0; i < byteCount; ++i)
    {
        const uint8_t byte = bytes[i];
        if (byte == '\r' || byte == '\n' || byte == '\t'
            || (byte >= 0x20 && byte <= 0x7E))
        {
            ++printable;
        }
    }

    return printable * 100 >= byteCount * 80;
}

// Formats a 64-bit number as fixed-width hexadecimal text.
std::string ToHex64(uint64_t value)
{
    std::ostringstream output;
    output << "0x"
        << std::hex
        << std::uppercase
        << std::setw(16)
        << std::setfill('0')
        << value;
    return output.str();
}

// Converts filesystem errors into readable scan messages.
std::string ErrorMessage(const std::string& prefix, const std::error_code& error)
{
    if (!error)
    {
        return prefix;
    }

    return prefix + ": " + error.message();
}

// Appends a file result and updates directory counters.
void AppendResult(DirectoryScanResult& directoryResult, FileScanResult fileResult)
{
    ++directoryResult.totalScanned;
    if (fileResult.status == FileScanStatus::Infected)
    {
        ++directoryResult.infectedCount;
    }
    else if (fileResult.status == FileScanStatus::Error)
    {
        ++directoryResult.errorCount;
    }

    directoryResult.results.push_back(std::move(fileResult));
}

// Creates an error result for a specific path.
FileScanResult MakeErrorResult(const std::filesystem::path& path, std::string message)
{
    FileScanResult result;
    result.status = FileScanStatus::Error;
    result.path = path;
    result.objectType = engine::AvObjectType::Unknown;
    result.message = std::move(message);
    return result;
}
} // namespace

// Loads the antivirus database from service disk paths with fallback.
bool LoadServiceAntivirusDatabase(engine::AvSignatureDatabase& database)
{
    return LoadServiceAntivirusDatabase(database, nullptr);
}

// Loads the antivirus database and returns detailed fallback diagnostics.
bool LoadServiceAntivirusDatabase(
    engine::AvSignatureDatabase& database,
    storage::AvDatabaseLoadResult* loadResult)
{
    const storage::AvDatabasePaths paths = storage::ResolveDefaultDatabasePaths();
    return LoadServiceAntivirusDatabase(database, paths, loadResult);
}

// Loads the antivirus database from supplied paths for tests and service bootstrap.
bool LoadServiceAntivirusDatabase(
    engine::AvSignatureDatabase& database,
    const storage::AvDatabasePaths& paths,
    storage::AvDatabaseLoadResult* loadResult)
{
    const storage::DemoHmacSha256SignatureVerifier signatureVerifier;
    storage::AvDatabaseLoadResult result =
        storage::LoadDatabaseWithFallback(paths, signatureVerifier, database);
    if (loadResult != nullptr)
    {
        *loadResult = result;
    }

    return result.loaded && result.databaseInfo.recordCount > 0;
}

// Returns database state in the format used by service RPC.
AvDatabaseRuntimeInfo GetDatabaseRuntimeInfo(
    const engine::AvSignatureDatabase& database,
    bool loaded,
    std::string sourceName,
    std::string lastUpdateStatus,
    std::string lastSuccessfulLoadUtc,
    std::string lastSuccessfulManifestVerificationUtc,
    size_t skippedRecordCount,
    std::string verifierName,
    bool schedulerEnabled,
    bool monitoringEnabled,
    std::string schedulerStatus,
    std::string monitoringStatus)
{
    AvDatabaseRuntimeInfo info;
    info.loaded = loaded;
    info.databaseInfo = database.GetInfo();
    info.sourceName = std::move(sourceName);
    info.lastUpdateStatus = std::move(lastUpdateStatus);
    info.lastSuccessfulLoadUtc = std::move(lastSuccessfulLoadUtc);
    info.lastSuccessfulManifestVerificationUtc = std::move(lastSuccessfulManifestVerificationUtc);
    info.skippedRecordCount = skippedRecordCount;
    info.verifierName = std::move(verifierName);
    info.schedulerEnabled = schedulerEnabled;
    info.monitoringEnabled = monitoringEnabled;
    info.schedulerStatus = std::move(schedulerStatus);
    info.monitoringStatus = std::move(monitoringStatus);
    return info;
}

// Opens and scans one file through the shared byte-stream antivirus engine.
FileScanResult ScanFilePath(const std::filesystem::path& path, const engine::AvSignatureDatabase& database)
{
    FileScanResult result;
    result.path = path;

    std::error_code existsError;
    if (!std::filesystem::exists(path, existsError))
    {
        result.status = FileScanStatus::Error;
        result.message = ErrorMessage("File does not exist", existsError);
        return result;
    }

    std::error_code regularFileError;
    if (!std::filesystem::is_regular_file(path, regularFileError))
    {
        result.status = FileScanStatus::Error;
        result.message = ErrorMessage("Path is not a regular file", regularFileError);
        return result;
    }

    engine::FileByteStream stream(path);
    if (!stream.IsOpen())
    {
        result.status = FileScanStatus::Error;
        result.message = "Cannot open file for scanning";
        return result;
    }

    result.objectType = DetectObjectType(stream, path);
    engine::AvScanner scanner(database);
    const engine::AvScanResult scanResult = scanner.Scan(stream, result.objectType);
    if (!scanResult.scanCompleted)
    {
        result.status = FileScanStatus::Error;
        result.message = "Scan did not complete";
        return result;
    }

    if (!scanResult.malicious)
    {
        result.status = FileScanStatus::Clean;
        result.message = "No matching signature";
        return result;
    }

    result.status = FileScanStatus::Infected;
    result.recordId = BuildRecordId(scanResult.matchedRecord);
    result.message = "Malware signature matched";
    return result;
}

// Recursively scans regular files under a directory and aggregates per-file results.
DirectoryScanResult ScanDirectoryPath(const std::filesystem::path& path, const engine::AvSignatureDatabase& database)
{
    DirectoryScanResult directoryResult;

    std::error_code existsError;
    if (!std::filesystem::exists(path, existsError))
    {
        AppendResult(directoryResult, MakeErrorResult(path, ErrorMessage("Directory does not exist", existsError)));
        return directoryResult;
    }

    std::error_code directoryError;
    if (!std::filesystem::is_directory(path, directoryError))
    {
        AppendResult(directoryResult, MakeErrorResult(path, ErrorMessage("Path is not a directory", directoryError)));
        return directoryResult;
    }

    std::error_code iteratorError;
    std::filesystem::recursive_directory_iterator it(
        path,
        std::filesystem::directory_options::skip_permission_denied,
        iteratorError);
    if (iteratorError)
    {
        AppendResult(directoryResult, MakeErrorResult(path, ErrorMessage("Cannot enumerate directory", iteratorError)));
        return directoryResult;
    }

    const std::filesystem::recursive_directory_iterator end;
    while (it != end)
    {
        const std::filesystem::path currentPath = it->path();

        std::error_code fileTypeError;
        if (it->is_regular_file(fileTypeError))
        {
            AppendResult(directoryResult, ScanFilePath(currentPath, database));
        }
        else if (fileTypeError)
        {
            AppendResult(directoryResult, MakeErrorResult(
                currentPath,
                ErrorMessage("Cannot read filesystem entry", fileTypeError)));
        }

        it.increment(iteratorError);
        if (iteratorError)
        {
            AppendResult(directoryResult, MakeErrorResult(
                currentPath,
                ErrorMessage("Cannot continue directory enumeration", iteratorError)));
            iteratorError.clear();
        }
    }

    return directoryResult;
}

// Scans all fixed drives through the existing directory scanner.
DirectoryScanResult ScanFixedDrives(const engine::AvSignatureDatabase& database)
{
    DirectoryScanResult aggregate;
    DWORD required = GetLogicalDriveStringsW(0, nullptr);
    if (required == 0)
    {
        AppendResult(aggregate, MakeErrorResult({}, "Cannot enumerate logical drives"));
        return aggregate;
    }

    std::vector<wchar_t> driveBuffer(required + 1, L'\0');
    if (GetLogicalDriveStringsW(required, driveBuffer.data()) == 0)
    {
        AppendResult(aggregate, MakeErrorResult({}, "Cannot read logical drives"));
        return aggregate;
    }

    for (const wchar_t* current = driveBuffer.data(); *current != L'\0'; current += std::wcslen(current) + 1)
    {
        if (GetDriveTypeW(current) != DRIVE_FIXED)
        {
            continue;
        }

        const DirectoryScanResult driveResult = ScanDirectoryPath(std::filesystem::path(current), database);
        aggregate.totalScanned += driveResult.totalScanned;
        aggregate.infectedCount += driveResult.infectedCount;
        aggregate.errorCount += driveResult.errorCount;
        aggregate.results.insert(
            aggregate.results.end(),
            driveResult.results.begin(),
            driveResult.results.end());
    }

    return aggregate;
}

// Detects the scanner object type from file bytes and filename extension.
engine::AvObjectType DetectObjectType(engine::IByteStream& stream, const std::filesystem::path& path)
{
    std::array<uint8_t, 64> header{};
    stream.Seek(0);
    const size_t bytesRead = stream.Read(header.data(), header.size());
    stream.Seek(0);

    if (bytesRead >= 2 && header[0] == 'M' && header[1] == 'Z')
    {
        return engine::AvObjectType::PE;
    }

    const std::string extension = ExtensionLower(path);
    if (IsPeExtension(extension))
    {
        return engine::AvObjectType::PE;
    }

    if (IsScriptTextExtension(extension) || LooksLikeText(header, bytesRead))
    {
        return engine::AvObjectType::ScriptText;
    }

    return engine::AvObjectType::Unknown;
}

// Builds a stable diagnostic id for the matched in-memory database record.
std::string BuildRecordId(const engine::AvSignatureRecord& record)
{
    std::ostringstream output;
    output
        << engine::ToString(record.ObjectType)
        << ":prefix="
        << ToHex64(record.ObjectSignaturePrefix)
        << ":length="
        << record.ObjectSignatureLength
        << ":offset="
        << record.OffsetBegin
        << "-"
        << record.OffsetEnd;
    return output.str();
}
} // namespace antivirus::service
