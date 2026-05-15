#include "AntivirusEngineSelfTest.h"

#include "AntivirusEngine.h"
#include "AntivirusScanService.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace antivirus::service
{
namespace
{
// Builds the PE demo signature used by scan self-tests.
std::vector<uint8_t> BuildPeSignature()
{
    return {
        'A', 'V', 'T', 'E', 'S', 'T', 'P', 'E',
        0x01, 0x02, 0x03, 0x04
    };
}

// Builds the EICAR test string as raw bytes.
std::vector<uint8_t> BuildEicarSignature()
{
    return {
        'X', '5', 'O', '!', 'P', '%', '@', 'A', 'P', '[', '4', '\\',
        'P', 'Z', 'X', '5', '4', '(', 'P', '^', ')', '7', 'C', 'C',
        ')', '7', '}', '$', 'E', 'I', 'C', 'A', 'R', '-', 'S', 'T',
        'A', 'N', 'D', 'A', 'R', 'D', '-', 'A', 'N', 'T', 'I', 'V',
        'I', 'R', 'U', 'S', '-', 'T', 'E', 'S', 'T', '-', 'F', 'I',
        'L', 'E', '!', '$', 'H', '+', 'H', '*'
    };
}

// Builds an object buffer with optional padding before the signature.
std::vector<uint8_t> BuildObjectBytes(const std::vector<uint8_t>& signature, size_t prefixPadding)
{
    std::vector<uint8_t> bytes(prefixPadding, 0x20);
    bytes.insert(bytes.end(), signature.begin(), signature.end());
    bytes.push_back(0x0A);
    return bytes;
}

// Adds one PE signature record to a fresh in-memory database.
engine::AvSignatureDatabase BuildDatabaseForRange(uint64_t offsetBegin, uint64_t offsetEnd)
{
    engine::AvSignatureDatabase database("2026-05-13T00:00:00Z");
    database.AddSignature(
        BuildPeSignature(),
        engine::AvObjectType::PE,
        offsetBegin,
        offsetEnd,
        { 'D', 'E', 'M', 'O' });
    return database;
}

// Adds PE and EICAR records to a fresh in-memory database.
engine::AvSignatureDatabase BuildTwoRecordDatabase()
{
    engine::AvSignatureDatabase database("2026-05-14T00:00:00Z");
    database.AddSignature(
        BuildPeSignature(),
        engine::AvObjectType::PE,
        0,
        1024,
        { 'D', 'E', 'M', 'O' });
    database.AddSignature(
        BuildEicarSignature(),
        engine::AvObjectType::ScriptText,
        0,
        std::numeric_limits<uint64_t>::max(),
        { 'D', 'E', 'M', 'O' });
    return database;
}

// Writes binary test content to disk.
bool WriteFileBytes(const std::filesystem::path& path, const std::vector<uint8_t>& bytes)
{
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        return false;
    }

    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return file.good();
}

// Reads binary test content from disk.
bool ReadFileBytes(const std::filesystem::path& path, std::vector<uint8_t>* bytes)
{
    if (bytes == nullptr)
    {
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        return false;
    }

    bytes->assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return file.good() || file.eof();
}

// Flips one byte in a binary file for corruption tests.
bool FlipByteInFile(const std::filesystem::path& path, size_t offset)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(path, &bytes) || offset >= bytes.size())
    {
        return false;
    }

    bytes[offset] ^= 0xFFu;
    return WriteFileBytes(path, bytes);
}

// Flips the manifest signature without touching record bytes.
bool CorruptManifestSignature(const std::filesystem::path& path)
{
    constexpr size_t unsignedManifestLength = 56;
    constexpr size_t manifestSignatureOffset = unsignedManifestLength + sizeof(uint32_t);
    return FlipByteInFile(path, manifestSignatureOffset);
}

// Flips the last record signature byte while keeping manifest content valid.
bool CorruptLastRecordSignature(const std::filesystem::path& path)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(path, &bytes) || bytes.empty())
    {
        return false;
    }

    return FlipByteInFile(path, bytes.size() - 1);
}

// Creates a unique temporary directory for scan self-tests.
std::filesystem::path BuildTempRoot()
{
    const auto ticks = std::chrono::system_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path()
        / ("AntivirusScanSelfTest_" + std::to_string(ticks));
}

// Reports one self-test check result.
bool ReportCase(const char* name, bool passed)
{
    std::printf("[%s] %s\n", passed ? "PASS" : "FAIL", name);
    return passed;
}

// Checks one file scan result.
bool ExpectFileStatus(
    const char* name,
    const FileScanResult& result,
    FileScanStatus expectedStatus,
    engine::AvObjectType expectedType)
{
    const bool passed = result.status == expectedStatus && result.objectType == expectedType;
    std::printf(
        "[%s] %s (status=%d, type=%s, record=%s)\n",
        passed ? "PASS" : "FAIL",
        name,
        static_cast<int>(result.status),
        engine::ToString(result.objectType),
        result.recordId.empty() ? "-" : result.recordId.c_str());
    return passed;
}

// Builds a complete temporary database layout for storage tests.
storage::AvDatabasePaths BuildTempDatabasePaths(const std::filesystem::path& tempRoot)
{
    const std::filesystem::path databaseRoot = tempRoot / "Databases";
    storage::AvDatabasePaths paths;
    paths.mainDatabasePath = databaseRoot / "main.avdb";
    paths.backupDatabasePath = databaseRoot / "backup.avdb";
    paths.defaultDatabasePath = databaseRoot / "default.avdb";
    paths.incomingDatabasePath = databaseRoot / "incoming.avdb";
    paths.temporaryDatabasePath = databaseRoot / "database.tmp";
    return paths;
}
} // namespace

// Runs the required antivirus engine checks and returns a process exit code.
int RunAntivirusEngineSelfTest()
{
    const std::vector<uint8_t> signature = BuildPeSignature();
    const std::vector<uint8_t> cleanBytes = { 'c', 'l', 'e', 'a', 'n', ' ', 'd', 'a', 't', 'a' };
    const std::vector<uint8_t> objectAtOffset4 = BuildObjectBytes(signature, 4);
    const std::vector<uint8_t> eicarBytes = BuildEicarSignature();

    const std::filesystem::path tempRoot = BuildTempRoot();
    std::error_code fsError;
    std::filesystem::create_directories(tempRoot, fsError);
    if (fsError)
    {
        std::printf("Cannot create self-test directory: %s\n", fsError.message().c_str());
        return 1;
    }

    const std::filesystem::path cleanFile = tempRoot / "clean.exe";
    const std::filesystem::path wrongTypeFile = tempRoot / "wrong-type.txt";
    const std::filesystem::path wrongOffsetFile = tempRoot / "wrong-offset.exe";
    const std::filesystem::path infectedFile = tempRoot / "infected.exe";
    const std::filesystem::path eicarFile = tempRoot / "TestAntivirus.com";
    const std::filesystem::path cleanTextFile = tempRoot / "clean.txt";

    if (!WriteFileBytes(cleanFile, cleanBytes)
        || !WriteFileBytes(wrongTypeFile, objectAtOffset4)
        || !WriteFileBytes(wrongOffsetFile, objectAtOffset4)
        || !WriteFileBytes(infectedFile, objectAtOffset4)
        || !WriteFileBytes(eicarFile, eicarBytes)
        || !WriteFileBytes(cleanTextFile, cleanBytes))
    {
        std::filesystem::remove_all(tempRoot, fsError);
        std::printf("Cannot write self-test files.\n");
        return 1;
    }

    int failed = 0;

    engine::AvSignatureDatabase noDetectDatabase = BuildDatabaseForRange(0, 1024);
    failed += ExpectFileStatus(
        "ScanFile returns clean when signature is absent",
        ScanFilePath(cleanFile, noDetectDatabase),
        FileScanStatus::Clean,
        engine::AvObjectType::PE) ? 0 : 1;

    engine::AvSignatureDatabase wrongTypeDatabase = BuildDatabaseForRange(0, 1024);
    failed += ExpectFileStatus(
        "ScanFile returns clean when object type does not match",
        ScanFilePath(wrongTypeFile, wrongTypeDatabase),
        FileScanStatus::Clean,
        engine::AvObjectType::ScriptText) ? 0 : 1;

    engine::AvSignatureDatabase wrongOffsetDatabase = BuildDatabaseForRange(5, 1024);
    failed += ExpectFileStatus(
        "ScanFile returns clean when offset does not match",
        ScanFilePath(wrongOffsetFile, wrongOffsetDatabase),
        FileScanStatus::Clean,
        engine::AvObjectType::PE) ? 0 : 1;

    engine::AvSignatureDatabase detectDatabase = BuildDatabaseForRange(4, 4);
    failed += ExpectFileStatus(
        "ScanFile returns infected when signature, type and offset match",
        ScanFilePath(infectedFile, detectDatabase),
        FileScanStatus::Infected,
        engine::AvObjectType::PE) ? 0 : 1;

    const DirectoryScanResult directoryResult = ScanDirectoryPath(tempRoot, detectDatabase);
    failed += ReportCase(
        "ScanDirectory scans several files and returns aggregate counters",
        directoryResult.totalScanned == 6
            && directoryResult.infectedCount == 2
            && directoryResult.errorCount == 0
            && directoryResult.results.size() == 6) ? 0 : 1;

    engine::AvSignatureDatabase defaultDatabase;
    const bool loaded = LoadServiceAntivirusDatabase(defaultDatabase);
    const AvDatabaseRuntimeInfo databaseInfo = GetDatabaseRuntimeInfo(
        defaultDatabase,
        loaded,
        "main",
        "self-test",
        engine::BuildCurrentUtcReleaseDate(),
        engine::BuildCurrentUtcReleaseDate(),
        0,
        "DEMO-HMAC-SHA256",
        true,
        true,
        "enabled",
        "enabled");
    failed += ReportCase(
        "GetAvDatabaseInfo has release date and records after initialization",
        databaseInfo.loaded
            && !databaseInfo.databaseInfo.releaseDateUtc.empty()
            && databaseInfo.databaseInfo.recordCount > 0) ? 0 : 1;

    failed += ExpectFileStatus(
        "Default database detects EICAR test file",
        ScanFilePath(eicarFile, defaultDatabase),
        FileScanStatus::Infected,
        engine::AvObjectType::ScriptText) ? 0 : 1;

    failed += ReportCase(
        "Aho-Corasick scanning path detects EICAR",
        ScanFilePath(eicarFile, defaultDatabase).status == FileScanStatus::Infected) ? 0 : 1;

    failed += ExpectFileStatus(
        "Default database does not detect clean text file",
        ScanFilePath(cleanTextFile, defaultDatabase),
        FileScanStatus::Clean,
        engine::AvObjectType::ScriptText) ? 0 : 1;

    const storage::DemoHmacSha256SignatureVerifier signatureVerifier;
    const storage::AvDatabasePaths databasePaths = BuildTempDatabasePaths(tempRoot);
    engine::AvSignatureDatabase diskDatabase = BuildTwoRecordDatabase();

    failed += ReportCase(
        "Binary database is saved on disk",
        storage::SaveDatabaseFileAtomically(
            diskDatabase,
            databasePaths.mainDatabasePath,
            databasePaths.temporaryDatabasePath,
            signatureVerifier)
            && std::filesystem::exists(databasePaths.mainDatabasePath)) ? 0 : 1;

    failed += ReportCase(
        "Default binary database is created",
        storage::EnsureDefaultDatabaseFile(databasePaths, signatureVerifier)
            && std::filesystem::exists(databasePaths.defaultDatabasePath)) ? 0 : 1;

    engine::AvSignatureDatabase loadedFromMain;
    storage::AvDatabaseLoadResult loadResult;
    const bool loadedMain = LoadServiceAntivirusDatabase(loadedFromMain, databasePaths, &loadResult);
    failed += ReportCase(
        "Service startup loads main database from disk",
        loadedMain
            && loadResult.source == storage::AvDatabaseLoadSource::Main
            && loadedFromMain.GetInfo().recordCount == 2) ? 0 : 1;

    std::filesystem::copy_file(
        databasePaths.mainDatabasePath,
        databasePaths.backupDatabasePath,
        std::filesystem::copy_options::overwrite_existing,
        fsError);
    const bool manifestWasCorrupted = CorruptManifestSignature(databasePaths.mainDatabasePath);
    engine::AvSignatureDatabase loadedFromBackup;
    storage::AvDatabaseLoadResult backupLoadResult;
    const bool loadedBackup = LoadServiceAntivirusDatabase(loadedFromBackup, databasePaths, &backupLoadResult);
    failed += ReportCase(
        "Bad manifest signature falls back to backup database",
        manifestWasCorrupted
            && loadedBackup
            && backupLoadResult.source == storage::AvDatabaseLoadSource::Backup
            && loadedFromBackup.GetInfo().recordCount == 2) ? 0 : 1;

    CorruptManifestSignature(databasePaths.backupDatabasePath);
    engine::AvSignatureDatabase loadedFromDefault;
    storage::AvDatabaseLoadResult defaultLoadResult;
    const bool loadedDefault = LoadServiceAntivirusDatabase(loadedFromDefault, databasePaths, &defaultLoadResult);
    failed += ReportCase(
        "Bad main and backup fall back to default database",
        loadedDefault
            && defaultLoadResult.source == storage::AvDatabaseLoadSource::Default
            && loadedFromDefault.GetInfo().recordCount > 0) ? 0 : 1;

    storage::SaveDatabaseFileAtomically(
        diskDatabase,
        databasePaths.mainDatabasePath,
        databasePaths.temporaryDatabasePath,
        signatureVerifier);
    std::filesystem::remove(databasePaths.backupDatabasePath, fsError);
    const bool mainWasCorruptedWithoutBackup = CorruptManifestSignature(databasePaths.mainDatabasePath);
    engine::AvSignatureDatabase loadedWithoutBackup;
    storage::AvDatabaseLoadResult missingBackupLoadResult;
    const bool loadedWithoutBackupOk = LoadServiceAntivirusDatabase(
        loadedWithoutBackup,
        databasePaths,
        &missingBackupLoadResult);
    failed += ReportCase(
        "Bad main without backup falls back to default database",
        mainWasCorruptedWithoutBackup
            && loadedWithoutBackupOk
            && missingBackupLoadResult.source == storage::AvDatabaseLoadSource::Default
            && loadedWithoutBackup.GetInfo().recordCount > 0) ? 0 : 1;

    storage::SaveDatabaseFileAtomically(
        diskDatabase,
        databasePaths.mainDatabasePath,
        databasePaths.temporaryDatabasePath,
        signatureVerifier);
    std::filesystem::remove(databasePaths.backupDatabasePath, fsError);
    const bool recordWasCorrupted = CorruptLastRecordSignature(databasePaths.mainDatabasePath);
    engine::AvSignatureDatabase loadedWithSkippedRecord;
    storage::AvDatabaseLoadResult skippedLoadResult;
    const bool loadedWithSkip = LoadServiceAntivirusDatabase(
        loadedWithSkippedRecord,
        databasePaths,
        &skippedLoadResult);
    failed += ReportCase(
        "Record with bad signature is skipped",
        recordWasCorrupted
            && loadedWithSkip
            && skippedLoadResult.source == storage::AvDatabaseLoadSource::Main
            && skippedLoadResult.skippedRecordCount == 1
            && loadedWithSkippedRecord.GetInfo().recordCount == 1) ? 0 : 1;

    std::filesystem::remove_all(tempRoot, fsError);

    if (failed != 0)
    {
        std::printf("Antivirus scan self-test failed: %d case(s).\n", failed);
        return 1;
    }

    std::printf("Antivirus scan self-test passed.\n");
    return 0;
}
} // namespace antivirus::service
