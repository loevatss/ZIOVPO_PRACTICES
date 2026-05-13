#include "AntivirusEngineSelfTest.h"

#include "AntivirusEngine.h"
#include "AntivirusScanService.h"

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
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
} // namespace

// Runs the required antivirus engine checks and returns a process exit code.
int RunAntivirusEngineSelfTest()
{
    const std::vector<uint8_t> signature = BuildPeSignature();
    const std::vector<uint8_t> cleanBytes = { 'c', 'l', 'e', 'a', 'n', ' ', 'd', 'a', 't', 'a' };
    const std::vector<uint8_t> objectAtOffset4 = BuildObjectBytes(signature, 4);
    const std::vector<uint8_t> eicarBytes = {
        'X', '5', 'O', '!', 'P', '%', '@', 'A', 'P', '[', '4', '\\',
        'P', 'Z', 'X', '5', '4', '(', 'P', '^', ')', '7', 'C', 'C',
        ')', '7', '}', '$', 'E', 'I', 'C', 'A', 'R', '-', 'S', 'T',
        'A', 'N', 'D', 'A', 'R', 'D', '-', 'A', 'N', 'T', 'I', 'V',
        'I', 'R', 'U', 'S', '-', 'T', 'E', 'S', 'T', '-', 'F', 'I',
        'L', 'E', '!', '$', 'H', '+', 'H', '*'
    };

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

    if (!WriteFileBytes(cleanFile, cleanBytes)
        || !WriteFileBytes(wrongTypeFile, objectAtOffset4)
        || !WriteFileBytes(wrongOffsetFile, objectAtOffset4)
        || !WriteFileBytes(infectedFile, objectAtOffset4)
        || !WriteFileBytes(eicarFile, eicarBytes))
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
        directoryResult.totalScanned == 5
            && directoryResult.infectedCount == 2
            && directoryResult.errorCount == 0
            && directoryResult.results.size() == 5) ? 0 : 1;

    engine::AvSignatureDatabase defaultDatabase;
    const bool loaded = LoadServiceAntivirusDatabase(defaultDatabase);
    const AvDatabaseRuntimeInfo databaseInfo = GetDatabaseRuntimeInfo(defaultDatabase, loaded);
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
