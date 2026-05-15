#pragma once

#include "AntivirusDatabaseStorage.h"
#include "AntivirusEngine.h"

#include <array>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::service
{
struct AvDatabaseUpdaterContext
{
    std::wstring apiBaseUrl;
    std::string accessToken;
    storage::AvDatabasePaths paths;
};

struct AvDatabaseUpdateResult
{
    bool attempted = false;
    bool downloaded = false;
    bool updated = false;
    bool rolledBack = false;
    size_t importedRecordCount = 0;
    size_t skippedRecordCount = 0;
    storage::AvDatabaseLoadResult loadResult;
    std::string message;
};

// Downloads the full binary signature export, saves it as the main compact DB and reloads it.
bool UpdateDatabaseFromServer(
    const AvDatabaseUpdaterContext& context,
    bool forceFullDownload,
    engine::AvSignatureDatabase& database,
    AvDatabaseUpdateResult* updateResult);

// Attempts to repair skipped compact DB records by UUID through /api/binary/signatures/by-ids.
bool RepairDamagedRecordsFromServer(
    const AvDatabaseUpdaterContext& context,
    const std::vector<std::array<uint8_t, 16>>& recordIds,
    engine::AvSignatureDatabase& database,
    AvDatabaseUpdateResult* updateResult);

// Returns true when the updater has enough local prerequisites to talk to the backend.
bool IsNetworkAvailable(const AvDatabaseUpdaterContext& context, std::string* reason);
} // namespace antivirus::service
