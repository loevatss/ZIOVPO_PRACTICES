#pragma once

#include "AntivirusEngine.h"

#include <array>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::storage
{
enum class AvDatabaseLoadSource
{
    None = 0,
    Main = 1,
    Backup = 2,
    Default = 3,
    Incoming = 4,
};

struct AvDatabasePaths
{
    std::filesystem::path mainDatabasePath;
    std::filesystem::path backupDatabasePath;
    std::filesystem::path defaultDatabasePath;
    std::filesystem::path incomingDatabasePath;
    std::filesystem::path temporaryDatabasePath;
};

struct AvDatabaseLoadResult
{
    bool loaded = false;
    AvDatabaseLoadSource source = AvDatabaseLoadSource::None;
    engine::AvDatabaseInfo databaseInfo;
    size_t skippedRecordCount = 0;
    std::vector<std::array<uint8_t, 16>> skippedRecordIds;
    std::string message;
};

class ISignatureVerifier
{
public:
    virtual ~ISignatureVerifier() = default;

    // Returns the compact algorithm name stored in the database manifest.
    virtual std::string AlgorithmName() const = 0;
    // Verifies a detached signature for the supplied signed payload.
    virtual bool Verify(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& signature) const = 0;
    // Creates a demo signature for default/test databases generated locally.
    virtual std::vector<uint8_t> CreateSignatureForDemo(const std::vector<uint8_t>& payload) const = 0;
};

class DemoHmacSha256SignatureVerifier final : public ISignatureVerifier
{
public:
    // Returns the demo HMAC/SHA-256 signature algorithm identifier.
    std::string AlgorithmName() const override;
    // Verifies the demo HMAC/SHA-256 signature using the built-in training key.
    bool Verify(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& signature) const override;
    // Creates a demo HMAC/SHA-256 signature using the built-in training key.
    std::vector<uint8_t> CreateSignatureForDemo(const std::vector<uint8_t>& payload) const override;
};

class RsaSha256SignatureVerifier final : public ISignatureVerifier
{
public:
    // Creates RSA/SHA-256 verifier with embedded backend public key or explicit override.
    explicit RsaSha256SignatureVerifier(std::string publicKeyBase64 = {});

    // Returns the backend signature algorithm identifier.
    std::string AlgorithmName() const override;
    // Verifies RSA PKCS#1 v1.5 signature over SHA-256 hash.
    bool Verify(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& signature) const override;
    // Real verifier cannot sign local compact payloads because the private key is not available.
    std::vector<uint8_t> CreateSignatureForDemo(const std::vector<uint8_t>& payload) const override;

    // Returns true when a public key is available for verification.
    bool IsConfigured() const;
    // Returns active public key in Base64 DER form.
    const std::string& PublicKeyBase64() const;

private:
    std::string publicKeyBase64_;
};

// Returns embedded backend public key, optionally overridden through the process environment.
std::string ResolveBackendPublicKeyBase64();

// Returns the service database file layout under ProgramData.
AvDatabasePaths ResolveDefaultDatabasePaths();
// Writes a database using a temporary file and then replaces the target file.
bool SaveDatabaseFileAtomically(
    const engine::AvSignatureDatabase& database,
    const std::filesystem::path& targetPath,
    const std::filesystem::path& temporaryPath,
    const ISignatureVerifier& signatureVerifier);
// Creates or repairs the signed default database file.
bool EnsureDefaultDatabaseFile(const AvDatabasePaths& paths, const ISignatureVerifier& signatureVerifier);
// Loads one signed binary database file into the in-memory engine database.
AvDatabaseLoadResult LoadDatabaseFile(
    const std::filesystem::path& path,
    const ISignatureVerifier& signatureVerifier,
    engine::AvSignatureDatabase& database);
// Loads main, then backup, then default database with manifest and record verification.
AvDatabaseLoadResult LoadDatabaseWithFallback(
    const AvDatabasePaths& paths,
    const ISignatureVerifier& signatureVerifier,
    engine::AvSignatureDatabase& database);
// Converts a database load source to a short diagnostic name.
const char* ToString(AvDatabaseLoadSource source);
} // namespace antivirus::storage
