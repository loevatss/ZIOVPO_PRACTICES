#pragma once

namespace antivirus::service
{
// Runs the required antivirus engine checks and returns a process exit code.
int RunAntivirusEngineSelfTest();
} // namespace antivirus::service
