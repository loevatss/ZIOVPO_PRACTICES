#pragma once

namespace antivirus::ui
{
enum class StopConfirmationResult
{
    Confirmed,
    Rejected,
    Failed
};

// Показывает подтверждение остановки службы на отдельном user desktop.
StopConfirmationResult ShowIsolatedStopConfirmation();
}
