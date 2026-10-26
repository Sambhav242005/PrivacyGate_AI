function Test-RecordedProcessIdentity {
    param(
        [System.Diagnostics.Process]$Process,
        [object]$RecordedStart
    )
    try {
        # Windows PowerShell 5 returns JSON dates as strings; PowerShell 7 can
        # return DateTime objects. Compare instants, never formatted strings.
        $recordedUtc = if ($RecordedStart -is [DateTimeOffset]) {
            $RecordedStart.UtcDateTime
        } elseif ($RecordedStart -is [DateTime]) {
            $RecordedStart.ToUniversalTime()
        } else {
            [DateTime]::ParseExact(
                [string]$RecordedStart,
                'o',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            ).ToUniversalTime()
        }
        return $Process.StartTime.ToUniversalTime().Ticks -eq $recordedUtc.Ticks
    } catch {
        # Unreadable process metadata or malformed records never permit a stop.
        return $false
    }
}
