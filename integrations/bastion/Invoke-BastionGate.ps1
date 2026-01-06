# Bastion-to-Skjoldr Gate Adapter
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File integrations/bastion/Invoke-BastionGate.ps1 -Decision <decision.json> -Skjoldr <SkjoldrFirewall.ps1> [<SkjoldrArgs>]

param(
    [Parameter(Mandatory=$true)]
    [string]$Decision,
    [Parameter(Mandatory=$true)]
    [string]$Skjoldr,
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$SkjoldrArgs
)

if (-not (Test-Path -LiteralPath $Decision)) {
    Write-Error "Decision file not found: $Decision"
    exit 2
}

try {
    $decisionObj = Get-Content -Raw -Path $Decision | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-Error "Failed to parse decision file as JSON: $Decision. $_"
    exit 5
}

if (-not $decisionObj -or -not $decisionObj.PSObject.Properties.Match('verdict') -or [string]::IsNullOrWhiteSpace([string]$decisionObj.verdict)) {
    Write-Error "Decision JSON is missing a valid 'verdict' property."
    exit 4
}

switch ($decisionObj.verdict) {
    "ALLOW" { break }
    "PAUSE" {
        Write-Error "Bastion verdict PAUSE. No enforcement performed."
        exit 3
    }
    default {
        Write-Error "Invalid or forbidden Bastion verdict: $($decisionObj.verdict)"
        exit 4
    }
}

# Optional: explicit operator emergency lockdown
if ($env:SKJOLDR_EMERGENCY -eq "FORTRESS") {
    Write-Warning "Emergency Fortress mode requested by operator."
    & $Skjoldr -Mode Fortress
    exit 0
}

# Only call Skjoldr if ALLOW
& $Skjoldr @SkjoldrArgs
exit $LASTEXITCODE
