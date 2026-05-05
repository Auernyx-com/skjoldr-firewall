#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Skjoldr Firewall CLI — Avars/Mk2 daemon integration entry point.

    Usage: SkjoldrCLI.ps1 <verb> [options]

    Verbs:
        status                          Show firewall profile status
        export                          Export current state as a baseline snapshot
        apply --profile <name>          Apply a named profile (conservative | fortress | reset)
        apply --file <path>             Apply a ruleset file (.json)
        restore --snapshot <path>       Restore from an exported baseline snapshot

    Options:
        --json                          Output JSON envelope { ok, data } or { ok, error_code, message }
        --dry-run                       Validate and preview without making changes
        --timeout <ms>                  Accepted for caller compatibility; not enforced here

    Ruleset file format (for apply --file):
        {
          "profile": "conservative",       // optional: apply a named profile first
          "rules": [                        // optional: additional custom rules
            {
              "name": "SKJOLDR-Allow-SSH",
              "direction": "inbound",
              "action": "allow",
              "protocol": "TCP",
              "localPort": "22",
              "program": "",               // optional
              "enabled": true
            }
          ]
        }

    Snapshot files are written to .\skjoldr-snapshots\ relative to this script.
    The snapshot path and SHA-256 hash are returned in the export response —
    supply both to skjoldrFirewallRestoreBaseline in Mk2 for integrity-verified restore.
#>

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RawArgs = @()
)

$ErrorActionPreference = "Stop"
$VerbosePreference     = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"

# ── Arg parsing ──────────────────────────────────────────────────────────────

$verb     = ""
$profile  = ""
$file     = ""
$snapshot = ""
$useJson  = $false
$dryRun   = $false

$i = 0
while ($i -lt $RawArgs.Count) {
    $a = $RawArgs[$i]
    switch -Exact ($a) {
        "--json"     { $useJson = $true }
        "--dry-run"  { $dryRun  = $true }
        "--profile"  { $i++; if ($i -lt $RawArgs.Count) { $profile  = $RawArgs[$i] } }
        "--file"     { $i++; if ($i -lt $RawArgs.Count) { $file     = $RawArgs[$i] } }
        "--snapshot" { $i++; if ($i -lt $RawArgs.Count) { $snapshot = $RawArgs[$i] } }
        "--timeout"  { $i++ }
        default      { if (-not $a.StartsWith("-") -and $verb -eq "") { $verb = $a.ToLower() } }
    }
    $i++
}

# ── Output helpers ───────────────────────────────────────────────────────────

function Write-Ok {
    param([object] $Data)
    @{ ok = $true; data = $Data } | ConvertTo-Json -Depth 10 -Compress
}

function Write-Fail {
    param([string] $ErrorCode, [string] $Message)
    if ($useJson) {
        @{ ok = $false; error_code = $ErrorCode; message = $Message } | ConvertTo-Json -Depth 3 -Compress
    } else {
        Write-Error "$ErrorCode`: $Message"
    }
}

# ── Profile data helpers ─────────────────────────────────────────────────────

function Get-ProfileData {
    Get-NetFirewallProfile -All | ForEach-Object {
        @{
            name             = [string] $_.Name
            enabled          = [string] $_.Enabled
            default_inbound  = [string] $_.DefaultInboundAction
            default_outbound = [string] $_.DefaultOutboundAction
            log_allowed      = [string] $_.LogAllowed
            log_blocked      = [string] $_.LogBlocked
        }
    }
}

# ── SHA-256 helper ───────────────────────────────────────────────────────────

function Get-FileSha256 {
    param([string] $Path)
    $bytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.IO.File]::ReadAllBytes($Path)
    )
    return [System.BitConverter]::ToString($bytes).Replace("-", "").ToLower()
}

# ── Snapshot helpers ─────────────────────────────────────────────────────────

$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$snapshotDir = Join-Path $scriptDir "skjoldr-snapshots"

function Export-Snapshot {
    if (-not (Test-Path $snapshotDir)) {
        New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
    }

    $timestamp    = Get-Date -Format "yyyyMMdd-HHmmss"
    $snapshotPath = Join-Path $snapshotDir "baseline-$timestamp.json"

    $managedRules = @(
        Get-NetFirewallRule -DisplayName "SKJOLDR-*" -ErrorAction SilentlyContinue |
        ForEach-Object {
            @{
                display_name = [string] $_.DisplayName
                direction    = [string] $_.Direction
                action       = [string] $_.Action
                enabled      = [string] $_.Enabled
                profile      = [string] $_.Profile
            }
        }
    )

    $payload = @{
        skjoldr_snapshot = "v1"
        exported_at      = (Get-Date -Format "o")
        profiles         = @(Get-ProfileData)
        custom_rules     = $managedRules
    }

    $payload | ConvertTo-Json -Depth 10 | Set-Content -Path $snapshotPath -Encoding UTF8
    return $snapshotPath
}

function Import-Snapshot {
    param([string] $Path)
    if (-not (Test-Path $Path)) { throw "Snapshot file not found: $Path" }
    $data = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($data.skjoldr_snapshot -ne "v1") { throw "Unrecognised snapshot schema: $($data.skjoldr_snapshot)" }
    return $data
}

# ── Firewall operations ──────────────────────────────────────────────────────

$EssentialOutbound = @(
    "C:\Windows\System32\svchost.exe",
    "C:\Windows\explorer.exe",
    "C:\Windows\System32\cmd.exe",
    "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "C:\Program Files\Google\Chrome\Application\chrome.exe",
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
)

function Apply-ConservativeProfile {
    Set-NetFirewallProfile -Profile Domain, Public, Private `
        -Enabled            True  `
        -DefaultInboundAction  Block `
        -DefaultOutboundAction Allow `
        -AllowInboundRules  False `
        -AllowLocalFirewallRules True `
        -NotifyOnListen     False `
        -LogAllowed         True  `
        -LogBlocked         True
}

function Apply-FortressProfile {
    Set-NetFirewallProfile -Profile Domain, Public, Private `
        -Enabled            True  `
        -DefaultInboundAction  Block `
        -DefaultOutboundAction Block `
        -AllowInboundRules  False `
        -AllowLocalFirewallRules False `
        -NotifyOnListen     False `
        -LogAllowed         True  `
        -LogBlocked         True

    foreach ($prog in $EssentialOutbound) {
        if (Test-Path $prog) {
            $ruleName = "SKJOLDR-Allow-$([System.IO.Path]::GetFileName($prog))"
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Direction   Outbound `
                -Program     $prog `
                -Action      Allow `
                -Enabled     True `
                -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

function Apply-ResetProfile {
    (New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults() | Out-Null
    Remove-NetFirewallRule -DisplayName "SKJOLDR-*" -ErrorAction SilentlyContinue
}

function Invoke-NamedProfile {
    param([string] $Name)
    switch ($Name) {
        "conservative" { Apply-ConservativeProfile }
        "fortress"     { Apply-FortressProfile }
        "reset"        { Apply-ResetProfile }
        default        { throw "Unknown profile: '$Name'. Valid: conservative | fortress | reset" }
    }
}

# ── Verb: status ─────────────────────────────────────────────────────────────

function Invoke-Status {
    Write-Ok @{ profiles = @(Get-ProfileData) }
}

# ── Verb: export ─────────────────────────────────────────────────────────────

function Invoke-Export {
    if ($dryRun) {
        $profileCount = @(Get-ProfileData).Count
        $ruleCount    = @(Get-NetFirewallRule -DisplayName "SKJOLDR-*" -ErrorAction SilentlyContinue).Count
        Write-Ok @{
            dry_run              = $true
            planned_profile_count = $profileCount
            planned_rule_count   = $ruleCount
            snapshot_dir         = $snapshotDir
        }
        return
    }

    $snapshotPath = Export-Snapshot
    $hash         = Get-FileSha256 -Path $snapshotPath

    Write-Ok @{
        snapshot_path = $snapshotPath
        hash          = $hash
        exported_at   = (Get-Date -Format "o")
    }
}

# ── Verb: apply ──────────────────────────────────────────────────────────────

function Invoke-Apply {
    if ($profile -ne "") {
        Invoke-ApplyProfile
    } elseif ($file -ne "") {
        Invoke-ApplyFile
    } else {
        Write-Fail "missing_argument" "apply requires --profile <name> or --file <path>"
        exit 1
    }
}

function Invoke-ApplyProfile {
    $name = $profile.ToLower().Trim()
    $validProfiles = @("conservative", "fortress", "reset")
    if ($name -notin $validProfiles) {
        Write-Fail "invalid_profile" "Unknown profile: '$profile'. Valid: $($validProfiles -join ' | ')"
        exit 1
    }

    if ($dryRun) {
        $planned = switch ($name) {
            "conservative" { "Block all inbound, allow outbound, enable logging on all profiles" }
            "fortress"     { "Block all inbound and outbound; add minimal essential outbound exceptions" }
            "reset"        { "Restore Windows Firewall factory defaults; remove all SKJOLDR-* rules" }
        }
        Write-Ok @{ dry_run = $true; profile = $name; planned_action = $planned }
        return
    }

    Invoke-NamedProfile -Name $name
    Write-Ok @{ profile = $name; applied = $true; post_status = @{ profiles = @(Get-ProfileData) } }
}

function Invoke-ApplyFile {
    if (-not (Test-Path $file)) {
        Write-Fail "file_not_found" "Ruleset file not found: $file"
        exit 1
    }

    $ruleset = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
    $applied = [System.Collections.Generic.List[string]]::new()

    if ($dryRun) {
        $plannedActions = [System.Collections.Generic.List[string]]::new()
        if ($ruleset.profile) { $plannedActions.Add("Apply profile: $($ruleset.profile)") }
        if ($ruleset.rules)   { $plannedActions.Add("Create $(@($ruleset.rules).Count) custom rule(s)") }
        Write-Ok @{
            dry_run         = $true
            file            = $file
            planned_actions = @($plannedActions)
            rule_count      = if ($ruleset.rules) { @($ruleset.rules).Count } else { 0 }
        }
        return
    }

    if ($ruleset.profile) {
        Invoke-NamedProfile -Name $ruleset.profile.ToLower().Trim()
        $applied.Add("profile:$($ruleset.profile)")
    }

    if ($ruleset.rules) {
        foreach ($rule in $ruleset.rules) {
            $params = @{
                DisplayName = [string] $rule.name
                Direction   = if ([string]$rule.direction -eq "inbound") { "Inbound" } else { "Outbound" }
                Action      = if ([string]$rule.action   -eq "allow")    { "Allow" }   else { "Block" }
                Enabled     = if ($null -ne $rule.enabled) { [bool]$rule.enabled } else { $true }
                ErrorAction = "SilentlyContinue"
            }
            if ($rule.protocol -and [string]$rule.protocol -ne "") { $params.Protocol  = [string]$rule.protocol }
            if ($rule.localPort -and [string]$rule.localPort -ne "") { $params.LocalPort = [string]$rule.localPort }
            if ($rule.program -and [string]$rule.program -ne "")   { $params.Program   = [string]$rule.program }

            New-NetFirewallRule @params | Out-Null
            $applied.Add("rule:$([string]$rule.name)")
        }
    }

    Write-Ok @{ file = $file; applied = @($applied); post_status = @{ profiles = @(Get-ProfileData) } }
}

# ── Verb: restore ────────────────────────────────────────────────────────────

function Invoke-Restore {
    if ($snapshot -eq "") {
        Write-Fail "missing_argument" "restore requires --snapshot <path>"
        exit 1
    }

    $data = Import-Snapshot -Path $snapshot

    if ($dryRun) {
        Write-Ok @{
            dry_run       = $true
            snapshot      = $snapshot
            exported_at   = [string] $data.exported_at
            profile_count = @($data.profiles).Count
            rule_count    = @($data.custom_rules).Count
        }
        return
    }

    # Restore profile settings
    foreach ($prof in $data.profiles) {
        $params = @{
            Profile              = [string] $prof.name
            DefaultInboundAction = [string] $prof.default_inbound
            DefaultOutboundAction = [string] $prof.default_outbound
            ErrorAction          = "SilentlyContinue"
        }
        $enabledStr = [string] $prof.enabled
        if ($enabledStr -ne "NotConfigured") { $params.Enabled = ($enabledStr -eq "True") }

        $logAllowedStr = [string] $prof.log_allowed
        if ($logAllowedStr -ne "NotConfigured") { $params.LogAllowed = ($logAllowedStr -eq "True") }

        $logBlockedStr = [string] $prof.log_blocked
        if ($logBlockedStr -ne "NotConfigured") { $params.LogBlocked = ($logBlockedStr -eq "True") }

        Set-NetFirewallProfile @params
    }

    # Replace SKJOLDR-* rules with snapshot versions
    Remove-NetFirewallRule -DisplayName "SKJOLDR-*" -ErrorAction SilentlyContinue

    foreach ($rule in $data.custom_rules) {
        New-NetFirewallRule `
            -DisplayName [string] $rule.display_name `
            -Direction   [string] $rule.direction `
            -Action      [string] $rule.action `
            -Enabled     ($([string]$rule.enabled) -eq "True") `
            -ErrorAction SilentlyContinue | Out-Null
    }

    Write-Ok @{
        snapshot    = $snapshot
        restored    = $true
        exported_at = [string] $data.exported_at
        post_status = @{ profiles = @(Get-ProfileData) }
    }
}

# ── Dispatch ─────────────────────────────────────────────────────────────────

try {
    switch -Exact ($verb) {
        "status"  { Invoke-Status }
        "export"  { Invoke-Export }
        "apply"   { Invoke-Apply }
        "restore" { Invoke-Restore }
        default {
            Write-Fail "unknown_verb" "Unknown verb: '$verb'. Expected: status | export | apply | restore"
            exit 1
        }
    }
} catch {
    $msg = $_.Exception.Message
    if ($useJson) {
        @{ ok = $false; error_code = "internal_error"; message = $msg } |
            ConvertTo-Json -Depth 3 -Compress
    } else {
        Write-Error $msg
    }
    exit 1
}
