# --- BEGIN: Set-SkjoldrConservativeMode ---
function Set-SkjoldrConservativeMode {
    Test-SkjoldrAdmin
    Write-Host "[SKJOLDR] Applying Conservative mode..." -ForegroundColor Yellow
    try {
        # Always start clean (prevents rule stacking across mode switches)
        Remove-SkjoldrRules
        # Conservative = Inbound Block, Outbound Allow
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -Enabled True `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
            -LogMaxSizeKilobytes 32767 | Out-Null
        # Optional explicit outbound allows (auditable intent; outbound default already allows)
        $rulesToCreate = @(
            @{ DisplayName = "SKJOLDR-Allow-DNS-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 53;  Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-HTTPS-Out"; Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 443; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-HTTP-Out";  Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 80;  Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-NTP-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 123; Action = "Allow"; Enabled = $true }
        )
        foreach ($rule in $rulesToCreate) {
            if (-not (Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue)) {
                try {
                    New-NetFirewallRule @rule -ErrorAction Stop
                    $verify = Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
                    if (-not $verify) { throw "Firewall rule '$($rule.DisplayName)' did not materialize after creation." }
                } catch {
                    throw "Failed to apply firewall rule '$($rule.DisplayName)': $($_.Exception.Message)"
                }
            }
        }
        Write-Host "[SKJOLDR] Conservative mode applied." -ForegroundColor Green
    }
    catch {
        Write-Host "[SKJOLDR] Conservative mode FAILED: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
# --- END: Set-SkjoldrConservativeMode ---

# --- BEGIN: Set-SkjoldrFortressMode ---
function Set-SkjoldrFortressMode {
    Test-SkjoldrAdmin
    Write-Host "[SKJOLDR] Applying Fortress mode..." -ForegroundColor Yellow
    try {
        # Always start clean
        Remove-SkjoldrRules
        # Fortress = Inbound Block, Outbound Block
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Block `
            -Enabled True `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
            -LogMaxSizeKilobytes 32767
        # Minimal outbound allows (DNS egress pinned to secure resolvers)
        $dnsServers = @("8.8.8.8","1.1.1.1")
        $rulesToCreate = @(
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-DNS-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 53;  RemoteAddress = $dnsServers; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-HTTPS-Out"; Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 443; RemoteAddress = "Any"; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-NTP-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 123; RemoteAddress = "Any"; Action = "Allow"; Enabled = $true }
        )
        foreach ($rule in $rulesToCreate) {
            if (-not (Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue)) {
                try {
                    New-NetFirewallRule @rule -ErrorAction Stop
                    $verify = Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
                    if (-not $verify) { throw "Firewall rule '$($rule.DisplayName)' did not materialize after creation." }
                } catch {
                    Write-Host "[SKJOLDR] Failed to create rule: $($rule.DisplayName) - $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        Write-Host "[SKJOLDR] Fortress mode applied (DNS egress pinned to $($dnsServers -join ", "))." -ForegroundColor Green
    }
    catch {
        Write-Host "[SKJOLDR] Fortress mode FAILED: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
# --- END: Set-SkjoldrFortressMode ---
# SkjoldrFirewall.ps1
# Skjoldr: Operator-controlled wrapper for Windows Defender Firewall
# Modes:
#  - Conservative: Inbound Block, Outbound Allow, Logging On, optional explicit allow rules (auditable)
#  - Fortress: Inbound Block, Outbound Block, Logging On, minimal explicit allow rules (DNS/HTTPS/NTP)
#  - Reset: Remove all SKJOLDR rules + restore sane defaults + logging off
# Notes:
#  - No domain/wildcard RemoteAddress rules. Windows Firewall needs IP/range/subnet/keywords, not FQDNs.
#  - This file is intentionally core-only. GUI/launcher should call these functions, not redefine logic.


# Bastion contract: refuse to run if BASTION_VERDICT is set and not ALLOW
if ($env:BASTION_VERDICT -and $env:BASTION_VERDICT -ne "ALLOW") {
    Write-Error "Skjoldr refused: BASTION_VERDICT is $($env:BASTION_VERDICT)"
    exit 3
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$global:SKJOLDR_GROUP  = "SKJOLDR"
$global:SKJOLDR_PREFIX = "SKJOLDR-"

function Test-SkjoldrAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Skjoldr requires an elevated PowerShell session (Run as Administrator)."
    }
}

function Remove-SkjoldrRules {
    # Removes both current SKJOLDR-* rules and legacy "Skjoldr - *" rules, plus anything grouped as SKJOLDR.
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -like "$($global:SKJOLDR_PREFIX)*" -or
            $_.Group -eq $global:SKJOLDR_GROUP -or
            $_.DisplayName -like "Skjoldr -*" -or
            $_.DisplayName -like "Skjoldr Fortress -*"
        } |
        ForEach-Object {
            Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
        }
}


function Reset-SkjoldrFirewall {
    Test-SkjoldrAdmin

    Remove-SkjoldrRules

    # Restore sane defaults: inbound block, outbound allow, logging off
    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogAllowed False `
        -LogBlocked False | Out-Null

    Write-Host "[SKJOLDR] Reset complete: removed SKJOLDR rules, restored profile defaults and disabled logging" -ForegroundColor Green
}

function Get-SkjoldrStatus {
    Test-SkjoldrAdmin

    $profiles = Get-NetFirewallProfile |
        Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName,LogMaxSizeKilobytes

    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "$($global:SKJOLDR_PREFIX)*" -or $_.Group -eq $global:SKJOLDR_GROUP } |
        Select-Object DisplayName,Direction,Action,Enabled,Profile,Group

    $outboundDefault = ($profiles | Select-Object -First 1).DefaultOutboundAction
    $modeGuess = if ($outboundDefault -eq "Allow") { "Conservative/Default" } else { "Fortress/Restricted" }

    [PSCustomObject]@{
        ModeGuess   = $modeGuess
        Profiles    = $profiles
        RuleCount   = ($rules | Measure-Object).Count
        Rules       = $rules
    }
}
