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
    Enable-NetFirewallProfile -Profile Domain,Public,Private
    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -NotifyOnListen True `
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

    function Show-SkjoldrReceipts {

    param([string] $Group)
    $groupName = $Group
    if (-not $groupName) { $groupName = $global:SKJOLDR_GROUP }
    if (-not $groupName) { $groupName = "SKJOLDR" }

    Write-Host "`n[DNS Health] Reachability of allowed DNS servers:" -ForegroundColor Cyan

    # Pull DNS servers from the Fortress rule if present; otherwise fall back to current OS DNS config
    $dnsFromRule = $null
    $dnsRule = Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Allow-DNS-Out*" } |
        Select-Object -First 1

    if ($dnsRule) {
        $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $dnsRule -ErrorAction SilentlyContinue
        if ($addr -and $addr.RemoteAddress -and ($addr.RemoteAddress -ne "Any")) {
            $dnsFromRule = @($addr.RemoteAddress)
        }
    }

    if (-not $dnsFromRule) {
        $dnsFromRule = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object { $_.ServerAddresses } |
            Where-Object { $_ } |
            Select-Object -Unique)
    }

    if (-not $dnsFromRule -or $dnsFromRule.Count -eq 0) {
        Write-Host "No DNS servers found to test." -ForegroundColor Yellow
    } else {
        $testDomain = "example.com"
        $dnsFromRule |
          ForEach-Object {
            $ip = $_
            $ok = $false
            try {
                Resolve-DnsName $testDomain -Server $ip -DnsOnly -NoHostsFile -ErrorAction Stop | Out-Null
                $ok = $true
            } catch { }
            [pscustomobject]@{
                Server = $ip
                Query  = $testDomain
                OK     = $ok
            }
          } | Format-Table -AutoSize
    }


    Write-Host "" 
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host "   SKJOLDR RECEIPTS  " -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan

    # 1) Firewall profile defaults (truth source)
    Write-Host "`n[Profiles] Default actions:" -ForegroundColor Cyan
    Get-NetFirewallProfile -Profile Domain,Public,Private |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Format-Table -AutoSize

    # 2) Skjoldr rules (truth source)
    Write-Host "`n[Rules] Skjoldr group rules:" -ForegroundColor Cyan
    $rules = Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "No rules found for group '$groupName'." -ForegroundColor Yellow
        return
    }

        $rules |
            Get-NetFirewallPortFilter |
            ForEach-Object {
                $r = $_
                $base = Get-NetFirewallRule -Name $r.InstanceID
                $addr = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $base -ErrorAction SilentlyContinue)
                [pscustomobject]@{
                    DisplayName   = $base.DisplayName
                    Enabled       = $base.Enabled
                    Direction     = $base.Direction
                    Action        = $base.Action
                    Protocol      = $r.Protocol
                    LocalPort     = $r.LocalPort
                    RemotePort    = $r.RemotePort
                    RemoteAddress = ($addr.RemoteAddress -join ",")
                }
            } |
            Sort-Object DisplayName |
            Format-Table -AutoSize

        # 3) Quick verdict for the usual outbound “open” ports (rule-name exact)
        Write-Host "`n[Summary] Expected outbound allowances (rule-name exact):" -ForegroundColor Cyan
        $names = @($rules.DisplayName)

        $checks = @(
            @{ Item = "DNS (53/UDP)";     RuleLike = "*Allow-DNS-Out*"   }
            @{ Item = "HTTPS (443/TCP)";  RuleLike = "*Allow-HTTPS-Out*" }
            @{ Item = "HTTP (80/TCP)";    RuleLike = "*Allow-HTTP-Out"   }
            @{ Item = "NTP (123/UDP)";    RuleLike = "*Allow-NTP-Out*"   }
        )

        $summary = foreach ($c in $checks) {
            $pattern = $c.RuleLike
            [pscustomobject]@{
                Item    = $c.Item
                Present = [bool]($names | Where-Object { $_ -like $pattern })
            }
        }

        $summary | Format-Table -AutoSize
    }

    function Apply-ConservativeMode {
        Test-SkjoldrAdmin
        Write-Host "[SKJOLDR] Applying Conservative mode..." -ForegroundColor Yellow
        try {
            # Always start clean (prevents rule stacking across mode switches)
            Remove-SkjoldrRules

            # Conservative = Inbound Block, Outbound Allow
            Set-NetFirewallProfile -Profile Domain,Public,Private `
                -DefaultInboundAction Block `
                -DefaultOutboundAction Allow `
                -LogAllowed True `
                -LogBlocked True `
                -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
                -LogMaxSizeKilobytes 32767 | Out-Null

            # Optional explicit outbound allows (auditable intent; outbound default already allows)
            New-NetFirewallRule -DisplayName "SKJOLDR-Allow-DNS-Out"   -Group $global:SKJOLDR_GROUP -Direction Outbound -Protocol UDP -RemotePort 53  -Action Allow | Out-Null
            New-NetFirewallRule -DisplayName "SKJOLDR-Allow-HTTPS-Out" -Group $global:SKJOLDR_GROUP -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow | Out-Null
            New-NetFirewallRule -DisplayName "SKJOLDR-Allow-HTTP-Out"  -Group $global:SKJOLDR_GROUP -Direction Outbound -Protocol TCP -RemotePort 80  -Action Allow | Out-Null
            New-NetFirewallRule -DisplayName "SKJOLDR-Allow-NTP-Out"   -Group $global:SKJOLDR_GROUP -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow | Out-Null

            Write-Host "[SKJOLDR] Conservative mode applied." -ForegroundColor Green
            try { Show-SkjoldrReceipts } catch { Write-Warning "[SKJOLDR] Receipts failed: $($_.Exception.Message)" }
        }
        catch {
            Write-Host "[SKJOLDR] Conservative mode FAILED: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

function Apply-FortressMode {
    [CmdletBinding()]
    param()

    try {
        Write-Host "[SKJOLDR] Applying Fortress mode..." -ForegroundColor Cyan

        if (-not (Test-SkjoldrAdmin)) { throw "Administrator privileges required." }

        # DNS servers you trust (restrict DNS hard in Fortress)
        $dnsServers = @("1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","149.112.112.112")

        # 1) Remove/neutralize HTTP allowances (Skjoldr + known Windows punch-throughs)
        Remove-SkjoldrRuleByDisplayName -DisplayName "SKJOLDR-Allow-HTTP-Out"
        Remove-SkjoldrRuleByDisplayName -DisplayName "SKJOLDR-FORTRESS-Allow-HTTP-Out"  # just in case old name exists

        foreach ($r in $script:SKJOLDR_WindowsAllowRules_HTTP80) {
            Disable-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue | Out-Null
        }

        # 2) Create Fortress allow rules (and explicit HTTP block)
        Ensure-SkjoldrRule -DisplayName "SKJOLDR-FORTRESS-Allow-DNS-Out"  -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53  -RemoteAddress $dnsServers
        Ensure-SkjoldrRule -DisplayName "SKJOLDR-FORTRESS-Allow-HTTPS-Out" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443
        Ensure-SkjoldrRule -DisplayName "SKJOLDR-FORTRESS-Allow-NTP-Out"   -Direction Outbound -Action Allow -Protocol UDP -RemotePort 123

        # Belt + suspenders: explicit HTTP block (beats random allow rules)
        Ensure-SkjoldrRule -DisplayName "SKJOLDR-FORTRESS-Block-HTTP-Out"  -Direction Outbound -Action Block -Protocol TCP -RemotePort 80

        # 3) Preflight: confirm at least DNS+HTTPS rules exist before outbound Block
        $need = @("SKJOLDR-FORTRESS-Allow-DNS-Out","SKJOLDR-FORTRESS-Allow-HTTPS-Out","SKJOLDR-FORTRESS-Allow-NTP-Out")
        $present = Get-NetFirewallRule -Group $global:SKJOLDR_GROUP -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
        foreach ($n in $need) {
            if ($present -notcontains $n) { throw "Fortress preflight failed: missing rule '$n' (refusing to block outbound)." }
        }

        # 4) Apply profile defaults LAST (avoid lockouts mid-run)
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Block | Out-Null

        Write-Host "[SKJOLDR] Fortress mode applied (DNS + HTTPS + NTP outbound allowed; HTTP blocked)." -ForegroundColor Green

        # 5) Receipts + live tests (never fail the mode)
        try {
            Write-Host "`n[Live Test] Connectivity checks:" -ForegroundColor Cyan
            Test-NetConnection 1.1.1.1 -Port 443 | Select-Object ComputerName,RemotePort,TcpTestSucceeded | Format-Table -AutoSize
            Test-NetConnection 1.1.1.1 -Port 80  | Select-Object ComputerName,RemotePort,TcpTestSucceeded | Format-Table -AutoSize
        } catch {
            Write-Warning "[SKJOLDR] Live tests failed: $($_.Exception.Message)"
        }

        try { Show-SkjoldrReceipts } catch { Write-Warning "[SKJOLDR] Receipts failed: $($_.Exception.Message)" }
    }
    catch {
        Write-Host "[SKJOLDR] Fortress mode FAILED: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Apply-ConservativeMode {
    [CmdletBinding()]
    param()

    try {
        Write-Host "[SKJOLDR] Applying Conservative mode..." -ForegroundColor Cyan

        if (-not (Test-SkjoldrAdmin)) { throw "Administrator privileges required." }

        # 1) Undo Fortress-specific restrictions
        # Remove the explicit Fortress HTTP block rule
        Remove-SkjoldrRuleByDisplayName -DisplayName "SKJOLDR-FORTRESS-Block-HTTP-Out"

        # Re-enable Windows “helper” allow rules (optional, but keeps Windows happy in normal mode)
        foreach ($r in $script:SKJOLDR_WindowsAllowRules_HTTP80) {
            Enable-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue | Out-Null
        }

        # 2) Conservative allow rules (outbound still allowed by profile, but rules provide explicit receipts)
        Ensure-SkjoldrRule -DisplayName "SKJOLDR-Allow-DNS-Out"   -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53
        Ensure-SkjoldrRule -DisplayName "SKJOLDR-Allow-HTTPS-Out" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443
        Ensure-SkjoldrRule -DisplayName "SKJOLDR-Allow-HTTP-Out"  -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80
        Ensure-SkjoldrRule -DisplayName "SKJOLDR-Allow-NTP-Out"   -Direction Outbound -Action Allow -Protocol UDP -RemotePort 123

        # 3) Apply profile defaults
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow | Out-Null

        Write-Host "[SKJOLDR] Conservative mode applied." -ForegroundColor Green

        # 4) Receipts (never fail the mode)
        try { Show-SkjoldrReceipts } catch { Write-Warning "[SKJOLDR] Receipts failed: $($_.Exception.Message)" }
    }
    catch {
        Write-Host "[SKJOLDR] Conservative mode FAILED: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
