# SkjoldrFirewall.Legacy.ps1
# Reference-only: Legacy SkjoldrFirewall functions and helpers
# This file is for historical review and should NOT be used or edited for implementation.

function Resolve-SkjoldrRuleEnabled {
    param([Parameter(Mandatory)][bool] $On)
    $enumTypeName = "Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled"
    $t = [Type]::GetType($enumTypeName, $false)
    if ($t) {
        return [Enum]::Parse($t, $On.ToString(), $true)
    }
    return $On
}

function Resolve-SkjoldrGpoBoolean {
    param([Parameter(Mandatory)][bool] $On)
    $t = [Type]::GetType("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean", $false)
    if (-not $t) {
        $t = [AppDomain]::CurrentDomain.GetAssemblies() |
            ForEach-Object { $_.GetType("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean", $false) } |
            Where-Object { $_ } |
            Select-Object -First 1
    }
    if ($t) {
        return [Enum]::Parse($t, $On.ToString(), $true)
    }
    return $On
}

function Set-SkjoldrConservativeMode {
    Test-SkjoldrAdmin
    Write-Host "[SKJOLDR] Applying Conservative mode..." -ForegroundColor Yellow
    try {
        Remove-SkjoldrRules
        Enable-NetFirewallProfile -Profile Domain,Public,Private
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -NotifyOnListen True `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
            -LogMaxSizeKilobytes 32767 | Out-Null
        $rulesToCreate = @(
            @{ DisplayName = "SKJOLDR-Allow-DNS-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 53;  Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-HTTPS-Out"; Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 443; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-HTTP-Out";  Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 80;  Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-NTP-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 123; Action = "Allow"; Enabled = $true }
        )
        foreach ($rule in $rulesToCreate) {
            if (-not (Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue)) {
                try {
                    if ($rule.ContainsKey('Enabled')) {
                        $rule.Enabled = Resolve-SkjoldrRuleEnabled ([bool]$rule.Enabled)
                    }
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

function Set-SkjoldrFortressMode {
    Test-SkjoldrAdmin
    Write-Host "[SKJOLDR] Applying Fortress mode..." -ForegroundColor Yellow
    try {
        Remove-SkjoldrRules
        Enable-NetFirewallProfile -Profile Domain,Public,Private
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Block `
            -NotifyOnListen True `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
            -LogMaxSizeKilobytes 32767
        $dnsServers = @("8.8.8.8","1.1.1.1")
        $rulesToCreate = @(
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-DNS-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 53;  RemoteAddress = $dnsServers; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-HTTPS-Out"; Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 443; RemoteAddress = "Any"; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-NTP-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 123; RemoteAddress = "Any"; Action = "Allow"; Enabled = $true }
        )
        foreach ($rule in $rulesToCreate) {
            if (-not (Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue)) {
                try {
                    if ($rule.ContainsKey('Enabled')) {
                        $rule.Enabled = Resolve-SkjoldrRuleEnabled ([bool]$rule.Enabled)
                    }
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

# End of legacy reference. Do not use for implementation.
