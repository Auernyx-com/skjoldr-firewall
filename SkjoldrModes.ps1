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
            -LogMaxSizeKilobytes 32767 | Out-Null

        # Minimal outbound allows (DNS egress pinned to secure resolvers).
        # Default to Google (8.8.8.8) and Cloudflare (1.1.1.1), but allow override via
        # environment variable SKJOLDR_DNS_SERVERS (comma-separated list of IPs).
        $defaultDnsServers = @("8.8.8.8","1.1.1.1")
        $dnsServersEnv = $env:SKJOLDR_DNS_SERVERS
        if ([string]::IsNullOrWhiteSpace($dnsServersEnv)) {
            $dnsServers = $defaultDnsServers
        }
        else {
            $dnsServers = $dnsServersEnv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if (-not $dnsServers -or $dnsServers.Count -eq 0) {
                $dnsServers = $defaultDnsServers
            }
        }
        $rulesToCreate = @(
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-DNS-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 53;  RemoteAddress = $dnsServers; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-HTTPS-Out"; Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 443; RemoteAddress = "Any"; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-FORTRESS-Allow-NTP-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 123; RemoteAddress = "Any"; Action = "Allow"; Enabled = $true }
        )
        foreach ($rule in $rulesToCreate) {
            if (-not (Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue)) {
                try {
                    $created = New-NetFirewallRule @rule -ErrorAction Stop
                    if (-not $created) { throw "Firewall rule '$($rule.DisplayName)' did not materialize after creation." }
                    Write-Host "[SKJOLDR] Created rule: $($rule.DisplayName)"
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
            @{ DisplayName = "SKJOLDR-Allow-DNS-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 53;  RemoteAddress = "Any"; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-HTTPS-Out"; Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 443; RemoteAddress = "Any"; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-HTTP-Out";  Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "TCP"; RemotePort = 80;  RemoteAddress = "Any"; Action = "Allow"; Enabled = $true },
            @{ DisplayName = "SKJOLDR-Allow-NTP-Out";   Group = $global:SKJOLDR_GROUP; Direction = "Outbound"; Protocol = "UDP"; RemotePort = 123; RemoteAddress = "Any"; Action = "Allow"; Enabled = $true }
        )
        foreach ($rule in $rulesToCreate) {
            if (-not (Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue)) {
                try {
                    $created = New-NetFirewallRule @rule -ErrorAction Stop
                    if (-not $created) { throw "Firewall rule '$($rule.DisplayName)' did not materialize after creation." }
                    Write-Host "[SKJOLDR] Created rule: $($rule.DisplayName)"
                } catch {
                    Write-Host "[SKJOLDR] Failed to create rule: $($rule.DisplayName) - $($_.Exception.Message)" -ForegroundColor Red
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
