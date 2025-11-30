############ SKJǪLDR FIREWALL CONTROL ############
# Three-Mode Windows Firewall Manager
# Conservative | Fortress | Reset | Status
# By: You

function Set-ConservativeFirewall {
    Write-Host "Applying Conservative Firewall Profile..." -ForegroundColor Cyan

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow `
        -AllowInboundRules False -AllowLocalFirewallRules True `
        -NotifyOnListen False -Verbose

    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -LogAllowed True -LogBlocked True -Verbose

    Write-Host "Conservative Mode Applied." -ForegroundColor Green
}

function Set-FortressFirewall {
    Write-Host "Applying Fortress Mode... Outbound lockdown." -ForegroundColor Yellow

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Block `
        -AllowInboundRules False -AllowLocalFirewallRules False `
        -NotifyOnListen False -Verbose

    # Minimal essential outbound whitelist - adjust as needed
    $essentialPrograms = @(
        "C:\Windows\System32\svchost.exe",
        "C:\Windows\explorer.exe",
        "C:\Windows\System32\cmd.exe",
        "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "C:\Program Files\Google\Chrome\Application\chrome.exe",
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    )

    foreach ($program in $essentialPrograms) {
        if (Test-Path $program) {
            New-NetFirewallRule -DisplayName "SKJOLDR-Allow-$([System.IO.Path]::GetFileName($program))" `
                -Direction Outbound -Program $program -Action Allow -Enabled True `
                -ErrorAction SilentlyContinue
        }
    }

    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -LogAllowed True -LogBlocked True -Verbose

    Write-Host "Fortress Mode Secured." -ForegroundColor Green
}

function Reset-FirewallDefaults {
    Write-Host "Resetting Windows Firewall to Factory Defaults..." -ForegroundColor Magenta
    
    (New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults()
    
    Write-Host "Firewall reset complete." -ForegroundColor Green
}

function Show-FirewallProfileStatus {
    Write-Host "=== Firewall Profile Status ===" -ForegroundColor Cyan
    Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction
}
###################################################
