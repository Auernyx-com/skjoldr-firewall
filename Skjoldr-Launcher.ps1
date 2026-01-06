Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "      Skjoldr Firewall        " -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""
# Skjoldr-Launcher.ps1
# Simple interactive launcher for SkjoldrFirewall.ps1

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$fw   = Join-Path $here "SkjoldrFirewall.ps1"

if (-not (Test-Path $fw)) {
    throw "Skjoldr firewall core not found: $fw"
}

# Load the firewall functions into this session
. $fw

function Show-SkjoldrMenu {
    Clear-Host
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "      Skjoldr Firewall" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1) Status"
    Write-Host "2) Conservative Mode"
    Write-Host "3) Fortress Mode"
    Write-Host "4) Reset (remove Skjoldr rules)"
    Write-Host ""
    Write-Host "Q) Quit"
    Write-Host ""
}

while ($true) {
    Show-SkjoldrMenu
    $choice = Read-Host "Select"

    switch ($choice.ToUpperInvariant()) {
        "1" {
            Get-SkjoldrStatus | Format-List *
            Pause
        }
        "2" {
            Set-SkjoldrConservativeMode -Verbose
            Pause
        }
        "3" {
            if (Get-Command Set-SkjoldrFortressMode -ErrorAction SilentlyContinue) {
                Set-SkjoldrFortressMode -Verbose
            } else {
                Write-Host "Fortress Mode isn't defined yet in SkjoldrFirewall.ps1." -ForegroundColor Yellow
            }
            Pause
        }
        "4" {
            Reset-SkjoldrFirewall -Verbose
            Pause
        }
        "Q" { break }
        default {
            Write-Host "Invalid selection." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 700
        }
    }
}
