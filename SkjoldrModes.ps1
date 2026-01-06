# SkjoldrModes.ps1
# Mode dispatcher only. No firewall logic here.

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$fw   = Join-Path $here "SkjoldrFirewall.ps1"

if (-not (Test-Path $fw)) {
    throw "SkjoldrFirewall.ps1 not found at $fw"
}

. $fw

function Invoke-SkjoldrMode {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Conservative","Fortress","Reset","Status")]
        [string] $Mode
    )

    switch ($Mode) {
        "Conservative" { Set-SkjoldrConservativeMode -Verbose }
        "Fortress"     { Set-SkjoldrFortressMode -Verbose }
        "Reset"        { Reset-SkjoldrFirewall -Verbose }
        "Status"       { Get-SkjoldrStatus }
    }
}
