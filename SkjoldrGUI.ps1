# =================================================
# SKJOLDR v1.0 — First-born of Aurenyx
# FINAL | RUNS | NO EXCUSES | AEsir-aligned
# =================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

function Hex([string]$h) { [System.Drawing.ColorTranslator]::FromHtml($h) }

# Admin check — must be elevated
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    [System.Windows.Forms.MessageBox]::Show(
        "Skjoldr demands elevation.`nRun as Administrator.",
        "Aurenyx - Access Denied",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit
}

# Core import
$core = Join-Path $PSScriptRoot "SkjoldrFirewall.ps1"
if (-not (Test-Path $core)) {
    [System.Windows.Forms.MessageBox]::Show(
        "SkjoldrFirewall.ps1 not found in script directory.",
        "Aurenyx - Core Missing",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit
}
. $core

# Form
$form = New-Object System.Windows.Forms.Form
$form.Text            = "Skjoldr - First-born of Aurenyx"
$form.Size            = New-Object System.Drawing.Size(780, 590)
$form.StartPosition   = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox     = $false
$form.BackColor       = Hex "#141418"

# Header label
$header = New-Object System.Windows.Forms.Label
$header.Location      = New-Object System.Drawing.Point(20, 15)
$header.Text          = "SKJOLDR"
$header.ForeColor     = Hex "#E6DCC8"
$header.Font          = New-Object System.Drawing.Font(
    "Segoe UI Semibold",
    14,
    [System.Drawing.FontStyle]::Bold
)
$header.AutoSize      = $true

# Subtitle
$sub = New-Object System.Windows.Forms.Label
$sub.Location         = New-Object System.Drawing.Point(20, 42)
$sub.Text             = "First-born shield of Aurenyx. Choose your stance."
$sub.ForeColor        = Hex "#B4B4B4"
$sub.AutoSize         = $true

# Mode indicator
$mode = New-Object System.Windows.Forms.Label
$mode.Location        = New-Object System.Drawing.Point(20, 68)
$mode.Text            = "Active Shield: Detecting..."
$mode.Font            = New-Object System.Drawing.Font("Segoe UI Semibold", 11)
$mode.AutoSize        = $true

# Log window
$log = New-Object System.Windows.Forms.TextBox
$log.Location         = New-Object System.Drawing.Point(20, 100)
$log.Size             = New-Object System.Drawing.Size(720, 340)
$log.Multiline        = $true
$log.ReadOnly         = $true
$log.ScrollBars       = "Vertical"
$log.Font             = New-Object System.Drawing.Font("Consolas", 10)
$log.BackColor        = Hex "#0C0C0E"
$log.ForeColor        = Hex "#CDEBCD"
$log.BorderStyle      = "FixedSingle"

# Footer
$footer = New-Object System.Windows.Forms.Label
$footer.Location      = New-Object System.Drawing.Point(20, 540)
$footer.Text          = "Aurenyx · Skjoldr v1.0 - First-born · AEsir lineage"
$footer.ForeColor     = Hex "#828296"
$footer.Font          = New-Object System.Drawing.Font("Segoe UI", 8)
$footer.AutoSize      = $true

# Buttons layout
[int]$x   = 20
[int]$gap = 12
[int]$w   = 160
[int]$h   = 46
[int]$y   = 460

$btnFont = New-Object System.Drawing.Font(
    "Segoe UI",
    10,
    [System.Drawing.FontStyle]::Bold
)

# Conservative button
$btnCons = New-Object System.Windows.Forms.Button
$btnCons.Location     = New-Object System.Drawing.Point([int]$x, [int]$y)
$btnCons.Size         = New-Object System.Drawing.Size($w, $h)
$btnCons.Text         = "Conservative"
$btnCons.BackColor    = Hex "#286028"
$btnCons.ForeColor    = "White"
$btnCons.Font         = $btnFont

# Fortress button
$btnFort = New-Object System.Windows.Forms.Button
$btnFort.Location     = New-Object System.Drawing.Point(
    [int]($x + $w + $gap),
    [int]$y
)
$btnFort.Size         = New-Object System.Drawing.Size($w, $h)
$btnFort.Text         = "FORTRESS"
$btnFort.BackColor    = Hex "#902020"
$btnFort.ForeColor    = "White"
$btnFort.Font         = $btnFont

# Reset button
$btnReset = New-Object System.Windows.Forms.Button
$btnReset.Location    = New-Object System.Drawing.Point(
    [int]($x + 2 * ($w + $gap)),
    [int]$y
)
$btnReset.Size        = New-Object System.Drawing.Size($w, $h)
$btnReset.Text        = "Reset All"
$btnReset.BackColor   = Hex "#484848"
$btnReset.ForeColor   = "White"
$btnReset.Font        = $btnFont

# Refresh button
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Location  = New-Object System.Drawing.Point(
    [int]($x + 3 * ($w + $gap)),
    [int]$y
)
$btnRefresh.Size      = New-Object System.Drawing.Size($w, $h)
$btnRefresh.Text      = "Refresh"
$btnRefresh.BackColor = Hex "#282868"
$btnRefresh.ForeColor = "White"
$btnRefresh.Font      = $btnFont

# Logging helpers
function Log-Skjoldr([string]$msg) {
    $t = (Get-Date).ToString("HH:mm:ss")
    $log.AppendText("[$t] $msg`r`n")
    $log.SelectionStart = $log.Text.Length
    $log.ScrollToCaret()
}

function Show-Profiles {
    Log-Skjoldr "=== Shield State ==="
    Get-NetFirewallProfile | ForEach-Object {
        $s = if ($_.Enabled) { "ON" } else { "OFF" }
        Log-Skjoldr ("{0} ({1}) -> In: {2} | Out: {3}" -f `
            $_.Name.PadRight(12), $s, $_.DefaultInboundAction, $_.DefaultOutboundAction)
    }
    Log-Skjoldr "===================="
}

# Detect current shield mode
function Get-SkjoldrMode {
    $p = Get-NetFirewallProfile
    $in  = $p.DefaultInboundAction  | Select-Object -Unique
    $out = $p.DefaultOutboundAction | Select-Object -Unique
    $fortRules = Get-NetFirewallRule -DisplayName "SKJOLDR-Allow-*" -ErrorAction SilentlyContinue

    $allInBlock  = $in.Count  -eq 1 -and $in  -eq "Block"
    $allOutAllow = $out.Count -eq 1 -and $out -eq "Allow"
    $allOutBlock = $out.Count -eq 1 -and $out -eq "Block"

    if ($allInBlock -and $allOutAllow) { return "Conservative" }
    if ($allInBlock -and $allOutBlock -and $fortRules) { return "FORTRESS" }
    return "Mortal / Unknown"
}

# Button actions
$btnCons.Add_Click({
    Log-Skjoldr "Applying Conservative Mode..."
    try {
        Apply-ConservativeMode
        Log-Skjoldr "Conservative shield raised."
        $mode.Text = "Active Shield: Conservative"
        $mode.ForeColor = Hex "#64FF64"
    } catch {
        Log-Skjoldr "ERROR: $_"
    }
    Show-Profiles
})

$btnFort.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "FORTRESS MODE = TOTAL ISOLATION`n`nAll paths sealed. No exceptions.`n`nAre you certain, Sovereign?",
        "ENGAGE FORTRESS",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        Log-Skjoldr "FORTRESS PROTOCOL ENGAGED."
        try {
            Apply-FortressMode
            Log-Skjoldr "FORTRESS ACTIVE - WORLD SEALED."
            $mode.Text = "Active Shield: FORTRESS"
            $mode.ForeColor = Hex "#FF5050"
            [System.Media.SystemSounds]::Hand.Play()
        } catch {
            Log-Skjoldr "FORTRESS FAILURE: $_"
        }
        Show-Profiles
    }
})

$btnReset.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Burn all custom rules and reset Windows Firewall to defaults?",
        "Reset Shield",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        Log-Skjoldr "Burning all runes..."
        try {
            Reset-FirewallDefaults
            Log-Skjoldr "Returned to mortal state."
            $mode.Text = "Active Shield: Mortal"
            $mode.ForeColor = Hex "#FFB640"
        } catch {
            Log-Skjoldr "RESET FAILED: $_"
        }
        Show-Profiles
    }
})

$btnRefresh.Add_Click({
    Show-Profiles
})

# Add controls to form
$form.Controls.Add($header)
$form.Controls.Add($sub)
$form.Controls.Add($mode)
$form.Controls.Add($log)
$form.Controls.Add($footer)
$form.Controls.Add($btnCons)
$form.Controls.Add($btnFort)
$form.Controls.Add($btnReset)
$form.Controls.Add($btnRefresh)

# Awakening
Log-Skjoldr "Skjoldr awakens - first-born of Aurenyx."
$mode.Text = "Active Shield: $(Get-SkjoldrMode)"
Show-Profiles

[void]$form.ShowDialog()
