# SkjoldrGUI.ps1
# WinForms GUI for Skjoldr core.
# GUI does NOT implement firewall logic. It only calls functions from SkjoldrFirewall.ps1.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-SkjoldrAdminSession {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit
    } catch {
        throw "Skjoldr GUI requires admin rights. Relaunch cancelled."
    }
}

# Resolve folder reliably even when launched weirdly
$baseDir = if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { $PSScriptRoot } else { (Get-Location).Path }
$corePath = Join-Path $baseDir "SkjoldrFirewall.ps1"

if (-not (Test-Path -LiteralPath $corePath)) {
    throw "Core file not found: $corePath"
}

# Require admin
if (-not (Test-Admin)) { Start-SkjoldrAdminSession }

# Load core
. $corePath

# Verify core functions exist
$required = @("Set-SkjoldrConservativeMode","Set-SkjoldrFortressMode","Reset-SkjoldrFirewall","Get-SkjoldrStatus")
$missing = @()
foreach ($fn in $required) {
    if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { $missing += $fn }
}
if ($missing.Count -gt 0) {
    throw "Missing core functions: " + ($missing -join ", ")
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- UI ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Skjoldr Firewall"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size(860, 600)
$form.MaximizeBox = $false
$form.FormBorderStyle = "FixedDialog"

# Dark theme
$form.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
$form.ForeColor = [System.Drawing.Color]::Gainsboro


$font = New-Object System.Drawing.Font("Segoe UI", 10)

$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = "Skjoldr (Core-controlled). Buttons call core functions only."
$lbl.AutoSize = $true
$lbl.Location = New-Object System.Drawing.Point(16, 16)
$lbl.Font = $font
$form.Controls.Add($lbl)

$btnCon = New-Object System.Windows.Forms.Button
$btnCon.Text = "Conservative (Inbound Block / Outbound Allow)"
$btnCon.Size = New-Object System.Drawing.Size(380, 40)
$btnCon.Location = New-Object System.Drawing.Point(16, 50)
$btnCon.Font = $font
$form.Controls.Add($btnCon)

$btnFor = New-Object System.Windows.Forms.Button
$btnFor.Text = "Fortress (Inbound+Outbound Block + minimal allows)"
$btnFor.Size = New-Object System.Drawing.Size(380, 40)
$btnFor.Location = New-Object System.Drawing.Point(16, 98)
$btnFor.Font = $font
$form.Controls.Add($btnFor)

$btnReset = New-Object System.Windows.Forms.Button
$btnReset.Text = "Reset (Remove SKJOLDR rules + defaults)"
$btnReset.Size = New-Object System.Drawing.Size(380, 40)
$btnReset.Location = New-Object System.Drawing.Point(16, 146)
$btnReset.Font = $font
$form.Controls.Add($btnReset)

$btnStatus = New-Object System.Windows.Forms.Button
$btnStatus.Text = "Refresh Status"
$btnStatus.Size = New-Object System.Drawing.Size(180, 40)
$btnStatus.Location = New-Object System.Drawing.Point(416, 50)
$btnStatus.Font = $font
$form.Controls.Add($btnStatus)

$btnCopy = New-Object System.Windows.Forms.Button
$btnCopy.Text = "Copy Status"
$btnCopy.Size = New-Object System.Drawing.Size(180, 40)
$btnCopy.Location = New-Object System.Drawing.Point(416, 98)
$btnCopy.Font = $font
$form.Controls.Add($btnCopy)

$controls = $form.Controls
foreach ($c in $controls) {
    if ($c -is [System.Windows.Forms.Button]) {
        $c.BackColor = [System.Drawing.Color]::FromArgb(45,45,48)
        $c.ForeColor = [System.Drawing.Color]::Gainsboro
        $c.FlatStyle = "Flat"
    }
}


$txt = New-Object System.Windows.Forms.TextBox
$txt.Multiline = $true
$txt.ScrollBars = "Vertical"
$txt.ReadOnly = $true
$txt.Font = New-Object System.Drawing.Font("Consolas", 10)
$txt.Location = New-Object System.Drawing.Point(16, 210)
$txt.Size = New-Object System.Drawing.Size(812, 330)

$txt.BackColor = [System.Drawing.Color]::FromArgb(20,20,20)
$txt.ForeColor = [System.Drawing.Color]::Gainsboro
$txt.BorderStyle = "FixedSingle"

$form.Controls.Add($txt)

function Write-Status {
    try {
        $s = Get-SkjoldrStatus
        $lines = @()
        $lines += "=== SKJOLDR STATUS ==="
        $lines += "Time: " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $lines += "ModeGuess: " + $s.ModeGuess
        $lines += ""

        $lines += "=== Profiles ==="
        foreach ($p in $s.Profiles) {
            $lines += ("{0,-7} In:{1,-5} Out:{2,-5} LogA:{3,-5} LogB:{4,-5}" -f $p.Name,$p.DefaultInboundAction,$p.DefaultOutboundAction,$p.LogAllowed,$p.LogBlocked)
        }
        $lines += ""

        $lines += ("=== SKJOLDR Rules ({0}) ===" -f $s.RuleCount)
        foreach ($r in $s.Rules) {
            $lines += ("{0} | {1} {2} | Enabled:{3} | Group:{4}" -f $r.DisplayName,$r.Direction,$r.Action,$r.Enabled,$r.Group)
        }

        $txt.Text = ($lines -join "`r`n")
    } catch {
        $txt.Text = "STATUS ERROR:`r`n" + $_.Exception.Message
    }
}

function Invoke-ActionWithStatus($actionName, [scriptblock]$sb) {
    $form.UseWaitCursor = $true
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        & $sb
        [System.Windows.Forms.MessageBox]::Show("$actionName complete.", "Skjoldr", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Skjoldr ERROR", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    } finally {
        $form.UseWaitCursor = $false
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        Write-Status
    }
}


# Button event handlers (all use approved verbs)
$btnCon.Add_Click({ Invoke-ActionWithStatus "Conservative mode" { Set-SkjoldrConservativeMode } })
$btnFor.Add_Click({ Invoke-ActionWithStatus "Fortress mode"      { Set-SkjoldrFortressMode } })
$btnReset.Add_Click({
    $res = [System.Windows.Forms.MessageBox]::Show(
        "Reset removes all SKJOLDR rules and restores defaults. Continue?",
        "Confirm Reset",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($res -eq [System.Windows.Forms.DialogResult]::Yes) {
        Invoke-ActionWithStatus "Reset" { Reset-SkjoldrFirewall }
    }
})
$btnStatus.Add_Click({ Write-Status })
$btnCopy.Add_Click({
    try {
        [System.Windows.Forms.Clipboard]::SetText($txt.Text)
        [System.Windows.Forms.MessageBox]::Show("Status copied to clipboard.", "Skjoldr", "OK", "Information") | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Clipboard copy failed: " + $_.Exception.Message, "Skjoldr ERROR", "OK", "Error") | Out-Null
    }
})

# Initial status
Write-Status

# Show form
[void]$form.ShowDialog()
