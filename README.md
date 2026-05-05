# Skjoldr Firewall
A lightweight, three-mode Windows Firewall controller with a clean PowerShell GUI — and a daemon-facing CLI for automated governance integration.

> **"The shield they should have given you."**

---

## Two ways to run Skjoldr

| Mode | File | When to use |
|---|---|---|
| **Interactive GUI** | `SkjoldrGUI.ps1` | Direct use at the machine |
| **Daemon / Avars integration** | `SkjoldrCLI.ps1` | Automated governance via Auernyx Mk2 |

Both modes use the same underlying firewall operations. The GUI is for humans at the keyboard. The CLI is for the orchestrator.

---

## Features

### Conservative Mode
- Enables Domain / Private / Public profiles
- Blocks all inbound traffic
- Allows outbound traffic
- Disables unsolicited listening notifications
- Enables logging for allowed and blocked connections

### Fortress Mode
- Enables all profiles
- Blocks both inbound and outbound
- Near-total network isolation
- Creates minimal essential outbound exceptions (configurable)

### Reset to Defaults
- Restores Windows Firewall to factory settings
- Removes all `SKJOLDR-*` rules

### Status
- Profile state (Domain / Private / Public)
- Default inbound and outbound action per profile
- Logging state

---

## File Overview

### `SkjoldrFirewall.ps1`
Core engine. Implements the firewall operations used by both the GUI and CLI:
- `Set-ConservativeFirewall`
- `Set-FortressFirewall`
- `Reset-FirewallDefaults`
- `Show-FirewallProfileStatus`

### `SkjoldrGUI.ps1`
Windows Forms graphical interface.
- Mode selection buttons
- Live log window
- Active shield indicators

### `SkjoldrCLI.ps1`
Daemon-facing CLI for Auernyx Mk2 / Avars integration.
Accepts verbs and flags, outputs a JSON envelope on stdout.
See [Avars Integration](#avars--auernyx-mk2-integration) below.

---

## Requirements
- Windows 10 or 11
- PowerShell 5.x or later
- Administrator privileges
- Execution policy allowing local scripts (`RemoteSigned` recommended)

---

## Installation

1. Clone or download to a local directory:
   ```
   C:\Projects\skjoldr-firewall
   ```

2. Unblock scripts if downloaded as a ZIP:
   - Right-click each `.ps1` → **Properties** → check **Unblock**
   - Or from PowerShell (admin):
     ```powershell
     Get-ChildItem C:\Projects\skjoldr-firewall\*.ps1 | Unblock-File
     ```

3. Set execution policy if not already done:
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```

---

## GUI Usage

1. Open PowerShell as Administrator
2. Navigate to the project:
   ```powershell
   cd C:\Projects\skjoldr-firewall
   ```
3. Launch the GUI:
   ```powershell
   .\SkjoldrGUI.ps1
   ```

### Modes
**Conservative** — Blocks inbound, allows outbound. Recommended for daily use.

**Fortress** — Blocks everything. Use only when physically at the machine. Will break internet, apps, updates, and remote access.

**Reset All** — Restores default Windows Firewall settings and removes all Skjoldr-managed rules.

---

## Avars / Auernyx Mk2 Integration

Skjoldr registers as a module in the Auernyx Mk2 trunk via `SkjoldrCLI.ps1`. The daemon calls this script directly and parses its JSON output — no GUI required, no manual interaction.

### Wiring it up

In your Mk2 deployment's `config/auernyx.config.json`, add the Skjoldr addon block:

```json
"addons": {
  "skjoldrFirewall": {
    "enabled": true,
    "path": "C:\\Projects\\skjoldr-firewall",
    "json": true,
    "timeoutMs": 15000
  }
}
```

Mk2 auto-detects `SkjoldrCLI.ps1` in the configured path. No `command` override needed unless you move the script.

### What the CLI exposes

| Mk2 capability | CLI call |
|---|---|
| `skjoldrFirewallStatus` | `status --json` |
| `skjoldrFirewallExportBaseline` | `export --json` |
| `skjoldrFirewallApplyProfile` | `apply --profile <name> --json` |
| `skjoldrFirewallApplyRulesetFile` | `apply --file <path> --json` |
| `skjoldrFirewallRestoreBaseline` | `restore --snapshot <path> --json` |
| `skjoldrFirewallAdviseInboundRuleSets` | `status --json` (read basis for advice) |

All write operations go through Mk2's Tier 2 approval flow before the CLI is called — the daemon enforces governance, Skjoldr executes the approved action.

### Baseline snapshots

`export` writes a versioned snapshot to `.\skjoldr-snapshots\` and returns the file path and SHA-256 hash. Store both in Mk2 config or pass them back to `skjoldrFirewallRestoreBaseline`. Mk2 verifies the hash before calling `restore` — if the snapshot file has been altered, the restore is blocked.

```json
{
  "ok": true,
  "data": {
    "snapshot_path": "C:\\Projects\\skjoldr-firewall\\skjoldr-snapshots\\baseline-20260504-120000.json",
    "hash": "a3f2...",
    "exported_at": "2026-05-04T12:00:00.000Z"
  }
}
```

### Ruleset file format

For `apply --file`, provide a JSON file:

```json
{
  "profile": "conservative",
  "rules": [
    {
      "name": "SKJOLDR-Allow-SSH",
      "direction": "inbound",
      "action": "allow",
      "protocol": "TCP",
      "localPort": "22",
      "enabled": true
    }
  ]
}
```

Both `profile` and `rules` are optional — include either, both, or neither (though neither is a no-op).

### Dry-run

Add `--dry-run` to any write verb to preview what would happen without touching the firewall. Mk2 uses this as a preflight check before the governed apply.

---

## Troubleshooting

### "Apply-ConservativeMode not recognized"
Both scripts must be in the same folder. Check that `SkjoldrGUI.ps1` contains:
```powershell
$core = Join-Path $PSScriptRoot "SkjoldrFirewall.ps1"
. $core
```

### Mk2 reports "Skjoldr command not configured/resolved"
- Confirm `addons.skjoldrFirewall.enabled` is `true` in `auernyx.config.json`
- Confirm `path` points to the directory containing `SkjoldrCLI.ps1`
- Confirm the scripts are unblocked (see Installation step 2)

### Mk2 reports "Skjoldr stdout was not valid JSON"
The CLI script outputs clean JSON with no extra text. If this error appears:
- Confirm you are running `SkjoldrCLI.ps1`, not `SkjoldrFirewall.ps1` or `SkjoldrGUI.ps1`
- Check that no other PowerShell profile script is outputting text on startup (`-NoProfile` should prevent this — Mk2 passes it automatically)

### Permission errors
All firewall operations require Administrator. Run the daemon with appropriate privileges or configure it to launch with elevation.

---

## Roadmap
- Per-profile configuration
- User-defined outbound allowlists
- Log viewer with filters
- Silent mode for sysadmin deployment

---

## Disclaimer
Skjoldr modifies Windows Firewall behavior directly. Test in a non-production environment before deploying. Fortress mode will interrupt network connectivity — only use it when you have physical access to the machine.
