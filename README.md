# Skjoldr Firewall
**A lightweight, paranoid-grade Windows Firewall controller**  
*“The shield they should have given you.”*

[![Version](https://img.shields.io/badge/version-1.1.0--dev-blue)]() [![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-0072C6?logo=powershell)]()

---

### Features

| Mode             | Inbound           | Outbound                  | Use Case                           |
|------------------|-------------------|---------------------------|------------------------------------|
| **Conservative** | Blocked           | Allowed (essential ports) | Daily driver, secure browsing      |
| **Fortress**     | Blocked           | Only DNS + HTTPS + NTP    | Maximum isolation / threat hunting |
| **Reset**        | Default (Allow)   | Default (Allow)           | Recovery / escape hatch            |

- Modern dark GUI (Windows Forms)
- One-click full forensic scan → `C:\ForensicDump`
- No external dependencies
- Runs entirely from `C:\Æsir\RUNTIME\skjoldr-firewall\`

---

### File Structure
C:\Æsir\RUNTIME\skjoldr-firewall
├── SkjoldrGUI.ps1              ← Main graphical interface
├── SkjoldrFirewall.ps1         ← Core firewall logic
├── Start-Skjoldr.bat           ← Double-click launcher
├── changelog.md
├── roadmap.md
└── scans
└── Skjoldr_fullscan.ps1    ← Deep forensic collection script


---

### Installation & Usage

1. Create the folder:
   ```powershell
   New-Item -ItemType Directory -Path "C:\Æsir\RUNTIME\skjoldr-firewall" -Force
   Drop all files into that folder (including the scans subfolder).
   (Recommended) Unblock files:PowerShellGet-ChildItem "C:\Æsir\RUNTIME\skjoldr-firewall" -Recurse | Unblock-File
   Launch — Double-click Start-Skjoldr.bat as AdministratorOr use this exact battle-tested batch file:

	@echo off
	title Skjoldr Firewall - AEsir Edition
	echo.
	echo   Launching Skjoldr Firewall...
	echo.

	powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SkjoldrGUI.ps1"

	if %errorlevel% equ 0 (
   	 echo.
    	echo   Skjoldr exited cleanly.
	) else (
    	echo.
   	 echo   Error: Skjoldr encountered a problem (likely not run as admin).
    	echo   Right-click Start-Skjoldr.bat - "Run as administrator"
	)

	echo.
	pause

      Current Version
      Skjoldr – Æsir Edition 1.1.0-dev
      Built for those who refuse to bleed packets.

      Links

      Changelog
      Roadmap

---

## 2026-01-06: Corrections & Improvements
- Fortress/Conservative modes are now idempotent and fully auditable
- Added helpers: Remove-SkjoldrRuleByDisplayName, Ensure-SkjoldrRule
- All rules managed by DisplayName for exact matching and safe updates
- Fortress disables Windows HTTP/HTTPS punch-through rules and enforces explicit HTTP block
- Conservative restores outbound allowances and re-enables Windows helper rules
- Defensive error handling: receipts and live tests are wrapped, never break mode application
- $global:SKJOLDR_GROUP is set once and used everywhere for group consistency
- DNS server restriction and live DNS query tests in Fortress mode
- Receipts/reporting logic is robust, group-agnostic, and does not depend on prior state
- Bastion Gate adapter contract and logic verified: no breakage, fully compatible

---

## 2026-01-06: Final Project Closure
- All modes (Fortress/Conservative) and receipts verified
- Bastion Gate adapter integration and error handling tested
- End-of-day baseline checks complete: no issues
- Hardened for governance, audit, and deterministic operation
- Project closed and ready for release
---

# License

This project is licensed under the Apache License, Version 2.0. See the LICENSE file for details.

# Governance and Enforcement

This project implements governance and enforcement tooling.
Runtime artifacts (decisions, receipts, ledgers) are intentionally excluded from version control.

# Bastion Integration Contract

- **ALLOW:** Skjoldr proceeds as normal.
- **PAUSE:** Skjoldr does nothing, exits non-zero, no firewall changes. Requires human correction.
- **DENY/unknown/missing:** Skjoldr refuses, logs, exits hard.
- **Emergency lockdown:** Only via SKJOLDR_EMERGENCY=FORTRESS or explicit operator command, never implicit.

# Usage
- Use the Bastion adapter: `integrations/bastion/Invoke-BastionGate.ps1`
- To force lockdown: set `SKJOLDR_EMERGENCY=FORTRESS` in the environment.

# Governance
- The Bastion→Skjoldr interface is locked. Changes require explicit review.
- No implicit escalation from PAUSE to lockdown.
- Auditable, fail-closed, and human-bound.


