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
    

