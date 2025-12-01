# Skjoldr Firewall  
A lightweight, three-mode Windows Firewall controller with a clean PowerShell GUI.

> **“The shield they should have given you.”**

---

## 🛡️ Features

### **Conservative Mode**
- Enables Domain / Private / Public profiles  
- Blocks *all inbound* traffic  
- Allows outbound traffic  
- Disables unsolicited listening notifications  
- Enables logging for allowed and blocked connections  

### **Fortress Mode**
- Enables all profiles  
- Blocks **both inbound and outbound**  
- Provides near-total network isolation  
- Creates minimal outbound allow rules for essential apps (configurable)

### **Reset to Defaults**
- Restores Windows Firewall to factory settings  
- Removes all `SKJOLDR-*` rules  

### **Status View**
- Shows:  
  - Profile state  
  - Default inbound action  
  - Default outbound action  

---

## 📁 File Overview

### **`SkjoldrGUI.ps1`**
Graphical interface using Windows Forms.  
Handles:
- Mode selection  
- Live log window  
- Active shield indicators  

### **`SkjoldrFirewall.ps1`**
Core engine implementing:
- `Set-ConservativeFirewall`
- `Set-FortressFirewall`
- `Reset-FirewallDefaults`
- `Show-FirewallProfileStatus`

And GUI integration functions:
- `Apply-ConservativeMode`
- `Apply-FortressMode`

### **`README.md`**
This file.

---

## 🧩 Requirements
- Windows 10 or 11  
- PowerShell 5.x+  
- Admin privileges  
- Execution policy allowing local scripts (`RemoteSigned` recommended)

---

## 🚀 Installation

1. Create the directory:
   ```
   C:\Projects\skjoldr-firewall
   ```

2. Place these files inside:
   - `SkjoldrGUI.ps1`
   - `SkjoldrFirewall.ps1`
   - `README.md`

3. Unblock scripts (if downloaded):
   - Right-click file → **Properties**  
   - Check **Unblock**  

---

## ▶️ Usage

1. Open **PowerShell as Administrator**
2. Navigate to the project:
   ```
   cd C:\Projects\skjoldr-firewall
   ```
3. Run Skjoldr:
   ```
   .\SkjoldrGUI.ps1
   ```

### **Modes**
#### Conservative
- Blocks inbound  
- Allows outbound  
- Recommended for daily use  

#### Fortress
- Blocks everything  
- Use only when physically at the machine  
- WILL break internet, apps, updates, remote access  

#### Reset All
- Restores default Windows Firewall  
- Removes Skjoldr rules  

---

## 📝 Troubleshooting

### **“Apply-ConservativeMode not recognized”**
Check:
- Both scripts are in the same folder  
- `SkjoldrGUI.ps1` includes:
  ```powershell
  $core = Join-Path $PSScriptRoot "SkjoldrFirewall.ps1"
  . $core
  ```
- Execution policy:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  ```

---

## 🗺️ Roadmap
- Per-profile configuration  
- User-defined outbound allowlists  
- Config export/import  
- Optional notifications  

---

## ⚠️ Disclaimer
Skjoldr modifies firewall behavior.  
Use with caution. Test before deploying in production.
