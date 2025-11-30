# *🛡️ Skjǫldr Firewall Controller*

*# Skjǫldr Firewall Controller*

*A lightweight, transparent, three-mode firewall management tool for Windows.*  

*Designed for users who want fast, reliable security profiles without installing invasive antivirus suites or kernel-level drivers.*



*Skjǫldr provides:*

*- One-click hardening*  

*- One-click outbound lockdown*  

*- One-click full reset to Windows defaults*  

*- Clear, readable PowerShell code for complete transparency*  



*---*



*## Features*



*### ✔ Conservative Mode*

*A secure, daily-driver configuration:*

*- Blocks all inbound connections*  

*- Allows outbound connections*  

*- Enables logging*  

*- Disables unsolicited listening behavior*  

*- Maintains local rules while reducing unnecessary exposure*  



*### ✔ Fortress Mode*

*A strict lockdown profile:*

*- Blocks inbound AND outbound traffic*  

*- Only allows a minimal whitelist of essential Windows processes*  

*- Ideal for high-risk environments, travel, or compromised networks*  

*- Logging enabled for full visibility*  



*### ✔ Reset to Defaults*

*Instantly restore Windows Firewall to factory settings using Microsoft’s native APIs:*

*- Removes all custom rules*  

*- Returns all profiles to their default behavior*  

*- Useful for debugging or post-incident recovery*  



*### ✔ Status Overview*

*Displays current firewall settings for all profiles:*

*- Enabled/Disabled*  

*- Inbound policy*  

*- Outbound policy*  



*---*



*## Installation*



*1. Download or copy `SkjoldrFirewall.ps1`*  

*2. Save it to a location such as:*







*C:\\Tools\\SkjoldrFirewall.ps1*





*3. Open \*\*PowerShell as Administrator\*\**  

*4. Load the script into your session:*



*```powershell*

*. C:\\Tools\\SkjoldrFirewall.ps1*



*Usage*

*Conservative Mode*

*Set-ConservativeFirewall*



*Fortress Mode*

*Set-FortressFirewall*



*Reset to Windows Defaults*

*Reset-FirewallDefaults*



*View Firewall Status*

*Show-FirewallProfileStatus*



*Requirements*



*Windows 10 or Windows 11*



*Administrator privileges*



*PowerShell 5.x or 7.x*



*Why Skjǫldr?*



*Most firewall tools fall into one of two categories:*



*Overly complex — requiring deep networking knowledge*



*Overly invasive — bundling antivirus suites, telemetry, or kernel drivers*



*Skjǫldr is deliberately simple:*



*Script-based*



*Fully transparent*



*No background services*



*No external dependencies*



*Easy to audit and modify*



*It gives users direct control over their system’s network surface without compromising system integrity.*



*Future Development*



*Planned enhancements include:*



*GUI version (WinUI/WPF)*



*Custom whitelist manager*



*Preset profiles for travel, public Wi-Fi, and clean-room usage*



*Logging dashboard*



*Installer package (MSIX or InnoSetup)*

