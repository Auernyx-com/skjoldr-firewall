# -----------------------------------------------------------
#  FORENSIC: FULL SYSTEM ENUMERATION + PERSISTENCE SCAN
# -----------------------------------------------------------

$Out = "C:\ForensicDump"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Function Dump($name, $data) {
    Try {
        $data | Out-File -FilePath "$Out\$name.txt" -Force -Encoding UTF8
    } Catch {
        "Failed to write $name" | Out-File "$Out\_errors.txt" -Append
    }
}

Dump "Running_Processes" (Get-Process | Select-Object Name,Id,Path,StartTime)
Dump "Process_modules" (Get-Process | ForEach-Object { $_.Modules } | Select-Object ModuleName,FileName)

Dump "Network_Connections" (Get-NetTCPConnection | Select-Object -Property LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess)
Dump "ARP_Table" (arp -a)

Dump "Services_All" (Get-Service | Select-Object Name,DisplayName,Status,StartType)
Dump "WMI_Persistence" (Get-WmiObject -Namespace "root\subscription" -Class __EventFilter)
Dump "WMI_Consumers" (Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer)
Dump "WMI_Bindings" (Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding)

Dump "Startup_Folders" (Get-ChildItem -Recurse "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
Dump "Startup_Registry_Run" (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run)
Dump "Startup_Registry_RunOnce" (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce)
Dump "Startup_User_Run" (Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run)

Dump "ScheduledTasks" (Get-ScheduledTask | Select-Object TaskName,TaskPath,State)
Dump "ScheduledTask_Actions" (Get-ScheduledTask | ForEach-Object { $_.Actions })

Dump "Drivers_Loaded" (driverquery /v /fo csv | ConvertFrom-Csv)
Dump "Signed_Files_System32" (Get-ChildItem C:\Windows\System32 -File | Get-AuthenticodeSignature)

Dump "Firewall_Rules" (Get-NetFirewallRule | Select DisplayName,Enabled,Direction,Profile,Action)
Dump "Firewall_Ports" (netsh advfirewall firewall show rule name=all)

Dump "Accounts_Local" (Get-LocalUser)
Dump "Accounts_Groups" (Get-LocalGroup)
Dump "Security_Logins" (Get-EventLog -LogName Security -Newest 200 | Where-Object { $_.EventID -eq 4624 })

Dump "PowerShell_History" (Get-Content (Get-PSReadLineOption).HistorySavePath)

Dump "SMB_Sessions" (Get-SmbSession)
Dump "SMB_Shares" (Get-SmbShare)

Dump "DNS_Cache" (ipconfig /displaydns)

Dump "AppCompatCache" (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Session\Manager\AppCompatCache)

Dump "Prefetch_Files" (Get-ChildItem C:\Windows\Prefetch)

Dump "ProgramData_Suspicious" (Get-ChildItem -Recurse C:\ProgramData -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'log|cfg|tmp|exe|bat|ps1|dll' })

Dump "User_Profile_Scan" (Get-ChildItem -Recurse C:\Users -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match 'exe|dll|scr|ps1|bat' })

Dump "Temp_Folder_Executables" (Get-ChildItem -Recurse $env:TEMP -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match 'exe|dll|scr' })

Dump "Autoruns_Keys" (reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /s)
Dump "Autoruns_Keys_User" (reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s)

Dump "Installed_Programs" (Get-WmiObject -Class Win32_Product | Select-Object Name,Version,InstallDate)

# End
# -----------------------------------------------------------
Write-Host "Forensic dump complete. Check C:\ForensicDump"
