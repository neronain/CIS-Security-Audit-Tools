# ==================================================================================
# CIS Windows 10/11 Security Audit Script with HTML Export
# Version: 2.1 - Complete Edition
# Author: Tananan Maiket
# Contact: https://www.facebook.com/neronain.minidev
# Description: ตรวจสอบการตั้งค่าความปลอดภัยของ Windows 10/11 ตามมาตรฐาน CIS
# License: MIT License
# Copyright (c) 2025 Tananan Maiket
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# ==================================================================================

param(
    [switch]$Help,
    [switch]$CreateHardening,
    [switch]$ExportResults,
    [switch]$ExportHTML,
    [switch]$ExportCSV,
    [string]$OutputPath = "C:\Temp",
    [string]$ReportTitle = "CIS Windows 10/11 Security Audit Report"
)

# Show help information
if ($Help) {
    Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║        CIS Windows 10/11 Security Audit Script v2.1           ║
║                  Created by Tananan Maiket                    ║
║           https://www.facebook.com/neronain.minidev           ║
╚════════════════════════════════════════════════════════════════╝

การใช้งาน:
    .\windows_complete_audit_script.ps1 [พารามิเตอร์]

พารามิเตอร์:
    -Help               : แสดงข้อมูลการใช้งาน
    -CreateHardening    : สร้าง hardening script อัตโนมัติ
    -ExportHTML         : ส่งออกรายงาน HTML (เปิดใช้งานโดยปริยาย)
    -ExportCSV          : ส่งออกรายงาน CSV
    -ExportResults      : ส่งออกทั้ง HTML และ CSV
    -OutputPath         : โฟลเดอร์สำหรับบันทึกรายงาน (ค่าปริยาย: C:\Temp)
    -ReportTitle        : ชื่อรายงาน

ตัวอย่าง:
    .\windows_complete_audit_script.ps1
    .\windows_complete_audit_script.ps1 -ExportResults -OutputPath "D:\Reports"
    .\windows_complete_audit_script.ps1 -CreateHardening

หมายเหตุ: ต้องรันด้วยสิทธิ์ Administrator
"@ -ForegroundColor Cyan
    exit 0
}

# Global Variables
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0
$script:InfoCount = 0
$script:TotalChecks = 0
$script:LogFile = ""
$script:Results = @()

# Color definitions for console output
$Colors = @{
    'PASS' = 'Green'
    'FAIL' = 'Red'
    'WARN' = 'Yellow'
    'INFO' = 'Cyan'
    'HEADER' = 'Magenta'
    'CRITICAL' = 'DarkRed'
}

# Initialize script
function Initialize-Script {
    Clear-Host
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host "ต้องการ PowerShell 5.1 หรือใหม่กว่า" -ForegroundColor Red
        exit 1
    }
    
    # Check if running as Administrator
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "กรุณารันสคริปต์นี้ในสิทธิ์ Administrator" -ForegroundColor Red
        Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        exit 1
    }
    
    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Set log file path
    $script:LogFile = Join-Path $OutputPath "CIS_Windows_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    # Display header
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $Colors.HEADER
    Write-Host "║        CIS Windows 10/11 Security Audit Script v2.1           ║" -ForegroundColor $Colors.HEADER
    Write-Host "║                  Created by Tananan Maiket                    ║" -ForegroundColor $Colors.HEADER
    Write-Host "║           https://www.facebook.com/neronain.minidev           ║" -ForegroundColor $Colors.HEADER
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor $Colors.HEADER
    Write-Host ""
}

# Function to write results
function Write-Result {
    param(
        [string]$Status,
        [string]$CheckID,
        [string]$Description,
        [string]$Details = "",
        [string]$Recommendation = "",
        [string]$RiskLevel = "Medium"
    )
    
    $script:TotalChecks++
    
    # Create result object
    $resultObj = [PSCustomObject]@{
        CheckID = $CheckID
        Status = $Status
        Description = $Description
        Details = $Details
        Recommendation = $Recommendation
        RiskLevel = $RiskLevel
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:Results += $resultObj
    
    # Update counters
    switch ($Status) {
        'PASS' { $script:PassCount++ }
        'FAIL' { $script:FailCount++ }
        'WARN' { $script:WarnCount++ }
        'INFO' { $script:InfoCount++ }
    }
    
    # Display to console
    $statusText = "[$Status]".PadRight(6)
    $color = $Colors[$Status]
    if ($RiskLevel -eq "Critical" -and $Status -eq "FAIL") {
        $color = $Colors.CRITICAL
    }
    
    Write-Host $statusText -ForegroundColor $color -NoNewline
    Write-Host " $Description"
    
    if ($Details) {
        Write-Host "       รายละเอียด: $Details" -ForegroundColor Gray
    }
    
    if ($Recommendation) {
        Write-Host "       คำแนะนำ: $Recommendation" -ForegroundColor Gray
    }
    
    if ($RiskLevel -eq "Critical") {
        Write-Host "       ⚠️  ระดับความเสี่ยง: สูงมาก" -ForegroundColor $Colors.CRITICAL
    }
    
    # Log to file
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Status] [$RiskLevel] $CheckID - $Description"
    if ($Details) { $logEntry += " | Details: $Details" }
    if ($Recommendation) { $logEntry += " | Recommendation: $Recommendation" }
    
    Add-Content -Path $script:LogFile -Value $logEntry
}

# Get system and domain information
function Get-SystemInfo {
    Write-Host "`n=== ข้อมูลระบบ ===" -ForegroundColor $Colors.HEADER
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        
        Write-Result "INFO" "SYS001" "OS Version: $($os.Caption) Build $($os.BuildNumber)"
        Write-Result "INFO" "SYS002" "Computer Name: $($computer.Name)"
        Write-Result "INFO" "SYS003" "Domain: $($computer.Domain)"
        Write-Result "INFO" "SYS004" "Total Physical Memory: $([math]::Round($computer.TotalPhysicalMemory/1GB, 2)) GB"
        Write-Result "INFO" "SYS005" "Last Boot Time: $($os.LastBootUpTime)"
        if ($bios) {
            Write-Result "INFO" "SYS006" "BIOS Version: $($bios.SMBIOSBIOSVersion)"
        }
        Write-Result "INFO" "SYS007" "Log File: $script:LogFile"
    }
    catch {
        Write-Result "WARN" "SYS999" "ไม่สามารถรวบรวมข้อมูลระบบได้" -Details $_.Exception.Message
    }
}

# 1. Account Policies
function Test-AccountPolicies {
    Write-Host "`n=== 1. การตรวจสอบ Account Policies ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Get security policy
        $tempFile = "$env:TEMP\secpol.cfg"
        $null = secedit /export /cfg $tempFile /quiet
        
        if (Test-Path $tempFile) {
            $secpolContent = Get-Content $tempFile -ErrorAction SilentlyContinue
            
            if ($secpolContent) {
                # Password Policy
                $minPwdLength = ($secpolContent | Where-Object { $_ -match "MinimumPasswordLength" }) -replace ".*= "
                if ([int]$minPwdLength -ge 14) {
                    Write-Result "PASS" "ACC001" "Minimum Password Length: $minPwdLength"
                } elseif ([int]$minPwdLength -ge 8) {
                    Write-Result "WARN" "ACC001" "Minimum Password Length: $minPwdLength" -Recommendation "แนะนำให้ตั้งค่าเป็น 14 ตัวอักษรหรือมากกว่า"
                } else {
                    Write-Result "FAIL" "ACC001" "Minimum Password Length: $minPwdLength" -RiskLevel "High" -Recommendation "ต้องตั้งค่าอย่างน้อย 8 ตัวอักษร"
                }
                
                # Password complexity
                $pwdComplexity = ($secpolContent | Where-Object { $_ -match "PasswordComplexity" }) -replace ".*= "
                if ($pwdComplexity -eq "1") {
                    Write-Result "PASS" "ACC002" "Password Complexity: เปิดใช้งาน"
                } else {
                    Write-Result "FAIL" "ACC002" "Password Complexity: ปิดใช้งาน" -RiskLevel "High" -Recommendation "เปิดใช้งาน Password Complexity ใน Local Security Policy"
                }
                
                # Account lockout threshold
                $lockoutThreshold = ($secpolContent | Where-Object { $_ -match "LockoutBadCount" }) -replace ".*= "
                if ([int]$lockoutThreshold -le 5 -and [int]$lockoutThreshold -gt 0) {
                    Write-Result "PASS" "ACC003" "Account Lockout Threshold: $lockoutThreshold"
                } else {
                    Write-Result "FAIL" "ACC003" "Account Lockout Threshold: $lockoutThreshold" -RiskLevel "Medium" -Recommendation "ตั้งค่าระหว่าง 1-5 ใน Local Security Policy"
                }
                
                # Password history
                $pwdHistory = ($secpolContent | Where-Object { $_ -match "PasswordHistorySize" }) -replace ".*= "
                if ([int]$pwdHistory -ge 12) {
                    Write-Result "PASS" "ACC004" "Password History: $pwdHistory passwords"
                } else {
                    Write-Result "WARN" "ACC004" "Password History: $pwdHistory passwords" -Recommendation "ตั้งค่าอย่างน้อย 12 ใน Local Security Policy"
                }
                
                # Maximum password age
                $maxPwdAge = ($secpolContent | Where-Object { $_ -match "MaximumPasswordAge" }) -replace ".*= "
                if ([int]$maxPwdAge -le 90 -and [int]$maxPwdAge -gt 0) {
                    Write-Result "PASS" "ACC005" "Maximum Password Age: $maxPwdAge days"
                } else {
                    Write-Result "WARN" "ACC005" "Maximum Password Age: $maxPwdAge days" -Recommendation "ตั้งค่าระหว่าง 30-90 วัน"
                }
                
                # Minimum password age
                $minPwdAge = ($secpolContent | Where-Object { $_ -match "MinimumPasswordAge" }) -replace ".*= "
                if ([int]$minPwdAge -ge 1) {
                    Write-Result "PASS" "ACC006" "Minimum Password Age: $minPwdAge days"
                } else {
                    Write-Result "WARN" "ACC006" "Minimum Password Age: $minPwdAge days" -Recommendation "ตั้งค่าอย่างน้อย 1 วัน"
                }
            }
            
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Result "WARN" "ACC999" "ไม่สามารถตรวจสอบ Account Policies ได้" -Details $_.Exception.Message
    }
}

# 2. Local Policies
function Test-LocalPolicies {
    Write-Host "`n=== 2. การตรวจสอบ Local Policies ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check if Guest account is disabled
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guestAccount -and -not $guestAccount.Enabled) {
            Write-Result "PASS" "LOC001" "Guest Account: ปิดใช้งาน"
        } elseif ($guestAccount -and $guestAccount.Enabled) {
            Write-Result "FAIL" "LOC001" "Guest Account: เปิดใช้งาน" -RiskLevel "High" -Recommendation "ปิดใช้งาน Guest Account: Disable-LocalUser Guest"
        } else {
            Write-Result "WARN" "LOC001" "Guest Account: ไม่พบ"
        }
        
        # Check Administrator account rename
        $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
        if ($adminAccount.Name -ne "Administrator") {
            Write-Result "PASS" "LOC002" "Administrator Account: ถูกเปลี่ยนชื่อเป็น '$($adminAccount.Name)'"
        } else {
            Write-Result "WARN" "LOC002" "Administrator Account: ยังใช้ชื่อ 'Administrator'" -Recommendation "เปลี่ยนชื่อ Administrator account ด้วย Local Users and Groups"
        }
        
        # Check Administrator account status
        if ($adminAccount -and -not $adminAccount.Enabled) {
            Write-Result "PASS" "LOC003" "Administrator Account: ปิดใช้งาน"
        } elseif ($adminAccount -and $adminAccount.Enabled) {
            Write-Result "WARN" "LOC003" "Administrator Account: เปิดใช้งาน" -Recommendation "ปิดใช้งาน built-in Administrator หากไม่จำเป็น"
        }
    }
    catch {
        Write-Result "WARN" "LOC999" "ไม่สามารถตรวจสอบ Local User Accounts ได้" -Details $_.Exception.Message
    }
    
    # Security Options via Registry
    $securityChecks = @(
        @{
            ID = "LOC004"
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            Name = "ClearPageFileAtShutdown"
            ExpectedValue = 1
            Description = "Clear Virtual Memory Pagefile"
            RiskLevel = "Medium"
        },
        @{
            ID = "LOC005"
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "LimitBlankPasswordUse"
            ExpectedValue = 1
            Description = "Accounts: Limit local account use of blank passwords"
            RiskLevel = "High"
        },
        @{
            ID = "LOC006"
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "NoLMHash"
            ExpectedValue = 1
            Description = "Network security: Do not store LAN Manager hash"
            RiskLevel = "Medium"
        },
        @{
            ID = "LOC007"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "EnableLUA"
            ExpectedValue = 1
            Description = "User Account Control (UAC)"
            RiskLevel = "Critical"
        },
        @{
            ID = "LOC008"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "ConsentPromptBehaviorAdmin"
            ExpectedValue = 2
            Description = "UAC: Behavior for Admin Approval Mode"
            RiskLevel = "High"
        }
    )
    
    foreach ($check in $securityChecks) {
        try {
            $value = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
            if ($value -and $value.($check.Name) -eq $check.ExpectedValue) {
                Write-Result "PASS" $check.ID $check.Description
            } else {
                $currentValue = if ($value) { $value.($check.Name) } else { "ไม่พบ" }
                Write-Result "FAIL" $check.ID $check.Description -Details "ค่าปัจจุบัน: $currentValue" -Recommendation "ตั้งค่าเป็น $($check.ExpectedValue) ใน Registry หรือ Group Policy" -RiskLevel $check.RiskLevel
            }
        }
        catch {
            Write-Result "WARN" $check.ID $check.Description -Details "ไม่สามารถอ่านค่า Registry ได้"
        }
    }
}

# 3. Windows Firewall
function Test-WindowsFirewall {
    Write-Host "`n=== 3. การตรวจสอบ Windows Firewall ===" -ForegroundColor $Colors.HEADER
    
    try {
        $firewallProfiles = @('Domain', 'Private', 'Public')
        
        foreach ($profile in $firewallProfiles) {
            try {
                $fw = Get-NetFirewallProfile -Name $profile -ErrorAction Stop
                
                if ($fw.Enabled -eq $true) {
                    Write-Result "PASS" "FW00$($firewallProfiles.IndexOf($profile) + 1)" "Windows Firewall ($profile): เปิดใช้งาน"
                } else {
                    Write-Result "FAIL" "FW00$($firewallProfiles.IndexOf($profile) + 1)" "Windows Firewall ($profile): ปิดใช้งาน" -RiskLevel "Critical" -Recommendation "เปิดใช้งาน Firewall: Set-NetFirewallProfile -Profile $profile -Enabled True"
                }
                
                # Check inbound/outbound rules
                if ($fw.DefaultInboundAction -eq 'Block') {
                    Write-Result "PASS" "FW00$($firewallProfiles.IndexOf($profile) + 4)" "Default Inbound Action ($profile): Block"
                } else {
                    Write-Result "WARN" "FW00$($firewallProfiles.IndexOf($profile) + 4)" "Default Inbound Action ($profile): $($fw.DefaultInboundAction)" -Recommendation "ตั้งค่าเป็น Block: Set-NetFirewallProfile -Profile $profile -DefaultInboundAction Block"
                }
                
                if ($fw.DefaultOutboundAction -eq 'Allow') {
                    Write-Result "PASS" "FW00$($firewallProfiles.IndexOf($profile) + 7)" "Default Outbound Action ($profile): Allow"
                } else {
                    Write-Result "WARN" "FW00$($firewallProfiles.IndexOf($profile) + 7)" "Default Outbound Action ($profile): $($fw.DefaultOutboundAction)" -Recommendation "ตั้งค่าเป็น Allow: Set-NetFirewallProfile -Profile $profile -DefaultOutboundAction Allow"
                }
            }
            catch {
                Write-Result "WARN" "FW00$($firewallProfiles.IndexOf($profile) + 1)" "ไม่สามารถตรวจสอบ Windows Firewall ($profile) ได้" -Details $_.Exception.Message
            }
        }
        
        # Check for dangerous firewall rules
        try {
            $dangerousRules = Get-NetFirewallRule | Where-Object { 
                $_.Enabled -eq "True" -and 
                $_.Direction -eq "Inbound" -and 
                $_.Action -eq "Allow"
            } | ForEach-Object {
                $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_
                if ($addressFilter.RemoteAddress -contains "Any") {
                    $_
                }
            }
            
            if ($dangerousRules.Count -eq 0) {
                Write-Result "PASS" "FW010" "ไม่พบ Firewall rules ที่อันตราย"
            } else {
                Write-Result "WARN" "FW010" "พบ $($dangerousRules.Count) inbound rules ที่อนุญาต Any address" -Recommendation "ตรวจสอบและจำกัด scope ของ firewall rules"
            }
        }
        catch {
            Write-Result "WARN" "FW010" "ไม่สามารถตรวจสอบ Firewall rules ได้" -Details $_.Exception.Message
        }
    }
    catch {
        Write-Result "WARN" "FW999" "ไม่สามารถตรวจสอบ Windows Firewall ได้" -Details $_.Exception.Message
    }
}

# 4. Windows Defender
function Test-WindowsDefender {
    Write-Host "`n=== 4. การตรวจสอบ Windows Defender ===" -ForegroundColor $Colors.HEADER
    
    try {
        $defender = Get-MpPreference -ErrorAction SilentlyContinue
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        if ($status) {
            # Real-time protection
            if ($status.RealTimeProtectionEnabled) {
                Write-Result "PASS" "DEF001" "Real-time Protection: เปิดใช้งาน"
            } else {
                Write-Result "FAIL" "DEF001" "Real-time Protection: ปิดใช้งาน" -RiskLevel "Critical" -Recommendation "เปิดใช้งาน Real-time Protection ใน Windows Security"
            }
            
            # Antivirus signature version
            if ($status.AntivirusSignatureLastUpdated) {
                $signatureAge = (Get-Date) - $status.AntivirusSignatureLastUpdated
                if ($signatureAge.Days -le 7) {
                    Write-Result "PASS" "DEF002" "Antivirus Signatures: อัพเดทล่าสุด $($signatureAge.Days) วันที่แล้ว"
                } else {
                    Write-Result "WARN" "DEF002" "Antivirus Signatures: อัพเดทล่าสุด $($signatureAge.Days) วันที่แล้ว" -Recommendation "อัพเดท signature: Update-MpSignature"
                }
            }
            
            # Cloud protection
            if ($defender -and $defender.MAPSReporting -ne 0) {
                Write-Result "PASS" "DEF003" "Cloud Protection: เปิดใช้งาน"
            } else {
                Write-Result "WARN" "DEF003" "Cloud Protection: ปิดใช้งาน" -Recommendation "เปิดใช้งาน Cloud Protection ใน Windows Security"
            }
            
            # Behavior monitoring
            if ($status.BehaviorMonitorEnabled) {
                Write-Result "PASS" "DEF004" "Behavior Monitoring: เปิดใช้งาน"
            } else {
                Write-Result "WARN" "DEF004" "Behavior Monitoring: ปิดใช้งาน" -Recommendation "เปิดใช้งาน Behavior Monitoring ใน Windows Security"
            }
            
            # On Access Protection
            if ($status.OnAccessProtectionEnabled) {
                Write-Result "PASS" "DEF005" "On Access Protection: เปิดใช้งาน"
            } else {
                Write-Result "FAIL" "DEF005" "On Access Protection: ปิดใช้งาน" -RiskLevel "High" -Recommendation "เปิดใช้งาน On Access Protection"
            }
            
            # Check exclusions
            if ($defender) {
                $totalExclusions = $defender.ExclusionPath.Count + $defender.ExclusionProcess.Count + $defender.ExclusionExtension.Count
                if ($totalExclusions -eq 0) {
                    Write-Result "PASS" "DEF006" "ไม่มี Defender Exclusions ที่กำหนด"
                } else {
                    Write-Result "WARN" "DEF006" "มี $totalExclusions Defender Exclusions" -Details "Paths: $($defender.ExclusionPath.Count), Processes: $($defender.ExclusionProcess.Count), Extensions: $($defender.ExclusionExtension.Count)" -Recommendation "ตรวจสอบความจำเป็นของ exclusions"
                }
            }
        } else {
            Write-Result "WARN" "DEF999" "ไม่สามารถตรวจสอบ Windows Defender ได้" -Details "Get-MpComputerStatus failed"
        }
    }
    catch {
        Write-Result "WARN" "DEF999" "ไม่สามารถตรวจสอบ Windows Defender ได้" -Details $_.Exception.Message
    }
}

# 5. Windows Updates
function Test-WindowsUpdates {
    Write-Host "`n=== 5. การตรวจสอบ Windows Updates ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check Windows Update service
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($wuService -and $wuService.Status -eq "Running") {
            Write-Result "PASS" "UPD001" "Windows Update Service: กำลังทำงาน"
        } else {
            Write-Result "WARN" "UPD001" "Windows Update Service: ไม่ทำงาน" -Recommendation "เริ่มใช้งาน Windows Update Service: Start-Service wuauserv"
        }
        
        # Check automatic updates setting
        $auOptions = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -ErrorAction SilentlyContinue
        if ($auOptions -and $auOptions.AUOptions -eq 4) {
            Write-Result "PASS" "UPD002" "Automatic Updates: เปิดใช้งาน (Install automatically)"
        } elseif ($auOptions -and $auOptions.AUOptions -eq 3) {
            Write-Result "WARN" "UPD002" "Automatic Updates: Download และแจ้งเตือนการติดตั้ง" -Recommendation "ตั้งค่าติดตั้งอัตโนมัติใน Windows Update settings"
        } else {
            Write-Result "FAIL" "UPD002" "Automatic Updates: ปิดใช้งานหรือตั้งค่าไม่เหมาะสม" -RiskLevel "High" -Recommendation "เปิดใช้งาน Automatic Updates ใน Windows Update settings"
        }
        
        # Check last update installation
        try {
            $lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
            if ($lastUpdate -and $lastUpdate.InstalledOn) {
                $daysSinceUpdate = (Get-Date) - $lastUpdate.InstalledOn
                if ($daysSinceUpdate.Days -le 30) {
                    Write-Result "PASS" "UPD003" "Last Update: $($daysSinceUpdate.Days) วันที่แล้ว ($($lastUpdate.HotFixID))"
                } else {
                    Write-Result "WARN" "UPD003" "Last Update: $($daysSinceUpdate.Days) วันที่แล้ว ($($lastUpdate.HotFixID))" -Recommendation "ตรวจสอบและติดตั้ง Windows Updates"
                }
            } else {
                Write-Result "WARN" "UPD003" "ไม่พบข้อมูล Update ล่าสุด"
            }
        }
        catch {
            Write-Result "WARN" "UPD003" "ไม่สามารถตรวจสอบข้อมูล Updates ล่าสุดได้"
        }
        
        # Check Windows Update for Business settings
        $wufbSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
        if ($wufbSettings) {
            if ($wufbSettings.DeferFeatureUpdates -eq 1) {
                Write-Result "PASS" "UPD004" "Feature Updates: Deferred (แนะนำสำหรับ business)"
            } else {
                Write-Result "WARN" "UPD004" "Feature Updates: Not deferred" -Recommendation "พิจารณา defer feature updates สำหรับ business environment"
            }
        } else {
            Write-Result "INFO" "UPD004" "Windows Update for Business: ไม่ได้กำหนดค่า"
        }
        
        # Check Delivery Optimization
        $doSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -ErrorAction SilentlyContinue
        if ($doSettings) {
            Write-Result "INFO" "UPD005" "Delivery Optimization: กำหนดค่าแล้ว"
        }
    }
    catch {
        Write-Result "WARN" "UPD999" "ไม่สามารถตรวจสอบ Windows Updates ได้" -Details $_.Exception.Message
    }
}

# 6. Network Security
function Test-NetworkSecurity {
    Write-Host "`n=== 6. การตรวจสอบ Network Security ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Network sharing and discovery
        $networkDiscovery = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -ErrorAction SilentlyContinue
        if ($networkDiscovery) {
            Write-Result "PASS" "NET001" "Network Discovery: ปิดใช้งาน"
        } else {
            Write-Result "WARN" "NET001" "Network Discovery: อาจเปิดใช้งาน" -Recommendation "ปิดใช้งานในเครือข่ายสาธารณะ"
        }
        
        # File and printer sharing (SMB settings)
        try {
            $fileSharing = Get-SmbServerConfiguration -ErrorAction Stop
            if (-not $fileSharing.EnableSMB1Protocol) {
                Write-Result "PASS" "NET002" "SMB1 Protocol: ปิดใช้งาน"
            } else {
                Write-Result "FAIL" "NET002" "SMB1 Protocol: เปิดใช้งาน" -RiskLevel "High" -Recommendation "ปิดใช้งาน SMB1: Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
            }
            
            if ($fileSharing.RequireSecuritySignature) {
                Write-Result "PASS" "NET003" "SMB Security Signature: บังคับใช้งาน"
            } else {
                Write-Result "WARN" "NET003" "SMB Security Signature: ไม่บังคับใช้งาน" -Recommendation "เปิดใช้งาน SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
            }
        }
        catch {
            Write-Result "WARN" "NET002" "ไม่สามารถตรวจสอบ SMB Configuration ได้" -Details $_.Exception.Message
        }
        
        # Remote Desktop
        $rdp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
        if ($rdp -and $rdp.fDenyTSConnections -eq 1) {
            Write-Result "PASS" "NET004" "Remote Desktop: ปิดใช้งาน"
        } else {
            Write-Result "WARN" "NET004" "Remote Desktop: เปิดใช้งาน" -Recommendation "ตรวจสอบว่าจำเป็นต้องใช้งาน RDP หรือไม่"
        }
        
        # Network Level Authentication for RDP
        if ($rdp -and $rdp.fDenyTSConnections -eq 0) {
            $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
            if ($nla -and $nla.UserAuthentication -eq 1) {
                Write-Result "PASS" "NET005" "RDP Network Level Authentication: เปิดใช้งาน"
            } else {
                Write-Result "FAIL" "NET005" "RDP Network Level Authentication: ปิดใช้งาน" -RiskLevel "High" -Recommendation "เปิดใช้งาน NLA สำหรับ RDP"
            }
        }
        
        # Windows Connect Now
        $wcn = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -ErrorAction SilentlyContinue
        if ($wcn -and $wcn.DisableFlashConfigRegistrar -eq 0) {
            Write-Result "PASS" "NET006" "Windows Connect Now: ปิดใช้งาน"
        } else {
            Write-Result "WARN" "NET006" "Windows Connect Now: อาจเปิดใช้งาน" -Recommendation "ปิดใช้งาน WCN ผ่าน Group Policy"
        }
        
        # LLMNR and NetBIOS
        $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
            Write-Result "PASS" "NET007" "LLMNR: ปิดใช้งาน"
        } else {
            Write-Result "WARN" "NET007" "LLMNR: เปิดใช้งาน" -Recommendation "ปิดใช้งาน LLMNR เพื่อป้องกัน credential harvesting"
        }
    }
    catch {
        Write-Result "WARN" "NET999" "ไม่สามารถตรวจสอบ Network Security ได้" -Details $_.Exception.Message
    }
}

# 7. System Services
function Test-SystemServices {
    Write-Host "`n=== 7. การตรวจสอบ System Services ===" -ForegroundColor $Colors.HEADER
    
    # List of potentially dangerous services
    $dangerousServices = @(
        @{ Name = "Telnet"; Service = "TlntSvr"; Description = "Telnet Service" },
        @{ Name = "FTP"; Service = "MSFTPSVC"; Description = "FTP Service" },
        @{ Name = "SNMP"; Service = "SNMP"; Description = "SNMP Service" },
        @{ Name = "RemoteRegistry"; Service = "RemoteRegistry"; Description = "Remote Registry Service" },
        @{ Name = "Messenger"; Service = "Messenger"; Description = "Messenger Service" },
        @{ Name = "NetMeeting"; Service = "mnmsrvc"; Description = "NetMeeting Remote Desktop Sharing" },
        @{ Name = "SimpleFileSharing"; Service = "SharedAccess"; Description = "Internet Connection Sharing" }
    )
    
    foreach ($svc in $dangerousServices) {
        try {
            $service = Get-Service -Name $svc.Service -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -eq "Stopped" -and $service.StartType -eq "Disabled") {
                    Write-Result "PASS" "SVC00$($dangerousServices.IndexOf($svc) + 1)" "$($svc.Description): ปิดใช้งาน"
                } elseif ($service.Status -eq "Stopped") {
                    Write-Result "WARN" "SVC00$($dangerousServices.IndexOf($svc) + 1)" "$($svc.Description): หยุดทำงานแต่ยังไม่ได้ disable" -Recommendation "Disable service: Set-Service $($svc.Service) -StartupType Disabled"
                } else {
                    Write-Result "FAIL" "SVC00$($dangerousServices.IndexOf($svc) + 1)" "$($svc.Description): กำลังทำงาน" -RiskLevel "High" -Recommendation "หยุดและ disable service: Stop-Service $($svc.Service); Set-Service $($svc.Service) -StartupType Disabled"
                }
            } else {
                Write-Result "PASS" "SVC00$($dangerousServices.IndexOf($svc) + 1)" "$($svc.Description): ไม่มีการติดตั้ง"
            }
        }
        catch {
            Write-Result "WARN" "SVC00$($dangerousServices.IndexOf($svc) + 1)" "ไม่สามารถตรวจสอบ $($svc.Description) ได้"
        }
    }
    
    # Essential services check
    $essentialServices = @(
        @{ Name = "EventLog"; Description = "Windows Event Log" },
        @{ Name = "Winmgmt"; Description = "Windows Management Instrumentation" },
        @{ Name = "RpcSs"; Description = "Remote Procedure Call (RPC)" },
        @{ Name = "Dhcp"; Description = "DHCP Client" },
        @{ Name = "Dnscache"; Description = "DNS Client" }
    )
    
    foreach ($essential in $essentialServices) {
        try {
            $service = Get-Service -Name $essential.Name -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Write-Result "PASS" "SVC10$($essentialServices.IndexOf($essential) + 1)" "$($essential.Description): กำลังทำงาน"
            } else {
                Write-Result "WARN" "SVC10$($essentialServices.IndexOf($essential) + 1)" "$($essential.Description): ไม่ทำงาน" -Recommendation "ตรวจสอบสาเหตุที่ service สำคัญไม่ทำงาน"
            }
        }
        catch {
            Write-Result "WARN" "SVC10$($essentialServices.IndexOf($essential) + 1)" "ไม่สามารถตรวจสอบ $($essential.Description) ได้"
        }
    }
    
    # Check Windows Time service
    try {
        $timeService = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        if ($timeService -and $timeService.Status -eq "Running") {
            Write-Result "PASS" "SVC106" "Windows Time Service: กำลังทำงาน"
        } else {
            Write-Result "WARN" "SVC106" "Windows Time Service: ไม่ทำงาน" -Recommendation "เริ่มใช้งาน Windows Time Service: Start-Service W32Time"
        }
    }
    catch {
        Write-Result "WARN" "SVC106" "ไม่สามารถตรวจสอบ Windows Time Service ได้"
    }
}

# 8. Registry Security
function Test-RegistrySecurity {
    Write-Host "`n=== 8. การตรวจสอบ Registry Security ===" -ForegroundColor $Colors.HEADER
    
    $registryChecks = @(
        @{
            ID = "REG001"
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
            Name = "RestrictAnonymous"
            ExpectedValue = 1
            Description = "Restrict Anonymous Access"
            RiskLevel = "Medium"
        },
        @{
            ID = "REG002"
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
            Name = "RestrictAnonymousSAM"
            ExpectedValue = 1
            Description = "Restrict Anonymous SAM Access"
            RiskLevel = "High"
        },
        @{
            ID = "REG003"
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Name = "AutoShareWks"
            ExpectedValue = 0
            Description = "Disable Administrative Shares"
            RiskLevel = "Medium"
        },
        @{
            ID = "REG004"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "EnableLUA"
            ExpectedValue = 1
            Description = "User Account Control (UAC)"
            RiskLevel = "Critical"
        },
        @{
            ID = "REG005"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "ConsentPromptBehaviorAdmin"
            ExpectedValue = 2
            Description = "UAC: Behavior for Admin Approval Mode"
            RiskLevel = "High"
        },
        @{
            ID = "REG006"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "PromptOnSecureDesktop"
            ExpectedValue = 1
            Description = "UAC: Switch to secure desktop"
            RiskLevel = "Medium"
        },
        @{
            ID = "REG007"
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "DisableDomainCreds"
            ExpectedValue = 1
            Description = "Network access: Do not store credentials"
            RiskLevel = "Medium"
        }
    )
    
    foreach ($check in $registryChecks) {
        try {
            $value = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
            if ($value -and $value.($check.Name) -eq $check.ExpectedValue) {
                Write-Result "PASS" $check.ID $check.Description
            } else {
                $currentValue = if ($value) { $value.($check.Name) } else { "ไม่พบ" }
                Write-Result "FAIL" $check.ID $check.Description -Details "ค่าปัจจุบัน: $currentValue" -Recommendation "ตั้งค่าเป็น $($check.ExpectedValue): Set-ItemProperty -Path '$($check.Path)' -Name '$($check.Name)' -Value $($check.ExpectedValue)" -RiskLevel $check.RiskLevel
            }
        }
        catch {
            Write-Result "WARN" $check.ID $check.Description -Details "ไม่สามารถอ่านค่า Registry ได้"
        }
    }
}

# 9. Audit Policy
function Test-AuditPolicy {
    Write-Host "`n=== 9. การตรวจสอบ Audit Policy ===" -ForegroundColor $Colors.HEADER
    
    try {
        $auditCategories = @(
            @{ Category = "Account Logon"; ID = "AUD001" },
            @{ Category = "Account Management"; ID = "AUD002" }, 
            @{ Category = "Logon/Logoff"; ID = "AUD003" },
            @{ Category = "Object Access"; ID = "AUD004" },
            @{ Category = "Policy Change"; ID = "AUD005" },
            @{ Category = "Privilege Use"; ID = "AUD006" },
            @{ Category = "System"; ID = "AUD007" }
        )
        
        foreach ($cat in $auditCategories) {
            try {
                $auditResult = auditpol /get /category:"$($cat.Category)" 2>$null
                if ($auditResult -match "Success and Failure") {
                    Write-Result "PASS" $cat.ID "Audit $($cat.Category): Success and Failure"
                } elseif ($auditResult -match "Success|Failure") {
                    Write-Result "WARN" $cat.ID "Audit $($cat.Category): บางส่วน" -Recommendation "ตั้งค่า Success and Failure: auditpol /set /category:`"$($cat.Category)`" /success:enable /failure:enable"
                } else {
                    Write-Result "FAIL" $cat.ID "Audit $($cat.Category): ไม่ได้เปิดใช้งาน" -RiskLevel "Medium" -Recommendation "เปิดใช้งาน audit: auditpol /set /category:`"$($cat.Category)`" /success:enable /failure:enable"
                }
            }
            catch {
                Write-Result "WARN" $cat.ID "ไม่สามารถตรวจสอบ Audit $($cat.Category) ได้"
            }
        }
        
        # Check audit log size
        try {
            $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
            if ($securityLog) {
                $logSizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)
                if ($logSizeMB -ge 100) {
                    Write-Result "PASS" "AUD008" "Security Log Size: $logSizeMB MB"
                } else {
                    Write-Result "WARN" "AUD008" "Security Log Size: $logSizeMB MB" -Recommendation "เพิ่มขนาด Security Event Log เป็นอย่างน้อย 100 MB"
                }
            }
        }
        catch {
            Write-Result "WARN" "AUD008" "ไม่สามารถตรวจสอบ Security Event Log ได้"
        }
    }
    catch {
        Write-Result "WARN" "AUD999" "ไม่สามารถตรวจสอบ Audit Policy ได้" -Details $_.Exception.Message
    }
}

# 10. Additional Security Checks
function Test-AdditionalSecurity {
    Write-Host "`n=== 10. การตรวจสอบความปลอดภัยเพิ่มเติม ===" -ForegroundColor $Colors.HEADER
    
    # BitLocker Status
    try {
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($bitlockerVolumes) {
            $systemDrive = $bitlockerVolumes | Where-Object { $_.MountPoint -eq "C:" }
            if ($systemDrive -and $systemDrive.ProtectionStatus -eq "On") {
                Write-Result "PASS" "ADD001" "BitLocker: เปิดใช้งานสำหรับ System Drive"
            } else {
                Write-Result "WARN" "ADD001" "BitLocker: ไม่ได้เปิดใช้งานสำหรับ System Drive" -Recommendation "เปิดใช้งาน BitLocker สำหรับ drive encryption"
            }
        } else {
            Write-Result "WARN" "ADD001" "BitLocker: ไม่สามารถตรวจสอบได้"
        }
    }
    catch {
        Write-Result "WARN" "ADD001" "BitLocker: ไม่สามารถตรวจสอบได้"
    }
    
    # PowerShell Execution Policy
    try {
        $executionPolicy = Get-ExecutionPolicy
        if ($executionPolicy -eq "Restricted" -or $executionPolicy -eq "RemoteSigned") {
            Write-Result "PASS" "ADD002" "PowerShell Execution Policy: $executionPolicy"
        } else {
            Write-Result "WARN" "ADD002" "PowerShell Execution Policy: $executionPolicy" -Recommendation "ตั้งค่าเป็น RemoteSigned: Set-ExecutionPolicy RemoteSigned"
        }
    }
    catch {
        Write-Result "WARN" "ADD002" "ไม่สามารถตรวจสอบ PowerShell Execution Policy ได้"
    }
    
    # Windows Script Host
    try {
        $wshEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($wshEnabled -and $wshEnabled.Enabled -eq 0) {
            Write-Result "PASS" "ADD003" "Windows Script Host: ปิดใช้งาน"
        } else {
            Write-Result "WARN" "ADD003" "Windows Script Host: เปิดใช้งาน" -Recommendation "พิจารณาปิดใช้งานหากไม่จำเป็น"
        }
    }
    catch {
        Write-Result "WARN" "ADD003" "ไม่สามารถตรวจสอบ Windows Script Host ได้"
    }
    
    # USB Device Control
    try {
        $usbPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -ErrorAction SilentlyContinue
        if ($usbPolicy -and $usbPolicy.Start -eq 4) {
            Write-Result "PASS" "ADD004" "USB Storage: ปิดใช้งาน"
        } else {
            Write-Result "WARN" "ADD004" "USB Storage: เปิดใช้งาน" -Recommendation "พิจารณาควบคุมการใช้งาน USB Storage"
        }
    }
    catch {
        Write-Result "WARN" "ADD004" "ไม่สามารถตรวจสอบ USB Storage Policy ได้"
    }
    
    # AutoRun/AutoPlay
    try {
        $autoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
        if ($autoRun -and $autoRun.NoDriveTypeAutoRun -eq 255) {
            Write-Result "PASS" "ADD005" "AutoRun: ปิดใช้งานสำหรับทุก drive types"
        } else {
            Write-Result "WARN" "ADD005" "AutoRun: อาจเปิดใช้งาน" -Recommendation "ปิดใช้งาน AutoRun: Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255"
        }
    }
    catch {
        Write-Result "WARN" "ADD005" "ไม่สามารถตรวจสอบ AutoRun Policy ได้"
    }
    
    # Windows Telemetry
    try {
        $telemetry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
        if ($telemetry -and $telemetry.AllowTelemetry -le 1) {
            Write-Result "PASS" "ADD006" "Windows Telemetry: ตั้งค่าระดับต่ำ (Level $($telemetry.AllowTelemetry))"
        } else {
            Write-Result "WARN" "ADD006" "Windows Telemetry: ระดับสูง" -Recommendation "ลด Telemetry level เพื่อความเป็นส่วนตัว"
        }
    }
    catch {
        Write-Result "WARN" "ADD006" "ไม่สามารถตรวจสอบ Windows Telemetry ได้"
    }
}

# Function to generate HTML report
function Export-HTMLReport {
    param(
        [string]$OutputPath = "C:\Temp",
        [string]$Title = "CIS Windows 10/11 Security Audit Report"
    )
    
    $htmlFile = Join-Path $OutputPath "CIS_Windows_Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    Write-Host "`nสร้างรายงาน HTML..." -ForegroundColor Cyan
    
    # Get system information
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $systemName = $computer.Name
    $osVersion = "$($os.Caption) Build $($os.BuildNumber)"
    $auditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $domain = $computer.Domain
    $generationTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
    
    # Calculate security score
    $securityScore = 0
    if ($script:TotalChecks -gt 0) {
        $securityScore = [math]::Round(($script:PassCount * 100) / $script:TotalChecks, 1)
    }
    
    # Determine security level
    $securityLevel = "ต้องปรับปรุง"
    $securityLevelClass = "level-poor"
    if ($securityScore -ge 85) {
        $securityLevel = "ดีเยี่ยม"
        $securityLevelClass = "level-excellent"
    } elseif ($securityScore -ge 70) {
        $securityLevel = "ดี"
        $securityLevelClass = "level-good"
    } elseif ($securityScore -ge 50) {
        $securityLevel = "ปานกลาง"
        $securityLevelClass = "level-medium"
    }
    
    # Count critical issues
    $criticalCount = ($script:Results | Where-Object { $_.RiskLevel -eq "Critical" -and $_.Status -eq "FAIL" }).Count

    # HTML Template with embedded CSS and JavaScript
    $htmlTemplate = @"
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        :root {
            --primary-color: #2563eb; --success-color: #059669; --warning-color: #d97706;
            --danger-color: #dc2626; --critical-color: #7c2d12; --info-color: #0891b2;
            --bg-light: #f8fafc; --bg-white: #ffffff; --text-dark: #1f2937;
            --text-gray: #6b7280; --border-color: #e5e7eb;
            --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: var(--bg-light); color: var(--text-dark); line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, var(--primary-color) 0%, #1d4ed8 100%); color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; box-shadow: var(--shadow-lg); }
        .header h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; }
        .header p { font-size: 1.1rem; opacity: 0.9; }
        .system-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .info-card { background: var(--bg-white); padding: 1.5rem; border-radius: 8px; box-shadow: var(--shadow); border-left: 4px solid var(--primary-color); }
        .info-card h3 { color: var(--text-gray); font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .info-card p { font-size: 1.125rem; font-weight: 600; color: var(--text-dark); }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .metric-card { background: var(--bg-white); padding: 1.5rem; border-radius: 12px; box-shadow: var(--shadow); text-align: center; position: relative; overflow: hidden; }
        .metric-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; }
        .metric-card.pass::before { background: var(--success-color); }
        .metric-card.fail::before { background: var(--danger-color); }
        .metric-card.warn::before { background: var(--warning-color); }
        .metric-card.critical::before { background: var(--critical-color); }
        .metric-number { font-size: 3rem; font-weight: 700; margin-bottom: 0.5rem; }
        .metric-card.pass .metric-number { color: var(--success-color); }
        .metric-card.fail .metric-number { color: var(--danger-color); }
        .metric-card.warn .metric-number { color: var(--warning-color); }
        .metric-card.critical .metric-number { color: var(--critical-color); }
        .metric-label { font-size: 1rem; color: var(--text-gray); font-weight: 500; }
        .security-score { background: var(--bg-white); padding: 2rem; border-radius: 12px; box-shadow: var(--shadow); margin-bottom: 2rem; text-align: center; }
        .score-text { font-size: 3rem; font-weight: 700; color: var(--text-dark); }
        .score-label { font-size: 1.25rem; color: var(--text-gray); margin-bottom: 1rem; }
        .score-level { display: inline-block; padding: 0.5rem 1rem; border-radius: 20px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
        .level-excellent { background: #d1fae5; color: var(--success-color); }
        .level-good { background: #dbeafe; color: var(--primary-color); }
        .level-medium { background: #fef3c7; color: var(--warning-color); }
        .level-poor { background: #fecaca; color: var(--danger-color); }
        .progress-bar { width: 100%; height: 20px; background: #e5e7eb; border-radius: 10px; overflow: hidden; margin: 1rem 0; }
        .progress-fill { height: 100%; border-radius: 10px; transition: width 0.5s ease; background: linear-gradient(90deg, var(--danger-color) 0%, var(--warning-color) 50%, var(--success-color) 100%); }
        .filters { background: var(--bg-white); padding: 1.5rem; border-radius: 12px; box-shadow: var(--shadow); margin-bottom: 2rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; }
        .filter-group { display: flex; align-items: center; gap: 0.5rem; }
        .filter-group label { font-weight: 500; color: var(--text-dark); }
        select, input { padding: 0.5rem; border: 1px solid var(--border-color); border-radius: 6px; font-size: 0.875rem; }
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 6px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
        .btn-primary { background: var(--primary-color); color: white; }
        .btn-primary:hover { background: #1d4ed8; }
        .results-section { background: var(--bg-white); border-radius: 12px; box-shadow: var(--shadow); overflow: hidden; margin-bottom: 2rem; }
        .section-header { background: #f9fafb; padding: 1.5rem; border-bottom: 1px solid var(--border-color); }
        .section-title { font-size: 1.5rem; font-weight: 700; color: var(--text-dark); }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f9fafb; padding: 1rem; text-align: left; font-weight: 600; color: var(--text-dark); border-bottom: 1px solid var(--border-color); }
        td { padding: 1rem; border-bottom: 1px solid #f3f4f6; word-wrap: break-word; max-width: 300px; }
        tr:hover { background: #f9fafb; }
        .status-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .status-pass { background: #d1fae5; color: var(--success-color); }
        .status-fail { background: #fecaca; color: var(--danger-color); }
        .status-warn { background: #fef3c7; color: var(--warning-color); }
        .status-info { background: #dbeafe; color: var(--info-color); }
        .risk-critical { background: #fef2f2; color: var(--critical-color); }
        .risk-high { background: #fecaca; color: var(--danger-color); }
        .risk-medium { background: #fef3c7; color: var(--warning-color); }
        .risk-low { background: #d1fae5; color: var(--success-color); }
        .critical-alert { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 1rem; margin-bottom: 2rem; }
        .critical-alert h3 { color: var(--danger-color); margin-bottom: 0.5rem; }
        .critical-alert ul { margin-left: 1rem; color: var(--text-dark); }
        .recommendations { background: var(--bg-white); padding: 2rem; border-radius: 12px; box-shadow: var(--shadow); margin-bottom: 2rem; }
        .recommendation-item { background: #fef9e7; border-left: 4px solid var(--warning-color); padding: 1rem; margin-bottom: 1rem; border-radius: 0 6px 6px 0; }
        .recommendation-title { font-weight: 600; color: var(--text-dark); margin-bottom: 0.5rem; }
        .recommendation-desc { color: var(--text-gray); font-size: 0.9rem; }
        .footer { text-align: center; padding: 2rem; color: var(--text-gray); border-top: 1px solid var(--border-color); margin-top: 2rem; }
        @media (max-width: 768px) { .dashboard { grid-template-columns: repeat(2, 1fr); } .filters { flex-direction: column; align-items: stretch; } table { font-size: 0.875rem; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 $Title</h1>
            <p>รายงานการตรวจสอบความปลอดภัยระบบ Windows ตามมาตรฐาน CIS</p>
        </div>

        <div class="system-info">
            <div class="info-card"><h3>System</h3><p>$systemName</p></div>
            <div class="info-card"><h3>OS Version</h3><p>$osVersion</p></div>
            <div class="info-card"><h3>Audit Date</h3><p>$auditDate</p></div>
            <div class="info-card"><h3>Domain</h3><p>$domain</p></div>
        </div>

        <div class="security-score">
            <h2>Security Score</h2>
            <div class="score-text">$securityScore%</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${securityScore}%"></div>
            </div>
            <div class="score-label">คะแนนความปลอดภัยโดยรวม</div>
            <div class="score-level $securityLevelClass">$securityLevel</div>
        </div>

        <div class="dashboard">
            <div class="metric-card pass">
                <div class="metric-number">$($script:PassCount)</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric-card fail">
                <div class="metric-number">$($script:FailCount)</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric-card warn">
                <div class="metric-number">$($script:WarnCount)</div>
                <div class="metric-label">Warnings</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-number">$criticalCount</div>
                <div class="metric-label">Critical Issues</div>
            </div>
        </div>
"@

    # Generate critical alert section
    $criticalIssues = $script:Results | Where-Object { $_.RiskLevel -eq "Critical" -and $_.Status -eq "FAIL" }
    if ($criticalIssues) {
        $criticalList = ($criticalIssues | ForEach-Object { "<li>$($_.Description)</li>" }) -join ""
        $htmlTemplate += @"

        <div class="critical-alert">
            <h3>⚠️ ปัญหาที่ต้องแก้ไขด่วน</h3>
            <ul>$criticalList</ul>
        </div>
"@
    }

    # Add filters and table
    $htmlTemplate += @"

        <div class="filters">
            <div class="filter-group">
                <label for="statusFilter">Status:</label>
                <select id="statusFilter" onchange="filterResults()">
                    <option value="">All</option>
                    <option value="PASS">Pass</option>
                    <option value="FAIL">Fail</option>
                    <option value="WARN">Warning</option>
                    <option value="INFO">Info</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="riskFilter">Risk Level:</label>
                <select id="riskFilter" onchange="filterResults()">
                    <option value="">All</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="searchFilter">Search:</label>
                <input type="text" id="searchFilter" placeholder="Search descriptions..." onkeyup="filterResults()">
            </div>
            <button class="btn btn-primary" onclick="exportCSV()">📄 Export CSV</button>
            <button class="btn btn-primary" onclick="window.print()">🖨️ Print</button>
        </div>

        <div class="results-section">
            <div class="section-header">
                <h2 class="section-title">Security Check Results</h2>
                <span style="float: right; color: var(--text-gray);">Total: $($script:TotalChecks) checks</span>
            </div>
            <div style="overflow-x: auto;">
                <table id="resultsTable">
                    <thead>
                        <tr>
                            <th>Check ID</th>
                            <th>Status</th>
                            <th>Description</th>
                            <th>Risk Level</th>
                            <th>Details</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    # Generate table rows
    foreach ($result in $script:Results) {
        $statusClass = "status-" + $result.Status.ToLower()
        $riskClass = "risk-" + $result.RiskLevel.ToLower()
        
        $htmlTemplate += @"
                        <tr>
                            <td>$($result.CheckID)</td>
                            <td><span class="status-badge $statusClass">$($result.Status)</span></td>
                            <td>$($result.Description)</td>
                            <td><span class="status-badge $riskClass">$($result.RiskLevel)</span></td>
                            <td>$($result.Details)</td>
                            <td>$($result.Recommendation)</td>
                        </tr>
"@
    }

    # Generate recommendations
    $recommendationsList = ""
    if ($script:FailCount -gt 0 -or $script:WarnCount -gt 0) {
        $recommendationsList = @"
        <div class="recommendation-item">
            <div class="recommendation-title">1. แก้ไขปัญหาความปลอดภัยที่สำคัญ</div>
            <div class="recommendation-desc">ตรวจสอบและแก้ไขรายการที่มีสถานะ FAIL ทันที โดยเฉพาะปัญหาระดับ Critical</div>
        </div>
        <div class="recommendation-item">
            <div class="recommendation-title">2. อัพเดท Windows และ Security Patches</div>
            <div class="recommendation-desc">ติดตั้ง Windows Updates และ security patches ผ่าน Windows Update</div>
        </div>
        <div class="recommendation-item">
            <div class="recommendation-title">3. ตรวจสอบการตั้งค่า Windows Defender</div>
            <div class="recommendation-desc">ตรวจสอบและปรับปรุงการตั้งค่า antivirus และ firewall</div>
        </div>
        <div class="recommendation-item">
            <div class="recommendation-title">4. ทำการ Backup และ Recovery Plan</div>
            <div class="recommendation-desc">ตั้งค่า automated backup และทดสอบ disaster recovery procedures</div>
        </div>
        <div class="recommendation-item">
            <div class="recommendation-title">5. ใช้ Hardening Script</div>
            <div class="recommendation-desc">รัน PowerShell script พร้อม parameter -CreateHardening เพื่อแก้ไขปัญหาอัตโนมัติ</div>
        </div>
"@
    } else {
        $recommendationsList = @"
        <div class="recommendation-item">
            <div class="recommendation-title">✅ ระบบมีความปลอดภัยในระดับดี</div>
            <div class="recommendation-desc">ควรคงมาตรฐานปัจจุบันและติดตามการปรับปรุงอย่างต่อเนื่อง</div>
        </div>
"@
    }

    # Complete the HTML
    $htmlTemplate += @"
                    </tbody>
                </table>
            </div>
        </div>

        <div class="recommendations">
            <h2>💡 คำแนะนำการปรับปรุง</h2>
            $recommendationsList
        </div>

        <div class="footer">
            <p>Generated by CIS Windows Security Audit Script | $generationTime</p>
            <p>สำหรับข้อมูลเพิ่มเติม โปรดอ้างอิง CIS Benchmarks และ security best practices</p>
            <p><strong>Created by:</strong> Tananan Maiket | <a href="https://www.facebook.com/neronain.minidev" style="color: #2563eb;">Facebook Profile</a></p>
        </div>
    </div>

    <script>
        function filterResults() {
            const statusFilter = document.getElementById('statusFilter').value;
            const riskFilter = document.getElementById('riskFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();
            const tbody = document.querySelector('#resultsTable tbody');
            const rows = tbody.getElementsByTagName('tr');

            let visibleCount = 0;
            for (let row of rows) {
                let show = true;
                const cells = row.getElementsByTagName('td');
                
                if (cells.length > 0) {
                    const status = cells[1].textContent.trim();
                    const description = cells[2].textContent.toLowerCase();
                    const risk = cells[3].textContent.trim();

                    if (statusFilter && !status.includes(statusFilter)) show = false;
                    if (riskFilter && !risk.includes(riskFilter)) show = false;
                    if (searchFilter && !description.includes(searchFilter)) show = false;
                }

                row.style.display = show ? '' : 'none';
                if (show) visibleCount++;
            }

            const sectionTitle = document.querySelector('.section-title');
            const totalSpan = sectionTitle.parentElement.querySelector('span');
            if (totalSpan) {
                totalSpan.textContent = 'Showing: ' + visibleCount + ' of $($script:TotalChecks) checks';
            }
        }

        function exportCSV() {
            const table = document.querySelector('table');
            const rows = Array.from(table.getElementsByTagName('tr'));
            const visibleRows = rows.filter(row => row.style.display !== 'none');
            
            let csv = '';
            visibleRows.forEach(row => {
                const cells = Array.from(row.getElementsByTagName('td')).concat(Array.from(row.getElementsByTagName('th')));
                const rowData = cells.map(cell => '"' + cell.textContent.replace(/"/g, '""') + '"').join(',');
                csv += rowData + '\n';
            });

            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'windows_security_audit_filtered_' + new Date().toISOString().split('T')[0] + '.csv';
            a.click();
            window.URL.revokeObjectURL(url);
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            // Animate numbers on load
            const numbers = document.querySelectorAll('.metric-number');
            numbers.forEach(num => {
                const target = parseInt(num.textContent);
                let current = 0;
                const increment = target / 20;
                const timer = setInterval(() => {
                    current += increment;
                    if (current >= target) {
                        current = target;
                        clearInterval(timer);
                    }
                    num.textContent = Math.floor(current);
                }, 50);
            });
        });
    </script>
</body>
</html>
"@

    # Write HTML file
    $htmlTemplate | Out-File -FilePath $htmlFile -Encoding UTF8
    
    Write-Host "HTML Report สร้างเสร็จแล้ว: $htmlFile" -ForegroundColor Green
    Write-Host "เปิดไฟล์ด้วย web browser เพื่อดูรายงาน" -ForegroundColor Cyan
    
    # Try to open with default browser
    try {
        Start-Process $htmlFile
    } catch {
        Write-Host "ไม่สามารถเปิดไฟล์อัตโนมัติได้ กรุณาเปิดไฟล์: $htmlFile" -ForegroundColor Yellow
    }
}

# Function to export CSV report
function Export-CSVReport {
    param(
        [string]$OutputPath = "C:\Temp"
    )
    
    $csvFile = Join-Path $OutputPath "CIS_Windows_Audit_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    Write-Host "`nสร้างรายงาน CSV..." -ForegroundColor Cyan
    
    $script:Results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    
    Write-Host "CSV Report สร้างเสร็จแล้ว: $csvFile" -ForegroundColor Green
}

# Function to create hardening script
function New-HardeningScript {
    $hardeningScriptPath = Join-Path $OutputPath "CIS_Windows_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
    
    Write-Host "`nสร้าง Hardening Script..." -ForegroundColor Cyan
    
    $hardeningScript = @"
# ==================================================================================
# CIS Windows 10/11 Hardening Script
# Created by: Tananan Maiket
# Contact: https://www.facebook.com/neronain.minidev
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# 
# ⚠️  WARNING: ใช้ความระมัดระวังอย่างยิ่งในการรัน script นี้
# แนะนำให้ backup การตั้งค่าและทดสอบในสภาพแวดล้อม test ก่อน
# ==================================================================================

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║                CIS Windows Hardening Script                   ║" -ForegroundColor Magenta
Write-Host "║                Created by Tananan Maiket                      ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""
Write-Host "สคริปต์นี้จะทำการ hardening ระบบ Windows ตาม CIS" -ForegroundColor Yellow
Write-Host "⚠️  การดำเนินการนี้อาจส่งผลกระทบต่อการทำงานของระบบ" -ForegroundColor Red
Write-Host "แนะนำให้ backup การตั้งค่าทั้งหมดก่อน" -ForegroundColor Yellow
Write-Host ""
`$confirm = Read-Host "ต้องการดำเนินการต่อหรือไม่? (y/N)"

if (`$confirm -ne 'y' -and `$confirm -ne 'Y') {
    Write-Host "ยกเลิกการดำเนินการ" -ForegroundColor Red
    exit
}

Write-Host "เริ่มการ hardening ระบบ..." -ForegroundColor Green

# Create system restore point
Write-Host "สร้าง System Restore Point..." -ForegroundColor Cyan
try {
    Checkpoint-Computer -Description "Pre-CIS-Hardening" -RestorePointType "MODIFY_SETTINGS"
    Write-Host "System Restore Point สร้างสำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถสร้าง System Restore Point ได้: `$(`$_.Exception.Message)" -ForegroundColor Yellow
}

# Disable Guest Account
Write-Host "ปิดใช้งาน Guest Account..." -ForegroundColor Cyan
try {
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Write-Host "ปิดใช้งาน Guest account สำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถปิดใช้งาน Guest account ได้" -ForegroundColor Yellow
}

# Windows Firewall
Write-Host "เปิดใช้งาน Windows Firewall..." -ForegroundColor Cyan
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Host "Windows Firewall กำหนดค่าสำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถกำหนดค่า Windows Firewall ได้: `$(`$_.Exception.Message)" -ForegroundColor Yellow
}

# Disable SMB1
Write-Host "ปิดใช้งาน SMB1 Protocol..." -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force
    Write-Host "ปิดใช้งาน SMB1 สำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถปิดใช้งาน SMB1 ได้: `$(`$_.Exception.Message)" -ForegroundColor Yellow
}

# Enable SMB Signing
Write-Host "เปิดใช้งาน SMB Signing..." -ForegroundColor Cyan
try {
    Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force
    Write-Host "เปิดใช้งาน SMB Signing สำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถเปิดใช้งาน SMB Signing ได้: `$(`$_.Exception.Message)" -ForegroundColor Yellow
}

# Enable UAC
Write-Host "เปิดใช้งาน UAC..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force
    Write-Host "UAC กำหนดค่าสำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถกำหนดค่า UAC ได้: `$(`$_.Exception.Message)" -ForegroundColor Yellow
}

# Registry Security Settings
Write-Host "กำหนดค่า Registry Security..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Force
    Write-Host "Registry Security กำหนดค่าสำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถกำหนดค่า Registry Security ได้: `$(`$_.Exception.Message)" -ForegroundColor Yellow
}

# PowerShell Execution Policy
Write-Host "กำหนดค่า PowerShell Execution Policy..." -ForegroundColor Cyan
try {
    Set-ExecutionPolicy RemoteSigned -Force
    Write-Host "PowerShell Execution Policy กำหนดค่าสำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถกำหนดค่า PowerShell Execution Policy ได้: `$(`$_.Exception.Message)" -ForegroundColor Yellow
}

# Disable unnecessary services
Write-Host "ปิดใช้งาน services ที่ไม่จำเป็น..." -ForegroundColor Cyan
$servicesToDisable = @("TlntSvr", "MSFTPSVC", "RemoteRegistry", "Messenger", "mnmsrvc", "SharedAccess")

foreach ($service in $servicesToDisable) {
    try {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "ปิดใช้งาน $service สำเร็จ" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "ไม่สามารถปิดใช้งาน $service ได้" -ForegroundColor Yellow
    }
}

# Enable Windows Update automatic updates
Write-Host "เปิดใช้งาน Windows Update..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4 -Force
    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    Write-Host "Windows Update กำหนดค่าสำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถกำหนดค่า Windows Update ได้: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Enable Windows Defender real-time protection
Write-Host "เปิดใช้งาน Windows Defender..." -ForegroundColor Cyan
try {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -MAPSReporting Advanced
    Update-MpSignature
    Write-Host "Windows Defender กำหนดค่าสำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถกำหนดค่า Windows Defender ได้: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Disable AutoRun for all drives
Write-Host "ปิดใช้งาน AutoRun..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Force
    Write-Host "ปิดใช้งาน AutoRun สำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถปิดใช้งาน AutoRun ได้: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Configure audit policies
Write-Host "กำหนดค่า Audit Policies..." -ForegroundColor Cyan
try {
    $auditCategories = @(
        "Account Logon",
        "Account Management", 
        "Logon/Logoff",
        "Object Access",
        "Policy Change",
        "Privilege Use",
        "System"
    )
    
    foreach ($category in $auditCategories) {
        auditpol /set /category:"$category" /success:enable /failure:enable | Out-Null
    }
    Write-Host "Audit Policies กำหนดค่าสำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถกำหนดค่า Audit Policies ได้: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Disable LLMNR
Write-Host "ปิดใช้งาน LLMNR..." -ForegroundColor Cyan
try {
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Force
    Write-Host "ปิดใช้งาน LLMNR สำเร็จ" -ForegroundColor Green
}
catch {
    Write-Host "ไม่สามารถปิดใช้งาน LLMNR ได้: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Set minimum password length
Write-Host "กำหนดค่า Password Policy..." -ForegroundColor Cyan
try {
    $tempFile = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $tempFile /quiet
    
    if (Test-Path $tempFile) {
        $content = Get-Content $tempFile
        $content = $content -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 14"
        $content = $content -replace "PasswordComplexity = \d+", "PasswordComplexity = 1"
        $content = $content -replace "LockoutBadCount = \d+", "LockoutBadCount = 5"
        $content = $content -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 12"
        
        $content | Set-Content $tempFile
        secedit /configure /db c:\windows\security\local.sdb /cfg $tempFile /areas SECURITYPOLICY /quiet
        Remove-Item $tempFile -ErrorAction SilentlyContinue
        Write-Host "Password Policy กำหนดค่าสำเร็จ" -ForegroundColor Green
    }
}
catch {
    Write-Host "ไม่สามารถกำหนดค่า Password Policy ได้: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                   Hardening เสร็จสมบูรณ์                       ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "⚠️  กรุณา RESTART ระบบเพื่อให้การตั้งค่าทั้งหมดมีผล" -ForegroundColor Yellow
Write-Host "📝 แนะนำให้รันการตรวจสอบอีกครั้งหลังจาก restart" -ForegroundColor Cyan
Write-Host "📧 หากพบปัญหา ติดต่อ: https://www.facebook.com/neronain.minidev" -ForegroundColor Cyan
"@
    
    $hardeningScript | Out-File -FilePath $hardeningScriptPath -Encoding UTF8
    
    Write-Host "Hardening Script สร้างเสร็จแล้ว: $hardeningScriptPath" -ForegroundColor Green
    Write-Host "⚠️  กรุณาอ่านและทำความเข้าใจ script ก่อนรัน" -ForegroundColor Red
    Write-Host "💡 แนะนำให้ทดสอบในสภาพแวดล้อม test ก่อน" -ForegroundColor Yellow
}

# Display summary
function Show-Summary {
    Write-Host "`n" + "="*80 -ForegroundColor $Colors.HEADER
    Write-Host "                           สรุปผลการตรวจสอบ                           " -ForegroundColor $Colors.HEADER
    Write-Host "="*80 -ForegroundColor $Colors.HEADER
    
    $securityScore = 0
    if ($script:TotalChecks -gt 0) {
        $securityScore = [math]::Round(($script:PassCount * 100) / $script:TotalChecks, 1)
    }
    
    Write-Host "📊 สถิติการตรวจสอบ:" -ForegroundColor $Colors.HEADER
    Write-Host "   ✅ ผ่าน (PASS): $script:PassCount" -ForegroundColor $Colors.PASS
    Write-Host "   ❌ ไม่ผ่าน (FAIL): $script:FailCount" -ForegroundColor $Colors.FAIL
    Write-Host "   ⚠️  เตือน (WARN): $script:WarnCount" -ForegroundColor $Colors.WARN
    Write-Host "   ℹ️  ข้อมูล (INFO): $script:InfoCount" -ForegroundColor $Colors.INFO
    Write-Host "   📝 รวมทั้งหมด: $script:TotalChecks ข้อ" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "🎯 คะแนนความปลอดภัย: $securityScore%" -ForegroundColor $(
        if ($securityScore -ge 85) { $Colors.PASS }
        elseif ($securityScore -ge 70) { $Colors.INFO }
        elseif ($securityScore -ge 50) { $Colors.WARN }
        else { $Colors.FAIL }
    )
    
    $criticalIssues = ($script:Results | Where-Object { $_.RiskLevel -eq "Critical" -and $_.Status -eq "FAIL" }).Count
    if ($criticalIssues -gt 0) {
        Write-Host "🔥 ปัญหาวิกฤติที่ต้องแก้ไขด่วน: $criticalIssues ข้อ" -ForegroundColor $Colors.CRITICAL
    }
    
    Write-Host ""
    Write-Host "📁 ไฟล์ log: $script:LogFile" -ForegroundColor Cyan
    
    if ($ExportHTML -or $ExportResults) {
        Write-Host "📊 รายงาน HTML จะถูกสร้างขึ้น..." -ForegroundColor Cyan
    }
    
    if ($ExportCSV -or $ExportResults) {
        Write-Host "📋 รายงาน CSV จะถูกสร้างขึ้น..." -ForegroundColor Cyan
    }
    
    if ($CreateHardening) {
        Write-Host "🔧 Hardening Script จะถูกสร้างขึ้น..." -ForegroundColor Cyan
    }
    
    Write-Host "="*80 -ForegroundColor $Colors.HEADER
}

# Main execution
function Main {
    try {
        Initialize-Script
        Get-SystemInfo
        Test-AccountPolicies
        Test-LocalPolicies
        Test-WindowsFirewall
        Test-WindowsDefender
        Test-WindowsUpdates
        Test-NetworkSecurity
        Test-SystemServices
        Test-RegistrySecurity
        Test-AuditPolicy
        Test-AdditionalSecurity
        
        Show-Summary
        
        # Export reports based on parameters
        if ($ExportHTML -or $ExportResults -or (-not $ExportCSV -and -not $CreateHardening)) {
            Export-HTMLReport -OutputPath $OutputPath -Title $ReportTitle
        }
        
        if ($ExportCSV -or $ExportResults) {
            Export-CSVReport -OutputPath $OutputPath
        }
        
        if ($CreateHardening) {
            New-HardeningScript
        }
        
        Write-Host "`n🎉 การตรวจสอบเสร็จสมบูรณ์!" -ForegroundColor Green
        Write-Host "📧 ติดต่อ: https://www.facebook.com/neronain.minidev" -ForegroundColor Cyan
        Write-Host "⭐ หากพอใจ กรุณาแชร์ให้เพื่อนๆ ด้วยครับ" -ForegroundColor Yellow
    }
    catch {
        Write-Host "❌ เกิดข้อผิดพลาดระหว่างการตรวจสอบ: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "📧 กรุณาติดต่อผู้พัฒนา: https://www.facebook.com/neronain.minidev" -ForegroundColor Yellow
        exit 1
    }
}

# Run the main function
Main