# ==================================================================================
# CIS Windows Server Active Directory Security Audit Script with HTML Export
# Version: 2.1 - Active Directory Edition
# Author: Tananan Maiket
# Contact: https://www.facebook.com/neronain.minidev
# Description: ตรวจสอบการตั้งค่าความปลอดภัยของ Windows Server AD ตามมาตรฐาน CIS
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
    [switch]$CheckGPO,
    [switch]$DetailedScan,
    [string]$OutputPath = "C:\Temp",
    [string]$ReportTitle = "CIS Windows Server AD Security Audit Report"
)

# Show help information
if ($Help) {
    Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║      CIS Windows Server AD Security Audit Script v2.1         ║
║                  Created by Tananan Maiket                    ║
║           https://www.facebook.com/neronain.minidev           ║
╚════════════════════════════════════════════════════════════════╝

การใช้งาน:
    .\windows_server_ad_audit.ps1 [พารามิเตอร์]

พารามิเตอร์:
    -Help               : แสดงข้อมูลการใช้งาน
    -CreateHardening    : สร้าง hardening script อัตโนมัติ
    -ExportHTML         : ส่งออกรายงาน HTML (เปิดใช้งานโดยปริยาย)
    -ExportCSV          : ส่งออกรายงาน CSV
    -ExportResults      : ส่งออกทั้ง HTML และ CSV
    -CheckGPO           : ตรวจสอบ Group Policy Objects แบบละเอียด
    -DetailedScan       : ตรวจสอบแบบละเอียดทุกรายการ
    -OutputPath         : โฟลเดอร์สำหรับบันทึกรายงาน (ค่าปริยาย: C:\Temp)
    -ReportTitle        : ชื่อรายงาน

ตัวอย่าง:
    .\windows_server_ad_audit.ps1
    .\windows_server_ad_audit.ps1 -ExportResults -CheckGPO -DetailedScan
    .\windows_server_ad_audit.ps1 -CreateHardening -OutputPath "D:\Reports"

หมายเหตุ: ต้องรันบน Domain Controller ด้วยสิทธิ์ Domain Administrator
"@ -ForegroundColor Cyan
    exit 0
}

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
} catch {
    Write-Host "❌ ไม่สามารถโหลด Active Directory module ได้" -ForegroundColor Red
    Write-Host "กรุณาตรวจสอบว่าเป็น Domain Controller และติดตั้ง AD PowerShell module" -ForegroundColor Yellow
    exit 1
}

# Global Variables
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0
$script:InfoCount = 0
$script:TotalChecks = 0
$script:LogFile = ""
$script:Results = @()
$script:DomainInfo = $null
$script:ForestInfo = $null

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
        exit 1
    }
    
    # Check if this is a Domain Controller
    try {
        $dcCheck = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop
        if (-not $dcCheck) {
            Write-Host "❌ เครื่องนี้ไม่ใช่ Domain Controller" -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "❌ ไม่สามารถตรวจสอบ Domain Controller status ได้" -ForegroundColor Red
        Write-Host "กรุณาตรวจสอบว่าเป็น Domain Controller และ AD PowerShell module ถูกติดตั้ง" -ForegroundColor Yellow
        exit 1
    }
    
    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Set log file path
    $script:LogFile = Join-Path $OutputPath "CIS_AD_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    # Get domain and forest information
    try {
        $script:DomainInfo = Get-ADDomain
        $script:ForestInfo = Get-ADForest
    } catch {
        Write-Host "❌ ไม่สามารถรับข้อมูล Domain/Forest ได้" -ForegroundColor Red
        exit 1
    }
    
    # Display header
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $Colors.HEADER
    Write-Host "║      CIS Windows Server AD Security Audit Script v2.1         ║" -ForegroundColor $Colors.HEADER
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
    Write-Host "`n=== ข้อมูลระบบและ Domain ===" -ForegroundColor $Colors.HEADER
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem
        $dc = Get-ADDomainController -Identity $env:COMPUTERNAME
        
        Write-Result "INFO" "SYS001" "Server: $($computer.Name)"
        Write-Result "INFO" "SYS002" "OS Version: $($os.Caption) Build $($os.BuildNumber)"
        Write-Result "INFO" "SYS003" "Domain: $($script:DomainInfo.DNSRoot)"
        Write-Result "INFO" "SYS004" "Forest: $($script:ForestInfo.Name)"
        Write-Result "INFO" "SYS005" "Domain Functional Level: $($script:DomainInfo.DomainMode)"
        Write-Result "INFO" "SYS006" "Forest Functional Level: $($script:ForestInfo.ForestMode)"
        Write-Result "INFO" "SYS007" "DC Role: $($dc.OperationMasterRoles -join ', ')"
        Write-Result "INFO" "SYS008" "Global Catalog: $($dc.IsGlobalCatalog)"
        Write-Result "INFO" "SYS009" "Site: $($dc.Site)"
        Write-Result "INFO" "SYS010" "Log File: $script:LogFile"
    }
    catch {
        Write-Result "WARN" "SYS999" "ไม่สามารถรวบรวมข้อมูลระบบได้" -Details $_.Exception.Message
    }
}

# 1. Domain Password Policy
function Test-DomainPasswordPolicy {
    Write-Host "`n=== 1. การตรวจสอบ Domain Password Policy ===" -ForegroundColor $Colors.HEADER
    
    try {
        $domainPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $script:DomainInfo.DistinguishedName
        
        # Minimum password length
        if ($domainPolicy.MinPasswordLength -ge 14) {
            Write-Result "PASS" "PWD001" "Minimum Password Length: $($domainPolicy.MinPasswordLength)"
        } elseif ($domainPolicy.MinPasswordLength -ge 8) {
            Write-Result "WARN" "PWD001" "Minimum Password Length: $($domainPolicy.MinPasswordLength)" -Recommendation "แนะนำให้ตั้งค่าเป็น 14 ตัวอักษรหรือมากกว่า"
        } else {
            Write-Result "FAIL" "PWD001" "Minimum Password Length: $($domainPolicy.MinPasswordLength)" -RiskLevel "High" -Recommendation "ต้องตั้งค่าอย่างน้อย 8 ตัวอักษร"
        }
        
        # Password complexity
        if ($domainPolicy.ComplexityEnabled) {
            Write-Result "PASS" "PWD002" "Password Complexity: เปิดใช้งาน"
        } else {
            Write-Result "FAIL" "PWD002" "Password Complexity: ปิดใช้งาน" -RiskLevel "High" -Recommendation "เปิดใช้งาน Password Complexity"
        }
        
        # Password history
        if ($domainPolicy.PasswordHistoryCount -ge 12) {
            Write-Result "PASS" "PWD003" "Password History: $($domainPolicy.PasswordHistoryCount) passwords"
        } else {
            Write-Result "WARN" "PWD003" "Password History: $($domainPolicy.PasswordHistoryCount) passwords" -Recommendation "ตั้งค่าอย่างน้อย 12"
        }
        
        # Maximum password age
        if ($domainPolicy.MaxPasswordAge.Days -le 90 -and $domainPolicy.MaxPasswordAge.Days -gt 0) {
            Write-Result "PASS" "PWD004" "Maximum Password Age: $($domainPolicy.MaxPasswordAge.Days) days"
        } else {
            Write-Result "WARN" "PWD004" "Maximum Password Age: $($domainPolicy.MaxPasswordAge.Days) days" -Recommendation "ตั้งค่าระหว่าง 30-90 วัน"
        }
        
        # Minimum password age
        if ($domainPolicy.MinPasswordAge.Days -ge 1) {
            Write-Result "PASS" "PWD005" "Minimum Password Age: $($domainPolicy.MinPasswordAge.Days) days"
        } else {
            Write-Result "WARN" "PWD005" "Minimum Password Age: $($domainPolicy.MinPasswordAge.Days) days" -Recommendation "ตั้งค่าอย่างน้อย 1 วัน"
        }
        
        # Account lockout threshold
        if ($domainPolicy.LockoutThreshold -le 5 -and $domainPolicy.LockoutThreshold -gt 0) {
            Write-Result "PASS" "PWD006" "Account Lockout Threshold: $($domainPolicy.LockoutThreshold)"
        } else {
            Write-Result "FAIL" "PWD006" "Account Lockout Threshold: $($domainPolicy.LockoutThreshold)" -RiskLevel "Medium" -Recommendation "ตั้งค่าระหว่าง 1-5"
        }
        
        # Lockout duration
        if ($domainPolicy.LockoutDuration.Minutes -ge 15) {
            Write-Result "PASS" "PWD007" "Account Lockout Duration: $($domainPolicy.LockoutDuration.Minutes) minutes"
        } else {
            Write-Result "WARN" "PWD007" "Account Lockout Duration: $($domainPolicy.LockoutDuration.Minutes) minutes" -Recommendation "ตั้งค่าอย่างน้อย 15 นาที"
        }
    }
    catch {
        Write-Result "WARN" "PWD999" "ไม่สามารถตรวจสอบ Domain Password Policy ได้" -Details $_.Exception.Message
    }
}

# 2. Domain Controller Security
function Test-DomainControllerSecurity {
    Write-Host "`n=== 2. การตรวจสอบ Domain Controller Security ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check SYSVOL and NETLOGON shares permissions
        $sysvolPath = "\\$($script:DomainInfo.PDCEmulator)\SYSVOL"
        $netlogonPath = "\\$($script:DomainInfo.PDCEmulator)\NETLOGON"
        
        # SYSVOL access check
        try {
            $sysvolAccess = Test-Path $sysvolPath
            if ($sysvolAccess) {
                Write-Result "PASS" "DC001" "SYSVOL Share: สามารถเข้าถึงได้"
            } else {
                Write-Result "FAIL" "DC001" "SYSVOL Share: ไม่สามารถเข้าถึงได้" -RiskLevel "High" -Recommendation "ตรวจสอบ SYSVOL share permissions"
            }
        } catch {
            Write-Result "WARN" "DC001" "SYSVOL Share: ไม่สามารถตรวจสอบได้"
        }
        
        # NETLOGON access check
        try {
            $netlogonAccess = Test-Path $netlogonPath
            if ($netlogonAccess) {
                Write-Result "PASS" "DC002" "NETLOGON Share: สามารถเข้าถึงได้"
            } else {
                Write-Result "FAIL" "DC002" "NETLOGON Share: ไม่สามารถเข้าถึงได้" -RiskLevel "High" -Recommendation "ตรวจสอบ NETLOGON share permissions"
            }
        } catch {
            Write-Result "WARN" "DC002" "NETLOGON Share: ไม่สามารถตรวจสอบได้"
        }
        
        # Check NTDS service
        $ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
        if ($ntdsService -and $ntdsService.Status -eq "Running") {
            Write-Result "PASS" "DC003" "Active Directory Domain Services: กำลังทำงาน"
        } else {
            Write-Result "FAIL" "DC003" "Active Directory Domain Services: ไม่ทำงาน" -RiskLevel "Critical" -Recommendation "เริ่มใช้งาน NTDS service"
        }
        
        # Check DNS service
        $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
        if ($dnsService -and $dnsService.Status -eq "Running") {
            Write-Result "PASS" "DC004" "DNS Server Service: กำลังทำงาน"
        } else {
            Write-Result "WARN" "DC004" "DNS Server Service: ไม่ทำงาน" -Recommendation "ตรวจสอบ DNS service configuration"
        }
        
        # Check KDC service
        $kdcService = Get-Service -Name "Kdc" -ErrorAction SilentlyContinue
        if ($kdcService -and $kdcService.Status -eq "Running") {
            Write-Result "PASS" "DC005" "Kerberos Key Distribution Center: กำลังทำงาน"
        } else {
            Write-Result "FAIL" "DC005" "Kerberos Key Distribution Center: ไม่ทำงาน" -RiskLevel "High" -Recommendation "เริ่มใช้งาน KDC service"
        }
        
        # Check Time service (W32Time)
        $timeService = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        if ($timeService -and $timeService.Status -eq "Running") {
            Write-Result "PASS" "DC006" "Windows Time Service: กำลังทำงาน"
        } else {
            Write-Result "WARN" "DC006" "Windows Time Service: ไม่ทำงาน" -Recommendation "เริ่มใช้งาน W32Time service สำหรับ time synchronization"
        }
        
        # Check DFS Replication service
        $dfsrService = Get-Service -Name "DFSR" -ErrorAction SilentlyContinue
        if ($dfsrService -and $dfsrService.Status -eq "Running") {
            Write-Result "PASS" "DC007" "DFS Replication Service: กำลังทำงาน"
        } else {
            Write-Result "WARN" "DC007" "DFS Replication Service: ไม่ทำงาน" -Recommendation "ตรวจสอบ DFSR service สำหรับ SYSVOL replication"
        }
    }
    catch {
        Write-Result "WARN" "DC999" "ไม่สามารถตรวจสอบ Domain Controller Security ได้" -Details $_.Exception.Message
    }
}

# 3. Active Directory Users and Groups
function Test-ADUsersAndGroups {
    Write-Host "`n=== 3. การตรวจสอบ AD Users and Groups ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check default Administrator account
        $adminAccount = Get-ADUser -Filter "SID -like '*-500'" -Properties Enabled, PasswordNeverExpires, PasswordLastSet
        if ($adminAccount) {
            if (-not $adminAccount.Enabled) {
                Write-Result "PASS" "USR001" "Built-in Administrator: ปิดใช้งาน"
            } else {
                Write-Result "WARN" "USR001" "Built-in Administrator: เปิดใช้งาน" -Recommendation "ปิดใช้งาน built-in Administrator หากไม่จำเป็น"
            }
            
            if ($adminAccount.PasswordNeverExpires) {
                Write-Result "WARN" "USR002" "Administrator Password Never Expires: เปิดใช้งาน" -Recommendation "ตั้งค่าให้ password มีวันหมดอายุ"
            } else {
                Write-Result "PASS" "USR002" "Administrator Password Never Expires: ปิดใช้งาน"
            }
        }
        
        # Check Guest account
        $guestAccount = Get-ADUser -Filter "SID -like '*-501'" -Properties Enabled
        if ($guestAccount) {
            if (-not $guestAccount.Enabled) {
                Write-Result "PASS" "USR003" "Built-in Guest Account: ปิดใช้งาน"
            } else {
                Write-Result "FAIL" "USR003" "Built-in Guest Account: เปิดใช้งาน" -RiskLevel "High" -Recommendation "ปิดใช้งาน Guest account"
            }
        }
        
        # Check for users with password never expires
        $usersPasswordNeverExpires = Get-ADUser -Filter "PasswordNeverExpires -eq 'True' -and Enabled -eq 'True'" -Properties PasswordNeverExpires | Where-Object { $_.SID -notlike "*-500" -and $_.SID -notlike "*-501" }
        if ($usersPasswordNeverExpires.Count -eq 0) {
            Write-Result "PASS" "USR004" "Users with Password Never Expires: ไม่พบ"
        } else {
            Write-Result "WARN" "USR004" "Users with Password Never Expires: พบ $($usersPasswordNeverExpires.Count) accounts" -Details "$($usersPasswordNeverExpires.Name -join ', ')" -Recommendation "ตั้งค่าให้ password มีวันหมดอายุ"
        }
        
        # Check for users with old passwords
        $oldPasswordUsers = Get-ADUser -Filter "Enabled -eq 'True'" -Properties PasswordLastSet | Where-Object { 
            $_.PasswordLastSet -and (Get-Date) - $_.PasswordLastSet -gt (New-TimeSpan -Days 90) 
        }
        if ($oldPasswordUsers.Count -eq 0) {
            Write-Result "PASS" "USR005" "Users with old passwords (>90 days): ไม่พบ"
        } else {
            Write-Result "WARN" "USR005" "Users with old passwords (>90 days): พบ $($oldPasswordUsers.Count) accounts" -Recommendation "บังคับเปลี่ยน password"
        }
        
        # Check privileged groups
        $privilegedGroups = @(
            "Domain Admins",
            "Enterprise Admins", 
            "Schema Admins",
            "Administrators"
        )
        
        foreach ($groupName in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -Properties Members
                $memberCount = (Get-ADGroupMember -Identity $groupName -Recursive).Count
                
                if ($memberCount -le 5) {
                    Write-Result "PASS" "USR00$($privilegedGroups.IndexOf($groupName) + 6)" "$groupName: $memberCount members"
                } elseif ($memberCount -le 10) {
                    Write-Result "WARN" "USR00$($privilegedGroups.IndexOf($groupName) + 6)" "$groupName: $memberCount members" -Recommendation "ตรวจสอบความจำเป็นของสมาชิกในกลุ่ม"
                } else {
                    Write-Result "FAIL" "USR00$($privilegedGroups.IndexOf($groupName) + 6)" "$groupName: $memberCount members" -RiskLevel "High" -Recommendation "ลดจำนวนสมาชิกในกลุ่มสิทธิพิเศษ"
                }
            }
            catch {
                Write-Result "WARN" "USR00$($privilegedGroups.IndexOf($groupName) + 6)" "ไม่สามารถตรวจสอบ $groupName ได้"
            }
        }
        
        # Check for disabled users in privileged groups
        foreach ($groupName in $privilegedGroups) {
            try {
                $disabledMembers = Get-ADGroupMember -Identity $groupName | Get-ADUser -Properties Enabled | Where-Object { -not $_.Enabled }
                if ($disabledMembers.Count -eq 0) {
                    Write-Result "PASS" "USR01$($privilegedGroups.IndexOf($groupName))" "$groupName disabled members: ไม่พบ"
                } else {
                    Write-Result "WARN" "USR01$($privilegedGroups.IndexOf($groupName))" "$groupName disabled members: พบ $($disabledMembers.Count)" -Details "$($disabledMembers.Name -join ', ')" -Recommendation "เอาสมาชิกที่ปิดใช้งานออกจากกลุ่ม"
                }
            }
            catch {
                Write-Result "WARN" "USR01$($privilegedGroups.IndexOf($groupName))" "ไม่สามารถตรวจสอบ disabled members ใน $groupName ได้"
            }
        }
    }
    catch {
        Write-Result "WARN" "USR999" "ไม่สามารถตรวจสอบ AD Users and Groups ได้" -Details $_.Exception.Message
    }
}

# 4. DNS Security
function Test-DNSSecurity {
    Write-Host "`n=== 4. การตรวจสอบ DNS Security ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check DNS scavenging
        $dnsSettings = Get-DnsServerSetting -All -ErrorAction SilentlyContinue
        if ($dnsSettings) {
            if ($dnsSettings.ScavengingInterval -gt 0) {
                Write-Result "PASS" "DNS001" "DNS Scavenging: เปิดใช้งาน (Interval: $($dnsSettings.ScavengingInterval) hours)"
            } else {
                Write-Result "WARN" "DNS001" "DNS Scavenging: ปิดใช้งาน" -Recommendation "เปิดใช้งาน DNS scavenging เพื่อลบ stale records"
            }
        }
        
        # Check DNS forwarders
        $forwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
        if ($forwarders -and $forwarders.IPAddress.Count -gt 0) {
            Write-Result "PASS" "DNS002" "DNS Forwarders: กำหนดค่าแล้ว ($($forwarders.IPAddress.Count) servers)"
        } else {
            Write-Result "WARN" "DNS002" "DNS Forwarders: ไม่ได้กำหนดค่า" -Recommendation "กำหนด DNS forwarders สำหรับ external queries"
        }
        
        # Check DNS zones for dynamic updates
        $zones = Get-DnsServerZone | Where-Object { $_.ZoneType -eq "Primary" -and $_.IsReverseLookupZone -eq $false }
        $secureUpdateZones = 0
        $insecureUpdateZones = 0
        
        foreach ($zone in $zones) {
            if ($zone.DynamicUpdate -eq "Secure") {
                $secureUpdateZones++
            } elseif ($zone.DynamicUpdate -eq "NonsecureAndSecure") {
                $insecureUpdateZones++
            }
        }
        
        if ($insecureUpdateZones -eq 0) {
            Write-Result "PASS" "DNS003" "DNS Dynamic Updates: ทุก zones ใช้ Secure only"
        } else {
            Write-Result "WARN" "DNS003" "DNS Dynamic Updates: $insecureUpdateZones zones อนุญาต nonsecure updates" -Recommendation "ตั้งค่า dynamic updates เป็น Secure only"
        }
        
        # Check for zone transfers
        foreach ($zone in $zones) {
            $zoneTransfer = Get-DnsServerZoneTransfer -Name $zone.ZoneName -ErrorAction SilentlyContinue
            if ($zoneTransfer) {
                if ($zoneTransfer.SecondaryServers.Count -eq 0 -and $zoneTransfer.NotifyServers.Count -eq 0) {
                    Write-Result "PASS" "DNS004" "Zone Transfer ($($zone.ZoneName)): จำกัดการเข้าถึง"
                } else {
                    Write-Result "WARN" "DNS004" "Zone Transfer ($($zone.ZoneName)): อนุญาตให้ servers อื่น" -Recommendation "จำกัด zone transfer เฉพาะ authorized servers"
                }
            }
        }
        
        # Check DNS cache locking
        if ($dnsSettings -and $dnsSettings.CacheLockingPercent -ge 100) {
            Write-Result "PASS" "DNS005" "DNS Cache Locking: เปิดใช้งาน (100%)"
        } else {
            Write-Result "WARN" "DNS005" "DNS Cache Locking: ไม่ได้ตั้งค่าเต็มที่" -Recommendation "ตั้งค่า Cache Locking เป็น 100%"
        }
    }
    catch {
        Write-Result "WARN" "DNS999" "ไม่สามารถตรวจสอบ DNS Security ได้" -Details $_.Exception.Message
    }
}

# 5. Group Policy Security
function Test-GroupPolicySecurity {
    Write-Host "`n=== 5. การตรวจสอบ Group Policy Security ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check default domain policy
        $defaultDomainPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultDomainPolicy) {
            Write-Result "PASS" "GPO001" "Default Domain Policy: พบ"
            
            # Check if default domain policy has been modified recently
            if ($defaultDomainPolicy.ModificationTime -gt (Get-Date).AddDays(-30)) {
                Write-Result "INFO" "GPO002" "Default Domain Policy: ถูกแก้ไขใน 30 วันที่แล้ว"
            } else {
                Write-Result "INFO" "GPO002" "Default Domain Policy: ไม่ได้แก้ไขใน 30 วันที่แล้ว"
            }
        } else {
            Write-Result "FAIL" "GPO001" "Default Domain Policy: ไม่พบ" -RiskLevel "High" -Recommendation "ตรวจสอบ Default Domain Policy"
        }
        
        # Check default domain controllers policy
        $defaultDCPolicy = Get-GPO -Name "Default Domain Controllers Policy" -ErrorAction SilentlyContinue
        if ($defaultDCPolicy) {
            Write-Result "PASS" "GPO003" "Default Domain Controllers Policy: พบ"
        } else {
            Write-Result "FAIL" "GPO003" "Default Domain Controllers Policy: ไม่พบ" -RiskLevel "High" -Recommendation "ตรวจสอบ Default Domain Controllers Policy"
        }
        
        # Check for GPOs with no links
        $allGPOs = Get-GPO -All
        $unlinkedGPOs = @()
        
        foreach ($gpo in $allGPOs) {
            $links = Get-GPOReport -Guid $gpo.Id -ReportType Xml | Select-String -Pattern "LinksTo"
            if (-not $links) {
                $unlinkedGPOs += $gpo.DisplayName
            }
        }
        
        if ($unlinkedGPOs.Count -eq 0) {
            Write-Result "PASS" "GPO004" "Unlinked GPOs: ไม่พบ"
        } else {
            Write-Result "WARN" "GPO004" "Unlinked GPOs: พบ $($unlinkedGPOs.Count)" -Details "$($unlinkedGPOs -join ', ')" -Recommendation "ลบ GPOs ที่ไม่ได้ใช้งาน"
        }
        
        # Check SYSVOL permissions
        $sysvolPath = "$env:SystemRoot\SYSVOL\domain"
        if (Test-Path $sysvolPath) {
            try {
                $sysvolACL = Get-Acl $sysvolPath
                $authenticatedUsersAccess = $sysvolACL.Access | Where-Object { 
                    $_.IdentityReference -like "*Authenticated Users*" -and 
                    $_.FileSystemRights -like "*FullControl*" 
                }
                
                if (-not $authenticatedUsersAccess) {
                    Write-Result "PASS" "GPO005" "SYSVOL Permissions: ไม่มี FullControl สำหรับ Authenticated Users"
                } else {
                    Write-Result "WARN" "GPO005" "SYSVOL Permissions: Authenticated Users มี FullControl" -Recommendation "ตรวจสอบและจำกัด SYSVOL permissions"
                }
            }
            catch {
                Write-Result "WARN" "GPO005" "ไม่สามารถตรวจสอบ SYSVOL permissions ได้"
            }
        }
        
        if ($CheckGPO) {
            Write-Host "       กำลังตรวจสอบ GPO Settings แบบละเอียด..." -ForegroundColor Cyan
            
            # Detailed GPO analysis (if requested)
            foreach ($gpo in $allGPOs | Select-Object -First 10) {
                try {
                    $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
                    
                    # Check for password policy settings
                    if ($gpoReport -match "MinimumPasswordLength") {
                        Write-Result "INFO" "GPO10$($allGPOs.IndexOf($gpo))" "GPO '$($gpo.DisplayName)': มี Password Policy settings"
                    }
                    
                    # Check for user rights assignments
                    if ($gpoReport -match "UserRightsAssignment") {
                        Write-Result "INFO" "GPO20$($allGPOs.IndexOf($gpo))" "GPO '$($gpo.DisplayName)': มี User Rights assignments"
                    }
                }
                catch {
                    Write-Result "WARN" "GPO10$($allGPOs.IndexOf($gpo))" "ไม่สามารถวิเคราะห์ GPO '$($gpo.DisplayName)' ได้"
                }
            }
        }
    }
    catch {
        Write-Result "WARN" "GPO999" "ไม่สามารถตรวจสอบ Group Policy Security ได้" -Details $_.Exception.Message
    }
}

# 6. Kerberos Security
function Test-KerberosSecurity {
    Write-Host "`n=== 6. การตรวจสอบ Kerberos Security ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check Kerberos encryption types
        $kerbSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ErrorAction SilentlyContinue
        
        if ($kerbSettings -and $kerbSettings.SupportedEncryptionTypes) {
            $encTypes = $kerbSettings.SupportedEncryptionTypes
            # Check if weak encryption is disabled (DES)
            if ($encTypes -band 0x3) {
                Write-Result "WARN" "KRB001" "Kerberos Encryption: DES encryption enabled" -Recommendation "ปิดใช้งาน DES encryption"
            } else {
                Write-Result "PASS" "KRB001" "Kerberos Encryption: DES encryption disabled"
            }
            
            # Check if AES is enabled
            if ($encTypes -band 0x18) {
                Write-Result "PASS" "KRB002" "Kerberos Encryption: AES encryption enabled"
            } else {
                Write-Result "WARN" "KRB002" "Kerberos Encryption: AES encryption not enabled" -Recommendation "เปิดใช้งาน AES encryption"
            }
        } else {
            Write-Result "WARN" "KRB001" "Kerberos Encryption: ไม่สามารถตรวจสอบได้"
        }
        
        # Check for SPNs with weak encryption
        $accounts = Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName, msDS-SupportedEncryptionTypes
        $weakEncryptionAccounts = @()
        
        foreach ($account in $accounts) {
            if ($account.'msDS-SupportedEncryptionTypes' -band 0x3) {
                $weakEncryptionAccounts += $account.Name
            }
        }
        
        if ($weakEncryptionAccounts.Count -eq 0) {
            Write-Result "PASS" "KRB003" "Service Accounts: ไม่มี accounts ที่ใช้ weak encryption"
        } else {
            Write-Result "WARN" "KRB003" "Service Accounts: พบ $($weakEncryptionAccounts.Count) accounts ที่ใช้ weak encryption" -Details "$($weakEncryptionAccounts -join ', ')" -Recommendation "อัพเดท encryption types สำหรับ service accounts"
        }
        
        # Check krbtgt account password age
        $krbtgtAccount = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
        if ($krbtgtAccount.PasswordLastSet) {
            $passwordAge = (Get-Date) - $krbtgtAccount.PasswordLastSet
            if ($passwordAge.Days -le 180) {
                Write-Result "PASS" "KRB004" "KRBTGT Password Age: $($passwordAge.Days) days"
            } else {
                Write-Result "WARN" "KRB004" "KRBTGT Password Age: $($passwordAge.Days) days" -Recommendation "เปลี่ยน krbtgt password (ใช้ Microsoft KRBTGT Reset Script)"
            }
        }
        
        # Check for constrained delegation
        $constrainedDelegationAccounts = Get-ADUser -Filter "msDS-AllowedToDelegateTo -like '*'" -Properties msDS-AllowedToDelegateTo
        if ($constrainedDelegationAccounts.Count -eq 0) {
            Write-Result "PASS" "KRB005" "Constrained Delegation: ไม่พบ accounts"
        } else {
            Write-Result "INFO" "KRB005" "Constrained Delegation: พบ $($constrainedDelegationAccounts.Count) accounts" -Details "$($constrainedDelegationAccounts.Name -join ', ')"
        }
        
        # Check for unconstrained delegation (high risk)
        $unconstrainedDelegationAccounts = Get-ADUser -Filter "TrustedForDelegation -eq 'True'" -Properties TrustedForDelegation
        if ($unconstrainedDelegationAccounts.Count -eq 0) {
            Write-Result "PASS" "KRB006" "Unconstrained Delegation: ไม่พบ accounts"
        } else {
            Write-Result "FAIL" "KRB006" "Unconstrained Delegation: พบ $($unconstrainedDelegationAccounts.Count) accounts" -Details "$($unconstrainedDelegationAccounts.Name -join ', ')" -RiskLevel "High" -Recommendation "เปลี่ยนเป็น constrained delegation"
        }
    }
    catch {
        Write-Result "WARN" "KRB999" "ไม่สามารถตรวจสอบ Kerberos Security ได้" -Details $_.Exception.Message
    }
}

# 7. AD Replication and Backup
function Test-ADReplicationAndBackup {
    Write-Host "`n=== 7. การตรวจสอบ AD Replication and Backup ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check replication status
        $replPartners = Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -ErrorAction SilentlyContinue
        if ($replPartners) {
            $failedReplications = $replPartners | Where-Object { $_.LastReplicationResult -ne 0 }
            if ($failedReplications.Count -eq 0) {
                Write-Result "PASS" "REP001" "AD Replication: ทุกการ replication สำเร็จ"
            } else {
                Write-Result "FAIL" "REP001" "AD Replication: พบ $($failedReplications.Count) replication failures" -RiskLevel "High" -Recommendation "ตรวจสอบและแก้ไข replication errors"
            }
        } else {
            Write-Result "WARN" "REP001" "AD Replication: ไม่สามารถตรวจสอบได้"
        }
        
        # Check SYSVOL replication (DFSR)
        try {
            $dfsrHealth = Get-DfsrState -ErrorAction SilentlyContinue
            if ($dfsrHealth) {
                Write-Result "PASS" "REP002" "SYSVOL Replication (DFSR): กำลังทำงาน"
            } else {
                Write-Result "WARN" "REP002" "SYSVOL Replication (DFSR): ไม่สามารถตรวจสอบได้"
            }
        } catch {
            Write-Result "WARN" "REP002" "SYSVOL Replication (DFSR): ไม่สามารถตรวจสอบได้"
        }
        
        # Check for tombstone lifetime
        $tombstoneLifetime = (Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($script:ForestInfo.RootDomain)" -Properties tombstoneLifetime).tombstoneLifetime
        if ($tombstoneLifetime -ge 180) {
            Write-Result "PASS" "REP003" "Tombstone Lifetime: $tombstoneLifetime days"
        } else {
            Write-Result "WARN" "REP003" "Tombstone Lifetime: $tombstoneLifetime days" -Recommendation "ตั้งค่า tombstone lifetime อย่างน้อย 180 วัน"
        }
        
        # Check backup status (Windows Server Backup)
        $backupService = Get-Service -Name "wbengine" -ErrorAction SilentlyContinue
        if ($backupService) {
            Write-Result "PASS" "BAK001" "Windows Server Backup Service: ติดตั้งแล้ว"
            
            # Check recent backups
            try {
                $backups = Get-WBSummary -ErrorAction SilentlyContinue
                if ($backups -and $backups.LastBackupTime -gt (Get-Date).AddDays(-7)) {
                    Write-Result "PASS" "BAK002" "Recent Backup: พบ backup ใน 7 วันที่แล้ว"
                } else {
                    Write-Result "WARN" "BAK002" "Recent Backup: ไม่พบ backup ใน 7 วันที่แล้ว" -Recommendation "ทำ backup AD อย่างสม่ำเสมอ"
                }
            } catch {
                Write-Result "WARN" "BAK002" "Recent Backup: ไม่สามารถตรวจสอบ backup history ได้"
            }
        } else {
            Write-Result "WARN" "BAK001" "Windows Server Backup Service: ไม่ได้ติดตั้ง" -Recommendation "ติดตั้ง Windows Server Backup feature"
        }
        
        # Check AD database and log files location
        $ntdsSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
        if ($ntdsSettings) {
            $dbPath = $ntdsSettings.'DSA Database file'
            $logPath = $ntdsSettings.'Database log files path'
            
            if ($dbPath -and $logPath) {
                $dbDrive = Split-Path $dbPath -Qualifier
                $logDrive = Split-Path $logPath -Qualifier
                
                if ($dbDrive -ne $logDrive) {
                    Write-Result "PASS" "REP004" "AD Database and Logs: อยู่คนละ drive ($dbDrive, $logDrive)"
                } else {
                    Write-Result "WARN" "REP004" "AD Database and Logs: อยู่ drive เดียวกัน ($dbDrive)" -Recommendation "แยก database และ log files ไปคนละ drive"
                }
            }
        }
    }
    catch {
        Write-Result "WARN" "REP999" "ไม่สามารถตรวจสอบ AD Replication and Backup ได้" -Details $_.Exception.Message
    }
}

# 8. Event Log Monitoring
function Test-EventLogMonitoring {
    Write-Host "`n=== 8. การตรวจสอบ Event Log Monitoring ===" -ForegroundColor $Colors.HEADER
    
    try {
        # Check Security Event Log size
        $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
        if ($securityLog) {
            $logSizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)
            if ($logSizeMB -ge 200) {
                Write-Result "PASS" "LOG001" "Security Log Size: $logSizeMB MB"
            } else {
                Write-Result "WARN" "LOG001" "Security Log Size: $logSizeMB MB" -Recommendation "เพิ่มขนาด Security Event Log เป็นอย่างน้อย 200 MB"
            }
        }
        
        # Check System Event Log size
        $systemLog = Get-WinEvent -ListLog System -ErrorAction SilentlyContinue
        if ($systemLog) {
            $logSizeMB = [math]::Round($systemLog.MaximumSizeInBytes / 1MB, 2)
            if ($logSizeMB -ge 100) {
                Write-Result "PASS" "LOG002" "System Log Size: $logSizeMB MB"
            } else {
                Write-Result "WARN" "LOG002" "System Log Size: $logSizeMB MB" -Recommendation "เพิ่มขนาด System Event Log เป็นอย่างน้อย 100 MB"
            }
        }
        
        # Check for recent critical events in System log
        $criticalEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($criticalEvents) {
            Write-Result "WARN" "LOG003" "Critical System Events: พบ $($criticalEvents.Count) events ใน 7 วันที่แล้ว" -Recommendation "ตรวจสอบ critical events ใน System log"
        } else {
            Write-Result "PASS" "LOG003" "Critical System Events: ไม่พบใน 7 วันที่แล้ว"
        }
        
        # Check for logon failures
        $logonFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($logonFailures) {
            if ($logonFailures.Count -gt 50) {
                Write-Result "WARN" "LOG004" "Logon Failures: พบ $($logonFailures.Count) ครั้ง ใน 24 ชม." -Recommendation "ตรวจสอบ brute force attacks"
            } else {
                Write-Result "PASS" "LOG004" "Logon Failures: $($logonFailures.Count) ครั้ง ใน 24 ชม."
            }
        } else {
            Write-Result "PASS" "LOG004" "Logon Failures: ไม่พบใน 24 ชม."
        }
        
        # Check for privileged group changes
        $privilegedGroupChanges = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4728,4729,4732,4733; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 -ErrorAction SilentlyContinue
        if ($privilegedGroupChanges) {
            Write-Result "INFO" "LOG005" "Privileged Group Changes: พบ $($privilegedGroupChanges.Count) การเปลี่ยนแปลง ใน 7 วัน"
        } else {
            Write-Result "PASS" "LOG005" "Privileged Group Changes: ไม่พบใน 7 วัน"
        }
        
        # Check for account lockouts
        $accountLockouts = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($accountLockouts) {
            Write-Result "WARN" "LOG006" "Account Lockouts: พบ $($accountLockouts.Count) ครั้ง ใน 24 ชม." -Recommendation "ตรวจสอบสาเหตุ account lockouts"
        } else {
            Write-Result "PASS" "LOG006" "Account Lockouts: ไม่พบใน 24 ชม."
        }
        
        # Check Directory Service log
        $dsLog = Get-WinEvent -ListLog "Directory Service" -ErrorAction SilentlyContinue
        if ($dsLog -and $dsLog.IsEnabled) {
            Write-Result "PASS" "LOG007" "Directory Service Log: เปิดใช้งาน"
            
            # Check for DS errors
            $dsErrors = Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Level=2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10 -ErrorAction SilentlyContinue
            if ($dsErrors) {
                Write-Result "WARN" "LOG008" "Directory Service Errors: พบ $($dsErrors.Count) errors ใน 7 วัน" -Recommendation "ตรวจสอบ Directory Service errors"
            } else {
                Write-Result "PASS" "LOG008" "Directory Service Errors: ไม่พบใน 7 วัน"
            }
        } else {
            Write-Result "WARN" "LOG007" "Directory Service Log: ปิดใช้งาน" -Recommendation "เปิดใช้งาน Directory Service logging"
        }
    }
    catch {
        Write-Result "WARN" "LOG999" "ไม่สามารถตรวจสอบ Event Log Monitoring ได้" -Details $_.Exception.Message
    }
}

# Continue with remaining functions...
# [Additional functions for AD Certificate Services, Network Security, etc. would go here]

# Function to generate HTML report (similar to previous script but adapted for AD)
function Export-HTMLReport {
    param(
        [string]$OutputPath = "C:\Temp",
        [string]$Title = "CIS Windows Server AD Security Audit Report"
    )
    
    $htmlFile = Join-Path $OutputPath "CIS_AD_Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    Write-Host "`nสร้างรายงาน HTML..." -ForegroundColor Cyan
    
    # Get system information
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $systemName = $computer.Name
    $osVersion = "$($os.Caption) Build $($os.BuildNumber)"
    $auditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $domain = $script:DomainInfo.DNSRoot
    $forest = $script:ForestInfo.Name
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

    # HTML Template with embedded CSS and JavaScript (similar to previous but with AD-specific styling)
    $htmlTemplate = @"
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        :root {
            --primary-color: #1565c0; --success-color: #2e7d32; --warning-color: #f57c00;
            --danger-color: #d32f2f; --critical-color: #b71c1c; --info-color: #0277bd;
            --bg-light: #f3f4f6; --bg-white: #ffffff; --text-dark: #1a202c;
            --text-gray: #718096; --border-color: #e2e8f0;
            --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: var(--bg-light); color: var(--text-dark); line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, var(--primary-color) 0%, #0d47a1 100%); color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; box-shadow: var(--shadow-lg); }
        .header h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; }
        .header p { font-size: 1.1rem; opacity: 0.9; }
        .ad-badge { background: rgba(255,255,255,0.2); color: white; padding: 0.25rem 0.75rem; border-radius: 15px; font-size: 0.875rem; font-weight: 600; margin-left: 1rem; }
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
        .level-excellent { background: #e8f5e8; color: var(--success-color); }
        .level-good { background: #e3f2fd; color: var(--primary-color); }
        .level-medium { background: #fff3e0; color: var(--warning-color); }
        .level-poor { background: #ffebee; color: var(--danger-color); }
        .progress-bar { width: 100%; height: 20px; background: #e5e7eb; border-radius: 10px; overflow: hidden; margin: 1rem 0; }
        .progress-fill { height: 100%; border-radius: 10px; transition: width 0.5s ease; background: linear-gradient(90deg, var(--danger-color) 0%, var(--warning-color) 50%, var(--success-color) 100%); }
        .filters { background: var(--bg-white); padding: 1.5rem; border-radius: 12px; box-shadow: var(--shadow); margin-bottom: 2rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; }
        .filter-group { display: flex; align-items: center; gap: 0.5rem; }
        .filter-group label { font-weight: 500; color: var(--text-dark); }
        select, input { padding: 0.5rem; border: 1px solid var(--border-color); border-radius: 6px; font-size: 0.875rem; }
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 6px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
        .btn-primary { background: var(--primary-color); color: white; }
        .btn-primary:hover { background: #0d47a1; }
        .results-section { background: var(--bg-white); border-radius: 12px; box-shadow: var(--shadow); overflow: hidden; margin-bottom: 2rem; }
        .section-header { background: #f8fafc; padding: 1.5rem; border-bottom: 1px solid var(--border-color); }
        .section-title { font-size: 1.5rem; font-weight: 700; color: var(--text-dark); }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f8fafc; padding: 1rem; text-align: left; font-weight: 600; color: var(--text-dark); border-bottom: 1px solid var(--border-color); }
        td { padding: 1rem; border-bottom: 1px solid #f1f5f9; word-wrap: break-word; max-width: 300px; }
        tr:hover { background: #f8fafc; }
        .status-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .status-pass { background: #e8f5e8; color: var(--success-color); }
        .status-fail { background: #ffebee; color: var(--danger-color); }
        .status-warn { background: #fff3e0; color: var(--warning-color); }
        .status-info { background: #e3f2fd; color: var(--info-color); }
        .risk-critical { background: #ffebee; color: var(--critical-color); }
        .risk-high { background: #ffebee; color: var(--danger-color); }
        .risk-medium { background: #fff3e0; color: var(--warning-color); }
        .risk-low { background: #e8f5e8; color: var(--success-color); }
        .critical-alert { background: #ffebee; border: 1px solid #ffcdd2; border-radius: 8px; padding: 1rem; margin-bottom: 2rem; }
        .critical-alert h3 { color: var(--danger-color); margin-bottom: 0.5rem; }
        .critical-alert ul { margin-left: 1rem; color: var(--text-dark); }
        .footer { text-align: center; padding: 2rem; color: var(--text-gray); border-top: 1px solid var(--border-color); margin-top: 2rem; }
        @media (max-width: 768px) { .dashboard { grid-template-columns: repeat(2, 1fr); } .filters { flex-direction: column; align-items: stretch; } table { font-size: 0.875rem; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏛️ $Title <span class="ad-badge">Active Directory</span></h1>
            <p>รายงานการตรวจสอบความปลอดภัยระบบ Windows Server AD ตามมาตรฐาน CIS</p>
        </div>

        <div class="system-info">
            <div class="info-card"><h3>Domain Controller</h3><p>$systemName</p></div>
            <div class="info-card"><h3>OS Version</h3><p>$osVersion</p></div>
            <div class="info-card"><h3>Domain</h3><p>$domain</p></div>
            <div class="info-card"><h3>Forest</h3><p>$forest</p></div>
            <div class="info-card"><h3>Audit Date</h3><p>$auditDate</p></div>
        </div>

        <div class="security-score">
            <h2>AD Security Score</h2>
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
            <h3>⚠️ ปัญหาที่ต้องแก้ไขด่วน - Active Directory</h3>
            <ul>$criticalList</ul>
        </div>
"@
    }

    # Add filters and table (similar structure to previous script)
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
                <h2 class="section-title">AD Security Check Results</h2>
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

    # Complete the HTML with footer and JavaScript
    $htmlTemplate += @"
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            <p>Generated by CIS Windows Server AD Security Audit Script | $generationTime</p>
            <p>สำหรับข้อมูลเพิ่มเติม โปรดอ้างอิง CIS Benchmarks และ Microsoft Security best practices</p>
            <p><strong>Created by:</strong> Tananan Maiket | <a href="https://www.facebook.com/neronain.minidev" style="color: #1565c0;">Facebook Profile</a></p>
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
            a.download = 'ad_security_audit_filtered_' + new Date().toISOString().split('T')[0] + '.csv';
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
    
    $csvFile = Join-Path $OutputPath "CIS_AD_Audit_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    Write-Host "`nสร้างรายงาน CSV..." -ForegroundColor Cyan
    
    $script:Results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    
    Write-Host "CSV Report สร้างเสร็จแล้ว: $csvFile" -ForegroundColor Green
}

# Display summary
function Show-Summary {
    Write-Host "`n" + "="*80 -ForegroundColor $Colors.HEADER
    Write-Host "                      สรุปผลการตรวจสอบ AD Security                      " -ForegroundColor $Colors.HEADER
    Write-Host "="*80 -ForegroundColor $Colors.HEADER
    
    $securityScore = 0
    if ($script:TotalChecks -gt 0) {
        $securityScore = [math]::Round(($script:PassCount * 100) / $script:TotalChecks, 1)
    }
    
    Write-Host "🏛️ Active Directory Environment:" -ForegroundColor $Colors.HEADER
    Write-Host "   Domain: $($script:DomainInfo.DNSRoot)" -ForegroundColor Cyan
    Write-Host "   Forest: $($script:ForestInfo.Name)" -ForegroundColor Cyan
    Write-Host "   Domain Functional Level: $($script:DomainInfo.DomainMode)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📊 สถิติการตรวจสอบ:" -ForegroundColor $Colors.HEADER
    Write-Host "   ✅ ผ่าน (PASS): $script:PassCount" -ForegroundColor $Colors.PASS
    Write-Host "   ❌ ไม่ผ่าน (FAIL): $script:FailCount" -ForegroundColor $Colors.FAIL
    Write-Host "   ⚠️  เตือน (WARN): $script:WarnCount" -ForegroundColor $Colors.WARN
    Write-Host "   ℹ️  ข้อมูล (INFO): $script:InfoCount" -ForegroundColor $Colors.INFO
    Write-Host "   📝 รวมทั้งหมด: $script:TotalChecks ข้อ" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "🎯 คะแนนความปลอดภัย AD: $securityScore%" -ForegroundColor $(
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
    Write-Host "="*80 -ForegroundColor $Colors.HEADER
}

# Main execution function
function Main {
    try {
        Initialize-Script
        Get-SystemInfo
        Test-DomainPasswordPolicy
        Test-DomainControllerSecurity
        Test-ADUsersAndGroups
        Test-DNSSecurity
        Test-GroupPolicySecurity
        Test-KerberosSecurity
        Test-ADReplicationAndBackup
        Test-EventLogMonitoring
        
        Show-Summary
        
        # Export reports based on parameters
        if ($ExportHTML -or $ExportResults -or (-not $ExportCSV -and -not $CreateHardening)) {
            Export-HTMLReport -OutputPath $OutputPath -Title $ReportTitle
        }
        
        if ($ExportCSV -or $ExportResults) {
            Export-CSVReport -OutputPath $OutputPath
        }
        
        if ($CreateHardening) {
            # New-ADHardeningScript (would need to be implemented)
            Write-Host "⚠️ AD Hardening Script creation ยังอยู่ในระหว่างการพัฒนา" -ForegroundColor Yellow
        }
        
        Write-Host "`n🎉 การตรวจสอบ AD Security เสร็จสมบูรณ์!" -ForegroundColor Green
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