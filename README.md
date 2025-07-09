# 🔐 CIS Security Audit Tools - Complete Deployment Guide 
(นำไปต่อยอดกันได้นะคัรบ ...)

## 📋 ภาพรวม Tools ที่สร้างแล้ว

### 🛠️ **Core Security Audit Scripts**
1. **Ubuntu Linux Script** - `cis_ubuntu_audit_v2.sh`
2. **Windows Client Script** - `CIS_Windows_Client_Audit_v2.ps1`
3. **Windows Server AD Script** - `CIS_WindowsServer_AD_Audit_v2.ps1`
4. **Standalone HTML Generator** - `security_html_generator.py`

### 📊 **Report Formats ที่รองรับ**
- **Console Output** - แสดงผลสีสันตามสถานะ
- **Log Files** - รายละเอียดครบถ้วนพร้อม timestamp
- **CSV Export** - สำหรับ data analysis
- **HTML Report** - Interactive dashboard พร้อม charts และ filters

---

## 🚀 Quick Start Guide

### **Ubuntu/Linux Systems**

```bash
# 1. Download และ setup
wget https://your-server/cis_ubuntu_audit_v2.sh
chmod +x cis_ubuntu_audit_v2.sh

# 2. รันการตรวจสอบพื้นฐาน
sudo ./cis_ubuntu_audit_v2.sh

# 3. รันพร้อม HTML และ CSV export
sudo ./cis_ubuntu_audit_v2.sh --html --csv --output-dir /var/log/security

# 4. รันเฉพาะการตรวจสอบเครือข่าย (custom)
sudo ./cis_ubuntu_audit_v2.sh --checks network,firewall --html

# 5. สร้าง hardening script
sudo ./cis_ubuntu_audit_v2.sh --create-hardening
```

### **Windows Client Systems**

```powershell
# 1. เปิด PowerShell ในสิทธิ์ Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# 2. รันการตรวจสอบพื้นฐาน
.\CIS_Windows_Client_Audit_v2.ps1

# 3. รันพร้อม HTML export
.\CIS_Windows_Client_Audit_v2.ps1 -ExportHTML -OutputPath "C:\SecurityReports"

# 4. รันพร้อม custom title
.\CIS_Windows_Client_Audit_v2.ps1 -ExportHTML -ReportTitle "Workstation Security Audit"

# 5. รันทั้ง HTML และ CSV
.\CIS_Windows_Client_Audit_v2.ps1 -ExportHTML -ExportCSV -OutputPath "D:\AuditReports"
```

### **Windows Server + Active Directory**

```powershell
# 1. ตรวจสอบ prerequisites
Import-Module ActiveDirectory
Import-Module GroupPolicy

# 2. รันการตรวจสอบครบถ้วน
.\CIS_WindowsServer_AD_Audit_v2.ps1 -ExportHTML -DetailedAD

# 3. รันสำหรับ specific domain
.\CIS_WindowsServer_AD_Audit_v2.ps1 -DomainName "contoso.com" -ExportHTML

# 4. รันพร้อมสร้าง hardening script
.\CIS_WindowsServer_AD_Audit_v2.ps1 -ExportHTML -CreateHardening
```

### **Standalone HTML Generator**

```bash
# 1. ติดตั้ง Python dependencies
pip3 install -r requirements.txt

# 2. แปลง CSV เป็น HTML
python3 security_html_generator.py --csv audit_results.csv --output report.html

# 3. แปลงพร้อม custom title
python3 security_html_generator.py \
    --csv windows_audit.csv \
    --output windows_report.html \
    --title "Windows Server Security Report" \
    --subtitle "รายงานการตรวจสอบ Windows Server 2022"

# 4. แปลงพร้อม custom system info
python3 security_html_generator.py \
    --csv audit.csv \
    --output report.html \
    --system-info '{"Environment":"Production","Location":"Bangkok","Owner":"IT Security Team"}'
```

---

## 🏗️ Enterprise Deployment

### **1. การติดตั้งสำหรับองค์กรขนาดใหญ่**

#### **Central Management Server**
```bash
# สร้าง directory structure
mkdir -p /opt/security-audit/{scripts,reports,templates,logs}
cd /opt/security-audit

# Copy scripts
cp cis_ubuntu_audit_v2.sh scripts/
cp security_html_generator.py scripts/
cp *.ps1 scripts/

# ตั้งค่า permissions
chmod +x scripts/*.sh
chmod +x scripts/*.py
chown -R security-team:security-team /opt/security-audit
```

#### **Windows Central Deployment**
```powershell
# สร้าง network share
New-SmbShare -Name "SecurityAudit" -Path "\\server\SecurityAudit" -FullAccess "Domain Admins"

# Copy scripts to share
Copy-Item "*.ps1" "\\server\SecurityAudit\Scripts\"
Copy-Item "templates\*" "\\server\SecurityAudit\Templates\"

# สร้าง GPO สำหรับ deployment
New-GPO -Name "Security Audit Deployment" -Domain "contoso.com"
```

### **2. Automated Scheduling**

#### **Linux Cron Jobs**
```bash
# เพิ่มใน /etc/crontab
# รันทุกวันจันทร์ 6:00 AM
0 6 * * 1 root /opt/security-audit/scripts/cis_ubuntu_audit_v2.sh --html --csv --output-dir /opt/security-audit/reports

# รันทุกวัน 2:00 AM (simplified check)
0 2 * * * root /opt/security-audit/scripts/cis_ubuntu_audit_v2.sh --checks critical --html
```

#### **Windows Scheduled Tasks**
```powershell
# สร้าง scheduled task สำหรับ weekly audit
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\CIS_Windows_Client_Audit_v2.ps1 -ExportHTML -OutputPath C:\SecurityReports"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6AM

$principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Weekly Security Audit" `
    -Action $action -Trigger $trigger -Principal $principal
```

### **3. Integration กับ SIEM/Monitoring**

#### **Log Forwarding Setup**
```bash
# rsyslog configuration
echo 'module(load="imfile")
input(type="imfile"
      File="/opt/security-audit/reports/*.log"
      Tag="security-audit"
      Severity="info"
      Facility="local0")

local0.* @@siem-server:514' >> /etc/rsyslog.d/security-audit.conf

systemctl restart rsyslog
```

#### **PowerShell SIEM Integration**
```powershell
# เพิ่มใน audit script
function Send-ToSIEM {
    param($Results)
    
    $criticalIssues = $Results | Where-Object { $_.Status -eq "FAIL" -and $_.RiskLevel -eq "Critical" }
    
    if ($criticalIssues) {
        $alertData = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Source = $env:COMPUTERNAME
            AlertType = "SecurityAuditFailed"
            CriticalCount = $criticalIssues.Count
            Issues = $criticalIssues | Select-Object CheckID, Description
        } | ConvertTo-Json
        
        Invoke-RestMethod -Uri "https://siem.company.com/api/alerts" `
            -Method POST -Body $alertData -ContentType "application/json"
    }
}
```

---

## 📊 Report Management

### **1. Central Report Repository**

```bash
#!/bin/bash
# collect_reports.sh - สำหรับรวบรวม reports จาก multiple servers

REPORT_SERVER="reports.company.com"
SERVERS=("web1" "web2" "db1" "db2" "dc1" "dc2")

for server in "${SERVERS[@]}"; do
    echo "Collecting reports from $server..."
    
    # Ubuntu servers
    if ssh $server "test -f /tmp/CIS_Ubuntu_Audit_Report_*.html"; then
        scp $server:/tmp/CIS_Ubuntu_Audit_Report_*.html /var/reports/ubuntu/
        scp $server:/tmp/CIS_Ubuntu_Audit_Results_*.csv /var/reports/ubuntu/
    fi
    
    # Windows servers (using PowerShell remoting)
    if ping -c 1 $server > /dev/null; then
        # Copy Windows reports via SMB
        smbclient //$server/c$ -c "cd SecurityReports; mget *.html /var/reports/windows/"
    fi
done

# Generate consolidated report
python3 /opt/scripts/generate_consolidated_report.py --input /var/reports --output /var/www/html/security-dashboard.html
```

### **2. Report Comparison และ Trending**

```python
#!/usr/bin/env python3
# trend_analysis.py

import csv
import json
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import os

def analyze_security_trends(report_directory):
    """วิเคราะห์แนวโน้มความปลอดภัยจาก reports หลายวัน"""
    
    trend_data = []
    
    for filename in os.listdir(report_directory):
        if filename.endswith('.csv'):
            date_str = filename.split('_')[-1].replace('.csv', '')
            try:
                report_date = datetime.strptime(date_str, '%Y%m%d')
                
                with open(os.path.join(report_directory, filename), 'r') as f:
                    reader = csv.DictReader(f)
                    
                    pass_count = sum(1 for row in reader if row['Status'] == 'PASS')
                    fail_count = sum(1 for row in reader if row['Status'] == 'FAIL')
                    total_count = pass_count + fail_count
                    
                    security_score = (pass_count / total_count * 100) if total_count > 0 else 0
                    
                    trend_data.append({
                        'date': report_date,
                        'security_score': security_score,
                        'pass_count': pass_count,
                        'fail_count': fail_count
                    })
            except ValueError:
                continue
    
    # Sort by date
    trend_data.sort(key=lambda x: x['date'])
    
    # Generate trend chart
    dates = [item['date'] for item in trend_data]
    scores = [item['security_score'] for item in trend_data]
    
    plt.figure(figsize=(12, 6))
    plt.plot(dates, scores, marker='o', linewidth=2, markersize=6)
    plt.title('Security Score Trend Analysis')
    plt.xlabel('Date')
    plt.ylabel('Security Score (%)')
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('security_trend.png', dpi=300, bbox_inches='tight')
    
    return trend_data

if __name__ == "__main__":
    trends = analyze_security_trends('/var/reports')
    print(f"Analyzed {len(trends)} reports")
```

---

## 🛡️ Security Best Practices

### **1. Script Security**

```bash
# ตรวจสอบ integrity ของ scripts
sha256sum cis_ubuntu_audit_v2.sh > checksums.txt
sha256sum security_html_generator.py >> checksums.txt

# Verify before running
sha256sum -c checksums.txt
```

### **2. Access Control**

```bash
# Linux file permissions
chmod 750 /opt/security-audit/scripts/*.sh
chmod 640 /opt/security-audit/reports/*
chown security-team:security-team /opt/security-audit -R

# SELinux contexts (if applicable)
setsebool -P httpd_can_network_connect 1
semanage fcontext -a -t httpd_exec_t "/opt/security-audit/scripts(/.*)?"
restorecon -R /opt/security-audit/scripts
```

### **3. Data Protection**

```powershell
# Windows report encryption
$reports = Get-ChildItem "C:\SecurityReports\*.html"
foreach ($report in $reports) {
    # Encrypt sensitive reports
    Protect-CmsMessage -To "CN=Security Team" -Path $report.FullName -OutFile "$($report.FullName).encrypted"
    Remove-Item $report.FullName -Force
}
```

---

## 🚨 Troubleshooting Guide

### **Common Issues และการแก้ไข**

#### **1. Permission Denied**
```bash
# Linux
sudo chown $(whoami):$(whoami) /opt/security-audit -R
sudo chmod +x *.sh

# Windows
# รัน PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### **2. Missing Dependencies**
```bash
# Ubuntu
sudo apt update
sudo apt install -y curl wget python3 python3-pip

# CentOS/RHEL
sudo yum install -y curl wget python3 python3-pip

# Windows - ติดตั้ง RSAT
Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD
```

#### **3. Network Connectivity Issues**
```bash
# Test connectivity
ping -c 4 target-server
telnet target-server 22    # SSH
telnet target-server 3389  # RDP
telnet target-server 5985  # WinRM
```

#### **4. HTML Report ไม่แสดงผล**
```bash
# ตรวจสอบ file permissions
ls -la *.html
chmod 644 *.html

# ตรวจสอบ content encoding
file *.html
head -20 *.html
```

---

## 📈 Performance Optimization

### **1. Large Environment Tuning**

```bash
# Parallel execution สำหรับ multiple servers
#!/bin/bash
servers=("server1" "server2" "server3" "server4")

# Function to run audit on single server
run_audit() {
    local server=$1
    echo "Starting audit on $server"
    ssh $server 'bash -s' < cis_ubuntu_audit_v2.sh --html --output-dir /tmp
    scp $server:/tmp/*_Report_*.html ./reports/$server/
    echo "Completed audit on $server"
}

# Export function for parallel use
export -f run_audit

# Run audits in parallel (max 4 concurrent)
printf '%s\n' "${servers[@]}" | xargs -n 1 -P 4 -I {} bash -c 'run_audit "$@"' _ {}
```

### **2. Report Size Optimization**

```python
# Optimize HTML report size
def compress_html_report(input_file, output_file):
    """ลด size ของ HTML report โดยการลบ whitespace และ minify"""
    
    import re
    
    with open(input_file, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Remove unnecessary whitespace
    html_content = re.sub(r'\s+', ' ', html_content)
    html_content = re.sub(r'>\s+<', '><', html_content)
    
    # Minify CSS
    html_content = re.sub(r'/\*.*?\*/', '', html_content, flags=re.DOTALL)
    html_content = re.sub(r';\s+', ';', html_content)
    html_content = re.sub(r'{\s+', '{', html_content)
    html_content = re.sub(r'\s+}', '}', html_content)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # Calculate compression ratio
    original_size = os.path.getsize(input_file)
    compressed_size = os.path.getsize(output_file)
    ratio = (1 - compressed_size/original_size) * 100
    
    print(f"Compressed: {original_size:,} → {compressed_size:,} bytes ({ratio:.1f}% reduction)")
```

---

## 🔄 Maintenance และ Updates

### **1. Script Version Management**

```bash
#!/bin/bash
# update_scripts.sh

SCRIPT_REPO="https://github.com/company/security-audit-scripts"
LOCAL_PATH="/opt/security-audit/scripts"
BACKUP_PATH="/opt/security-audit/backup/$(date +%Y%m%d)"

# Create backup
mkdir -p $BACKUP_PATH
cp $LOCAL_PATH/* $BACKUP_PATH/

# Download latest versions
cd /tmp
git clone $SCRIPT_REPO security-scripts-latest

# Compare versions
if ! diff -q $LOCAL_PATH/cis_ubuntu_audit_v2.sh security-scripts-latest/cis_ubuntu_audit_v2.sh; then
    echo "Updates available for Ubuntu script"
    cp security-scripts-latest/cis_ubuntu_audit_v2.sh $LOCAL_PATH/
    chmod +x $LOCAL_PATH/cis_ubuntu_audit_v2.sh
fi

# Clean up
rm -rf security-scripts-latest
```

### **2. Database Integration**

```sql
-- สร้าง database สำหรับเก็บ audit results
CREATE TABLE security_audits (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255),
    os_type VARCHAR(50),
    audit_date TIMESTAMP,
    security_score INTEGER,
    pass_count INTEGER,
    fail_count INTEGER,
    warn_count INTEGER,
    critical_count INTEGER,
    report_path VARCHAR(500)
);

CREATE INDEX idx_audit_date ON security_audits(audit_date);
CREATE INDEX idx_hostname ON security_audits(hostname);
```

---

## 📞 Support และ Documentation

### **ติดต่อและขอความช่วยเหลือ**
- **GitHub Issues**: https://github.com/company/security-audit-scripts/issues
- **Internal Wiki**: https://wiki.company.com/security-audit-tools
- **Security Team**: security-team@company.com
- **Emergency**: +66-2-xxx-xxxx (24/7 Security Hotline)

### **Additional Resources**
- 📚 **CIS Benchmarks**: https://www.cisecurity.org/cis-benchmarks/
- 🔧 **Script Documentation**: `/opt/security-audit/docs/`
- 📊 **Report Templates**: `/opt/security-audit/templates/`
- 🚀 **Best Practices Guide**: https://security.company.com/audit-best-practices

---

## ✅ Checklist สำหรับ Deployment

### **Pre-Deployment**
- [ ] ทดสอบ scripts ในสภาพแวดล้อม test
- [ ] ตรวจสอบ dependencies และ permissions
- [ ] เตรียม backup และ rollback plan
- [ ] กำหนด maintenance windows
- [ ] แจ้ง stakeholders

### **Deployment**
- [ ] Deploy scripts ตาม deployment guide
- [ ] ตั้งค่า scheduled tasks/cron jobs
- [ ] ทดสอบ report generation
- [ ] ตรวจสอบ log forwarding
- [ ] Verify monitoring integration

### **Post-Deployment**
- [ ] Monitor initial runs
- [ ] ตรวจสอบ report quality
- [ ] รวบรวม feedback จาก users
- [ ] ปรับปรุง configuration ตามความต้องการ
- [ ] Update documentation

---

**🎉 ยินดีด้วย! คุณได้ติดตั้ง CIS Security Audit Tools เรียบร้อยแล้ว**

*สำหรับคำถามหรือการสนับสนุนเพิ่มเติม โปรดติดต่อ Security Team*

!! DONATE : USDT (ERC20) 0xf254d3ae1aa3d46134c35cb98d20bd89982c156b 
