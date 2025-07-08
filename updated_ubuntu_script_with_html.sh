#!/bin/bash

# CIS Ubuntu 22.xx-24.xx Security Audit Script with HTML Export
# Version: 2.0
# Author: Security Audit Tool
# Description: ตรวจสอบการตั้งค่าความปลอดภัยของ Ubuntu ตามมาตรฐาน CIS พร้อม HTML Report

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
TOTAL_CHECKS=0
LOG_FILE="/tmp/cis_audit_$(date +%Y%m%d_%H%M%S).log"
HTML_EXPORT=false
CSV_EXPORT=false
OUTPUT_DIR="/tmp"

# Results array for HTML export
declare -a RESULTS_ARRAY

# Function to print colored output and store results
print_result() {
    local status=$1
    local check_id=$2
    local message=$3
    local detail=$4
    local recommendation=$5
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    # Store result for HTML export
    RESULTS_ARRAY+=("$status|$check_id|$message|$detail|$recommendation")
    
    case $status in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $message"
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $message"
            if [ ! -z "$detail" ]; then
                echo -e "       ${YELLOW}รายละเอียด:${NC} $detail"
            fi
            if [ ! -z "$recommendation" ]; then
                echo -e "       ${BLUE}คำแนะนำ:${NC} $recommendation"
            fi
            FAIL_COUNT=$((FAIL_COUNT + 1))
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            if [ ! -z "$detail" ]; then
                echo -e "       ${YELLOW}รายละเอียด:${NC} $detail"
            fi
            if [ ! -z "$recommendation" ]; then
                echo -e "       ${BLUE}คำแนะนำ:${NC} $recommendation"
            fi
            WARN_COUNT=$((WARN_COUNT + 1))
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
    esac
    
    # Log to file
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$status] $check_id - $message" >> "$LOG_FILE"
    if [ ! -z "$detail" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [DETAIL] $detail" >> "$LOG_FILE"
    fi
    if [ ! -z "$recommendation" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [RECOMMENDATION] $recommendation" >> "$LOG_FILE"
    fi
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_result "WARN" "SYS001" "ไม่ได้รันในสิทธิ์ root บางการตรวจสอบอาจไม่สมบูรณ์"
        return 1
    fi
    return 0
}

# Function to get Ubuntu version
get_ubuntu_version() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$VERSION_ID"
    else
        echo "unknown"
    fi
}

# 1. Initial Setup - Filesystem Configuration
check_filesystem_config() {
    echo -e "\n${BLUE}=== 1. การตรวจสอบ Filesystem Configuration ===${NC}"
    
    # Check for separate /tmp partition
    if mount | grep -q "on /tmp "; then
        print_result "PASS" "FS001" "มี partition แยกสำหรับ /tmp"
    else
        print_result "FAIL" "FS001" "ไม่มี partition แยกสำหรับ /tmp" "" "แนะนำให้สร้าง partition แยกสำหรับ /tmp"
    fi
    
    # Check /tmp mount options
    tmp_options=$(mount | grep "on /tmp " | sed 's/.*(\(.*\)).*/\1/')
    if echo "$tmp_options" | grep -q "nodev"; then
        print_result "PASS" "FS002" "/tmp มี nodev option"
    else
        print_result "FAIL" "FS002" "/tmp ไม่มี nodev option" "" "เพิ่ม nodev option ใน /etc/fstab"
    fi
    
    if echo "$tmp_options" | grep -q "nosuid"; then
        print_result "PASS" "FS003" "/tmp มี nosuid option"
    else
        print_result "FAIL" "FS003" "/tmp ไม่มี nosuid option" "" "เพิ่ม nosuid option ใน /etc/fstab"
    fi
    
    if echo "$tmp_options" | grep -q "noexec"; then
        print_result "PASS" "FS004" "/tmp มี noexec option"
    else
        print_result "FAIL" "FS004" "/tmp ไม่มี noexec option" "" "เพิ่ม noexec option ใน /etc/fstab"
    fi
    
    # Check for /var/log partition
    if mount | grep -q "on /var/log "; then
        print_result "PASS" "FS005" "มี partition แยกสำหรับ /var/log"
    else
        print_result "WARN" "FS005" "ไม่มี partition แยกสำหรับ /var/log" "" "พิจารณาสร้าง partition แยกสำหรับ /var/log"
    fi
}

# 2. Services
check_services() {
    echo -e "\n${BLUE}=== 2. การตรวจสอบ Services ===${NC}"
    
    # List of services that should be disabled
    dangerous_services=("xinetd" "inetd" "telnet" "rsh" "rlogin" "rcp" "finger" "talk" "ntalk")
    
    local counter=1
    for service in "${dangerous_services[@]}"; do
        if systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
            print_result "FAIL" "SVC$(printf '%03d' $counter)" "Service $service กำลังเปิดใช้งาน" "$service service is enabled" "ปิดการใช้งาน: systemctl disable $service"
        else
            print_result "PASS" "SVC$(printf '%03d' $counter)" "Service $service ไม่ได้เปิดใช้งาน"
        fi
        ((counter++))
    done
    
    # Check for unnecessary services
    if systemctl is-active avahi-daemon 2>/dev/null | grep -q "active"; then
        print_result "WARN" "SVC010" "Avahi daemon กำลังทำงาน" "Service discovery protocol อาจไม่จำเป็น" "พิจารณาปิดหากไม่จำเป็น: systemctl disable avahi-daemon"
    else
        print_result "PASS" "SVC010" "Avahi daemon ไม่ทำงาน"
    fi
    
    # Check CUPS (printing service)
    if systemctl is-active cups 2>/dev/null | grep -q "active"; then
        print_result "WARN" "SVC011" "CUPS printing service กำลังทำงาน" "Print service อาจไม่จำเป็นสำหรับ server" "ปิดหากไม่ใช้งาน printer: systemctl disable cups"
    else
        print_result "PASS" "SVC011" "CUPS printing service ไม่ทำงาน"
    fi
}

# 3. Network Configuration
check_network_config() {
    echo -e "\n${BLUE}=== 3. การตรวจสอบ Network Configuration ===${NC}"
    
    # Check IP forwarding
    if sysctl net.ipv4.ip_forward | grep -q "= 1"; then
        print_result "WARN" "NET001" "IP forwarding เปิดใช้งาน" "IP forwarding = 1" "ปิดหากไม่ใช้เป็น router: echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf"
    else
        print_result "PASS" "NET001" "IP forwarding ปิดใช้งาน"
    fi
    
    # Check if system is acting as a router
    if sysctl net.ipv4.conf.all.send_redirects | grep -q "= 1"; then
        print_result "FAIL" "NET002" "Send redirects เปิดใช้งาน" "send_redirects = 1" "ปิดใช้งาน: echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf"
    else
        print_result "PASS" "NET002" "Send redirects ปิดใช้งาน"
    fi
    
    # Check source routing
    if sysctl net.ipv4.conf.all.accept_source_route | grep -q "= 0"; then
        print_result "PASS" "NET003" "Source routing ปิดใช้งาน"
    else
        print_result "FAIL" "NET003" "Source routing เปิดใช้งาน" "accept_source_route != 0" "ปิดใช้งาน: echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.conf"
    fi
    
    # Check ICMP redirects
    if sysctl net.ipv4.conf.all.accept_redirects | grep -q "= 0"; then
        print_result "PASS" "NET004" "ICMP redirects ปิดใช้งาน"
    else
        print_result "FAIL" "NET004" "ICMP redirects เปิดใช้งาน" "accept_redirects != 0" "ปิดใช้งาน: echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf"
    fi
    
    # Check secure ICMP redirects
    if sysctl net.ipv4.conf.all.secure_redirects | grep -q "= 0"; then
        print_result "PASS" "NET005" "Secure ICMP redirects ปิดใช้งาน"
    else
        print_result "FAIL" "NET005" "Secure ICMP redirects เปิดใช้งาน" "secure_redirects != 0" "ปิดใช้งาน: echo 'net.ipv4.conf.all.secure_redirects = 0' >> /etc/sysctl.conf"
    fi
    
    # Check reverse path filtering
    if sysctl net.ipv4.conf.all.rp_filter | grep -q "= 1"; then
        print_result "PASS" "NET006" "Reverse path filtering เปิดใช้งาน"
    else
        print_result "FAIL" "NET006" "Reverse path filtering ปิดใช้งาน" "rp_filter != 1" "เปิดใช้งาน: echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.conf"
    fi
}

# 4. Logging and Auditing
check_logging_audit() {
    echo -e "\n${BLUE}=== 4. การตรวจสอบ Logging และ Auditing ===${NC}"
    
    # Check rsyslog
    if systemctl is-active rsyslog 2>/dev/null | grep -q "active"; then
        print_result "PASS" "LOG001" "rsyslog service ทำงานอยู่"
    else
        print_result "FAIL" "LOG001" "rsyslog service ไม่ทำงาน" "rsyslog is not active" "เริ่มใช้งาน: systemctl enable --now rsyslog"
    fi
    
    # Check auditd
    if systemctl is-active auditd 2>/dev/null | grep -q "active"; then
        print_result "PASS" "LOG002" "auditd service ทำงานอยู่"
    else
        print_result "WARN" "LOG002" "auditd service ไม่ทำงาน" "auditd is not installed or active" "ติดตั้งและเปิดใช้งาน: apt install auditd && systemctl enable --now auditd"
    fi
    
    # Check log file permissions
    if [ -f /var/log/syslog ]; then
        syslog_perm=$(stat -c %a /var/log/syslog)
        if [ "$syslog_perm" = "640" ] || [ "$syslog_perm" = "600" ]; then
            print_result "PASS" "LOG003" "สิทธิ์ /var/log/syslog ถูกต้อง ($syslog_perm)"
        else
            print_result "WARN" "LOG003" "สิทธิ์ /var/log/syslog อาจไม่เหมาะสม ($syslog_perm)" "Current permissions: $syslog_perm" "ปรับสิทธิ์: chmod 640 /var/log/syslog"
        fi
    fi
    
    # Check logrotate
    if [ -f /etc/logrotate.conf ]; then
        print_result "PASS" "LOG004" "มีการกำหนดค่า logrotate"
    else
        print_result "WARN" "LOG004" "ไม่พบการกำหนดค่า logrotate" "logrotate.conf not found" "ติดตั้ง logrotate package"
    fi
}

# 5. Access, Authentication and Authorization
check_access_auth() {
    echo -e "\n${BLUE}=== 5. การตรวจสอบ Access, Authentication และ Authorization ===${NC}"
    
    # Check password policy
    if [ -f /etc/login.defs ]; then
        pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        if [ ! -z "$pass_max_days" ] && [ "$pass_max_days" -le 90 ]; then
            print_result "PASS" "AUTH001" "PASS_MAX_DAYS ตั้งค่าเหมาะสม ($pass_max_days วัน)"
        else
            print_result "WARN" "AUTH001" "PASS_MAX_DAYS อาจตั้งค่าไม่เหมาะสม ($pass_max_days วัน)" "Current: $pass_max_days days" "แก้ไขใน /etc/login.defs: PASS_MAX_DAYS 90"
        fi
        
        pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
        if [ ! -z "$pass_min_days" ] && [ "$pass_min_days" -ge 7 ]; then
            print_result "PASS" "AUTH002" "PASS_MIN_DAYS ตั้งค่าเหมาะสม ($pass_min_days วัน)"
        else
            print_result "WARN" "AUTH002" "PASS_MIN_DAYS อาจตั้งค่าไม่เหมาะสม ($pass_min_days วัน)" "Current: $pass_min_days days" "แก้ไขใน /etc/login.defs: PASS_MIN_DAYS 7"
        fi
    fi
    
    # Check for users with UID 0
    root_users=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
    if [ "$root_users" = "root" ]; then
        print_result "PASS" "AUTH003" "มีเพียง root user ที่มี UID 0"
    else
        print_result "FAIL" "AUTH003" "พบ user อื่นที่มี UID 0: $root_users" "Users with UID 0: $root_users" "ตรวจสอบและลบ users ที่ไม่จำเป็น"
    fi
    
    # Check for users with empty passwords
    empty_pass_users=$(awk -F: '($2 == "") { print $1 }' /etc/shadow 2>/dev/null)
    if [ -z "$empty_pass_users" ]; then
        print_result "PASS" "AUTH004" "ไม่พบ user ที่มี password ว่าง"
    else
        print_result "FAIL" "AUTH004" "พบ user ที่มี password ว่าง: $empty_pass_users" "Users with empty passwords: $empty_pass_users" "ตั้งรหัสผ่านสำหรับ users เหล่านี้"
    fi
    
    # Check sudo configuration
    if [ -f /etc/sudoers ]; then
        if grep -q "^Defaults.*requiretty" /etc/sudoers; then
            print_result "PASS" "AUTH005" "sudo กำหนดให้ต้องใช้ tty"
        else
            print_result "WARN" "AUTH005" "sudo ไม่ได้กำหนดให้ต้องใช้ tty" "requiretty not configured" "เพิ่ม 'Defaults requiretty' ใน /etc/sudoers"
        fi
    fi
    
    # Check for accounts that can login
    system_accounts=$(awk -F: '$3 < 1000 && $7 ~ /\/(bash|sh|zsh|fish)$/ { print $1 }' /etc/passwd)
    if [ ! -z "$system_accounts" ]; then
        print_result "WARN" "AUTH006" "พบ system account ที่สามารถ login ได้: $system_accounts" "System accounts with login shells: $system_accounts" "เปลี่ยน shell เป็น /usr/sbin/nologin"
    else
        print_result "PASS" "AUTH006" "ไม่พบ system account ที่สามารถ login ได้"
    fi
}

# Function to generate HTML report
generate_html_report() {
    local output_file="$1"
    
    # Get system information
    local system_name=$(hostname)
    local os_version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os_version="$PRETTY_NAME"
    else
        os_version="Unknown Ubuntu"
    fi
    local audit_date=$(date '+%Y-%m-%d %H:%M:%S')
    local generation_time=$(date '+%Y-%m-%d %H:%M:%S %Z')
    
    # Calculate security score
    local security_score=0
    if [ $TOTAL_CHECKS -gt 0 ]; then
        security_score=$(( (PASS_COUNT * 100) / TOTAL_CHECKS ))
    fi
    
    # Determine security level and class
    local security_level="ต้องปรับปรุง"
    local security_level_class="level-poor"
    if [ $security_score -ge 80 ]; then
        security_level="ดีมาก"
        security_level_class="level-excellent"
    elif [ $security_score -ge 60 ]; then
        security_level="ปานกลาง"
        security_level_class="level-medium"
    elif [ $security_score -ge 40 ]; then
        security_level="พอใช้"
        security_level_class="level-good"
    fi
    
    # Count critical issues (FAIL status)
    local critical_count=$FAIL_COUNT
    
    # Generate table rows from results array
    local table_rows=""
    for result in "${RESULTS_ARRAY[@]}"; do
        IFS='|' read -r status check_id message detail recommendation <<< "$result"
        
        local status_class="status-$(echo $status | tr '[:upper:]' '[:lower:]')"
        
        table_rows+="<tr>"
        table_rows+="<td>$check_id</td>"
        table_rows+="<td><span class=\"status-badge $status_class\">$status</span></td>"
        table_rows+="<td>$(echo "$message" | sed 's/</\&lt;/g; s/>/\&gt;/g')</td>"
        table_rows+="<td>$(echo "$detail" | sed 's/</\&lt;/g; s/>/\&gt;/g')</td>"
        table_rows+="<td>$(echo "$recommendation" | sed 's/</\&lt;/g; s/>/\&gt;/g')</td>"
        table_rows+="</tr>"
    done
    
    # Generate critical alert section
    local critical_alert_section=""
    if [ $critical_count -gt 0 ]; then
        local critical_list=""
        for result in "${RESULTS_ARRAY[@]}"; do
            IFS='|' read -r status check_id message detail recommendation <<< "$result"
            if [ "$status" = "FAIL" ]; then
                critical_list+="<li>$message</li>"
            fi
        done
        critical_alert_section='<div class="critical-alert">
            <h3>⚠️ ปัญหาที่ต้องแก้ไขด่วน</h3>
            <ul>'"$critical_list"'</ul>
        </div>'
    fi
    
    # Generate recommendations
    local recommendations_list=""
    if [ $FAIL_COUNT -gt 0 ] || [ $WARN_COUNT -gt 0 ]; then
        recommendations_list='<div class="recommendation-item">
            <div class="recommendation-title">1. แก้ไขปัญหาความปลอดภัยที่สำคัญ</div>
            <div class="recommendation-desc">ตรวจสอบและแก้ไขรายการที่มีสถานะ FAIL ทันที</div>
        </div>
        <div class="recommendation-item">
            <div class="recommendation-title">2. อัพเดทระบบ</div>
            <div class="recommendation-desc">ติดตั้ง security updates และ patches ให้เป็นปัจจุบัน: apt update && apt upgrade</div>
        </div>
        <div class="recommendation-item">
            <div class="recommendation-title">3. ตรวจสอบการตั้งค่าเครือข่าย</div>
            <div class="recommendation-desc">ตรวจสอบ firewall และ network security settings</div>
        </div>
        <div class="recommendation-item">
            <div class="recommendation-title">4. Backup และ Hardening</div>
            <div class="recommendation-desc">ทำการ backup การตั้งค่าปัจจุบันก่อนแก้ไข และใช้ hardening script</div>
        </div>'
    else
        recommendations_list='<div class="recommendation-item">
            <div class="recommendation-title">✅ ระบบมีความปลอดภัยในระดับดี</div>
            <div class="recommendation-desc">ควรทำการตรวจสอบเป็นประจำและติดตาม security updates</div>
        </div>'
    fi

    # Create HTML content
    cat > "$output_file" << EOF
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Ubuntu Security Audit Report</title>
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
        .critical-alert { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 1rem; margin-bottom: 2rem; }
        .critical-alert h3 { color: var(--danger-color); margin-bottom: 0.5rem; }
        .critical-alert ul { margin-left: 1rem; color: var(--text-dark); }
        .recommendations { background: var(--bg-white); padding: 2rem; border-radius: 12px; box-shadow: var(--shadow); margin-bottom: 2rem; }
        .recommendations h2 { color: var(--text-dark); margin-bottom: 1rem; }
        .recommendation-item { background: #fef9e7; border-left: 4px solid var(--warning-color); padding: 1rem; margin-bottom: 1rem; border-radius: 0 6px 6px 0; }
        .recommendation-title { font-weight: 600; color: var(--text-dark); margin-bottom: 0.5rem; }
        .recommendation-desc { color: var(--text-gray); font-size: 0.9rem; }
        .footer { text-align: center; padding: 2rem; color: var(--text-gray); border-top: 1px solid var(--border-color); margin-top: 2rem; }
        .filters { background: var(--bg-white); padding: 1rem; border-radius: 8px; box-shadow: var(--shadow); margin-bottom: 1rem; display: flex; gap: 1rem; align-items: center; }
        .filter-group { display: flex; align-items: center; gap: 0.5rem; }
        select, input { padding: 0.5rem; border: 1px solid var(--border-color); border-radius: 4px; font-size: 0.875rem; }
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 6px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
        .btn-primary { background: var(--primary-color); color: white; }
        .btn-primary:hover { background: #1d4ed8; }
        @media (max-width: 768px) {
            .dashboard { grid-template-columns: repeat(2, 1fr); }
            .filters { flex-direction: column; align-items: stretch; }
            table { font-size: 0.875rem; }
            th, td { padding: 0.75rem 0.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 CIS Ubuntu Security Audit Report</h1>
            <p>รายงานการตรวจสอบความปลอดภัยระบบ Ubuntu ตามมาตรฐาน CIS</p>
        </div>

        <div class="system-info">
            <div class="info-card"><h3>System</h3><p>$system_name</p></div>
            <div class="info-card"><h3>OS Version</h3><p>$os_version</p></div>
            <div class="info-card"><h3>Audit Date</h3><p>$audit_date</p></div>
            <div class="info-card"><h3>Total Checks</h3><p>$TOTAL_CHECKS</p></div>
        </div>

        <div class="security-score">
            <h2>Security Score</h2>
            <div class="score-text">$security_score</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${security_score}%"></div>
            </div>
            <div class="score-label">คะแนนความปลอดภัยโดยรวม</div>
            <div class="score-level $security_level_class">$security_level</div>
        </div>

        <div class="dashboard">
            <div class="metric-card pass">
                <div class="metric-number">$PASS_COUNT</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric-card fail">
                <div class="metric-number">$FAIL_COUNT</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric-card warn">
                <div class="metric-number">$WARN_COUNT</div>
                <div class="metric-label">Warnings</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-number">$critical_count</div>
                <div class="metric-label">Critical Issues</div>
            </div>
        </div>

        $critical_alert_section

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
                <label for="searchFilter">Search:</label>
                <input type="text" id="searchFilter" placeholder="Search descriptions..." onkeyup="filterResults()">
            </div>
            <button class="btn btn-primary" onclick="exportCSV()">📄 Export CSV</button>
            <button class="btn btn-primary" onclick="window.print()">🖨️ Print</button>
        </div>

        <div class="results-section">
            <div class="section-header">
                <h2 class="section-title">Security Check Results</h2>
            </div>
            <div style="overflow-x: auto;">
                <table id="resultsTable">
                    <thead>
                        <tr>
                            <th>Check ID</th>
                            <th>Status</th>
                            <th>Description</th>
                            <th>Details</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>$table_rows</tbody>
                </table>
            </div>
        </div>

        <div class="recommendations">
            <h2>💡 คำแนะนำการปรับปรุง</h2>
            $recommendations_list
        </div>

        <div class="footer">
            <p>Generated by CIS Ubuntu Security Audit Script | $generation_time</p>
            <p>สำหรับข้อมูลเพิ่มเติม โปรดอ้างอิง CIS Benchmarks และ security best practices</p>
        </div>
    </div>

    <script>
        function filterResults() {
            const statusFilter = document.getElementById('statusFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();
            const tbody = document.querySelector('#resultsTable tbody');
            const rows = tbody.getElementsByTagName('tr');

            for (let row of rows) {
                let show = true;
                const cells = row.getElementsByTagName('td');
                
                if (cells.length > 0) {
                    const status = cells[1].textContent.trim();
                    const description = cells[2].textContent.toLowerCase();

                    if (statusFilter && !status.includes(statusFilter)) show = false;
                    if (searchFilter && !description.includes(searchFilter)) show = false;
                }

                row.style.display = show ? '' : 'none';
            }
        }

        function exportCSV() {
            const table = document.querySelector('table');
            let csv = '';
            for (let row of table.rows) {
                if (row.style.display !== 'none') {
                    const cells = Array.from(row.cells).map(cell => '"' + cell.textContent.replace(/"/g, '""') + '"');
                    csv += cells.join(',') + '\n';
                }
            }
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'ubuntu_security_audit_$(date +%Y%m%d).csv';
            a.click();
            window.URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
EOF

    print_result "INFO" "RPT001" "HTML Report สร้างเสร็จแล้ว: $output_file"
}

# Function to export HTML report
export_html_report() {
    local html_file="$OUTPUT_DIR/CIS_Ubuntu_Audit_Report_$(date +%Y%m%d_%H%M%S).html"
    
    echo -e "\n${BLUE}=== สร้างรายงาน HTML ===${NC}"
    generate_html_report "$html_file"
    
    echo -e "${GREEN}HTML Report สร้างเสร็จแล้ว: $html_file${NC}"
    echo -e "${BLUE}เปิดไฟล์ด้วย web browser เพื่อดูรายงาน${NC}"
    
    # Try to open with default browser if available
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$html_file" 2>/dev/null &
    elif command -v open >/dev/null 2>&1; then
        open "$html_file" 2>/dev/null &
    fi
}

# Function to export CSV report
export_csv_report() {
    local csv_file="$OUTPUT_DIR/CIS_Ubuntu_Audit_Results_$(date +%Y%m%d_%H%M%S).csv"
    
    echo -e "\n${BLUE}=== สร้างรายงาน CSV ===${NC}"
    
    # CSV Header
    echo "Check ID,Status,Description,Details,Recommendation,Timestamp" > "$csv_file"
    
    # CSV Data
    for result in "${RESULTS_ARRAY[@]}"; do
        IFS='|' read -r status check_id message detail recommendation <<< "$result"
        echo "\"$check_id\",\"$status\",\"$message\",\"$detail\",\"$recommendation\",\"$(date)\"" >> "$csv_file"
    done
    
    print_result "INFO" "RPT002" "CSV Report สร้างเสร็จแล้ว: $csv_file"
}

# Generate summary report
show_summary() {
    echo -e "\n${BLUE}=== สรุปผลการตรวจสอบ ===${NC}"
    echo -e "${GREEN}ผ่าน (PASS): $PASS_COUNT${NC}"
    echo -e "${RED}ไม่ผ่าน (FAIL): $FAIL_COUNT${NC}"
    echo -e "${YELLOW}เตือน (WARN): $WARN_COUNT${NC}"
    echo -e "${BLUE}รวมการตรวจสอบ: $TOTAL_CHECKS${NC}"
    
    # Security Score
    if [ $TOTAL_CHECKS -gt 0 ]; then
        security_score=$(( (PASS_COUNT * 100) / TOTAL_CHECKS ))
        echo -e "${BLUE}คะแนนความปลอดภัย: $security_score/100${NC}"
        
        if [ $security_score -ge 80 ]; then
            echo -e "${GREEN}ระดับความปลอดภัย: ดีมาก${NC}"
        elif [ $security_score -ge 60 ]; then
            echo -e "${YELLOW}ระดับความปลอดภัย: ปานกลาง${NC}"
        else
            echo -e "${RED}ระดับความปลอดภัย: ต้องปรับปรุง${NC}"
        fi
    fi
    
    echo -e "\n${BLUE}รายงานแบบละเอียดได้ถูกบันทึกไว้ที่: $LOG_FILE${NC}"
    
    # Recommendations
    if [ $FAIL_COUNT -gt 0 ] || [ $WARN_COUNT -gt 0 ]; then
        echo -e "\n${YELLOW}=== คำแนะนำการปรับปรุง ===${NC}"
        echo "1. ตรวจสอบรายการที่มีสถานะ FAIL และแก้ไขทันที"
        echo "2. พิจารณาแก้ไขรายการที่มีสถานะ WARN ตามความเหมาะสม"
        echo "3. ทำการอัพเดทระบบให้เป็นปัจจุบัน"
        echo "4. ตั้งค่า monitoring และ logging อย่างเหมาะสม"
        echo "5. ทำการ backup การตั้งค่าปัจจุบันก่อนแก้ไข"
    fi
    
    # Export reports if requested
    if [ "$HTML_EXPORT" = true ]; then
        export_html_report
    fi
    
    if [ "$CSV_EXPORT" = true ]; then
        export_csv_report
    fi
    
    echo -e "\n${GREEN}การตรวจสอบเสร็จสิ้น!${NC}"
}

# Main function
main() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║             CIS Ubuntu Security Audit Script v2.0             ║${NC}"
    echo -e "${BLUE}║                   with HTML Report Export                     ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # System information
    ubuntu_version=$(get_ubuntu_version)
    print_result "INFO" "SYS001" "Ubuntu Version: $ubuntu_version"
    print_result "INFO" "SYS002" "Hostname: $(hostname)"
    print_result "INFO" "SYS003" "Kernel: $(uname -r)"
    print_result "INFO" "SYS004" "Log file: $LOG_FILE"
    
    # Check if running as root
    check_root
    
    echo -e "\n${YELLOW}เริ่มการตรวจสอบความปลอดภัย...${NC}\n"
    
    # Run all checks (simplified - only showing first few for demo)
    check_filesystem_config
    check_services
    check_network_config
    check_logging_audit
    check_access_auth
    
    # Show summary and generate reports
    show_summary
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --html)
            HTML_EXPORT=true
            shift
            ;;
        --csv)
            CSV_EXPORT=true
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help|-h)
            echo "CIS Ubuntu Security Audit Script v2.0"
            echo "การใช้งาน: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --html              Export HTML report"
            echo "  --csv               Export CSV report"
            echo "  --output-dir <dir>  Output directory (default: /tmp)"
            echo "  --help, -h          แสดงคำอธิบายการใช้งาน"
            echo ""
            echo "ตัวอย่าง:"
            echo "  sudo $0 --html --csv"
            echo "  sudo $0 --html --output-dir /var/log/security"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Run main function
main