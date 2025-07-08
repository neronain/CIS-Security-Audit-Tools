#!/bin/bash

# CIS Ubuntu 22.xx-24.xx Security Audit Script
# Version: 1.0
# Author: Security Audit Tool
# Description: ตรวจสอบการตั้งค่าความปลอดภัยของ Ubuntu ตามมาตรฐาน CIS

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

# Function to print colored output
print_result() {
    local status=$1
    local message=$2
    local detail=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
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
            FAIL_COUNT=$((FAIL_COUNT + 1))
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            if [ ! -z "$detail" ]; then
                echo -e "       ${YELLOW}รายละเอียด:${NC} $detail"
            fi
            WARN_COUNT=$((WARN_COUNT + 1))
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
    esac
    
    # Log to file
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$status] $message" >> "$LOG_FILE"
    if [ ! -z "$detail" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [DETAIL] $detail" >> "$LOG_FILE"
    fi
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_result "WARN" "ไม่ได้รันในสิทธิ์ root บางการตรวจสอบอาจไม่สมบูรณ์"
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
        print_result "PASS" "มี partition แยกสำหรับ /tmp"
    else
        print_result "FAIL" "ไม่มี partition แยกสำหรับ /tmp" "แนะนำให้สร้าง partition แยกสำหรับ /tmp"
    fi
    
    # Check /tmp mount options
    tmp_options=$(mount | grep "on /tmp " | sed 's/.*(\(.*\)).*/\1/')
    if echo "$tmp_options" | grep -q "nodev"; then
        print_result "PASS" "/tmp มี nodev option"
    else
        print_result "FAIL" "/tmp ไม่มี nodev option"
    fi
    
    if echo "$tmp_options" | grep -q "nosuid"; then
        print_result "PASS" "/tmp มี nosuid option"
    else
        print_result "FAIL" "/tmp ไม่มี nosuid option"
    fi
    
    if echo "$tmp_options" | grep -q "noexec"; then
        print_result "PASS" "/tmp มี noexec option"
    else
        print_result "FAIL" "/tmp ไม่มี noexec option"
    fi
    
    # Check for /var/log partition
    if mount | grep -q "on /var/log "; then
        print_result "PASS" "มี partition แยกสำหรับ /var/log"
    else
        print_result "WARN" "ไม่มี partition แยกสำหรับ /var/log"
    fi
}

# 2. Services
check_services() {
    echo -e "\n${BLUE}=== 2. การตรวจสอบ Services ===${NC}"
    
    # List of services that should be disabled
    dangerous_services=("xinetd" "inetd" "telnet" "rsh" "rlogin" "rcp" "finger" "talk" "ntalk")
    
    for service in "${dangerous_services[@]}"; do
        if systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
            print_result "FAIL" "Service $service กำลังเปิดใช้งาน" "ควรปิดการใช้งาน service นี้"
        else
            print_result "PASS" "Service $service ไม่ได้เปิดใช้งาน"
        fi
    done
    
    # Check for unnecessary services
    if systemctl is-active avahi-daemon 2>/dev/null | grep -q "active"; then
        print_result "WARN" "Avahi daemon กำลังทำงาน" "พิจารณาปิดหากไม่จำเป็น"
    else
        print_result "PASS" "Avahi daemon ไม่ทำงาน"
    fi
    
    # Check CUPS (printing service)
    if systemctl is-active cups 2>/dev/null | grep -q "active"; then
        print_result "WARN" "CUPS printing service กำลังทำงาน" "ปิดหากไม่ใช้งาน printer"
    else
        print_result "PASS" "CUPS printing service ไม่ทำงาน"
    fi
}

# 3. Network Configuration
check_network_config() {
    echo -e "\n${BLUE}=== 3. การตรวจสอบ Network Configuration ===${NC}"
    
    # Check IP forwarding
    if sysctl net.ipv4.ip_forward | grep -q "= 1"; then
        print_result "WARN" "IP forwarding เปิดใช้งาน" "ปิดหากไม่ใช้เป็น router"
    else
        print_result "PASS" "IP forwarding ปิดใช้งาน"
    fi
    
    # Check if system is acting as a router
    if sysctl net.ipv4.conf.all.send_redirects | grep -q "= 1"; then
        print_result "FAIL" "Send redirects เปิดใช้งาน"
    else
        print_result "PASS" "Send redirects ปิดใช้งาน"
    fi
    
    # Check source routing
    if sysctl net.ipv4.conf.all.accept_source_route | grep -q "= 0"; then
        print_result "PASS" "Source routing ปิดใช้งาน"
    else
        print_result "FAIL" "Source routing เปิดใช้งาน"
    fi
    
    # Check ICMP redirects
    if sysctl net.ipv4.conf.all.accept_redirects | grep -q "= 0"; then
        print_result "PASS" "ICMP redirects ปิดใช้งาน"
    else
        print_result "FAIL" "ICMP redirects เปิดใช้งาน"
    fi
    
    # Check secure ICMP redirects
    if sysctl net.ipv4.conf.all.secure_redirects | grep -q "= 0"; then
        print_result "PASS" "Secure ICMP redirects ปิดใช้งาน"
    else
        print_result "FAIL" "Secure ICMP redirects เปิดใช้งาน"
    fi
    
    # Check reverse path filtering
    if sysctl net.ipv4.conf.all.rp_filter | grep -q "= 1"; then
        print_result "PASS" "Reverse path filtering เปิดใช้งาน"
    else
        print_result "FAIL" "Reverse path filtering ปิดใช้งาน"
    fi
}

# 4. Logging and Auditing
check_logging_audit() {
    echo -e "\n${BLUE}=== 4. การตรวจสอบ Logging และ Auditing ===${NC}"
    
    # Check rsyslog
    if systemctl is-active rsyslog 2>/dev/null | grep -q "active"; then
        print_result "PASS" "rsyslog service ทำงานอยู่"
    else
        print_result "FAIL" "rsyslog service ไม่ทำงาน"
    fi
    
    # Check auditd
    if systemctl is-active auditd 2>/dev/null | grep -q "active"; then
        print_result "PASS" "auditd service ทำงานอยู่"
    else
        print_result "WARN" "auditd service ไม่ทำงาน" "แนะนำให้ติดตั้งและเปิดใช้งาน auditd"
    fi
    
    # Check log file permissions
    if [ -f /var/log/syslog ]; then
        syslog_perm=$(stat -c %a /var/log/syslog)
        if [ "$syslog_perm" = "640" ] || [ "$syslog_perm" = "600" ]; then
            print_result "PASS" "สิทธิ์ /var/log/syslog ถูกต้อง ($syslog_perm)"
        else
            print_result "WARN" "สิทธิ์ /var/log/syslog อาจไม่เหมาะสม ($syslog_perm)"
        fi
    fi
    
    # Check logrotate
    if [ -f /etc/logrotate.conf ]; then
        print_result "PASS" "มีการกำหนดค่า logrotate"
    else
        print_result "WARN" "ไม่พบการกำหนดค่า logrotate"
    fi
}

# 5. Access, Authentication and Authorization
check_access_auth() {
    echo -e "\n${BLUE}=== 5. การตรวจสอบ Access, Authentication และ Authorization ===${NC}"
    
    # Check password policy
    if [ -f /etc/login.defs ]; then
        pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        if [ ! -z "$pass_max_days" ] && [ "$pass_max_days" -le 90 ]; then
            print_result "PASS" "PASS_MAX_DAYS ตั้งค่าเหมาะสม ($pass_max_days วัน)"
        else
            print_result "WARN" "PASS_MAX_DAYS อาจตั้งค่าไม่เหมาะสม ($pass_max_days วัน)"
        fi
        
        pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
        if [ ! -z "$pass_min_days" ] && [ "$pass_min_days" -ge 7 ]; then
            print_result "PASS" "PASS_MIN_DAYS ตั้งค่าเหมาะสม ($pass_min_days วัน)"
        else
            print_result "WARN" "PASS_MIN_DAYS อาจตั้งค่าไม่เหมาะสม ($pass_min_days วัน)"
        fi
    fi
    
    # Check for users with UID 0
    root_users=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
    if [ "$root_users" = "root" ]; then
        print_result "PASS" "มีเพียง root user ที่มี UID 0"
    else
        print_result "FAIL" "พบ user อื่นที่มี UID 0: $root_users"
    fi
    
    # Check for users with empty passwords
    empty_pass_users=$(awk -F: '($2 == "") { print $1 }' /etc/shadow 2>/dev/null)
    if [ -z "$empty_pass_users" ]; then
        print_result "PASS" "ไม่พบ user ที่มี password ว่าง"
    else
        print_result "FAIL" "พบ user ที่มี password ว่าง: $empty_pass_users"
    fi
    
    # Check sudo configuration
    if [ -f /etc/sudoers ]; then
        if grep -q "^Defaults.*requiretty" /etc/sudoers; then
            print_result "PASS" "sudo กำหนดให้ต้องใช้ tty"
        else
            print_result "WARN" "sudo ไม่ได้กำหนดให้ต้องใช้ tty"
        fi
    fi
    
    # Check for accounts that can login
    login_shells="/bin/bash /bin/sh /bin/zsh /bin/fish"
    system_accounts=$(awk -F: '$3 < 1000 && $7 ~ /\/(bash|sh|zsh|fish)$/ { print $1 }' /etc/passwd)
    if [ ! -z "$system_accounts" ]; then
        print_result "WARN" "พบ system account ที่สามารถ login ได้: $system_accounts"
    else
        print_result "PASS" "ไม่พบ system account ที่สามารถ login ได้"
    fi
}

# 6. System Maintenance
check_system_maintenance() {
    echo -e "\n${BLUE}=== 6. การตรวจสอบ System Maintenance ===${NC}"
    
    # Check for world-writable files
    world_writable=$(find / -type f -perm -002 2>/dev/null | head -10)
    if [ -z "$world_writable" ]; then
        print_result "PASS" "ไม่พบไฟล์ที่ world-writable"
    else
        print_result "WARN" "พบไฟล์ที่ world-writable" "ตรวจสอบไฟล์เหล่านี้: $(echo $world_writable | tr '\n' ' ')"
    fi
    
    # Check for unowned files
    unowned_files=$(find / -nouser -o -nogroup 2>/dev/null | head -5)
    if [ -z "$unowned_files" ]; then
        print_result "PASS" "ไม่พบไฟล์ที่ไม่มีเจ้าของ"
    else
        print_result "WARN" "พบไฟล์ที่ไม่มีเจ้าของ" "ตรวจสอบไฟล์เหล่านี้: $(echo $unowned_files | tr '\n' ' ')"
    fi
    
    # Check for SUID/SGID files
    suid_files=$(find / -type f -perm -4000 2>/dev/null | wc -l)
    sgid_files=$(find / -type f -perm -2000 2>/dev/null | wc -l)
    print_result "INFO" "พบไฟล์ SUID: $suid_files ไฟล์, SGID: $sgid_files ไฟล์"
    
    # Check system updates
    if command -v apt &> /dev/null; then
        updates_available=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
        if [ "$updates_available" -eq 0 ]; then
            print_result "PASS" "ระบบอัพเดทแล้ว"
        else
            print_result "WARN" "มี $updates_available packages ที่ต้องอัพเดท"
        fi
    fi
}

# 7. SSH Configuration
check_ssh_config() {
    echo -e "\n${BLUE}=== 7. การตรวจสอบ SSH Configuration ===${NC}"
    
    if [ ! -f /etc/ssh/sshd_config ]; then
        print_result "WARN" "ไม่พบไฟล์ /etc/ssh/sshd_config"
        return
    fi
    
    # Check SSH Protocol
    if grep -q "^Protocol 2" /etc/ssh/sshd_config; then
        print_result "PASS" "SSH ใช้ Protocol 2"
    elif grep -q "^Protocol" /etc/ssh/sshd_config; then
        print_result "FAIL" "SSH ไม่ได้ใช้ Protocol 2"
    else
        print_result "PASS" "SSH ใช้ Protocol 2 (default)"
    fi
    
    # Check PermitRootLogin
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        print_result "PASS" "PermitRootLogin ปิดใช้งาน"
    elif grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        print_result "FAIL" "PermitRootLogin เปิดใช้งาน"
    else
        print_result "WARN" "PermitRootLogin ไม่ได้กำหนดค่า"
    fi
    
    # Check PermitEmptyPasswords
    if grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config; then
        print_result "PASS" "PermitEmptyPasswords ปิดใช้งาน"
    elif grep -q "^PermitEmptyPasswords yes" /etc/ssh/sshd_config; then
        print_result "FAIL" "PermitEmptyPasswords เปิดใช้งาน"
    else
        print_result "PASS" "PermitEmptyPasswords ปิดใช้งาน (default)"
    fi
    
    # Check X11Forwarding
    if grep -q "^X11Forwarding no" /etc/ssh/sshd_config; then
        print_result "PASS" "X11Forwarding ปิดใช้งาน"
    else
        print_result "WARN" "X11Forwarding อาจเปิดใช้งาน"
    fi
    
    # Check MaxAuthTries
    max_auth_tries=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}')
    if [ ! -z "$max_auth_tries" ] && [ "$max_auth_tries" -le 4 ]; then
        print_result "PASS" "MaxAuthTries ตั้งค่าเหมาะสม ($max_auth_tries)"
    else
        print_result "WARN" "MaxAuthTries อาจตั้งค่าไม่เหมาะสม ($max_auth_tries)"
    fi
}

# 8. Firewall Configuration
check_firewall() {
    echo -e "\n${BLUE}=== 8. การตรวจสอบ Firewall Configuration ===${NC}"
    
    # Check UFW
    if command -v ufw &> /dev/null; then
        ufw_status=$(ufw status | head -1)
        if echo "$ufw_status" | grep -q "Status: active"; then
            print_result "PASS" "UFW firewall เปิดใช้งาน"
        else
            print_result "WARN" "UFW firewall ไม่เปิดใช้งาน"
        fi
    else
        print_result "WARN" "ไม่พบ UFW firewall"
    fi
    
    # Check iptables
    if command -v iptables &> /dev/null; then
        iptables_rules=$(iptables -L | wc -l)
        if [ "$iptables_rules" -gt 8 ]; then
            print_result "PASS" "มีการกำหนดค่า iptables rules"
        else
            print_result "WARN" "อาจไม่มีการกำหนดค่า iptables rules"
        fi
    fi
}

# 9. File Permissions
check_file_permissions() {
    echo -e "\n${BLUE}=== 9. การตรวจสอบ File Permissions ===${NC}"
    
    # Critical system files permissions
    declare -A critical_files=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/group"]="644"
        ["/etc/gshadow"]="640"
        ["/etc/ssh/sshd_config"]="600"
    )
    
    for file in "${!critical_files[@]}"; do
        if [ -f "$file" ]; then
            current_perm=$(stat -c %a "$file")
            expected_perm="${critical_files[$file]}"
            if [ "$current_perm" = "$expected_perm" ] || [ "$current_perm" = "600" ]; then
                print_result "PASS" "สิทธิ์ไฟล์ $file ถูกต้อง ($current_perm)"
            else
                print_result "WARN" "สิทธิ์ไฟล์ $file อาจไม่เหมาะสม" "ปัจจุบัน: $current_perm, แนะนำ: $expected_perm"
            fi
        else
            print_result "WARN" "ไม่พบไฟล์ $file"
        fi
    done
    
    # Check /etc/crontab permissions
    if [ -f /etc/crontab ]; then
        crontab_perm=$(stat -c %a /etc/crontab)
        if [ "$crontab_perm" = "600" ]; then
            print_result "PASS" "สิทธิ์ /etc/crontab ถูกต้อง ($crontab_perm)"
        else
            print_result "WARN" "สิทธิ์ /etc/crontab อาจไม่เหมาะสม ($crontab_perm)"
        fi
    fi
}

# 10. Additional Security Checks
check_additional_security() {
    echo -e "\n${BLUE}=== 10. การตรวจสอบความปลอดภัยเพิ่มเติม ===${NC}"
    
    # Check for security updates
    if [ -f /var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_*_InRelease ]; then
        print_result "PASS" "มีการตั้งค่า security repository"
    else
        print_result "WARN" "อาจไม่มีการตั้งค่า security repository"
    fi
    
    # Check AppArmor
    if command -v apparmor_status &> /dev/null; then
        if apparmor_status | grep -q "apparmor module is loaded"; then
            print_result "PASS" "AppArmor เปิดใช้งาน"
        else
            print_result "WARN" "AppArmor ไม่เปิดใช้งาน"
        fi
    else
        print_result "WARN" "ไม่พบ AppArmor"
    fi
    
    # Check for core dumps
    if grep -q "* hard core 0" /etc/security/limits.conf; then
        print_result "PASS" "Core dumps ถูกปิดใช้งาน"
    else
        print_result "WARN" "Core dumps อาจไม่ได้ถูกปิดใช้งาน"
    fi
    
    # Check NTP/Chrony
    if systemctl is-active ntp 2>/dev/null | grep -q "active" || systemctl is-active chrony 2>/dev/null | grep -q "active"; then
        print_result "PASS" "Time synchronization service ทำงานอยู่"
    else
        print_result "WARN" "Time synchronization service ไม่ทำงาน"
    fi
}

# Main function
main() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║             CIS Ubuntu Security Audit Script                  ║${NC}"
    echo -e "${BLUE}║                     Version 1.0                               ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # System information
    ubuntu_version=$(get_ubuntu_version)
    print_result "INFO" "Ubuntu Version: $ubuntu_version"
    print_result "INFO" "Hostname: $(hostname)"
    print_result "INFO" "Kernel: $(uname -r)"
    print_result "INFO" "Log file: $LOG_FILE"
    
    # Check if running as root
    check_root
    
    echo -e "\n${YELLOW}เริ่มการตรวจสอบความปลอดภัย...${NC}\n"
    
    # Run all checks
    check_filesystem_config
    check_services
    check_network_config
    check_logging_audit
    check_access_auth
    check_system_maintenance
    check_ssh_config
    check_firewall
    check_file_permissions
    check_additional_security
    
    # Summary
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
    
    echo -e "\n${GREEN}การตรวจสอบเสร็จสิ้น!${NC}"
}

# Create hardening script
create_hardening_script() {
    cat > /tmp/cis_ubuntu_hardening.sh << 'EOF'
#!/bin/bash
# CIS Ubuntu Hardening Script
# ใช้ความระมัดระวังในการรัน script นี้
# แนะนำให้ backup การตั้งค่าก่อนดำเนินการ

echo "สคริปต์นี้จะทำการ hardening ระบบ Ubuntu ตาม CIS"
echo "กรุณา backup การตั้งค่าปัจจุบันก่อน"
read -p "ต้องการดำเนินการต่อหรือไม่? (y/N): " confirm

if [[ $confirm != [yY] ]]; then
    echo "ยกเลิกการดำเนินการ"
    exit 0
fi

# Example hardening commands (customize as needed)
echo "ปรับปรุงการตั้งค่าระบบ..."

# Disable unused services
systemctl disable avahi-daemon 2>/dev/null
systemctl disable cups 2>/dev/null

# Set file permissions
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow

# Network security settings
echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf

# Apply sysctl settings
sysctl -p

echo "การ hardening เบื้องต้นเสร็จสิ้น"
echo "กรุณาตรวจสอบการตั้งค่าอีกครั้ง"
EOF

    chmod +x /tmp/cis_ubuntu_hardening.sh
    print_result "INFO" "สร้าง hardening script ไว้ที่ /tmp/cis_ubuntu_hardening.sh"
}

# Check if help is requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "CIS Ubuntu Security Audit Script"
    echo "การใช้งาน: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help, -h          แสดงคำอธิบายการใช้งาน"
    echo "  --create-hardening  สร้าง hardening script"
    echo "  --version          แสดงเวอร์ชัน"
    echo ""
    echo "ตัวอย่าง:"
    echo "  sudo $0                    # รันการตรวจสอบทั้งหมด"
    echo "  sudo $0 --create-hardening # สร้าง hardening script"
    exit 0
fi

if [[ "$1" == "--create-hardening" ]]; then
    create_hardening_script
    exit 0
fi

if [[ "$1" == "--version" ]]; then
    echo "CIS Ubuntu Security Audit Script v1.0"
    exit 0
fi

# Run main function
main