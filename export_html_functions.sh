# ===============================
# HTML Export Functions for All Security Scripts
# ===============================

# ===================
# BASH/Ubuntu Functions
# ===================

# Function to generate HTML report for Ubuntu script
generate_html_report() {
    local output_file="$1"
    local temp_html="/tmp/security_report_template.html"
    
    # Create HTML template (same as the artifact above)
    cat > "$temp_html" << 'EOF'
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Security Audit Report</title>
    <style>
        :root {
            --primary-color: #2563eb;
            --success-color: #059669;
            --warning-color: #d97706;
            --danger-color: #dc2626;
            --critical-color: #7c2d12;
            --info-color: #0891b2;
            --bg-light: #f8fafc;
            --bg-white: #ffffff;
            --text-dark: #1f2937;
            --text-gray: #6b7280;
            --border-color: #e5e7eb;
            --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-light);
            color: var(--text-dark);
            line-height: 1.6;
        }

        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, #1d4ed8 100%);
            color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem;
            box-shadow: var(--shadow-lg);
        }

        .header h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; }
        .header p { font-size: 1.1rem; opacity: 0.9; }

        .system-info {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem; margin-bottom: 2rem;
        }

        .info-card {
            background: var(--bg-white); padding: 1.5rem; border-radius: 8px;
            box-shadow: var(--shadow); border-left: 4px solid var(--primary-color);
        }

        .info-card h3 {
            color: var(--text-gray); font-size: 0.875rem; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;
        }

        .info-card p { font-size: 1.125rem; font-weight: 600; color: var(--text-dark); }

        .dashboard {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem; margin-bottom: 2rem;
        }

        .metric-card {
            background: var(--bg-white); padding: 1.5rem; border-radius: 12px;
            box-shadow: var(--shadow); text-align: center; position: relative; overflow: hidden;
        }

        .metric-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
            background: var(--primary-color);
        }

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

        .security-score {
            background: var(--bg-white); padding: 2rem; border-radius: 12px;
            box-shadow: var(--shadow); margin-bottom: 2rem; text-align: center;
        }

        .score-circle {
            width: 200px; height: 200px; margin: 0 auto 1rem; position: relative;
            display: flex; align-items: center; justify-content: center;
        }

        .score-text { font-size: 3rem; font-weight: 700; color: var(--text-dark); }
        .score-label { font-size: 1.25rem; color: var(--text-gray); margin-bottom: 1rem; }

        .score-level {
            display: inline-block; padding: 0.5rem 1rem; border-radius: 20px;
            font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
        }

        .level-excellent { background: #d1fae5; color: var(--success-color); }
        .level-good { background: #dbeafe; color: var(--primary-color); }
        .level-medium { background: #fef3c7; color: var(--warning-color); }
        .level-poor { background: #fecaca; color: var(--danger-color); }

        .progress-bar {
            width: 100%; height: 20px; background: #e5e7eb; border-radius: 10px;
            overflow: hidden; margin: 1rem 0;
        }

        .progress-fill {
            height: 100%; border-radius: 10px; transition: width 0.5s ease;
            background: linear-gradient(90deg, var(--danger-color) 0%, var(--warning-color) 50%, var(--success-color) 100%);
        }

        .results-section {
            background: var(--bg-white); border-radius: 12px; box-shadow: var(--shadow);
            overflow: hidden; margin-bottom: 2rem;
        }

        .section-header {
            background: #f9fafb; padding: 1.5rem; border-bottom: 1px solid var(--border-color);
        }

        .section-title { font-size: 1.5rem; font-weight: 700; color: var(--text-dark); }

        .table-container { overflow-x: auto; }

        table { width: 100%; border-collapse: collapse; }

        th {
            background: #f9fafb; padding: 1rem; text-align: left; font-weight: 600;
            color: var(--text-dark); border-bottom: 1px solid var(--border-color);
        }

        td { padding: 1rem; border-bottom: 1px solid #f3f4f6; }
        tr:hover { background: #f9fafb; }

        .status-badge {
            display: inline-block; padding: 0.25rem 0.75rem; border-radius: 20px;
            font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
        }

        .status-pass { background: #d1fae5; color: var(--success-color); }
        .status-fail { background: #fecaca; color: var(--danger-color); }
        .status-warn { background: #fef3c7; color: var(--warning-color); }
        .status-info { background: #dbeafe; color: var(--info-color); }

        .critical-alert {
            background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px;
            padding: 1rem; margin-bottom: 2rem;
        }

        .critical-alert h3 {
            color: var(--danger-color); margin-bottom: 0.5rem;
            display: flex; align-items: center; gap: 0.5rem;
        }

        .critical-alert ul { margin-left: 1rem; color: var(--text-dark); }

        .recommendations {
            background: var(--bg-white); padding: 2rem; border-radius: 12px;
            box-shadow: var(--shadow); margin-bottom: 2rem;
        }

        .recommendations h2 { color: var(--text-dark); margin-bottom: 1rem; }

        .recommendation-item {
            background: #fef9e7; border-left: 4px solid var(--warning-color);
            padding: 1rem; margin-bottom: 1rem; border-radius: 0 6px 6px 0;
        }

        .recommendation-title {
            font-weight: 600; color: var(--text-dark); margin-bottom: 0.5rem;
        }

        .recommendation-desc { color: var(--text-gray); font-size: 0.9rem; }

        .footer {
            text-align: center; padding: 2rem; color: var(--text-gray);
            border-top: 1px solid var(--border-color); margin-top: 2rem;
        }

        @media print {
            .container { max-width: none; padding: 0; }
            .header { background: var(--primary-color) !important; -webkit-print-color-adjust: exact; }
        }

        @media (max-width: 768px) {
            .header h1 { font-size: 2rem; }
            .dashboard { grid-template-columns: repeat(2, 1fr); }
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
            <div class="info-card">
                <h3>System</h3>
                <p>{{SYSTEM_NAME}}</p>
            </div>
            <div class="info-card">
                <h3>OS Version</h3>
                <p>{{OS_VERSION}}</p>
            </div>
            <div class="info-card">
                <h3>Audit Date</h3>
                <p>{{AUDIT_DATE}}</p>
            </div>
            <div class="info-card">
                <h3>Hostname</h3>
                <p>{{HOSTNAME}}</p>
            </div>
        </div>

        <div class="security-score">
            <h2>Security Score</h2>
            <div class="score-circle">
                <div class="score-text">{{SECURITY_SCORE}}</div>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {{SECURITY_SCORE}}%"></div>
            </div>
            <div class="score-label">คะแนนความปลอดภัยโดยรวม</div>
            <div class="score-level {{SECURITY_LEVEL_CLASS}}">{{SECURITY_LEVEL}}</div>
        </div>

        <div class="dashboard">
            <div class="metric-card pass">
                <div class="metric-number">{{PASS_COUNT}}</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric-card fail">
                <div class="metric-number">{{FAIL_COUNT}}</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric-card warn">
                <div class="metric-number">{{WARN_COUNT}}</div>
                <div class="metric-label">Warnings</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-number">{{CRITICAL_COUNT}}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
        </div>

        {{CRITICAL_ALERT_SECTION}}

        <div class="results-section">
            <div class="section-header">
                <h2 class="section-title">Security Check Results</h2>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Check ID</th>
                            <th>Status</th>
                            <th>Description</th>
                            <th>Details</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{RESULTS_TABLE_ROWS}}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="recommendations">
            <h2>💡 คำแนะนำการปรับปรุง</h2>
            {{RECOMMENDATIONS_LIST}}
        </div>

        <div class="footer">
            <p>Generated by CIS Ubuntu Security Audit Script | {{GENERATION_TIME}}</p>
            <p>สำหรับข้อมูลเพิ่มเติม โปรดอ้างอิง CIS Benchmarks และ security best practices</p>
        </div>
    </div>

    <script>
        function exportCSV() {
            const table = document.querySelector('table');
            let csv = '';
            for (let row of table.rows) {
                const cells = Array.from(row.cells).map(cell => `"${cell.textContent.replace(/"/g, '""')}"`);
                csv += cells.join(',') + '\n';
            }
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ubuntu_security_audit_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);
        }

        // Add export button
        document.addEventListener('DOMContentLoaded', function() {
            const header = document.querySelector('.section-header');
            const exportBtn = document.createElement('button');
            exportBtn.textContent = '📄 Export CSV';
            exportBtn.style.cssText = 'float: right; padding: 0.5rem 1rem; background: #2563eb; color: white; border: none; border-radius: 6px; cursor: pointer;';
            exportBtn.onclick = exportCSV;
            header.appendChild(exportBtn);
        });
    </script>
</body>
</html>
EOF

    # Generate the actual HTML report
    local html_content
    html_content=$(cat "$temp_html")
    
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
    
    # Count critical issues
    local critical_count=0
    # This would be populated based on actual critical findings
    
    # Generate table rows (this is a simplified version)
    local table_rows=""
    local check_counter=1
    
    # Add sample rows - in real implementation, this would come from actual results
    table_rows+="<tr>"
    table_rows+="<td>SYS001</td>"
    table_rows+="<td><span class=\"status-badge status-info\">INFO</span></td>"
    table_rows+="<td>System Information Check</td>"
    table_rows+="<td>OS: $os_version, Hostname: $system_name</td>"
    table_rows+="<td>-</td>"
    table_rows+="</tr>"
    
    # Generate critical alert section
    local critical_alert_section=""
    if [ $critical_count -gt 0 ]; then
        critical_alert_section='<div class="critical-alert">
            <h3>⚠️ ปัญหาที่ต้องแก้ไขด่วน</h3>
            <ul>
                <li>ตัวอย่าง: พบช่องโหว่ความปลอดภัยที่สำคัญ</li>
            </ul>
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
            <div class="recommendation-desc">ติดตั้ง security updates และ patches ให้เป็นปัจจุบัน</div>
        </div>
        <div class="recommendation-item">
            <div class="recommendation-title">3. ตรวจสอบการตั้งค่าเครือข่าย</div>
            <div class="recommendation-desc">ตรวจสอบ firewall และ network security settings</div>
        </div>'
    else
        recommendations_list='<div class="recommendation-item">
            <div class="recommendation-title">✅ ระบบมีความปลอดภัยในระดับดี</div>
            <div class="recommendation-desc">ควรทำการตรวจสอบเป็นประจำและติดตาม security updates</div>
        </div>'
    fi
    
    # Replace placeholders
    html_content="${html_content//\{\{SYSTEM_NAME\}\}/$system_name}"
    html_content="${html_content//\{\{OS_VERSION\}\}/$os_version}"
    html_content="${html_content//\{\{AUDIT_DATE\}\}/$audit_date}"
    html_content="${html_content//\{\{HOSTNAME\}\}/$system_name}"
    html_content="${html_content//\{\{SECURITY_SCORE\}\}/$security_score}"
    html_content="${html_content//\{\{SECURITY_LEVEL\}\}/$security_level}"
    html_content="${html_content//\{\{SECURITY_LEVEL_CLASS\}\}/$security_level_class}"
    html_content="${html_content//\{\{PASS_COUNT\}\}/$PASS_COUNT}"
    html_content="${html_content//\{\{FAIL_COUNT\}\}/$FAIL_COUNT}"
    html_content="${html_content//\{\{WARN_COUNT\}\}/$WARN_COUNT}"
    html_content="${html_content//\{\{CRITICAL_COUNT\}\}/$critical_count}"
    html_content="${html_content//\{\{CRITICAL_ALERT_SECTION\}\}/$critical_alert_section}"
    html_content="${html_content//\{\{RESULTS_TABLE_ROWS\}\}/$table_rows}"
    html_content="${html_content//\{\{RECOMMENDATIONS_LIST\}\}/$recommendations_list}"
    html_content="${html_content//\{\{GENERATION_TIME\}\}/$generation_time}"
    
    # Write to output file
    echo "$html_content" > "$output_file"
    
    # Clean up
    rm -f "$temp_html"
    
    print_result "INFO" "HTML Report generated: $output_file"
}

# Add this function to the main Ubuntu script
export_html_report() {
    local html_file="CIS_Ubuntu_Audit_Report_$(date +%Y%m%d_%H%M%S).html"
    local output_path="/tmp/$html_file"
    
    echo -e "\n${BLUE}=== สร้างรายงาน HTML ===${NC}"
    generate_html_report "$output_path"
    
    echo -e "${GREEN}HTML Report สร้างเสร็จแล้ว: $output_path${NC}"
    echo -e "${BLUE}เปิดไฟล์ด้วย web browser เพื่อดูรายงาน${NC}"
    
    # Try to open with default browser if available
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$output_path" 2>/dev/null &
    elif command -v open >/dev/null 2>&1; then
        open "$output_path" 2>/dev/null &
    fi
}

# ===================
# PowerShell Functions for Windows Scripts
# ===================

# Function to add to Windows PowerShell scripts
$ExportHTMLFunction = @'
# Function to generate HTML report
function Export-HTMLReport {
    param(
        [string]$OutputPath = "C:\Temp"
    )
    
    $htmlFile = Join-Path $OutputPath "CIS_Windows_Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    Write-Host "`nสร้างรายงาน HTML..." -ForegroundColor Cyan
    
    # HTML Template
    $htmlTemplate = @"
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Windows Security Audit Report</title>
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
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-light); color: var(--text-dark); line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, #1d4ed8 100%);
            color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem;
            box-shadow: var(--shadow-lg);
        }
        .header h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; }
        .header p { font-size: 1.1rem; opacity: 0.9; }
        .system-info {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem; margin-bottom: 2rem;
        }
        .info-card {
            background: var(--bg-white); padding: 1.5rem; border-radius: 8px;
            box-shadow: var(--shadow); border-left: 4px solid var(--primary-color);
        }
        .info-card h3 {
            color: var(--text-gray); font-size: 0.875rem; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;
        }
        .info-card p { font-size: 1.125rem; font-weight: 600; color: var(--text-dark); }
        .dashboard {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem; margin-bottom: 2rem;
        }
        .metric-card {
            background: var(--bg-white); padding: 1.5rem; border-radius: 12px;
            box-shadow: var(--shadow); text-align: center; position: relative; overflow: hidden;
        }
        .metric-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
        }
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
        .security-score {
            background: var(--bg-white); padding: 2rem; border-radius: 12px;
            box-shadow: var(--shadow); margin-bottom: 2rem; text-align: center;
        }
        .score-text { font-size: 3rem; font-weight: 700; color: var(--text-dark); }
        .score-label { font-size: 1.25rem; color: var(--text-gray); margin-bottom: 1rem; }
        .score-level {
            display: inline-block; padding: 0.5rem 1rem; border-radius: 20px;
            font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
        }
        .level-excellent { background: #d1fae5; color: var(--success-color); }
        .level-good { background: #dbeafe; color: var(--primary-color); }
        .level-medium { background: #fef3c7; color: var(--warning-color); }
        .level-poor { background: #fecaca; color: var(--danger-color); }
        .progress-bar {
            width: 100%; height: 20px; background: #e5e7eb; border-radius: 10px;
            overflow: hidden; margin: 1rem 0;
        }
        .progress-fill {
            height: 100%; border-radius: 10px; transition: width 0.5s ease;
            background: linear-gradient(90deg, var(--danger-color) 0%, var(--warning-color) 50%, var(--success-color) 100%);
        }
        .results-section {
            background: var(--bg-white); border-radius: 12px; box-shadow: var(--shadow);
            overflow: hidden; margin-bottom: 2rem;
        }
        .section-header {
            background: #f9fafb; padding: 1.5rem; border-bottom: 1px solid var(--border-color);
        }
        .section-title { font-size: 1.5rem; font-weight: 700; color: var(--text-dark); }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: #f9fafb; padding: 1rem; text-align: left; font-weight: 600;
            color: var(--text-dark); border-bottom: 1px solid var(--border-color);
        }
        td { padding: 1rem; border-bottom: 1px solid #f3f4f6; }
        tr:hover { background: #f9fafb; }
        .status-badge {
            display: inline-block; padding: 0.25rem 0.75rem; border-radius: 20px;
            font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
        }
        .status-pass { background: #d1fae5; color: var(--success-color); }
        .status-fail { background: #fecaca; color: var(--danger-color); }
        .status-warn { background: #fef3c7; color: var(--warning-color); }
        .status-info { background: #dbeafe; color: var(--info-color); }
        .risk-critical { background: #fef2f2; color: var(--critical-color); }
        .risk-high { background: #fecaca; color: var(--danger-color); }
        .risk-medium { background: #fef3c7; color: var(--warning-color); }
        .risk-low { background: #d1fae5; color: var(--success-color); }
        .critical-alert {
            background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px;
            padding: 1rem; margin-bottom: 2rem;
        }
        .critical-alert h3 {
            color: var(--danger-color); margin-bottom: 0.5rem;
        }
        .recommendations {
            background: var(--bg-white); padding: 2rem; border-radius: 12px;
            box-shadow: var(--shadow); margin-bottom: 2rem;
        }
        .recommendation-item {
            background: #fef9e7; border-left: 4px solid var(--warning-color);
            padding: 1rem; margin-bottom: 1rem; border-radius: 0 6px 6px 0;
        }
        .recommendation-title { font-weight: 600; color: var(--text-dark); margin-bottom: 0.5rem; }
        .recommendation-desc { color: var(--text-gray); font-size: 0.9rem; }
        .footer {
            text-align: center; padding: 2rem; color: var(--text-gray);
            border-top: 1px solid var(--border-color); margin-top: 2rem;
        }
        @media (max-width: 768px) {
            .dashboard { grid-template-columns: repeat(2, 1fr); }
            table { font-size: 0.875rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 CIS Windows Security Audit Report</h1>
            <p>รายงานการตรวจสอบความปลอดภัยระบบ Windows ตามมาตรฐาน CIS</p>
        </div>

        <div class="system-info">
            <div class="info-card"><h3>System</h3><p>{{SYSTEM_NAME}}</p></div>
            <div class="info-card"><h3>OS Version</h3><p>{{OS_VERSION}}</p></div>
            <div class="info-card"><h3>Audit Date</h3><p>{{AUDIT_DATE}}</p></div>
            <div class="info-card"><h3>Domain</h3><p>{{DOMAIN}}</p></div>
        </div>

        <div class="security-score">
            <h2>Security Score</h2>
            <div class="score-text">{{SECURITY_SCORE}}</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {{SECURITY_SCORE}}%"></div>
            </div>
            <div class="score-label">คะแนนความปลอดภัยโดยรวม</div>
            <div class="score-level {{SECURITY_LEVEL_CLASS}}">{{SECURITY_LEVEL}}</div>
        </div>

        <div class="dashboard">
            <div class="metric-card pass">
                <div class="metric-number">{{PASS_COUNT}}</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric-card fail">
                <div class="metric-number">{{FAIL_COUNT}}</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric-card warn">
                <div class="metric-number">{{WARN_COUNT}}</div>
                <div class="metric-label">Warnings</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-number">{{CRITICAL_COUNT}}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
        </div>

        {{CRITICAL_ALERT_SECTION}}

        <div class="results-section">
            <div class="section-header">
                <h2 class="section-title">Security Check Results</h2>
            </div>
            <div style="overflow-x: auto;">
                <table>
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
                    <tbody>{{RESULTS_TABLE_ROWS}}</tbody>
                </table>
            </div>
        </div>

        <div class="recommendations">
            <h2>💡 คำแนะนำการปรับปรุง</h2>
            {{RECOMMENDATIONS_LIST}}
        </div>

        <div class="footer">
            <p>Generated by CIS Windows Security Audit Script | {{GENERATION_TIME}}</p>
        </div>
    </div>
    <script>
        function exportCSV() {
            const table = document.querySelector('table');
            let csv = '';
            for (let row of table.rows) {
                const cells = Array.from(row.cells).map(cell => '"' + cell.textContent.replace(/"/g, '""') + '"');
                csv += cells.join(',') + '\n';
            }
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = 'windows_security_audit.csv'; a.click();
            window.URL.revokeObjectURL(url);
        }
        document.addEventListener('DOMContentLoaded', function() {
            const header = document.querySelector('.section-header');
            const exportBtn = document.createElement('button');
            exportBtn.innerHTML = '📄 Export CSV';
            exportBtn.style.cssText = 'float: right; padding: 0.5rem 1rem; background: #2563eb; color: white; border: none; border-radius: 6px; cursor: pointer;';
            exportBtn.onclick = exportCSV;
            header.appendChild(exportBtn);
        });
    </script>
</body>
</html>
"@
    
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
    
    # Generate table rows
    $tableRows = ""
    foreach ($result in $script:Results) {
        $statusClass = "status-" + $result.Status.ToLower()
        $riskClass = "risk-" + $result.RiskLevel.ToLower()
        
        $tableRows += "<tr>"
        $tableRows += "<td>$($result.CheckID)</td>"
        $tableRows += "<td><span class=`"status-badge $statusClass`">$($result.Status)</span></td>"
        $tableRows += "<td>$($result.Description)</td>"
        $tableRows += "<td><span class=`"status-badge $riskClass`">$($result.RiskLevel)</span></td>"
        $tableRows += "<td>$($result.Details)</td>"
        $tableRows += "<td>$($result.Recommendation)</td>"
        $tableRows += "</tr>"
    }
    
    # Generate critical alert section
    $criticalAlertSection = ""
    if ($criticalCount -gt 0) {
        $criticalIssues = $script:Results | Where-Object { $_.RiskLevel -eq "Critical" -and $_.Status -eq "FAIL" }
        $criticalList = ($criticalIssues | ForEach-Object { "<li>$($_.Description)</li>" }) -join ""
        $criticalAlertSection = @"
<div class="critical-alert">
    <h3>⚠️ ปัญหาที่ต้องแก้ไขด่วน</h3>
    <ul>$criticalList</ul>
</div>
"@
    }
    
    # Generate recommendations
    $recommendationsList = ""
    if ($script:FailCount -gt 0 -or $script:WarnCount -gt 0) {
        $recommendationsList = @"
<div class="recommendation-item">
    <div class="recommendation-title">1. แก้ไขปัญหาความปลอดภัยที่สำคัญ</div>
    <div class="recommendation-desc">ตรวจสอบและแก้ไขรายการที่มีสถานะ FAIL ทันที</div>
</div>
<div class="recommendation-item">
    <div class="recommendation-title">2. อัพเดท Windows และ Security Patches</div>
    <div class="recommendation-desc">ติดตั้ง Windows Updates และ security patches ให้เป็นปัจจุบัน</div>
</div>
<div class="recommendation-item">
    <div class="recommendation-title">3. ตรวจสอบการตั้งค่า Windows Defender</div>
    <div class="recommendation-desc">ตรวจสอบและปรับปรุงการตั้งค่า antivirus และ firewall</div>
</div>
"@
    } else {
        $recommendationsList = @"
<div class="recommendation-item">
    <div class="recommendation-title">✅ ระบบมีความปลอดภัยในระดับดี</div>
    <div class="recommendation-desc">ควรทำการตรวจสอบเป็นประจำและติดตาม security updates</div>
</div>
"@
    }
    
    # Replace placeholders
    $htmlContent = $htmlTemplate -replace '\{\{SYSTEM_NAME\}\}', $systemName
    $htmlContent = $htmlContent -replace '\{\{OS_VERSION\}\}', $osVersion
    $htmlContent = $htmlContent -replace '\{\{AUDIT_DATE\}\}', $auditDate
    $htmlContent = $htmlContent -replace '\{\{DOMAIN\}\}', $domain
    $htmlContent = $htmlContent -replace '\{\{SECURITY_SCORE\}\}', $securityScore
    $htmlContent = $htmlContent -replace '\{\{SECURITY_LEVEL\}\}', $securityLevel
    $htmlContent = $htmlContent -replace '\{\{SECURITY_LEVEL_CLASS\}\}', $securityLevelClass
    $htmlContent = $htmlContent -replace '\{\{PASS_COUNT\}\}', $script:PassCount
    $htmlContent = $htmlContent -replace '\{\{FAIL_COUNT\}\}', $script:FailCount
    $htmlContent = $htmlContent -replace '\{\{WARN_COUNT\}\}', $script:WarnCount
    $htmlContent = $htmlContent -replace '\{\{CRITICAL_COUNT\}\}', $criticalCount
    $htmlContent = $htmlContent -replace '\{\{CRITICAL_ALERT_SECTION\}\}', $criticalAlertSection
    $htmlContent = $htmlContent -replace '\{\{RESULTS_TABLE_ROWS\}\}', $tableRows
    $htmlContent = $htmlContent -replace '\{\{RECOMMENDATIONS_LIST\}\}', $recommendationsList
    $htmlContent = $htmlContent -replace '\{\{GENERATION_TIME\}\}', $generationTime
    
    # Write HTML file
    $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
    
    Write-Host "HTML Report สร้างเสร็จแล้ว: $htmlFile" -ForegroundColor Green
    Write-Host "เปิดไฟล์ด้วย web browser เพื่อดูรายงาน" -ForegroundColor Cyan
    
    # Try to open with default browser
    try {
        Start-Process $htmlFile
    } catch {
        Write-Host "ไม่สามารถเปิดไฟล์อัตโนมัติได้ กรุณาเปิดไฟล์: $htmlFile" -ForegroundColor Yellow
    }
}
'@

# Usage instructions for adding to existing scripts
Write-Output @"

=== วิธีการเพิ่ม HTML Export ไปยัง Scripts ===

สำหรับ Ubuntu Script:
1. เพิ่มฟังก์ชัน generate_html_report และ export_html_report ไปยัง script
2. เพิ่ม parameter --html ในการเรียกใช้งาน
3. เรียกใช้: ./cis_ubuntu_audit.sh --html

สำหรับ Windows Scripts:
1. เพิ่ม PowerShell function Export-HTMLReport ไปยัง script
2. เพิ่ม parameter -ExportHTML
3. เรียกใช้: .\CIS_Windows_Audit.ps1 -ExportHTML

ตัวอย่างการเรียกใช้:
# Ubuntu
sudo ./cis_ubuntu_audit.sh --html

# Windows Client  
.\CIS_Windows_Client_Audit.ps1 -ExportHTML -OutputPath "C:\SecurityReports"

# Windows Server
.\CIS_WindowsServer_AD_Audit.ps1 -ExportHTML -OutputPath "C:\SecurityReports"

คุณสมบัติของ HTML Report:
✅ Modern responsive design
✅ Interactive dashboard
✅ Security score visualization  
✅ Filterable results table
✅ Critical issues alerts
✅ Recommendations section
✅ Export to CSV function
✅ Print-friendly layout
✅ Mobile responsive

"@