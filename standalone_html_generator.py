#!/usr/bin/env python3
"""
Standalone HTML Report Generator for CIS Security Audit
Version: 1.0
Author: Security Audit Tool
Description: แปลงไฟล์ CSV จาก security audit เป็น HTML Report ที่สวยงาม

Usage:
    python3 html_generator.py --csv audit_results.csv --output report.html
    python3 html_generator.py --csv results.csv --output report.html --title "Custom Title"
"""

import csv
import json
import argparse
import sys
from datetime import datetime
from pathlib import Path

class SecurityReportGenerator:
    def __init__(self):
        self.html_template = """<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}}</title>
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
        .chart-container {
            background: var(--bg-white); padding: 2rem; border-radius: 12px;
            box-shadow: var(--shadow); margin-bottom: 2rem; text-align: center;
        }
        .chart { width: 100%; height: 300px; margin: 1rem 0; }
        .filters {
            background: var(--bg-white); padding: 1.5rem; border-radius: 12px;
            box-shadow: var(--shadow); margin-bottom: 2rem; display: flex;
            gap: 1rem; flex-wrap: wrap; align-items: center;
        }
        .filter-group { display: flex; align-items: center; gap: 0.5rem; }
        .filter-group label { font-weight: 500; color: var(--text-dark); }
        select, input {
            padding: 0.5rem; border: 1px solid var(--border-color);
            border-radius: 6px; font-size: 0.875rem;
        }
        .btn {
            padding: 0.5rem 1rem; border: none; border-radius: 6px;
            font-weight: 500; cursor: pointer; transition: all 0.2s;
        }
        .btn-primary { background: var(--primary-color); color: white; }
        .btn-primary:hover { background: #1d4ed8; }
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
            position: sticky; top: 0; z-index: 10;
        }
        td { padding: 1rem; border-bottom: 1px solid #f3f4f6; word-wrap: break-word; }
        tr:hover { background: #f9fafb; }
        .status-badge {
            display: inline-block; padding: 0.25rem 0.75rem; border-radius: 20px;
            font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
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
        .recommendation-item:last-child { margin-bottom: 0; }
        .recommendation-title {
            font-weight: 600; color: var(--text-dark); margin-bottom: 0.5rem;
        }
        .recommendation-desc { color: var(--text-gray); font-size: 0.9rem; }
        .footer {
            text-align: center; padding: 2rem; color: var(--text-gray);
            border-top: 1px solid var(--border-color); margin-top: 2rem;
        }
        @media print {
            .filters, .btn { display: none; }
            .container { max-width: none; padding: 0; }
            .header { background: var(--primary-color) !important; -webkit-print-color-adjust: exact; }
        }
        @media (max-width: 768px) {
            .header h1 { font-size: 2rem; }
            .dashboard { grid-template-columns: repeat(2, 1fr); }
            .filters { flex-direction: column; align-items: stretch; }
            .filter-group { justify-content: space-between; }
            table { font-size: 0.875rem; }
            th, td { padding: 0.75rem 0.5rem; }
        }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 {{TITLE}}</h1>
            <p>{{SUBTITLE}}</p>
        </div>

        <div class="system-info">
            {{SYSTEM_INFO}}
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
            {{DASHBOARD_METRICS}}
        </div>

        <div class="chart-container">
            <h2>Security Overview</h2>
            <canvas id="statusChart" class="chart"></canvas>
        </div>

        {{CRITICAL_ALERT_SECTION}}

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
            <button class="btn btn-primary" onclick="exportResults()">📄 Export CSV</button>
            <button class="btn btn-primary" onclick="window.print()">🖨️ Print</button>
        </div>

        <div class="results-section">
            <div class="section-header">
                <h2 class="section-title">Security Check Results</h2>
                <span style="float: right; color: var(--text-gray);">Total: {{TOTAL_CHECKS}} checks</span>
            </div>
            <div class="table-container">
                <table id="resultsTable">
                    <thead>
                        <tr>
                            {{TABLE_HEADERS}}
                        </tr>
                    </thead>
                    <tbody id="resultsBody">
                        {{RESULTS_TABLE_ROWS}}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="recommendations">
            <h2>💡 คำแนะนำการปรับปรุง</h2>
            <div id="recommendationsList">
                {{RECOMMENDATIONS_LIST}}
            </div>
        </div>

        <div class="footer">
            <p>Generated by Security Audit HTML Generator | {{GENERATION_TIME}}</p>
            <p>สำหรับข้อมูลเพิ่มเติม โปรดอ้างอิง CIS Benchmarks และ security best practices</p>
        </div>
    </div>

    <script>
        // Chart data
        const chartData = {{CHART_DATA}};
        
        // Initialize chart
        const ctx = document.getElementById('statusChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Pass', 'Fail', 'Warning', 'Info'],
                datasets: [{
                    data: [chartData.pass, chartData.fail, chartData.warn, chartData.info],
                    backgroundColor: ['#059669', '#dc2626', '#d97706', '#0891b2'],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' },
                    title: { display: true, text: 'Security Check Status Distribution' }
                }
            }
        });

        // Filter function
        function filterResults() {
            const statusFilter = document.getElementById('statusFilter').value;
            const riskFilter = document.getElementById('riskFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();
            const tbody = document.getElementById('resultsBody');
            const rows = tbody.getElementsByTagName('tr');

            let visibleCount = 0;
            for (let row of rows) {
                let show = true;
                const cells = row.getElementsByTagName('td');
                
                if (cells.length > 0) {
                    const status = cells[1].textContent.trim();
                    const description = cells[2].textContent.toLowerCase();
                    const risk = cells.length > 3 ? cells[3].textContent.trim() : '';

                    if (statusFilter && !status.includes(statusFilter)) show = false;
                    if (riskFilter && !risk.includes(riskFilter)) show = false;
                    if (searchFilter && !description.includes(searchFilter)) show = false;
                }

                row.style.display = show ? '' : 'none';
                if (show) visibleCount++;
            }

            // Update section header with visible count
            const sectionTitle = document.querySelector('.section-title');
            const totalSpan = sectionTitle.parentElement.querySelector('span');
            if (totalSpan) {
                totalSpan.textContent = `Showing: ${visibleCount} of {{TOTAL_CHECKS}} checks`;
            }
        }

        // Export function
        function exportResults() {
            const table = document.getElementById('resultsTable');
            const rows = Array.from(table.getElementsByTagName('tr'));
            const visibleRows = rows.filter(row => row.style.display !== 'none');
            
            let csv = '';
            visibleRows.forEach(row => {
                const cells = Array.from(row.getElementsByTagName('td')).concat(Array.from(row.getElementsByTagName('th')));
                const rowData = cells.map(cell => `"${cell.textContent.replace(/"/g, '""')}"`).join(',');
                csv += rowData + '\\n';
            });

            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security_audit_filtered_${new Date().toISOString().split('T')[0]}.csv`;
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
</html>"""

    def parse_csv(self, csv_file_path):
        """Parse CSV file and extract audit results"""
        results = []
        
        try:
            with open(csv_file_path, 'r', encoding='utf-8') as file:
                # Try to detect the delimiter
                sample = file.read(1024)
                file.seek(0)
                
                # Common delimiters
                if ',' in sample:
                    delimiter = ','
                elif ';' in sample:
                    delimiter = ';'
                elif '\t' in sample:
                    delimiter = '\t'
                else:
                    delimiter = ','
                
                reader = csv.DictReader(file, delimiter=delimiter)
                
                # Normalize header names (remove spaces, lowercase)
                fieldnames = [field.strip().lower().replace(' ', '_') for field in reader.fieldnames]
                
                for row in reader:
                    # Normalize the row keys
                    normalized_row = {}
                    for original_key, value in row.items():
                        normalized_key = original_key.strip().lower().replace(' ', '_')
                        normalized_row[normalized_key] = value.strip() if value else ''
                    
                    results.append(normalized_row)
                    
        except Exception as e:
            print(f"❌ Error parsing CSV file: {e}")
            sys.exit(1)
            
        return results, fieldnames

    def calculate_metrics(self, results):
        """Calculate security metrics from results"""
        metrics = {
            'pass': 0,
            'fail': 0,
            'warn': 0,
            'info': 0,
            'total': len(results),
            'critical': 0
        }
        
        for result in results:
            status = result.get('status', '').upper()
            risk_level = result.get('risk_level', result.get('risk', '')).lower()
            
            if status == 'PASS':
                metrics['pass'] += 1
            elif status == 'FAIL':
                metrics['fail'] += 1
                if 'critical' in risk_level:
                    metrics['critical'] += 1
            elif status == 'WARN' or status == 'WARNING':
                metrics['warn'] += 1
            elif status == 'INFO':
                metrics['info'] += 1
        
        # Calculate security score
        if metrics['total'] > 0:
            metrics['security_score'] = round((metrics['pass'] * 100) / metrics['total'], 1)
        else:
            metrics['security_score'] = 0
            
        return metrics

    def get_security_level(self, score):
        """Determine security level based on score"""
        if score >= 85:
            return "ดีเยี่ยม", "level-excellent"
        elif score >= 70:
            return "ดี", "level-good"
        elif score >= 50:
            return "ปานกลาง", "level-medium"
        else:
            return "ต้องปรับปรุง", "level-poor"

    def generate_system_info(self, csv_file_path, custom_info=None):
        """Generate system information cards"""
        file_stat = Path(csv_file_path).stat()
        audit_date = datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        info_cards = []
        
        if custom_info:
            for key, value in custom_info.items():
                info_cards.append(f"""
                <div class="info-card">
                    <h3>{key}</h3>
                    <p>{value}</p>
                </div>
                """)
        else:
            # Default system info
            default_info = {
                'Audit Source': Path(csv_file_path).stem,
                'File Date': audit_date,
                'Report Generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'File Size': f"{file_stat.st_size / 1024:.1f} KB"
            }
            
            for key, value in default_info.items():
                info_cards.append(f"""
                <div class="info-card">
                    <h3>{key}</h3>
                    <p>{value}</p>
                </div>
                """)
        
        return ''.join(info_cards)

    def generate_dashboard_metrics(self, metrics):
        """Generate dashboard metric cards"""
        cards = []
        
        metric_config = [
            ('pass', metrics['pass'], 'Passed'),
            ('fail', metrics['fail'], 'Failed'),
            ('warn', metrics['warn'], 'Warnings'),
            ('critical', metrics['critical'], 'Critical Issues')
        ]
        
        for card_type, count, label in metric_config:
            cards.append(f"""
            <div class="metric-card {card_type}">
                <div class="metric-number">{count}</div>
                <div class="metric-label">{label}</div>
            </div>
            """)
        
        return ''.join(cards)

    def generate_table_content(self, results, fieldnames):
        """Generate table headers and rows"""
        # Map common field names
        field_mapping = {
            'check_id': 'Check ID',
            'status': 'Status',
            'description': 'Description',
            'details': 'Details',
            'recommendation': 'Recommendation',
            'risk_level': 'Risk Level',
            'risk': 'Risk Level',
            'timestamp': 'Timestamp'
        }
        
        # Generate headers
        headers = []
        display_fields = []
        
        for field in fieldnames:
            if field in field_mapping:
                headers.append(f"<th>{field_mapping[field]}</th>")
                display_fields.append(field)
            elif field not in ['timestamp']:  # Skip timestamp by default
                headers.append(f"<th>{field.replace('_', ' ').title()}</th>")
                display_fields.append(field)
        
        # Generate rows
        rows = []
        for result in results:
            row_cells = []
            for field in display_fields:
                value = result.get(field, '')
                
                if field == 'status':
                    status_class = f"status-{value.lower()}" if value else "status-info"
                    cell_content = f'<span class="status-badge {status_class}">{value}</span>'
                elif field in ['risk_level', 'risk'] and value:
                    risk_class = f"risk-{value.lower()}"
                    cell_content = f'<span class="status-badge {risk_class}">{value}</span>'
                else:
                    cell_content = value
                
                row_cells.append(f"<td>{cell_content}</td>")
            
            rows.append(f"<tr>{''.join(row_cells)}</tr>")
        
        return ''.join(headers), ''.join(rows)

    def generate_critical_alert(self, results):
        """Generate critical issues alert section"""
        critical_issues = []
        
        for result in results:
            status = result.get('status', '').upper()
            risk_level = result.get('risk_level', result.get('risk', '')).lower()
            
            if status == 'FAIL' and 'critical' in risk_level:
                description = result.get('description', 'Critical security issue')
                critical_issues.append(f"<li>{description}</li>")
        
        if critical_issues:
            return f"""
            <div class="critical-alert">
                <h3>⚠️ ปัญหาที่ต้องแก้ไขด่วน</h3>
                <ul>{''.join(critical_issues)}</ul>
            </div>
            """
        return ""

    def generate_recommendations(self, metrics):
        """Generate recommendations based on metrics"""
        recommendations = []
        
        if metrics['fail'] > 0:
            recommendations.append("""
            <div class="recommendation-item">
                <div class="recommendation-title">1. แก้ไขปัญหาความปลอดภัยที่สำคัญ</div>
                <div class="recommendation-desc">ตรวจสอบและแก้ไขรายการที่มีสถานะ FAIL ทันที โดยเฉพาะปัญหาระดับ Critical</div>
            </div>
            """)
        
        if metrics['warn'] > 0:
            recommendations.append("""
            <div class="recommendation-item">
                <div class="recommendation-title">2. ปรับปรุงการตั้งค่าที่มีคำเตือน</div>
                <div class="recommendation-desc">พิจารณาแก้ไขรายการที่มีสถานะ WARNING ตามความเหมาะสมของระบบ</div>
            </div>
            """)
        
        recommendations.append("""
        <div class="recommendation-item">
            <div class="recommendation-title">3. อัพเดทระบบเป็นประจำ</div>
            <div class="recommendation-desc">ติดตั้ง security updates และ patches ให้เป็นปัจจุบัน</div>
        </div>
        """)
        
        recommendations.append("""
        <div class="recommendation-item">
            <div class="recommendation-title">4. ทำการตรวจสอบเป็นประจำ</div>
            <div class="recommendation-desc">ตั้งค่า automated security audit และ monitoring เพื่อติดตามสถานะความปลอดภัย</div>
        </div>
        """)
        
        if metrics['security_score'] >= 80:
            recommendations.insert(0, """
            <div class="recommendation-item">
                <div class="recommendation-title">✅ ระบบมีความปลอดภัยในระดับดี</div>
                <div class="recommendation-desc">ควรคงมาตรฐานปัจจุบันและติดตามการปรับปรุงอย่างต่อเนื่อง</div>
            </div>
            """)
        
        return ''.join(recommendations)

    def generate_html_report(self, csv_file_path, output_file, title=None, subtitle=None, custom_info=None):
        """Generate complete HTML report from CSV data"""
        print(f"📊 Parsing CSV file: {csv_file_path}")
        results, fieldnames = self.parse_csv(csv_file_path)
        
        if not results:
            print("❌ No data found in CSV file")
            return False
        
        print(f"✅ Found {len(results)} audit results")
        
        # Calculate metrics
        metrics = self.calculate_metrics(results)
        security_level, security_level_class = self.get_security_level(metrics['security_score'])
        
        # Generate content sections
        system_info = self.generate_system_info(csv_file_path, custom_info)
        dashboard_metrics = self.generate_dashboard_metrics(metrics)
        table_headers, table_rows = self.generate_table_content(results, fieldnames)
        critical_alert = self.generate_critical_alert(results)
        recommendations = self.generate_recommendations(metrics)
        
        # Prepare chart data
        chart_data = {
            'pass': metrics['pass'],
            'fail': metrics['fail'],
            'warn': metrics['warn'],
            'info': metrics['info']
        }
        
        # Replace placeholders in template
        html_content = self.html_template
        replacements = {
            '{{TITLE}}': title or 'CIS Security Audit Report',
            '{{SUBTITLE}}': subtitle or 'รายงานการตรวจสอบความปลอดภัยระบบตามมาตรฐาน CIS',
            '{{SYSTEM_INFO}}': system_info,
            '{{SECURITY_SCORE}}': str(metrics['security_score']),
            '{{SECURITY_LEVEL}}': security_level,
            '{{SECURITY_LEVEL_CLASS}}': security_level_class,
            '{{DASHBOARD_METRICS}}': dashboard_metrics,
            '{{CRITICAL_ALERT_SECTION}}': critical_alert,
            '{{TABLE_HEADERS}}': table_headers,
            '{{RESULTS_TABLE_ROWS}}': table_rows,
            '{{RECOMMENDATIONS_LIST}}': recommendations,
            '{{TOTAL_CHECKS}}': str(metrics['total']),
            '{{CHART_DATA}}': json.dumps(chart_data),
            '{{GENERATION_TIME}}': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
        }
        
        for placeholder, value in replacements.items():
            html_content = html_content.replace(placeholder, value)
        
        # Write HTML file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"✅ HTML report generated successfully: {output_file}")
            
            # Print summary
            print(f"\n📋 Report Summary:")
            print(f"   • Security Score: {metrics['security_score']}/100 ({security_level})")
            print(f"   • Total Checks: {metrics['total']}")
            print(f"   • Passed: {metrics['pass']}")
            print(f"   • Failed: {metrics['fail']}")
            print(f"   • Warnings: {metrics['warn']}")
            print(f"   • Critical Issues: {metrics['critical']}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error writing HTML file: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='Generate beautiful HTML reports from security audit CSV files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 html_generator.py --csv audit_results.csv --output report.html
  python3 html_generator.py --csv results.csv --output report.html --title "Ubuntu Security Audit"
  python3 html_generator.py --csv windows_audit.csv --output windows_report.html --title "Windows Server Audit" --subtitle "รายงานการตรวจสอบ Windows Server"
        """
    )
    
    parser.add_argument('--csv', required=True, help='Path to CSV file containing audit results')
    parser.add_argument('--output', required=True, help='Output HTML file path')
    parser.add_argument('--title', help='Custom report title')
    parser.add_argument('--subtitle', help='Custom report subtitle')
    parser.add_argument('--system-info', help='JSON string with custom system information')
    
    args = parser.parse_args()
    
    # Validate input file
    if not Path(args.csv).exists():
        print(f"❌ CSV file not found: {args.csv}")
        sys.exit(1)
    
    # Parse custom system info if provided
    custom_info = None
    if args.system_info:
        try:
            custom_info = json.loads(args.system_info)
        except json.JSONDecodeError:
            print("❌ Invalid JSON format for system-info")
            sys.exit(1)
    
    # Generate report
    generator = SecurityReportGenerator()
    success = generator.generate_html_report(
        args.csv,
        args.output,
        args.title,
        args.subtitle,
        custom_info
    )
    
    if success:
        print(f"\n🎉 Report ready! Open {args.output} in your web browser")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()