"""
kadmin_web.py - Web-based Administrative Dashboard and REST API for KDC.

Serves KAdmin Web Console on port 8088. Zero external dependencies.
"""

import os
import sys
import json
import sqlite3
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from kdc.database import (
    DEFAULT_KEYTAB_PATH,
    audit_event,
    connect,
    ensure_schema,
    get_principal,
    upsert_principal,
)
from core.messages import KADMIN_WEB_HOST, KADMIN_WEB_PORT, REALM
from core.keytab import write_keytab
from core.crypto import str_to_key

HTML_CONTENT = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>KAdmin Web Console - Kerberos V5</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            --page-bg: #f4f6f8;
            --surface: #ffffff;
            --surface-muted: #f8fafc;
            --border: #d8dee8;
            --border-strong: #b8c2d2;
            --text: #172033;
            --text-muted: #667085;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --success: #12805c;
            --danger: #ef4444;
            --warning: #b45309;
            --accent: #0f766e;
            --shadow-sm: 0 1px 2px rgba(16, 24, 40, 0.06);
            --shadow-md: 0 12px 30px rgba(16, 24, 40, 0.10);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: var(--page-bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            overflow-x: hidden;
        }

        .sidebar {
            width: 264px;
            background: #ffffff;
            border-right: 1px solid var(--border);
            padding: 24px 18px;
            display: flex;
            flex-direction: column;
            gap: 28px;
            position: sticky;
            top: 0;
            min-height: 100vh;
        }

        .logo {
            font-size: 18px;
            font-weight: 700;
            color: var(--text);
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 0 8px 18px;
            border-bottom: 1px solid var(--border);
        }

        .logo svg {
            color: var(--primary);
        }

        .brand-text {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }

        .brand-caption {
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
        }

        .menu {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .menu-item {
            padding: 10px 12px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            color: var(--text-muted);
            transition: background 0.16s ease, color 0.16s ease, box-shadow 0.16s ease;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border: 1px solid transparent;
        }

        .menu-item:hover, .menu-item.active {
            color: var(--primary);
            background: #eef4ff;
            border-color: #c7d7fe;
            box-shadow: var(--shadow-sm);
        }

        .main-content {
            flex: 1;
            padding: 28px 32px 40px;
            overflow-y: auto;
            max-width: 1440px;
            margin: 0 auto;
            width: 100%;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            gap: 16px;
        }

        h1 {
            font-size: 26px;
            font-weight: 700;
            letter-spacing: 0;
        }

        .status-badge {
            background: #ecfdf3;
            color: var(--success);
            padding: 7px 12px;
            border-radius: 999px;
            border: 1px solid #abefc6;
            font-size: 13px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 6px;
            white-space: nowrap;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            box-shadow: 0 0 0 3px rgba(18, 128, 92, 0.16);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            box-shadow: var(--shadow-sm);
        }

        .stat-card:hover {
            border-color: var(--border-strong);
            box-shadow: var(--shadow-md);
        }

        .stat-title {
            color: var(--text-muted);
            font-size: 13px;
            font-weight: 700;
            margin-bottom: 10px;
            text-transform: uppercase;
        }

        .stat-value {
            font-size: 30px;
            font-weight: 700;
            line-height: 1.1;
        }

        .stat-desc {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 8px;
        }

        .success-text { color: var(--success); }
        .danger-text { color: var(--danger); }

        .panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: var(--shadow-sm);
            overflow-x: auto;
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            gap: 12px;
            flex-wrap: wrap;
        }

        .panel-title {
            font-size: 18px;
            font-weight: 700;
        }

        .btn {
            background: var(--primary);
            color: #ffffff;
            border: 1px solid var(--primary);
            padding: 9px 14px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.16s ease, border-color 0.16s ease, color 0.16s ease, box-shadow 0.16s ease;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: var(--shadow-sm);
            white-space: nowrap;
        }

        .btn:hover {
            background: var(--primary-hover);
            border-color: var(--primary-hover);
        }

        .btn-danger {
            background: #fff5f5;
            color: var(--danger);
            border: 1px solid #fecaca;
        }

        .btn-danger:hover {
            background: var(--danger);
            color: #ffffff;
            border-color: var(--danger);
        }

        .btn-secondary {
            background: #ffffff;
            color: var(--text);
            border: 1px solid var(--border-strong);
        }

        .btn-secondary:hover {
            background: var(--surface-muted);
            border-color: var(--text-muted);
        }

        .btn-sm {
            padding: 6px 10px;
            font-size: 12px;
            min-height: 30px;
        }

        .action-group {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            min-width: 760px;
        }

        th, td {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        th {
            color: var(--text-muted);
            font-weight: 700;
            font-size: 12px;
            background: var(--surface-muted);
            text-transform: uppercase;
            white-space: nowrap;
        }

        td {
            font-size: 14px;
        }

        tr:hover td {
            background: #fbfdff;
        }

        .badge {
            padding: 4px 9px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
            display: inline-block;
            border: 1px solid transparent;
        }

        .badge-user { background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; }
        .badge-service { background: #fffbeb; color: #92400e; border-color: #fde68a; }
        .badge-tgs { background: #f0fdfa; color: #0f766e; border-color: #99f6e4; }
        .badge-active { background: #ecfdf3; color: var(--success); border-color: #abefc6; }
        .badge-disabled { background: #fff1f2; color: var(--danger); border-color: #fecdd3; }

        .filters {
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }

        .filter-input {
            background: #ffffff;
            border: 1px solid var(--border);
            color: var(--text);
            padding: 9px 12px;
            border-radius: 8px;
            font-family: inherit;
            font-size: 14px;
            outline: none;
            min-width: 180px;
            transition: border-color 0.16s ease, box-shadow 0.16s ease;
        }

        .filter-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
        }

        .filter-search {
            flex: 1;
            min-width: 250px;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(23, 32, 51, 0.42);
            z-index: 1000;
            justify-content: center;
            align-items: center;
            opacity: 0;
            transition: opacity 0.16s ease;
            padding: 20px;
        }

        .modal.show {
            display: flex;
            opacity: 1;
        }

        .modal-content {
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            width: min(520px, 100%);
            padding: 24px;
            box-shadow: var(--shadow-md);
            transform: translateY(8px);
            transition: transform 0.16s ease;
        }

        .modal.show .modal-content {
            transform: translateY(0);
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-label {
            display: block;
            font-size: 14px;
            font-weight: 700;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .form-control {
            width: 100%;
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            color: var(--text);
            outline: none;
            font-size: 14px;
            font-family: inherit;
        }

        .form-control:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
        }

        .checkbox-group {
            display: flex;
            gap: 16px;
            margin-top: 8px;
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 14px;
            cursor: pointer;
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 12px;
            margin-top: 24px;
        }

        .log-detail {
            background: #0f172a;
            font-family: "Cascadia Mono", "SFMono-Regular", Consolas, monospace;
            padding: 12px;
            border-radius: 8px;
            font-size: 12px;
            border: 1px solid #1f2937;
            white-space: pre-wrap;
            margin-top: 10px;
            color: #38bdf8;
            max-height: 200px;
            overflow-y: auto;
        }

        @media (max-width: 860px) {
            body {
                display: block;
            }

            .sidebar {
                width: 100%;
                min-height: auto;
                position: static;
                border-right: none;
                border-bottom: 1px solid var(--border);
            }

            .menu {
                flex-direction: row;
                overflow-x: auto;
            }

            .menu-item {
                min-width: max-content;
            }

            .main-content {
                padding: 20px 16px 32px;
            }

            header {
                align-items: flex-start;
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
            <span class="brand-text">
                <span>KAdmin Console</span>
                <span class="brand-caption">Kerberos operations</span>
            </span>
        </div>
        <ul class="menu">
            <li class="menu-item active" onclick="switchTab('dashboard')">
                Dashboard
            </li>
            <li class="menu-item" onclick="switchTab('principals')">
                Principals
            </li>
            <li class="menu-item" onclick="switchTab('logs')">
                Audit Logs
            </li>
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <header>
            <h1 id="page-title">Dashboard Overview</h1>
            <div class="status-badge">
                <span class="status-dot"></span>
                KDC ONLINE
            </div>
        </header>

        <!-- DASHBOARD TAB -->
        <div id="tab-dashboard">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-title">Total Principals</div>
                    <div class="stat-value" id="stat-principals">-</div>
                    <div class="stat-desc">Users, services, and krbtgt</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">AS Requests</div>
                    <div class="stat-value" id="stat-as">-</div>
                    <div class="stat-desc">Authentication Service requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">TGS Requests</div>
                    <div class="stat-value" id="stat-tgs">-</div>
                    <div class="stat-desc">Ticket Granting Service requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Security Success Rate</div>
                    <div class="stat-value success-text" id="stat-success">-</div>
                    <div class="stat-desc"><span id="stat-failures" class="danger-text">0</span> authentication failures</div>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">Recent Authentication Activity</div>
                </div>
                <table id="recent-logs-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Principal</th>
                            <th>Component</th>
                            <th>Event</th>
                            <th>Outcome</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Recent logs populated here -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- PRINCIPALS TAB -->
        <div id="tab-principals" style="display: none;">
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">Database Principals</div>
                    <button class="btn" onclick="openAddModal()">
                        + Add Principal
                    </button>
                </div>
                <table id="principals-table">
                    <thead>
                        <tr>
                            <th>Principal Name</th>
                            <th>Type</th>
                            <th>Realm</th>
                            <th>KVNO</th>
                            <th>Enctype</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Principals populated here -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- LOGS TAB -->
        <div id="tab-logs" style="display: none;">
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">Audit Trails</div>
                </div>
                <div class="filters">
                    <input type="text" class="filter-input filter-search" id="filter-search" placeholder="Search by principal or IP..." oninput="loadLogs()">
                    <select class="filter-input" id="filter-component" onchange="loadLogs()">
                        <option value="">All Components</option>
                        <option value="AS">AS Handler</option>
                        <option value="TGS">TGS Handler</option>
                        <option value="kadmin">KAdmin CLI</option>
                        <option value="kadmin_web">Web Dashboard</option>
                    </select>
                    <select class="filter-input" id="filter-outcome" onchange="loadLogs()">
                        <option value="">All Outcomes</option>
                        <option value="success">Success</option>
                        <option value="failure">Failure</option>
                    </select>
                </div>
                <table id="logs-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Component</th>
                            <th>Event</th>
                            <th>Principal</th>
                            <th>Peer Address</th>
                            <th>Outcome</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Logs populated here -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Add Principal Modal -->
    <div class="modal" id="add-modal">
        <div class="modal-content">
            <h2>Add New Principal</h2>
            <div style="margin-top: 20px;">
                <div class="form-group">
                    <label class="form-label">Username / Principal Name</label>
                    <input type="text" class="form-control" id="form-name" placeholder="e.g. charlie">
                </div>
                <div class="form-group">
                    <label class="form-label">Realm</label>
                    <select class="form-control" id="form-realm">
                        <option value="DEMO.LOCAL">DEMO.LOCAL</option>
                        <option value="PARTNER.LOCAL">PARTNER.LOCAL</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-control" id="form-password" placeholder="••••••••">
                </div>
                <div class="form-group">
                    <label class="form-label">Principal Type</label>
                    <select class="form-control" id="form-type">
                        <option value="user">User Principal</option>
                        <option value="service">Service Principal</option>
                    </select>
                </div>
                <div class="form-group" id="form-groups-container">
                    <label class="form-label">Groups (RBAC)</label>
                    <div class="checkbox-group">
                        <label class="checkbox-label">
                            <input type="checkbox" id="group-users" checked> users
                        </label>
                        <label class="checkbox-label">
                            <input type="checkbox" id="group-admins"> admins
                        </label>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeAddModal()">Cancel</button>
                <button class="btn" onclick="savePrincipal()">Save Principal</button>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.menu-item').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-dashboard').style.display = 'none';
            document.getElementById('tab-principals').style.display = 'none';
            document.getElementById('tab-logs').style.display = 'none';

            document.getElementById('tab-' + tabId).style.display = 'block';
            
            // Set active class on menu
            const activeIndex = tabId === 'dashboard' ? 0 : tabId === 'principals' ? 1 : 2;
            document.querySelectorAll('.menu-item')[activeIndex].classList.add('active');
            
            // Set title
            document.getElementById('page-title').innerText = tabId.charAt(0).toUpperCase() + tabId.slice(1) + (tabId !== 'dashboard' ? ' Management' : ' Overview');

            if (tabId === 'dashboard') {
                loadDashboardData();
            } else if (tabId === 'principals') {
                loadPrincipals();
            } else if (tabId === 'logs') {
                loadLogs();
            }
        }

        function loadDashboardData() {
            fetch('/api/statistics')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('stat-principals').innerText = data.total_principals;
                    document.getElementById('stat-as').innerText = data.as_requests;
                    document.getElementById('stat-tgs').innerText = data.tgs_requests;
                    document.getElementById('stat-failures').innerText = data.failed_requests;
                    document.getElementById('stat-success').innerText = data.success_rate.toFixed(1) + '%';
                });

            fetch('/api/audit_logs?limit=5')
                .then(r => r.json())
                .then(logs => {
                    const tbody = document.querySelector('#recent-logs-table tbody');
                    tbody.innerHTML = '';
                    logs.forEach(log => {
                        const tr = document.createElement('tr');
                        const timeStr = new Date(log.timestamp * 1000).toLocaleString();
                        const outcomeClass = log.outcome === 'success' ? 'badge-active' : 'badge-disabled';
                        tr.innerHTML = `
                            <td>${timeStr}</td>
                            <td>${log.principal || 'N/A'}</td>
                            <td>${log.component}</td>
                            <td>${log.event}</td>
                            <td><span class="badge ${outcomeClass}">${log.outcome}</span></td>
                        `;
                        tbody.appendChild(tr);
                    });
                });
        }

        function loadPrincipals() {
            fetch('/api/principals')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.querySelector('#principals-table tbody');
                    tbody.innerHTML = '';
                    data.forEach(p => {
                        const tr = document.createElement('tr');
                        const typeClass = p.principal_type === 'user' ? 'badge-user' : p.principal_type === 'service' ? 'badge-service' : 'badge-tgs';
                        const statusClass = p.disabled === 0 ? 'badge-active' : 'badge-disabled';
                        const statusText = p.disabled === 0 ? 'Active' : 'Disabled';
                        const toggleText = p.disabled === 0 ? 'Disable' : 'Enable';
                        
                        tr.innerHTML = `
                            <td><strong>${p.principal_name}</strong></td>
                            <td><span class="badge ${typeClass}">${p.principal_type}</span></td>
                            <td>${p.realm}</td>
                            <td>${p.kvno}</td>
                            <td>${p.enctype || 'N/A'}</td>
                            <td><span class="badge ${statusClass}">${statusText}</span></td>
                            <td>
                                <span class="action-group">
                                <button class="btn btn-secondary btn-sm" onclick="togglePrincipal('${p.principal_name}')">
                                    ${toggleText}
                                </button>
                                <button class="btn btn-danger btn-sm" onclick="deletePrincipal('${p.principal_name}')">
                                    Delete
                                </button>
                                </span>
                            </td>
                        `;
                        tbody.appendChild(tr);
                    });
                });
        }

        function togglePrincipal(name) {
            fetch('/api/principals/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ principal_name: name })
            }).then(() => loadPrincipals());
        }

        function deletePrincipal(name) {
            if (confirm('Are you sure you want to delete principal ' + name + '?')) {
                fetch('/api/principals/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ principal_name: name })
                }).then(() => loadPrincipals());
            }
        }

        function loadLogs() {
            const component = document.getElementById('filter-component').value;
            const outcome = document.getElementById('filter-outcome').value;
            const search = document.getElementById('filter-search').value;
            
            let url = `/api/audit_logs?component=${encodeURIComponent(component)}&outcome=${encodeURIComponent(outcome)}&search=${encodeURIComponent(search)}`;
            
            fetch(url)
                .then(r => r.json())
                .then(data => {
                    const tbody = document.querySelector('#logs-table tbody');
                    tbody.innerHTML = '';
                    data.forEach(log => {
                        const tr = document.createElement('tr');
                        const timeStr = new Date(log.timestamp * 1000).toLocaleString();
                        const outcomeClass = log.outcome === 'success' ? 'badge-active' : 'badge-disabled';
                        
                        // Main row
                        tr.innerHTML = `
                            <td>${timeStr}</td>
                            <td>${log.component}</td>
                            <td>${log.event}</td>
                            <td>${log.principal || 'N/A'}</td>
                            <td>${log.peer || 'N/A'}</td>
                            <td><span class="badge ${outcomeClass}">${log.outcome}</span></td>
                        `;
                        
                        // Detail toggle on click
                        tr.style.cursor = 'pointer';
                        tr.onclick = function() {
                            let nextRow = tr.nextSibling;
                            if (nextRow && nextRow.classList && nextRow.classList.contains('detail-row')) {
                                nextRow.remove();
                            } else {
                                const detailRow = document.createElement('tr');
                                detailRow.classList.add('detail-row');
                                detailRow.innerHTML = `
                                    <td colspan="6">
                                        <div class="log-detail">${log.detail ? JSON.stringify(JSON.parse(log.detail), null, 2) : 'No extra details available.'}</div>
                                    </td>
                                `;
                                tr.parentNode.insertBefore(detailRow, tr.nextSibling);
                            }
                        };
                        
                        tbody.appendChild(tr);
                    });
                });
        }

        function openAddModal() {
            document.getElementById('add-modal').classList.add('show');
        }

        function closeAddModal() {
            document.getElementById('add-modal').classList.remove('show');
            // reset form
            document.getElementById('form-name').value = '';
            document.getElementById('form-password').value = '';
            document.getElementById('group-users').checked = true;
            document.getElementById('group-admins').checked = false;
        }

        function savePrincipal() {
            const name = document.getElementById('form-name').value.trim();
            const realm = document.getElementById('form-realm').value;
            const password = document.getElementById('form-password').value;
            const type = document.getElementById('form-type').value;
            
            if (!name || !password) {
                alert('Please enter username/name and password.');
                return;
            }

            const groups = [];
            if (document.getElementById('group-users').checked) groups.push('users');
            if (document.getElementById('group-admins').checked) groups.push('admins');

            const payload = {
                principal_name: name + '@' + realm,
                password: password,
                type: type,
                groups: groups
            };

            fetch('/api/principals', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => {
                if (res.ok) {
                    closeAddModal();
                    loadPrincipals();
                } else {
                    res.json().then(err => alert('Error: ' + err.error));
                }
            });
        }

        // Initialize dashboard
        loadDashboardData();
    </script>
</body>
</html>
"""


class KAdminWebHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Clean logs
        sys.stdout.write(f"[KAdminWeb] HTTP {self.address_string()} {format % args}\n")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_CONTENT.encode("utf-8"))
            return

        elif path == "/api/statistics":
            self.handle_api_statistics()
            return

        elif path == "/api/principals":
            self.handle_api_list_principals()
            return

        elif path == "/api/audit_logs":
            self.handle_api_list_logs(parsed_url.query)
            return

        # Not found
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/principals":
            self.handle_api_add_principal()
            return

        elif path == "/api/principals/delete":
            self.handle_api_delete_principal()
            return

        elif path == "/api/principals/toggle":
            self.handle_api_toggle_principal()
            return

        # Not found
        self.send_response(404)
        self.end_headers()

    def handle_api_statistics(self):
        conn = connect()
        try:
            cursor = conn.cursor()
            
            # Count total principals
            cursor.execute("SELECT COUNT(*) FROM principals")
            total_principals = cursor.fetchone()[0]

            # Count AS/TGS outcomes using the actual audit event names emitted by
            # the handlers. Successful AS requests are logged as tgt_issued;
            # pre-authentication/lookup failures are logged as preauth/as_req.
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE component = 'AS'
                  AND event IN ('as_req', 'preauth', 'tgt_issued')
                  AND outcome IN ('success', 'failure')
                """
            )
            as_requests = cursor.fetchone()[0]

            # TGS has several validation stages, but each handled request emits
            # one success/failure audit outcome under component TGS.
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE component = 'TGS'
                  AND outcome IN ('success', 'failure')
                """
            )
            tgs_requests = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE component IN ('AS', 'TGS')
                  AND outcome = 'success'
                """
            )
            successful_requests = cursor.fetchone()[0]

            # Count failed authentication outcomes only, not kadmin/db events.
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE component IN ('AS', 'TGS')
                  AND outcome = 'failure'
                """
            )
            failed_requests = cursor.fetchone()[0]

            total_requests = successful_requests + failed_requests
            success_rate = 100.0
            if total_requests > 0:
                success_rate = (successful_requests / total_requests) * 100.0

            data = {
                "total_principals": total_principals,
                "as_requests": as_requests,
                "tgs_requests": tgs_requests,
                "failed_requests": failed_requests,
                "success_rate": success_rate
            }

            self.send_json_response(200, data)
        except Exception as e:
            self.send_json_response(500, {"error": str(e)})
        finally:
            conn.close()

    def handle_api_list_principals(self):
        conn = connect()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT principal_name, principal_type, realm, kvno, enctype, disabled, groups FROM principals")
            rows = cursor.fetchall()
            
            principals = []
            for row in rows:
                principals.append({
                    "principal_name": row[0],
                    "principal_type": row[1],
                    "realm": row[2],
                    "kvno": row[3],
                    "enctype": row[4],
                    "disabled": row[5],
                    "groups": json.loads(row[6]) if row[6] else []
                })
            
            self.send_json_response(200, principals)
        except Exception as e:
            self.send_json_response(500, {"error": str(e)})
        finally:
            conn.close()

    def handle_api_list_logs(self, query_str):
        params = urllib.parse.parse_qs(query_str)
        limit = int(params.get("limit", [50])[0])
        component = params.get("component", [""])[0]
        outcome = params.get("outcome", [""])[0]
        search = params.get("search", [""])[0]

        conn = connect()
        try:
            cursor = conn.cursor()
            query = "SELECT id, timestamp, component, event, principal, peer, outcome, detail FROM audit_log WHERE 1=1"
            sql_args = []

            if component:
                query += " AND component = ?"
                sql_args.append(component)
            if outcome:
                query += " AND outcome = ?"
                sql_args.append(outcome)
            if search:
                query += " AND (principal LIKE ? OR peer LIKE ? OR event LIKE ?)"
                search_term = f"%{search}%"
                sql_args.extend([search_term, search_term, search_term])

            query += " ORDER BY timestamp DESC LIMIT ?"
            sql_args.append(limit)

            cursor.execute(query, sql_args)
            rows = cursor.fetchall()

            logs = []
            for row in rows:
                logs.append({
                    "id": row[0],
                    "timestamp": row[1],
                    "component": row[2],
                    "event": row[3],
                    "principal": row[4],
                    "peer": row[5],
                    "outcome": row[6],
                    "detail": row[7]
                })

            self.send_json_response(200, logs)
        except Exception as e:
            self.send_json_response(500, {"error": str(e)})
        finally:
            conn.close()

    def handle_api_add_principal(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body)
            principal_name = data.get("principal_name")
            password = data.get("password")
            p_type = data.get("type", "user")
            groups = data.get("groups", ["users"])

            if not principal_name or not password:
                self.send_json_response(400, {"error": "Missing principal_name or password"})
                return

            conn = connect()
            try:
                ensure_schema(conn)
                if get_principal(conn.cursor(), principal_name, resolve_alias=False):
                    self.send_json_response(409, {"error": f"Principal '{principal_name}' already exists"})
                    return

                # Add to DB
                record = upsert_principal(
                    conn,
                    principal_name,
                    password,
                    p_type,
                    groups=json.dumps(groups)
                )

                # Write keytab if service principal
                if p_type == "service":
                    write_keytab(
                        DEFAULT_KEYTAB_PATH,
                        record["principal_name"],
                        record["key"],
                        record["kvno"],
                        record["enctype"],
                        record["realm"]
                    )

                audit_event(conn, "kadmin_web", "principal_created", principal_name, "success",
                            {"type": p_type, "groups": groups})
                conn.commit()
                self.send_json_response(201, {"status": "success", "principal": record["principal_name"]})
            except Exception as e:
                self.send_json_response(500, {"error": f"Database error: {e}"})
            finally:
                conn.close()

        except Exception as e:
            self.send_json_response(400, {"error": f"Invalid JSON payload: {e}"})

    def handle_api_delete_principal(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body)
            principal_name = data.get("principal_name")

            if not principal_name:
                self.send_json_response(400, {"error": "Missing principal_name"})
                return

            conn = connect()
            try:
                conn.execute("DELETE FROM principals WHERE principal_name = ?", (principal_name,))
                conn.execute("DELETE FROM principal_aliases WHERE principal_name = ?", (principal_name,))
                audit_event(conn, "kadmin_web", "principal_deleted", principal_name, "success")
                conn.commit()
                self.send_json_response(200, {"status": "success"})
            except Exception as e:
                self.send_json_response(500, {"error": str(e)})
            finally:
                conn.close()
        except Exception as e:
            self.send_json_response(400, {"error": str(e)})

    def handle_api_toggle_principal(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body)
            principal_name = data.get("principal_name")

            if not principal_name:
                self.send_json_response(400, {"error": "Missing principal_name"})
                return

            conn = connect()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT disabled FROM principals WHERE principal_name = ?", (principal_name,))
                row = cursor.fetchone()
                if not row:
                    self.send_json_response(404, {"error": "Principal not found"})
                    return
                
                new_status = 1 if row[0] == 0 else 0
                conn.execute("UPDATE principals SET disabled = ? WHERE principal_name = ?", (new_status, principal_name))
                audit_event(conn, "kadmin_web", "principal_toggled", principal_name, "success", {"disabled": new_status})
                conn.commit()
                self.send_json_response(200, {"status": "success", "disabled": new_status})
            except Exception as e:
                self.send_json_response(500, {"error": str(e)})
            finally:
                conn.close()
        except Exception as e:
            self.send_json_response(400, {"error": str(e)})

    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))


def start_web_server(host=KADMIN_WEB_HOST, port=KADMIN_WEB_PORT):
    server_address = (host, port)
    httpd = HTTPServer(server_address, KAdminWebHandler)
    print(f"\\n{'='*60}")
    print("  KAdmin Web Console & REST API Server")
    print(f"  Url:       http://{host}:{port}/")
    print(f"{'='*60}")
    print("[KAdminWeb] Waiting for requests...\\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\\n[KAdminWeb] Server shutting down...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    start_web_server()
