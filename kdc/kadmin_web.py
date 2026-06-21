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
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(255, 255, 255, 0.03);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #3b82f6;
            --primary-glow: rgba(59, 130, 246, 0.5);
            --success: #10b981;
            --success-glow: rgba(16, 185, 129, 0.4);
            --danger: #ef4444;
            --danger-glow: rgba(239, 68, 68, 0.4);
            --warning: #f59e0b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: radial-gradient(circle at top right, #1e1b4b, #090d16 60%);
            color: var(--text-color);
            min-height: 100vh;
            display: flex;
            overflow-x: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(12px);
            border-right: 1px solid var(--card-border);
            padding: 30px 20px;
            display: flex;
            flex-direction: column;
            gap: 40px;
        }

        .logo {
            font-size: 20px;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa, #3b82f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .menu {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .menu-item {
            padding: 12px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            color: var(--text-muted);
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .menu-item:hover, .menu-item.active {
            color: var(--text-color);
            background: var(--card-bg);
            box-shadow: inset 0 0 10px rgba(255, 255, 255, 0.02);
            border-left: 3px solid var(--primary);
        }

        /* Main Content */
        .main-content {
            flex: 1;
            padding: 40px;
            overflow-y: auto;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
        }

        h1 {
            font-size: 28px;
            font-weight: 700;
        }

        .status-badge {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
            padding: 6px 12px;
            border-radius: 20px;
            border: 1px solid var(--success-glow);
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--success);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.3); opacity: 0.5; }
            100% { transform: scale(1); opacity: 1; }
        }

        /* Dashboard View */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }

        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 24px;
            backdrop-filter: blur(10px);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
            border-color: rgba(59, 130, 246, 0.2);
        }

        .stat-title {
            color: var(--text-muted);
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 12px;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 700;
        }

        .stat-desc {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 8px;
        }

        .success-text { color: var(--success); }
        .danger-text { color: var(--danger); }

        /* General Tables and Panels */
        .panel {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 30px;
            backdrop-filter: blur(10px);
            margin-bottom: 30px;
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }

        .panel-title {
            font-size: 18px;
            font-weight: 600;
        }

        /* Buttons */
        .btn {
            background: var(--primary);
            color: var(--text-color);
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .btn:hover {
            background: #2563eb;
            box-shadow: 0 0 12px var(--primary-glow);
        }

        .btn-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border: 1px solid var(--danger-glow);
        }

        .btn-danger:hover {
            background: var(--danger);
            color: var(--text-color);
            box-shadow: 0 0 12px var(--danger-glow);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-color);
            border: 1px solid var(--card-border);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        /* Table */
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th, td {
            padding: 16px;
            border-bottom: 1px solid var(--card-border);
        }

        th {
            color: var(--text-muted);
            font-weight: 600;
            font-size: 14px;
            background: rgba(0, 0, 0, 0.1);
        }

        td {
            font-size: 14px;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.01);
        }

        .badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }

        .badge-user { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
        .badge-service { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
        .badge-tgs { background: rgba(167, 139, 250, 0.15); color: #c084fc; }
        .badge-active { background: rgba(16, 185, 129, 0.15); color: var(--success); }
        .badge-disabled { background: rgba(239, 68, 68, 0.15); color: var(--danger); }

        /* Filter Controls */
        .filters {
            display: flex;
            gap: 16px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }

        .filter-input {
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--card-border);
            color: var(--text-color);
            padding: 10px 16px;
            border-radius: 8px;
            font-family: inherit;
            font-size: 14px;
            outline: none;
            min-width: 180px;
            transition: border-color 0.3s ease;
        }

        .filter-input:focus {
            border-color: var(--primary);
        }

        .filter-search {
            flex: 1;
            min-width: 250px;
        }

        /* Modal styling */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(8px);
            z-index: 1000;
            justify-content: center;
            align-items: center;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .modal.show {
            display: flex;
            opacity: 1;
        }

        .modal-content {
            background: #0f172a;
            border: 1px solid var(--card-border);
            border-radius: 16px;
            width: 480px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            transform: scale(0.9);
            transition: transform 0.3s ease;
        }

        .modal.show .modal-content {
            transform: scale(1);
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .form-control {
            width: 100%;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 10px 14px;
            color: var(--text-color);
            outline: none;
            font-size: 14px;
        }

        .form-control:focus {
            border-color: var(--primary);
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
            margin-top: 30px;
        }

        /* Log Detail view */
        .log-detail {
            background: rgba(0, 0, 0, 0.3);
            font-family: monospace;
            padding: 12px;
            border-radius: 8px;
            font-size: 12px;
            border: 1px solid var(--card-border);
            white-space: pre-wrap;
            margin-top: 10px;
            color: #38bdf8;
            max-height: 200px;
            overflow-y: auto;
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
            KAdmin Console
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
                    <div class="panel-title">Recent Authenticaton Activity</div>
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
                                <button class="btn btn-secondary" style="padding: 4px 8px; font-size:12px;" onclick="togglePrincipal('${p.principal_name}')">
                                    ${toggleText}
                                </button>
                                <button class="btn btn-danger" style="padding: 4px 8px; font-size:12px;" onclick="deletePrincipal('${p.principal_name}')">
                                    Delete
                                </button>
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

            # Count AS requests
            cursor.execute("SELECT COUNT(*) FROM audit_log WHERE event = 'as_req'")
            as_requests = cursor.fetchone()[0]

            # Count TGS requests
            cursor.execute("SELECT COUNT(*) FROM audit_log WHERE event = 'tgs_req'")
            tgs_requests = cursor.fetchone()[0]

            # Count failed outcomes
            cursor.execute("SELECT COUNT(*) FROM audit_log WHERE outcome = 'failure'")
            failed_requests = cursor.fetchone()[0]

            total_requests = as_requests + tgs_requests
            success_rate = 100.0
            if total_requests > 0:
                success_rate = ((total_requests - failed_requests) / total_requests) * 100.0
                if success_rate < 0:
                    success_rate = 0.0

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
