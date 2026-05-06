# 🛡️ Sentinel Investigator

**A production-ready SOC investigation platform for Microsoft Sentinel**

Sentinel Investigator is an intelligent assistant that allows SOC analysts to quickly find logs, run investigations, triage alerts, hunt for threats, and document findings inside Microsoft Sentinel — without writing complex KQL from scratch every time.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔬 **NL → KQL** | Natural language to Kusto Query Language conversion via OpenAI (with offline mock fallback) |
| 📋 **Investigation Playbooks** | 7 pre-built playbooks: Suspicious Sign-ins, Malware, Phishing, Lateral Movement, C2, Privilege Escalation, Data Exfiltration |
| 🎯 **Threat Hunting** | 11 MITRE ATT&CK–mapped hunting templates (Recon → Impact) |
| 🔎 **Entity Enrichment** | IP reputation (VirusTotal + AbuseIPDB), file hash analysis, user profile lookup (Microsoft Graph) |
| 🗒 **Investigation Sessions** | Timeline tracking, evidence collection, entity tracking, analyst notes |
| 📄 **Report Export** | Word (.docx), Excel (.xlsx), and self-contained HTML reports |
| 📊 **Visualisations** | Plotly timelines, frequency charts, geo maps, risk gauges — all in dark SOC mode |
| 🔐 **Secure Auth** | Azure AD Device Code, Service Principal, and Managed Identity authentication |
| 🗂 **Query Library** | Save and search personal/team KQL queries with tags |
| 🚀 **Docker Ready** | One-command deployment via Docker Compose |

---

## 🏗 Architecture

```
sentinel-investigator/
├── app/
│   ├── main.py                   # Streamlit entry point
│   ├── config.py                 # Pydantic-settings configuration
│   ├── auth/
│   │   └── azure_auth.py         # Azure AD auth (Device Code / SP / MI)
│   ├── sentinel/
│   │   ├── client.py             # Azure Monitor LogsQueryClient wrapper
│   │   └── workspace.py          # Multi-workspace management
│   ├── kql/
│   │   ├── generator.py          # NL → KQL (OpenAI + mock fallback)
│   │   ├── validator.py          # Static KQL analysis / cost estimation
│   │   └── library.py            # Saved query library
│   ├── playbooks/                # 7 investigation playbooks
│   ├── hunting/
│   │   └── templates.py          # 11 MITRE ATT&CK hunting templates
│   ├── enrichment/               # IP, hash, user enrichment
│   ├── investigation/
│   │   └── session.py            # Session/evidence/timeline tracker
│   ├── reporting/
│   │   └── exporter.py           # Word/Excel/HTML report generator
│   └── ui/
│       ├── pages/                # Streamlit page modules
│       └── components/           # Sidebar, visualisations
├── tests/                        # Pytest test suite (60 tests)
├── data/                         # Runtime data (sessions, exports, queries)
├── .env.example                  # Environment variable template
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

**Tech stack:**
- **Python 3.11+** with type hints throughout
- **Streamlit** — dark-mode SOC-friendly web UI
- **Azure SDK** — `azure-identity`, `azure-monitor-query`
- **OpenAI** — GPT-4o for natural language → KQL
- **Plotly** — interactive visualisations
- **httpx** — async HTTP for threat intel APIs
- **Pydantic v2** — configuration and data validation
- **python-docx / openpyxl** — report generation

---

## 🚀 Quick Start

### Option 1: Local (Python)

```bash
# 1. Clone
git clone https://github.com/pulkitrais/soc-agent.git
cd soc-agent

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and fill in your values (see Configuration section)

# 5. Launch
streamlit run app/main.py
```

The app will be available at **http://localhost:8501**

### Option 2: Docker Compose

```bash
# 1. Clone & configure
git clone https://github.com/pulkitrais/soc-agent.git
cd soc-agent
cp .env.example .env
# Edit .env with your credentials

# 2. Build and run
docker-compose up -d

# 3. Open http://localhost:8501
```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure:

```ini
# ── Azure Authentication ──────────────────────────────────
# device_code | service_principal | managed_identity
AZURE_AUTH_METHOD=device_code

# Required for service_principal
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# ── Sentinel Workspace ────────────────────────────────────
SENTINEL_WORKSPACE_ID=your-workspace-id
SENTINEL_SUBSCRIPTION_ID=your-subscription-id
SENTINEL_RESOURCE_GROUP=your-resource-group

# ── OpenAI (for NL→KQL, optional) ────────────────────────
OPENAI_API_KEY=sk-...          # Falls back to template-based mock if not set
OPENAI_MODEL=gpt-4o

# ── Threat Intel APIs (optional) ─────────────────────────
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
```

### Azure RBAC Requirements

The identity used (service principal, managed identity, or interactive user) needs:

| Role | Scope | Purpose |
|---|---|---|
| `Log Analytics Reader` | Workspace | Run KQL queries |
| `Microsoft Sentinel Reader` | Resource Group | Access Sentinel data |
| `Security Reader` | Subscription | Read security data (optional) |

---

## 🔐 Authentication Methods

### Device Code Flow (Default — Interactive)
Best for local development. Opens a browser to authenticate.
```ini
AZURE_AUTH_METHOD=device_code
AZURE_TENANT_ID=optional-tenant-id
```

### Service Principal
Best for CI/CD and automation.
```ini
AZURE_AUTH_METHOD=service_principal
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-app-client-id
AZURE_CLIENT_SECRET=your-client-secret
```

### Managed Identity
Best for Azure-hosted deployments (ACI, AKS, App Service).
```ini
AZURE_AUTH_METHOD=managed_identity
```

---

## 🎮 Usage Guide

### Query Lab
1. Type a question in plain English: *"show me all failed RDP logons in the last 6 hours"*
2. Click **⚡ Generate KQL** — the query appears with warnings/suggestions
3. Review the **cost estimate**, edit if needed, click **▶ Run in Query Lab**
4. View results as a table + timeline/frequency charts
5. Save to your **Query Library** for reuse

### Investigation Playbooks
1. Select a playbook (e.g. **Suspicious Sign-ins**)
2. Each step shows MITRE technique, description, and editable KQL
3. Run steps one-by-one — results appear inline
4. All results auto-save to your active investigation session

### Threat Hunting
1. Filter by MITRE tactic or severity
2. Click **▶ Run Hunt** — findings are highlighted in red
3. Drill into results with built-in visualisations
4. Link directly to MITRE ATT&CK technique pages

### Entity Enrichment
- **IP**: Enter any IP → VirusTotal + AbuseIPDB results + risk gauge
- **Hash**: MD5/SHA1/SHA256 → detection ratio and malware family
- **User**: UPN or Object ID → profile, risk level, group memberships

### Investigation Sessions
1. Create a session from the **🗒 Investigations** page
2. Set it as active in the sidebar
3. All queries, enrichments, and notes are automatically saved
4. Export to HTML, Word, or Excel when done

---

## 📋 Playbooks

| Playbook | MITRE Tactic | Steps |
|---|---|---|
| Suspicious Sign-ins | Initial Access (TA0001) | 6 |
| Malware / Suspicious Process Execution | Execution / Defence Evasion | 6 |
| Phishing / Email Investigation | Initial Access – T1566 | 6 |
| Lateral Movement | Lateral Movement (TA0008) | 6 |
| Command & Control | C2 (TA0011) | 5 |
| Privilege Escalation | Privilege Escalation (TA0004) | 5 |
| Data Exfiltration | Exfiltration (TA0010) | 6 |

---

## 🎯 Threat Hunting Templates

| ID | Name | Technique | Severity |
|---|---|---|---|
| hunt-001 | Account Enumeration via LDAP | T1087 | Medium |
| hunt-002 | External IP Sign-in to Admin Accounts | T1078 | High |
| hunt-003 | LSASS Memory Dump | T1003.001 | Critical |
| hunt-004 | Windows Credential Access via Registry | T1003.002 | Critical |
| hunt-005 | Scheduled Task Creation | T1053.005 | Medium |
| hunt-006 | Registry Run Key Persistence | T1547.001 | High |
| hunt-007 | Audit Log Clearing | T1070.001 | Critical |
| hunt-008 | Network Port Scanning | T1046 | Medium |
| hunt-009 | Clipboard Data Access | T1115 | Medium |
| hunt-010 | Anomalous SharePoint Access | T1530 | High |
| hunt-011 | Ransomware File Extension Pattern | T1486 | Critical |

---

## 🧪 Running Tests

```bash
# Run all 60 tests
pytest tests/ -v

# Run specific module
pytest tests/test_kql.py -v
pytest tests/test_playbooks.py -v
pytest tests/test_enrichment.py -v
pytest tests/test_investigation.py -v
pytest tests/test_hunting.py -v
```

---

## 🔒 Security Best Practices

- **Never commit secrets** — `.env` is git-ignored; use `.env.example` as template
- **Least privilege** — assign only the minimum required Azure RBAC roles
- **Input sanitisation** — all user inputs to KQL templates are sanitised via `_sanitise_substitution()`
- **KQL validation** — queries are statically analysed before execution (dangerous operations blocked)
- **Docker security** — container runs as non-root user (`socapp`) with `no-new-privileges`
- **No data exfiltration** — investigation data stays local in the `data/` directory
- **API keys** — stored in environment variables, never logged or exposed in UI

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and add tests
4. Run `pytest tests/ -v` to ensure all tests pass
5. Submit a pull request

---

## 📄 License

This project is open source. See the repository for license details.

---

*Built with ❤️ for SOC analysts who deserve better tools.*
