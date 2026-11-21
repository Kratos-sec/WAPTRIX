# WAPTrix

**Passive Web Application Security Auditing & OWASP Top 10 (2025) Compliance Platform**

WAPTrix is a lightweight, strictly passive web application security auditing framework modeled after **Burp Suite's Passive Audit**. Feed it a list of authorized subdomains and WAPTrix performs non-intrusive HTTP/TLS inspection, maps every finding to **CWE**, **OWASP WSTG v4.2**, **CVSS v3.1**, and the **OWASP Top 10 (2025)**, and generates a subdomain-wise compliance dashboard alongside exportable security reports.

> **Strictly Passive by Design:** WAPTrix only performs standard read-only HTTP `GET` requests and TLS handshakes. It does **not** perform fuzzing, injection, brute-forcing, or destructive active scanning.

## Key Features

- **Subdomain-Wise Visibility:** Audit dozens of subdomains concurrently and inspect each target's HTTP status, TLS posture, captured headers, individual compliance grade (`A`–`F`), and raw evidence.
- **OWASP Top 10 (2025) Compliance Matrix:** Interactive **Subdomain × OWASP Top 10** heatmap (`Pass` / `Warning` / `Fail` / `Manual Review`). Categories that cannot be verified passively are honestly flagged as `Manual Review Required` rather than false passes.
- **Burp-Style Passive Audit Checks:**
   - **Security Headers:** `CSP`, `HSTS`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`.
   - **Transport & TLS:** Missing HTTPS redirects, deprecated TLS versions (`< TLS 1.2`), certificate expiry/mismatch, and mixed-content references.
   - **Cookie Hygiene:** Missing `Secure`, `HttpOnly`, `SameSite`, and overly broad domain scoping.
   - **CORS & Caching:** Misconfigured `Access-Control-Allow-Origin` / credentials pairs and missing `Cache-Control: no-store` on authenticated responses.
   - **Information & Exception Disclosure:** Verbose `Server` / `X-Powered-By` banners, framework stack traces, debug pages, and developer comments in HTML.
   - **Client-Side & Form Hygiene:** Insecure `http://` form actions, missing anti-CSRF token patterns, missing Subresource Integrity (`SRI`) on external scripts, and passive library fingerprinting.
   - **Security Metadata:** Passive inspection of `/.well-known/security.txt` and `/robots.txt`.
- **Declarative Scope Guard:** Enforces an authorization reference, host normalization/deduplication, private-IP protection, and per-host rate limiting.
- **Multi-Format Reporting:** Export either the **full engagement** or a **single subdomain** to **PDF**, **HTML**, **JSON**, **CSV**, and **SARIF 2.1.0** (ready for GitHub Code Scanning / CI pipelines).
- **Offline Demo Mode:** Includes a realistic 5-subdomain sample dataset for instant testing and offline demonstrations.

## Tech Stack

| Layer | Technologies |
| --- | --- |
| **Backend & Passive Engine** | Python 3.11+, FastAPI, Pydantic v2, `httpx` (async), `beautifulsoup4`, `cryptography` |
| **CLI & Storage** | Typer, SQLite |
| **Reporting** | Jinja2, WeasyPrint (PDF), SARIF 2.1.0, CSV, JSON |
| **Frontend Dashboard** | React 18, Vite, Tailwind CSS, Recharts, Lucide Icons |
| **Testing** | `pytest`, `pytest-asyncio` |

## Project Structure

```
waptrix/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI REST API
│   │   ├── cli.py                      # Typer CLI (`waptrix audit`, `waptrix demo`)
│   │   ├── db.py                       # SQLite persistence
│   │   ├── models/                     # Pydantic schemas (Audit, Finding)
│   │   ├── engine/                     # Scope guard, async HTTP/TLS fetcher, auditor
│   │   ├── checks/                     # Modular Burp-style passive check rules
│   │   ├── compliance/                 # OWASP Top 10 (2025) mapping & scoring engine
│   │   └── reporting/                  # PDF, HTML, JSON, CSV, SARIF 2.1.0 exporters
│   ├── sample_data/                    # Built-in 5-subdomain demo dataset
│   ├── tests/                          # Unit tests for checks & compliance scoring
│   └── requirements.txt
├── frontend/                           # React + Vite + Tailwind dark-mode dashboard
└── README.md
```

## Quick Start

### Prerequisites

- **Python 3.11+**
- **Node.js 18+** & `npm`

### 1. Clone & Set Up Backend

```
git clone https://github.com/<your-username>/waptrix.git
cd waptrix/backend

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the Backend API

```
uvicorn app.main:app --reload --port 8000
```

The API will be live at `http://localhost:8000` (Swagger docs at `http://localhost:8000/docs`).

### 3. Set Up & Run the Frontend Dashboard

In a second terminal:

```
cd waptrix/frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser. You can paste a list of authorized subdomains, upload a `.txt` file, or click **Load Demo Audit** to explore the dashboard immediately.

## CLI Usage

Run a passive audit directly from the terminal:

```
# Audit a list of subdomains and export HTML, PDF, JSON, CSV, and SARIF reports
python -m app.cli audit \
  --subdomains subdomains.txt \
  --auth-ref "ENG-2026-001" \
  --out ./reports

# Run against the built-in 5-subdomain offline demo dataset
python -m app.cli demo --out ./demo_reports
```

Example `subdomains.txt`:

```
app.example.com
api.example.com
admin.example.com
static.example.com
```

## OWASP Top 10 (2025) Passive Coverage

WAPTrix maps passive indicators transparently and distinguishes between passively observable controls and areas requiring manual testing:

| OWASP Top 10 (2025) Category | Passive Coverage | Examples Checked |
| --- | --- | --- |
| **A01: Broken Access Control** | Partial | Permissive CORS headers, exposed sensitive paths in `robots.txt` |
| **A02: Security Misconfiguration** | High | Missing CSP/HSTS/XCTO/XFO, verbose server banners, debug headers |
| **A03: Software Supply Chain Failures** | Partial | Passive detection of exposed outdated client-side JS libraries |
| **A04: Cryptographic Failures** | High | Weak TLS (`< 1.2`), expiring certs, missing HTTPS redirects, mixed content, insecure cookies |
| **A05: Injection** | Passive Indicators Only | Missing `CSP` / `X-Content-Type-Options` defense-in-depth headers |
| **A06: Insecure Design** | Partial | Insecure form actions (`http://`), missing anti-CSRF token patterns |
| **A07: Authentication Failures** | Partial | Session cookies missing `HttpOnly`, `Secure`, `SameSite`, or `Cache-Control: no-store` |
| **A08: Software or Data Integrity Failures** | High | External `<script>` tags missing Subresource Integrity (`integrity` attribute) |
| **A09: Logging & Alerting Failures** | Manual Review | Flagged as `Manual Review Required` (not verifiable passively) |
| **A10: Mishandling of Exceptional Conditions** | Partial | Raw stack traces and framework exception dumps in HTTP responses |

## Running Tests

```
cd backend
pytest -v
```

## Legal & Ethical Disclaimer

WAPTrix is intended **strictly for authorized security assessments, educational research, and auditing assets you own or have explicit written permission to test**. Even though WAPTrix performs passive, read-only inspection, always ensure you hold proper authorization before auditing any domain.

## Authors

Developed at the **Department of Computer Engineering, Vishwakarma University, Pune**:

- Aryan Raskar
- Mithilesh Sawant
- Neev Mittal
- Niraj Wadkar
- Sarthak Patankar
