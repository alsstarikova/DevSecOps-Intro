# Lab 2 Submission — Threat Modeling with Threagile

## Task 1 — Threagile Baseline Model (6 pts)

### 1.1: Baseline Threat Model Generation

Successfully generated baseline threat model for OWASP Juice Shop deployment using Threagile v1.0.0.

**Command executed:**
```bash
mkdir -p labs/lab2/baseline labs/lab2/secure

docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

**Generated artifacts in `labs/lab2/baseline/`:**
- `report.pdf` — comprehensive threat model report
- `data-flow-diagram.png` — system data flow visualization
- `data-asset-diagram.png` — data asset dependencies
- `risks.json` — machine-readable risk details
- `stats.json` — risk statistics summary
- `technical-assets.json` — asset inventory and properties

### 1.2: Baseline Risk Statistics

| Severity Level | Count |
|---|---:|
| **Critical** | 0 |
| **Elevated** | 4 |
| **High** | 0 |
| **Medium** | 14 |
| **Low** | 5 |
| **Total Risks** | **23** |

### 1.3: Generated Diagrams & Visual References

#### **Data Flow Diagram (Baseline)**
![Data Flow Diagram](lab2/baseline/data-flow-diagram.png)
- **Reference file:** [labs/lab2/baseline/data-flow-diagram.png](lab2/baseline/data-flow-diagram.png)
- **Shows:** System components, communication links, and data movement paths
- **Key observations:** HTTP protocol on direct-to-app path, unencrypted internal proxy-to-app communication, data flowing through persistent storage

#### **Data Asset Diagram (Baseline)**
![Data Asset Diagram](lab2/baseline/data-asset-diagram.png)
- **Reference file:** [labs/lab2/baseline/data-asset-diagram.png](lab2/baseline/data-asset-diagram.png)
- **Shows:** Which assets are processed/stored by each technical component
- **Key observations:** User Accounts and Orders stored on unencrypted persistent storage; tokens processed by both proxy and app

#### **Full Threat Model Report**
- **Reference file:** [labs/lab2/baseline/report.pdf](lab2/baseline/report.pdf)
- **Contains:** Executive summary, detailed risk descriptions, STRIDE analysis, mitigation recommendations, threat severity breakdowns

---

### 1.4: Top 5 Risks Analysis

#### Risk Ranking Methodology

**Composite Risk Score Formula:**
$$\text{Composite Score} = \text{Severity} × 100 + \text{Likelihood} × 10 + \text{Impact}$$

**Severity Weights:** critical (5) > elevated (4) > high (3) > medium (2) > low (1)  
**Likelihood Weights:** very-likely (4) > likely (3) > possible (2) > unlikely (1)  
**Impact Weights:** high (3) > medium (2) > low (1)

#### Top 5 Risks Detailed Table

| # | Risk Title | Category | Severity | Likelihood | Impact | Asset | Composite Score |
|---|---|---|---:|---:|---:|---|---:|
| **1** | Unencrypted Communication (Direct to App) | unencrypted-communication | **Elevated** (4) | Likely (3) | High (3) | user-browser | 433 |
| **2** | Cross-Site Scripting (XSS) | cross-site-scripting | **Elevated** (4) | Likely (3) | Medium (2) | juice-shop | 432 |
| **3** | Unencrypted Communication (Proxy to App) | unencrypted-communication | **Elevated** (4) | Likely (3) | Medium (2) | reverse-proxy | 432 |
| **4** | Missing Authentication | missing-authentication | **Elevated** (4) | Likely (3) | Medium (2) | reverse-proxy | 432 |
| **5** | Cross-Site Request Forgery (CSRF) | cross-site-request-forgery | Medium (2) | Very-Likely (4) | Low (1) | juice-shop | 241 |

---

### 1.5: Critical Security Concerns Identified

#### **Issue #1: Unencrypted Communication (Score: 433)**
- **Problem:** User → App direct connection uses HTTP (port 3000), exposing authentication tokens and session data in transit
- **Impact:** Attackers on the same network can intercept credentials, session IDs, and sensitive user data via man-in-the-middle (MITM) attacks
- **Affected Data Assets:** User Accounts, Tokens & Sessions, Orders
- **Recommendation:** Mandate HTTPS for all client-facing communication; use HTTPS reverse proxy with valid TLS certificates

#### **Issue #2: Cross-Site Scripting (XSS) (Score: 432)**
- **Problem:** Application lacks input validation and output encoding, allowing stored/reflected XSS attacks via product reviews, comments, or search parameters
- **Impact:** Attackers inject malicious JavaScript that executes in other users' browsers, stealing session tokens, credentials, or redirecting to phishing sites
- **Affected Data Assets:** Product Catalog, Tokens & Sessions, User Accounts
- **Recommendation:** Implement context-aware output encoding (HTML, JavaScript, URL), input validation, Content Security Policy (CSP) headers

#### **Issue #3: Internal Communication Over HTTP (Score: 432)**
- **Problem:** Reverse proxy forwards traffic to the app container over HTTP (no encryption between proxy and app)
- **Impact:** If proxy and app are on separate machines/networks, traffic can be intercepted; even containerized environments benefit from internal TLS
- **Affected Data Assets:** Tokens & Sessions, Product Catalog, Orders
- **Recommendation:** Enable HTTPS between reverse proxy and app container; use self-signed certificates if purely local

#### **Issue #4: Missing Authentication (Score: 432)**
- **Problem:** Reverse proxy lacks authentication mechanism for incoming requests; no API key validation, OAuth, or mutual TLS authentication between browser and proxy
- **Impact:** 
  - Unauthorized users can directly access the application without providing credentials
  - Unauthenticated attackers can enumerate system functionality, access public data, and potentially exploit endpoint vulnerabilities
  - No origin verification allows impersonation of legitimate clients
- **Affected Data Assets:** User Accounts, Orders, Product Catalog, Tokens & Sessions
- **Recommendation:** 
  1. **Implement reverse proxy authentication:** Use HTTP Basic Auth, OAuth 2.0, or API key validation at the proxy level
  2. **Enable mutual TLS (mTLS):** Require client certificates for proxy-to-app communication
  3. **Add rate limiting:** Implement per-IP request throttling to prevent brute-force attacks
  4. **Use Web Application Firewall (WAF):** Deploy WAF rules to enforce authentication policies and block suspicious patterns
  5. **Session validation:** Ensure robust session token validation and implement session timeouts

#### **Issue #5: CSRF Attacks (Score: 241)**
- **Problem:** Application likely lacks CSRF token validation on state-changing requests (POST, PUT, DELETE)
- **Impact:** Attackers can trick authenticated users into performing unwanted actions (e.g., changing password, transferring money, deleting data)
- **Affected Data Assets:** User Accounts, Orders
- **Recommendation:** Implement double-submit cookie pattern or CSRF tokens; use SameSite=Strict cookie attribute; validate Origin/Referer headers

---

### 1.6: Security Architecture Summary

**Current Deployment Model:**
```
Internet
    ↓
[User Browser] →(HTTP/443)→ [Reverse Proxy (Nginx)]
                                    ↓
                             (HTTP/3000) →
                          [Juice Shop App]
                                ↓
                          [Persistent Storage]
                          (database, logs)
```

**Key Risk Vectors:**
1. **Network Layer:** HTTP traffic exposes credentials and session tokens
2. **Application Layer:** No input validation allows XSS attacks
3. **Infrastructure:** No encryption at rest for sensitive data stored on volume
4. **Session Management:** Weak CSRF protection and missing two-factor authentication

---

## Task 2 — HTTPS Variant & Risk Comparison (4 pts)

### 2.1: Security Enhancements Applied

Created `labs/lab2/threagile-model.secure.yaml` with the following hardening measures:

| Change | Field | Before | After | Risk Impact |
|---|---|---|---|---|
| **1. Direct to App** | `protocol` | `http` | `https` | Protects auth tokens in transit |
| **2. Proxy to App** | `protocol` | `http` | `https` | Secures internal communication |
| **3. Storage Layer** | `encryption` | `none` | `transparent` | Encrypts data at rest |

### 2.2: Secure Model Generation

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

**Secure variant artifacts in `labs/lab2/secure/`:**
- Enhanced threat model report with improved architecture
- Updated data-flow & data-asset diagrams
- Revised risk assessments for encrypted channels
- 20 total risks (vs 23 baseline) — **3 risk reduction**

---

### 2.3: Risk Category Delta Analysis

| Category | Baseline | Secure | Δ |
|---|---:|---:|---:|
| container-baseimage-backdooring | 1 | 1 | 0 |
| cross-site-request-forgery | 2 | 2 | 0 |
| cross-site-scripting | 1 | 1 | 0 |
| missing-authentication | 1 | 1 | 0 |
| missing-authentication-second-factor | 2 | 2 | 0 |
| missing-build-infrastructure | 1 | 1 | 0 |
| missing-hardening | 2 | 2 | 0 |
| missing-identity-store | 1 | 1 | 0 |
| missing-vault | 1 | 1 | 0 |
| missing-waf | 1 | 1 | 0 |
| server-side-request-forgery | 2 | 2 | 0 |
| unencrypted-asset | 2 | 1 | -1 |
| unencrypted-communication | 2 | 0 | -2 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

### 2.4: Delta Run Explanation

#### **What Changed?**

The secure variant introduces **encryption in transit and at rest**, directly addressing communication and storage vulnerabilities identified in the baseline:

1. **HTTPS Protocol (Direct Browser → App)**
   - **Before:** HTTP on port 3000 transmitted authentication tokens, session IDs, and user data in plaintext
   - **After:** HTTPS encryption prevents network-level interception attacks
   - **Result:** Eliminates `unencrypted-communication` risk for direct user access

2. **HTTPS Protocol (Reverse Proxy → App)**
   - **Before:** Internal HTTP forwarding between proxy and app was unencrypted
   - **After:** HTTPS secures proxy-to-app communication (even within local network/container boundaries)
   - **Result:** Reduces risk of internal network sniffing or container escape attacks

3. **Transparent Encryption (Persistent Storage)**
   - **Before:** Database, logs, and file uploads stored without encryption on host volume
   - **After:** Transparent encryption (e.g., filesystem-level encryption, container native encryption) protects data at rest
   - **Result:** Eliminates `unencrypted-asset` risk for stored secrets, user accounts, and order data

#### **Why These Changes Matter**

- **2 Unencrypted-Communication Risks Eliminated:** HTTPS removes the primary attack vector for credential theft and session hijacking. Attackers can no longer passively intercept authentication data with network sniffing tools (e.g., tcpdump, Wireshark).
  
- **1 Unencrypted-Asset Risk Reduced:** Transparent encryption ensures that even if an attacker gains filesystem access to the host volume or container storage, sensitive data (user accounts, orders, logs) cannot be read in plaintext. This is particularly important in multi-tenant or shared hosting scenarios.

---

### 2.5: Secure Variant Generated Diagrams

#### **Data Flow Diagram (Secure)**
![Data Flow Diagram Secure](lab2/secure/data-flow-diagram.png)
- **Reference file:** [labs/lab2/secure/data-flow-diagram.png](lab2/secure/data-flow-diagram.png)
- **Improvements:** Shows HTTPS channels replaced HTTP; internal proxy-to-app communication now encrypted
- **Comparison:** Compared to baseline, demonstrates hardened communication paths

#### **Data Asset Diagram (Secure)**
![Data Asset Diagram Secure](lab2/secure/data-asset-diagram.png)
- **Reference file:** [labs/lab2/secure/data-asset-diagram.png](lab2/secure/data-asset-diagram.png)
- **Improvements:** Highlights encrypted storage layer protecting User Accounts and Orders
- **Same assets:** Same data assets as baseline, but now with transport and storage encryption

#### **Full Secure Threat Model Report**
- **Reference file:** [labs/lab2/secure/report.pdf](lab2/secure/report.pdf)
- **Comparison:** Regenerated threat model showing risk reduction from 23 → 20 risks
- **Key findings:** No more unencrypted-communication risks; reduced unencrypted-asset risks

---
