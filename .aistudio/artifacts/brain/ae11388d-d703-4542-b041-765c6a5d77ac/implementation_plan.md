# DeltaShield: Real-Time VirusTotal Threat Protection & Chrome Extension

DeltaShield is a security browser extension (Chrome Manifest V3) and companion Threat Operations Dashboard that inspects web traffic and file downloads in real time via the VirusTotal API v3, actively intercepting high-risk sites and malicious payloads before execution while archiving detailed scan reports.

## User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural parameters have been confirmed from your answers and govern the implementation:

- **Delivery & Package Format**: Full Chrome Extension (Manifest V3) codebase with an in-app **Download Extension (.ZIP)** bundler (complete with `manifest.json`, background service worker `background.js`, `content_script.js`, popup UI `popup.html`, intercept page `intercept.html`, and icons), coupled with an **interactive live dashboard** and testing simulator for immediate web preview.
- **VirusTotal API Connectivity**: Strict VirusTotal API v3 key enforcement for live external threat intelligence analysis. Users can input and validate their VirusTotal API key in the dashboard or extension popup, test connection status, check API quotas, and safely inspect real-time URL and file analysis results.
- **Interception & Security Policy**: Active interception when malicious detections exceed threat threshold ($\ge 1$ engine detection or high-risk classification). Navigations trigger an **Intercept Warning Screen** presenting security engine verdict tallies, threat tags, engine breakdowns, and explicit choices to either return to safety or proceed via audited bypass.
- **Download Protection Flow**: Extension hooks into `chrome.downloads` (and the web dashboard provides a live drag-and-drop file analyzer / download interceptor) computing client-side SHA-256 hashes to query existing VirusTotal file reports instantly, with direct file upload capability for unindexed binaries.

---

## 1. Overview & Core Concept

- **What It Does**: DeltaShield monitors active browser navigation and incoming downloads. Every target URL and file hash is queried against the VirusTotal API v3. Clean destinations load seamlessly; detected threats (malware, phishing, command-and-control, cryptominers) trigger an instantaneous blocking shield with threat attribution, sandbox analysis metrics, and scan log persistence.
- **Target Audience / Persona**: Security engineers, researchers, remote workers, and safety-conscious web users seeking automated, zero-trust protection against phishing, malicious drive-by downloads, and suspicious web domains without needing to manually copy/paste links into threat scanners.
- **Key Value**: Closes the security gap between browsing and threat intelligence by automating URL and download hash lookups in real time, presenting clear actionable telemetry, and keeping a permanent, searchable audit ledger of all inspected assets.

---

## 2. User Experience & Visual Design

### Key User Flows

1. **Dashboard & Threat Center Overview**:
   - The user opens DeltaShield to an executive Security Operations Center (SOC) view featuring clean stat cards (Total Inspected, Clean, Suspicious, Malicious Blocked, and API Quota).
   - Real-time stream of recent scans displaying timestamp, target resource (URL / file name), engine detection ratio (e.g., `0/89 Clean` or `14/92 Malicious`), threat categories, and direct links to full VirusTotal reports.
2. **Real-Time URL & File Inspection Simulator**:
   - An interactive workbench allows entering any live URL or uploading/dropping a file to perform an immediate live VirusTotal scan.
   - Shows live progress: URL submission $\to$ Analysis ID polling $\to$ Engine verdict aggregation $\to$ Comprehensive report breakdown.
3. **DeltaShield Intercept Warning Screen**:
   - Standalone warning screen simulation (and extension intercept page `intercept.html`) showing threat level, malicious engine tally, identified malware families, URL reputation score, and safety buttons: **Return to Safety (Recommended)** and **Bypass Warning (Proceed Anyway)** with reason logging.
4. **Extension Package Export & Installation Guide**:
   - Dedicated "Extension Package" view generating a ready-to-load Chrome extension bundle. Users can click **Download Extension ZIP** (using client-side JSZip) containing all valid Manifest V3 files (`manifest.json`, `background.js`, `content.js`, `popup.html`, `popup.js`, `intercept.html`, icons, and README).
   - Step-by-step visual onboarding showing how to enable Chrome Developer Mode and load the unpacked extension.
5. **VirusTotal Key & Policy Configuration**:
   - Modal/drawer to configure API key with live verification against `https://www.virustotal.com/api/v3/users/{apiKey}`.
   - Configurable sensitivity thresholds (e.g. block on $\ge 1$ vs $\ge 3$ malicious detections), download hash auto-scan toggle, and domain allowlist/denylist management.

### Visual Identity & Theme

- **Aesthetic Direction**: High-precision cybersecurity monitoring terminal inspired by modern defense platforms (CrowdStrike, Cloudflare Zero Trust, VirusTotal Intelligence). Technical, clean, highly readable, and free of gratuitous sci-fi effects.
- **Color Palette**:
  - Dominant Neutral Canvas: Deep slate `#0B0F19` with structural containers `#111827` and hairline borders `#1F2937`.
  - Primary Accent: Precision cyan `#06B6D4` and cobalt `#2563EB` for high-intent actions, active tabs, and primary controls.
  - Semantic Status:
    - Clean / Verified: Emerald `#10B981` (paired with explicit "Clean" labels).
    - Suspicious / Warning: Amber `#F59E0B`.
    - Malicious / Blocked: Crimson `#EF4444`.
- **Typography & Hierarchy**:
  - Display & Headings: `Plus Jakarta Sans` for crisp titles and navigation.
  - Body: `DM Sans` / `Plus Jakarta Sans` for high density and scannability.
  - Data, Hashes, & Timestamps: Strict monospace tabular figures (`JetBrains Mono` / `tabular-nums`) for SHA-256 hashes, IP addresses, detection ratios, and scan IDs.
- **Component Styling & Layout**:
  - Desktop-first 1440px viewport with a structured 240px sidebar navigation + contextual header + high-density data grid.
  - No decorative pulsing dots; status indicators strictly convey live connection states and verified scan results with accompanying text labels.
  - Zero-pill metadata discipline: tags and timestamps formatted with clean typographic separators (`·` or `/`).

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Dual-Mode Operation (Extension Bundle + In-Browser Simulator)**
  - *Chosen Approach*: Deliver both the complete, exportable Chrome Extension (Manifest V3) codebase with instant one-click ZIP generation AND an integrated in-browser execution harness that mirrors extension behavior directly in AI Studio.
  - *Why*: Allows instant interactive verification and threat testing inside the AI Studio sandbox without requiring the user to switch windows or install extensions before evaluating functionality, while providing the exact production-ready extension package ready for Chrome.
- **Decision 2: Strict VirusTotal API Key Verification & Secure Proxy**
  - *Chosen Approach*: VirusTotal API v3 requests are executed with user-supplied API keys. In the web dashboard preview, queries route through a local Express proxy (`/api/vt/*`) to prevent browser CORS restrictions (as VirusTotal API v3 enforces CORS on client browsers). In the exported Chrome extension, background service workers invoke `fetch` directly with `x-apikey` headers without CORS limits.
  - *Why*: Solves browser sandbox CORS restrictions while ensuring 100% compliance with strict VirusTotal API requirements.
- **Decision 3: SHA-256 Client-Side Hashing for Downloads**
  - *Chosen Approach*: When a file download or upload is intercepted, DeltaShield calculates the SHA-256 hash using the Web Crypto API (`crypto.subtle.digest`) before querying VirusTotal `/api/v3/files/{hash}`.
  - *Why*: Instantaneous analysis without uploading large files unless the file hash is novel, respecting bandwidth and VirusTotal upload rate limits.

---

## 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DeltaShield Architecture                        │
└────────────────────────────────────────────────────────────────────────┘

  [ Browser Navigation / Download Event ]
                    │
                    ▼
  ┌─────────────────────────────────────┐
  │  DeltaShield Service Worker / Core  │
  │  (webRequest / downloads listener)  │
  └──────────────────┬──────────────────┘
                     │  Extract URL or compute SHA-256 hash
                     ▼
  ┌─────────────────────────────────────┐
  │       VirusTotal API v3 Engine      │
  │   - GET /api/v3/urls/{id}           │
  │   - GET /api/v3/files/{hash}        │
  │   - POST /api/v3/urls (rescan)      │
  └──────────────────┬──────────────────┘
                     │ Threat Telemetry Verdict (Clean / Malicious)
                     ▼
      ┌──────────────┴──────────────┐
      │                             │
[ Detection >= Threshold ]    [ Clean / Allowed ]
      │                             │
      ▼                             ▼
┌─────────────────────────┐   ┌───────────────────────────┐
│ Intercept Shield Screen │   │ Direct Navigation Allowed │
│ - Engine ratio breakdown│   │ - Background report log   │
│ - Threat categories     │   └───────────────────────────┘
│ - Bypass vs Go Back     │
└─────────────┬───────────┘
              │
              ▼
┌────────────────────────────────────────────────────────────────────────┐
│                DeltaShield Central SOC Dashboard                       │
│  - Active Scan Stream & Telemetry Ledger (LocalStorage persisted)     │
│  - Interactive Live URL & File Threat Analyzer                        │
│  - Extension Package Builder & ZIP Exporter (Manifest V3)              │
│  - Security Policies, Allowlist/Denylist & VirusTotal API Manager      │
└────────────────────────────────────────────────────────────────────────┘
```

### Data Model & State Entities

- **ScanReport**:
  - `id`: Unique string (UUID or VT analysis ID)
  - `type`: `'url' | 'download' | 'file'`
  - `target`: URL string or File Name
  - `hash`: SHA-256 hash (for downloads/files) or base64 URL identifier
  - `timestamp`: ISO timestamp
  - `status`: `'clean' | 'suspicious' | 'malicious' | 'scanning' | 'error'`
  - `stats`: `{ malicious: number, suspicious: number, harmless: number, undetected: number, timeout: number }`
  - `threatNames`: Array of detected engine classifications (e.g. `Trojan.Generic`, `Phish.Suspicious`)
  - `engineCount`: Total engines scanned (e.g., 88)
  - `permalink`: Direct link to VirusTotal web report
  - `actionTaken`: `'allowed' | 'blocked' | 'bypassed'`
- **DeltaShieldConfig**:
  - `apiKey`: VirusTotal API Key
  - `detectionThreshold`: Minimum malicious engines to trigger intercept (default: 1)
  - `autoScanDownloads`: boolean
  - `autoScanSites`: boolean
  - `allowlist`: Array of approved domains
  - `denylist`: Array of blocked domains

### Implementation Phases & Tasks

1. **Backend API Proxy (`server.ts` & Vite integration)**:
   - Provide `/api/vt/check-key`, `/api/vt/url`, `/api/vt/file`, and `/api/vt/analyze` server-side endpoints forwarding requests with `x-apikey` headers to `https://www.virustotal.com/api/v3/`, handling rate limits and CORS seamlessly.
2. **Chrome Extension Bundle Generator (`src/extension/`)**:
   - `manifest.json`: Manifest V3 specification with `webNavigation`, `declarativeNetRequest`, `downloads`, `storage`, and `alarms` permissions.
   - `background.js`: Service worker implementing `chrome.webNavigation.onBeforeNavigate` and `chrome.downloads.onCreated` listeners, query deduplication cache, and URL redirect to `intercept.html` when malicious.
   - `popup.html` & `popup.js`: Quick extension badge status, active protection switch, recent threats ticker, and quick link to dashboard.
   - `intercept.html` & `intercept.js`: High-visibility security warning screen with threat score, engine breakdown, and audited bypass action.
   - JSZip exporter creating `deltashield-extension.zip` on demand.
3. **DeltaShield Web Dashboard UI**:
   - **Header & Metrics**: Top Bar Contract with brand wordmark, tab navigation (Live Feed, Threat Analyzer, Intercept Simulator, Extension Package, Settings), and API key badge.
   - **Scan Ledger**: High-density table with tabular numerals, search filter, threat classification filter, detail slide-over modal showing full engine verdict breakdown (Kaspersky, BitDefender, Microsoft, Sophos, Google Safebrowsing, etc.).
   - **Interactive Live Threat Analyzer**: Drag-and-drop file upload with client-side SHA-256 hashing and URL input box.
   - **Simulated Browser Intercept Tester**: Test live navigations against known malicious domains or test files (e.g., EICAR test string) to preview the warning screen experience.
