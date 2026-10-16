import JSZip from 'jszip';

// Manifest V3 definition
export const MANIFEST_JSON = {
  manifest_version: 3,
  name: 'DeltaShield - VirusTotal Threat Protection',
  version: '1.0.0',
  description: 'Automated real-time VirusTotal threat scanning for visited sites and downloads with active threat interception.',
  permissions: [
    'storage',
    'webNavigation',
    'downloads',
    'notifications',
    'tabs'
  ],
  host_permissions: [
    '<all_urls>',
    'https://www.virustotal.com/*'
  ],
  background: {
    service_worker: 'background.js',
    type: 'module'
  },
  action: {
    default_popup: 'popup.html',
    default_title: 'DeltaShield Security Status',
    default_icon: {
      16: 'icons/icon16.png',
      48: 'icons/icon48.png',
      128: 'icons/icon128.png'
    }
  },
  options_page: 'options.html',
  web_accessible_resources: [
    {
      resources: ['intercept.html', 'icons/*'],
      matches: ['<all_urls>']
    }
  ],
  icons: {
    16: 'icons/icon16.png',
    48: 'icons/icon48.png',
    128: 'icons/icon128.png'
  }
};

// Background Service Worker
export const BACKGROUND_JS = `// DeltaShield Chrome Extension - Background Service Worker (Manifest V3)
const CACHE_EXPIRY_MS = 1000 * 60 * 30; // 30 minutes cache
const urlCache = new Map();
const bypassedUrls = new Set();

// Utility: Normalize and encode URL for VirusTotal v3 API
function getVirusTotalUrlId(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    // Ignore internal protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    const cleanUrl = parsed.origin + parsed.pathname + parsed.search;
    const base64 = btoa(cleanUrl).replace(/=/g, '');
    return { urlId: base64, cleanUrl };
  } catch (e) {
    return null;
  }
}

// Retrieve settings from sync storage
async function getConfig() {
  const result = await chrome.storage.sync.get({
    apiKey: '',
    detectionThreshold: 1,
    autoScanSites: true,
    autoScanDownloads: true,
    allowlist: ['google.com', 'virustotal.com', 'github.com', 'microsoft.com'],
    denylist: []
  });
  return result;
}

// Log scan report to local storage
async function logScanReport(report) {
  try {
    const { scanHistory = [] } = await chrome.storage.local.get({ scanHistory: [] });
    const updated = [report, ...scanHistory.filter(r => r.id !== report.id && r.target !== report.target)].slice(0, 100);
    await chrome.storage.local.set({ scanHistory: updated });
  } catch (err) {
    console.error('[DeltaShield] Failed to record report:', err);
  }
}

// VirusTotal URL lookup
async function checkUrlWithVirusTotal(targetUrl, apiKey, threshold) {
  const meta = getVirusTotalUrlId(targetUrl);
  if (!meta) return { safe: true };

  // Check in-memory cache
  if (urlCache.has(meta.cleanUrl)) {
    const cached = urlCache.get(meta.cleanUrl);
    if (Date.now() - cached.timestamp < CACHE_EXPIRY_MS) {
      return cached.result;
    }
  }

  try {
    const res = await fetch(\`https://www.virustotal.com/api/v3/urls/\${meta.urlId}\`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      }
    });

    if (res.status === 404) {
      // Submit URL for async analysis
      fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: \`url=\${encodeURIComponent(meta.cleanUrl)}\`
      }).catch(() => {});

      const result = { safe: true, pending: true };
      urlCache.set(meta.cleanUrl, { timestamp: Date.now(), result });
      return result;
    }

    if (!res.ok) {
      return { safe: true, error: 'VT API returned ' + res.status };
    }

    const json = await res.json();
    const stats = json?.data?.attributes?.last_analysis_stats || { malicious: 0, suspicious: 0 };
    const threatNames = [];
    const results = json?.data?.attributes?.last_analysis_results || {};
    
    for (const [engine, info] of Object.entries(results)) {
      if ((info.category === 'malicious' || info.category === 'suspicious') && info.result) {
        if (!threatNames.includes(info.result)) threatNames.push(info.result);
      }
    }

    const isMalicious = stats.malicious >= threshold;
    const scanReport = {
      id: json?.data?.id || 'vt-' + Date.now(),
      type: 'url',
      target: meta.cleanUrl,
      timestamp: new Date().toISOString(),
      status: isMalicious ? 'malicious' : stats.suspicious > 0 ? 'suspicious' : 'clean',
      stats,
      threatNames: threatNames.slice(0, 5),
      engineCount: Object.keys(results).length || 85,
      permalink: \`https://www.virustotal.com/gui/url/\${meta.urlId}\`,
      actionTaken: isMalicious ? 'blocked' : 'allowed'
    };

    await logScanReport(scanReport);

    const verdict = {
      safe: !isMalicious,
      stats,
      threatNames,
      reportId: json?.data?.id,
      permalink: scanReport.permalink
    };

    urlCache.set(meta.cleanUrl, { timestamp: Date.now(), result: verdict });
    return verdict;
  } catch (err) {
    console.warn('[DeltaShield] VT Query failed:', err);
    return { safe: true, error: err.message };
  }
}

// 1. Navigation Listener: Inspect visited URLs
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only top-level main frame
  const url = details.url;
  
  // Ignore chrome://, extension URLs, and user bypassed URLs
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.includes('/intercept.html')) {
    return;
  }
  if (bypassedUrls.has(url)) {
    return;
  }

  const config = await getConfig();
  if (!config.autoScanSites || !config.apiKey) return;

  const urlObj = new URL(url);
  // Check domain allowlist
  if (config.allowlist.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain))) {
    return;
  }

  // Check domain denylist
  if (config.denylist.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain))) {
    const interceptUrl = chrome.runtime.getURL(\`intercept.html?target=\${encodeURIComponent(url)}&reason=denylist&engines=Denylist\`);
    chrome.tabs.update(details.tabId, { url: interceptUrl });
    return;
  }

  const verdict = await checkUrlWithVirusTotal(url, config.apiKey, config.detectionThreshold);

  if (!verdict.safe) {
    const params = new URLSearchParams({
      target: url,
      malicious: verdict.stats?.malicious || 1,
      suspicious: verdict.stats?.suspicious || 0,
      engines: verdict.threatNames?.join(', ') || 'Known Malicious URL',
      permalink: verdict.permalink || ''
    });
    const interceptUrl = chrome.runtime.getURL(\`intercept.html?\${params.toString()}\`);
    chrome.tabs.update(details.tabId, { url: interceptUrl });
  }
});

// 2. Download Listener: Inspect incoming downloads
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const config = await getConfig();
  if (!config.autoScanDownloads || !config.apiKey) return;

  const downloadUrl = downloadItem.url || downloadItem.finalUrl;
  if (!downloadUrl) return;

  const verdict = await checkUrlWithVirusTotal(downloadUrl, config.apiKey, config.detectionThreshold);

  if (!verdict.safe) {
    // Pause malicious download immediately
    try {
      await chrome.downloads.pause(downloadItem.id);
    } catch (e) {}

    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'DeltaShield Download Blocked',
      message: \`Malicious payload detected: \${downloadItem.filename || 'download'}. VirusTotal detections: \${verdict.stats?.malicious || 1}\`,
      priority: 2
    });

    const params = new URLSearchParams({
      target: downloadItem.filename || downloadUrl,
      malicious: verdict.stats?.malicious || 1,
      suspicious: verdict.stats?.suspicious || 0,
      engines: verdict.threatNames?.join(', ') || 'Trojan / Exploit payload',
      permalink: verdict.permalink || '',
      type: 'download',
      downloadId: downloadItem.id
    });

    chrome.tabs.create({ url: chrome.runtime.getURL(\`intercept.html?\${params.toString()}\`) });
  }
});

// Message handling for Bypass & Config from extension pages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'BYPASS_URL' && message.url) {
    bypassedUrls.add(message.url);
    // Allow for 15 minutes
    setTimeout(() => bypassedUrls.delete(message.url), 15 * 60 * 1000);
    sendResponse({ success: true });
  } else if (message.type === 'GET_STATUS') {
    sendResponse({ active: true, cacheSize: urlCache.size });
  }
  return true;
});
`;

// Intercept Screen HTML
export const INTERCEPT_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DeltaShield Threat Intercept</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #0b0f19;
      color: #f1f5f9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      max-width: 680px;
      width: 100%;
      padding: 36px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
    }
    .header {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 24px;
      padding-bottom: 20px;
      border-bottom: 1px solid #1f2937;
    }
    .shield-icon {
      width: 52px;
      height: 52px;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ef4444;
      flex-shrink: 0;
    }
    .brand-title {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #06b6d4;
      font-weight: 600;
      margin-bottom: 4px;
    }
    h1 {
      font-size: 22px;
      font-weight: 700;
      color: #ffffff;
    }
    .target-box {
      background: #0b0f19;
      border: 1px solid #1f2937;
      padding: 14px 18px;
      border-radius: 8px;
      margin-bottom: 24px;
      word-break: break-all;
    }
    .target-label {
      font-size: 11px;
      text-transform: uppercase;
      color: #64748b;
      margin-bottom: 4px;
    }
    .target-url {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 13px;
      color: #f87171;
    }
    .threat-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 24px;
    }
    .threat-stat {
      background: #1e293b;
      border: 1px solid #334155;
      padding: 16px;
      border-radius: 8px;
    }
    .threat-stat-title {
      font-size: 12px;
      color: #94a3b8;
      margin-bottom: 4px;
    }
    .threat-stat-val {
      font-size: 20px;
      font-weight: 700;
      color: #ef4444;
      font-variant-numeric: tabular-nums;
    }
    .tags-section {
      margin-bottom: 28px;
      font-size: 13px;
      color: #94a3b8;
    }
    .tags-section strong {
      color: #e2e8f0;
    }
    .actions {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .btn-safety {
      background: #2563eb;
      color: white;
      border: none;
      padding: 14px 20px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      text-align: center;
      transition: background 0.15s;
    }
    .btn-safety:hover { background: #1d4ed8; }
    .btn-bypass {
      background: transparent;
      color: #94a3b8;
      border: 1px solid #334155;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 13px;
      cursor: pointer;
      text-align: center;
      transition: all 0.15s;
    }
    .btn-bypass:hover {
      background: rgba(239, 68, 68, 0.08);
      color: #fca5a5;
      border-color: rgba(239, 68, 68, 0.4);
    }
    .permalink-link {
      color: #06b6d4;
      text-decoration: none;
      font-size: 12px;
      display: inline-block;
      margin-top: 6px;
    }
    .permalink-link:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="shield-icon">
        <svg width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01"/>
        </svg>
      </div>
      <div>
        <div class="brand-title">DeltaShield Threat Defense</div>
        <h1>Security Threat Intercepted</h1>
      </div>
    </div>

    <div class="target-box">
      <div class="target-label" id="type-label">Suspicious Target URL</div>
      <div class="target-url" id="target-display">Analyzing...</div>
    </div>

    <div class="threat-grid">
      <div class="threat-stat">
        <div class="threat-stat-title">Malicious Engine Detections</div>
        <div class="threat-stat-val" id="malicious-count">0 Detections</div>
      </div>
      <div class="threat-stat">
        <div class="threat-stat-title">Risk Assessment</div>
        <div class="threat-stat-val" style="color: #f87171;">High Threat</div>
      </div>
    </div>

    <div class="tags-section">
      <div><strong>Identified Signatures:</strong> <span id="threat-names">Phishing / Malicious Payload</span></div>
      <div id="permalink-container"></div>
    </div>

    <div class="actions">
      <button class="btn-safety" id="btn-back">Return to Safety (Recommended)</button>
      <button class="btn-bypass" id="btn-bypass">I understand the risks, bypass and proceed</button>
    </div>
  </div>

  <script src="intercept.js"></script>
</body>
</html>`;

// Intercept Screen Script
export const INTERCEPT_JS = `const params = new URLSearchParams(window.location.search);
const target = params.get('target') || 'Unknown Destination';
const malicious = params.get('malicious') || '1+';
const engines = params.get('engines') || 'Security engine detection';
const permalink = params.get('permalink') || '';
const isDownload = params.get('type') === 'download';

document.getElementById('target-display').textContent = target;
document.getElementById('type-label').textContent = isDownload ? 'Malicious Download Payload' : 'Suspicious Target URL';
document.getElementById('malicious-count').textContent = malicious + ' Engines';
document.getElementById('threat-names').textContent = engines;

if (permalink) {
  const container = document.getElementById('permalink-container');
  const a = document.createElement('a');
  a.href = permalink;
  a.target = '_blank';
  a.className = 'permalink-link';
  a.textContent = 'View verified VirusTotal Intelligence Report →';
  container.appendChild(a);
}

document.getElementById('btn-back').addEventListener('click', () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = 'https://www.google.com';
  }
});

document.getElementById('btn-bypass').addEventListener('click', () => {
  const confirmBypass = confirm('Are you sure you want to bypass DeltaShield protection? This site or download contains confirmed malicious signatures.');
  if (confirmBypass) {
    chrome.runtime.sendMessage({ type: 'BYPASS_URL', url: target }, () => {
      window.location.href = target;
    });
  }
});
`;

// Extension Popup HTML
export const POPUP_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DeltaShield</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      width: 320px;
      background: #0b0f19;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 16px;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: 12px;
      border-bottom: 1px solid #1f2937;
      margin-bottom: 12px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 700;
      font-size: 14px;
      color: #ffffff;
    }
    .brand span { color: #06b6d4; }
    .status-badge {
      font-size: 11px;
      color: #10b981;
      font-weight: 600;
    }
    .stats-card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 12px;
    }
    .stat-row {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      padding: 4px 0;
      color: #94a3b8;
    }
    .stat-row strong {
      color: #f1f5f9;
      font-family: ui-monospace, monospace;
    }
    .btn-dashboard {
      display: block;
      width: 100%;
      background: #2563eb;
      color: white;
      text-align: center;
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      padding: 10px;
      border-radius: 6px;
      cursor: pointer;
      border: none;
    }
    .btn-dashboard:hover { background: #1d4ed8; }
    .recent-title {
      font-size: 11px;
      text-transform: uppercase;
      color: #64748b;
      margin-bottom: 6px;
      font-weight: 600;
    }
    .recent-list {
      max-height: 120px;
      overflow-y: auto;
      font-size: 11px;
      margin-bottom: 12px;
    }
    .recent-item {
      padding: 6px 0;
      border-bottom: 1px solid #1e293b;
      display: flex;
      justify-content: space-between;
      gap: 8px;
    }
    .recent-url {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      color: #cbd5e1;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <svg width="18" height="18" fill="none" stroke="#06b6d4" stroke-width="2" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Delta<span>Shield</span>
    </div>
    <div class="status-badge" id="protection-status">Active</div>
  </div>

  <div class="stats-card">
    <div class="stat-row">
      <span>VirusTotal Real-time Engine</span>
      <strong id="api-status">Connected</strong>
    </div>
    <div class="stat-row">
      <span>Web & Download Protection</span>
      <strong>Enabled</strong>
    </div>
    <div class="stat-row">
      <span>Threat Detections</span>
      <strong id="threats-count" style="color: #ef4444;">0</strong>
    </div>
  </div>

  <div class="recent-title">Recent Scans</div>
  <div class="recent-list" id="recent-scans">
    <div style="color: #64748b; text-align: center; padding: 12px 0;">No active scans yet</div>
  </div>

  <button class="btn-dashboard" id="open-dashboard">Open Threat Operations Dashboard</button>

  <script src="popup.js"></script>
</body>
</html>`;

// Extension Popup Script
export const POPUP_JS = `document.addEventListener('DOMContentLoaded', async () => {
  const { apiKey } = await chrome.storage.sync.get({ apiKey: '' });
  const apiStatusEl = document.getElementById('api-status');
  if (!apiKey) {
    apiStatusEl.textContent = 'Key Required';
    apiStatusEl.style.color = '#f59e0b';
  }

  const { scanHistory = [] } = await chrome.storage.local.get({ scanHistory: [] });
  const threatsCount = scanHistory.filter(r => r.status === 'malicious').length;
  document.getElementById('threats-count').textContent = threatsCount;

  const recentList = document.getElementById('recent-scans');
  if (scanHistory.length > 0) {
    recentList.innerHTML = '';
    scanHistory.slice(0, 5).forEach(item => {
      const div = document.createElement('div');
      div.className = 'recent-item';
      const cleanTarget = item.target.replace(/^https?:\\/\\//, '');
      div.innerHTML = \`
        <span class="recent-url" title="\${item.target}">\${cleanTarget}</span>
        <span style="color: \${item.status === 'malicious' ? '#ef4444' : '#10b981'}; font-weight: 600;">
          \${item.status === 'malicious' ? item.stats.malicious + ' threats' : 'Clean'}
        </span>
      \`;
      recentList.appendChild(div);
    });
  }

  document.getElementById('open-dashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html') });
  });
});
`;

// Extension Options HTML
export const OPTIONS_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DeltaShield Extension Settings</title>
  <style>
    body {
      background: #0b0f19;
      color: #f1f5f9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      max-width: 640px;
      margin: 40px auto;
      padding: 24px;
    }
    h1 { font-size: 22px; margin-bottom: 8px; color: #fff; }
    p { color: #94a3b8; font-size: 14px; margin-bottom: 24px; }
    .form-group { margin-bottom: 20px; }
    label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; color: #cbd5e1; }
    input[type="text"], input[type="password"] {
      width: 100%;
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 6px;
      padding: 10px 14px;
      color: #fff;
      font-family: monospace;
      font-size: 13px;
    }
    .btn-save {
      background: #2563eb;
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-save:hover { background: #1d4ed8; }
    .saved-msg { color: #10b981; font-size: 13px; margin-left: 12px; display: none; }
  </style>
</head>
<body>
  <h1>DeltaShield Configuration</h1>
  <p>Manage your VirusTotal API key and real-time defense policies.</p>

  <div class="form-group">
    <label>VirusTotal API Key (v3)</label>
    <input type="password" id="api-key" placeholder="Enter 64-character VirusTotal API Key">
  </div>

  <div class="form-group">
    <label>Malicious Engine Threshold</label>
    <input type="text" id="threshold" value="1" style="width: 80px;">
  </div>

  <button class="btn-save" id="btn-save">Save Settings</button>
  <span class="saved-msg" id="saved-msg">✓ Settings saved successfully</span>

  <script src="options.js"></script>
</body>
</html>`;

export const OPTIONS_JS = `document.addEventListener('DOMContentLoaded', async () => {
  const config = await chrome.storage.sync.get({ apiKey: '', detectionThreshold: 1 });
  document.getElementById('api-key').value = config.apiKey || '';
  document.getElementById('threshold').value = config.detectionThreshold || 1;

  document.getElementById('btn-save').addEventListener('click', async () => {
    const apiKey = document.getElementById('api-key').value.trim();
    const detectionThreshold = parseInt(document.getElementById('threshold').value, 10) || 1;

    await chrome.storage.sync.set({ apiKey, detectionThreshold });
    const msg = document.getElementById('saved-msg');
    msg.style.display = 'inline';
    setTimeout(() => { msg.style.display = 'none'; }, 2500);
  });
});
`;

export const EXTENSION_README = `# DeltaShield Chrome Extension (Manifest V3)

DeltaShield protects you by automatically checking every URL you navigate to and every file you download against the VirusTotal API v3 in real time. If malicious engines flag a destination, DeltaShield intercepts execution and presents a warning screen.

## Installation in Google Chrome

1. Unzip the downloaded \`deltashield-extension-v1.0.0.zip\` file into a folder on your computer.
2. In Google Chrome, navigate to: \`chrome://extensions/\`
3. Toggle on **Developer mode** in the top right corner.
4. Click the **Load unpacked** button in the top left.
5. Select the unzipped folder containing \`manifest.json\`.
6. Click the DeltaShield shield icon in your Chrome toolbar, configure your **VirusTotal API Key**, and automated protection begins immediately!
`;

// Helper to bundle all extension files into a downloadable ZIP
export async function generateExtensionZip(userApiKey?: string): Promise<Blob> {
  const zip = new JSZip();

  // Create manifest
  zip.file('manifest.json', JSON.stringify(MANIFEST_JSON, null, 2));

  // If user provided an API key in the web dashboard, pre-seed it into background config
  const backgroundContent = userApiKey
    ? BACKGROUND_JS.replace("apiKey: '',", `apiKey: '${userApiKey.trim()}',`)
    : BACKGROUND_JS;

  zip.file('background.js', backgroundContent);
  zip.file('intercept.html', INTERCEPT_HTML);
  zip.file('intercept.js', INTERCEPT_JS);
  zip.file('popup.html', POPUP_HTML);
  zip.file('popup.js', POPUP_JS);
  zip.file('options.html', OPTIONS_HTML);
  zip.file('options.js', OPTIONS_JS);
  zip.file('README.md', EXTENSION_README);

  // Generate lightweight SVG icons for extension
  const iconsFolder = zip.folder('icons');
  if (iconsFolder) {
    const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;
    iconsFolder.file('icon.svg', svgIcon);
    // Base64 transparent 1x1 png placeholder for compatibility
    const pngPlaceholder = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    iconsFolder.file('icon16.png', pngPlaceholder, { base64: true });
    iconsFolder.file('icon48.png', pngPlaceholder, { base64: true });
    iconsFolder.file('icon128.png', pngPlaceholder, { base64: true });
  }

  const content = await zip.generateAsync({ type: 'blob' });
  return content;
}
