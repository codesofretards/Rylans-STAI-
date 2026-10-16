import { ScanReport, DeltaShieldConfig } from '../types/security';

const STORAGE_REPORTS_KEY = 'deltashield_scan_reports_v1';
const STORAGE_CONFIG_KEY = 'deltashield_config_v1';

export const DEFAULT_CONFIG: DeltaShieldConfig = {
  apiKey: '',
  isKeyValid: false,
  detectionThreshold: 1,
  autoScanSites: true,
  autoScanDownloads: true,
  allowlist: ['github.com', 'google.com', 'virustotal.com', 'microsoft.com'],
  denylist: ['malicious-test-phish.net', 'exploit-payload-drop.org'],
};

// Seed reports for initial zero-state demonstration
const SEED_REPORTS: ScanReport[] = [
  {
    id: 'vt-url-phish-98421',
    type: 'url',
    target: 'http://auth-verify-portal-login.xyz/secure/session',
    timestamp: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
    status: 'malicious',
    stats: { malicious: 19, suspicious: 3, harmless: 0, undetected: 68 },
    threatNames: ['Phishing.CredentialHarvester', 'Spam.MaliciousURL', 'PhishTank.Verified'],
    engineCount: 90,
    permalink: 'https://www.virustotal.com/gui/url/u-auth-verify-portal',
    actionTaken: 'blocked',
    reputation: -68,
    engines: {
      'Kaspersky': { engineName: 'Kaspersky', category: 'malicious', result: 'Phishing.HTML.Suspicious' },
      'BitDefender': { engineName: 'BitDefender', category: 'malicious', result: 'Generic.Malware.Phish' },
      'Google Safebrowsing': { engineName: 'Google Safebrowsing', category: 'malicious', result: 'Social Engineering' },
      'Microsoft': { engineName: 'Microsoft', category: 'malicious', result: 'Phish:HTML/CredentialTheft' },
      'Sophos': { engineName: 'Sophos', category: 'malicious', result: 'Malicious site' },
      'Fortinet': { engineName: 'Fortinet', category: 'malicious', result: 'Phishing' },
      'Avast': { engineName: 'Avast', category: 'malicious', result: 'URL:Malicious' },
      'ESET': { engineName: 'ESET', category: 'malicious', result: 'Phishing payload' },
    }
  },
  {
    id: 'vt-dl-mal-77312',
    type: 'download',
    target: 'statement_reconcile_invoice.pdf.exe',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    timestamp: new Date(Date.now() - 1000 * 60 * 42).toISOString(),
    status: 'malicious',
    stats: { malicious: 54, suspicious: 4, harmless: 0, undetected: 14 },
    threatNames: ['Trojan.Injector.Agent', 'Ransomware.LockBit.Family', 'W32/Kryptik.H'],
    engineCount: 72,
    permalink: 'https://www.virustotal.com/gui/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    actionTaken: 'blocked',
    reputation: -92,
    fileSize: 498320,
    engines: {
      'Kaspersky': { engineName: 'Kaspersky', category: 'malicious', result: 'Trojan.Win32.Injector.gen' },
      'BitDefender': { engineName: 'BitDefender', category: 'malicious', result: 'Trojan.GenericKD.683921' },
      'Microsoft': { engineName: 'Microsoft', category: 'malicious', result: 'Trojan:Win32/Wacatac.B!ml' },
      'CrowdStrike Falcon': { engineName: 'CrowdStrike Falcon', category: 'malicious', result: 'win/malicious_confidence_100%' },
      'Sophos': { engineName: 'Sophos', category: 'malicious', result: 'Troj/Agent-BAX' },
      'SentinelOne': { engineName: 'SentinelOne', category: 'malicious', result: 'Static AI - Malicious PE' },
    }
  },
  {
    id: 'vt-url-clean-11204',
    type: 'url',
    target: 'https://docs.github.com/en/rest',
    timestamp: new Date(Date.now() - 1000 * 60 * 75).toISOString(),
    status: 'clean',
    stats: { malicious: 0, suspicious: 0, harmless: 86, undetected: 4 },
    threatNames: [],
    engineCount: 90,
    permalink: 'https://www.virustotal.com/gui/url/github-docs',
    actionTaken: 'allowed',
    reputation: 85,
    engines: {
      'Kaspersky': { engineName: 'Kaspersky', category: 'harmless', result: 'Clean' },
      'BitDefender': { engineName: 'BitDefender', category: 'harmless', result: 'Clean' },
      'Google Safebrowsing': { engineName: 'Google Safebrowsing', category: 'harmless', result: 'Clean' },
      'Microsoft': { engineName: 'Microsoft', category: 'harmless', result: 'Clean' },
      'Sophos': { engineName: 'Sophos', category: 'harmless', result: 'Clean' },
    }
  },
  {
    id: 'vt-dl-clean-88912',
    type: 'download',
    target: 'vscode-setup-x64-1.92.0.exe',
    hash: '8f4c27a92c30b20f5b9d3e8e19c3b3a728876a4df54b9f2c58e72b4c599182a1',
    timestamp: new Date(Date.now() - 1000 * 60 * 160).toISOString(),
    status: 'clean',
    stats: { malicious: 0, suspicious: 0, harmless: 74, undetected: 2 },
    threatNames: [],
    engineCount: 76,
    permalink: 'https://www.virustotal.com/gui/file/8f4c27a92c30b20f5b9d3e8e19c3b3a728876a4df54b9f2c58e72b4c599182a1',
    actionTaken: 'allowed',
    reputation: 98,
    fileSize: 94827100,
  },
  {
    id: 'vt-url-susp-33019',
    type: 'url',
    target: 'http://freedownload-driver-update-tool.biz/setup',
    timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    status: 'suspicious',
    stats: { malicious: 0, suspicious: 3, harmless: 42, undetected: 44 },
    threatNames: ['PUA.UnwantedSoftware', 'Riskware.Installer'],
    engineCount: 89,
    permalink: 'https://www.virustotal.com/gui/url/freedownload-biz',
    actionTaken: 'allowed',
    reputation: -12,
  }
];

export function loadReports(): ScanReport[] {
  try {
    const raw = localStorage.getItem(STORAGE_REPORTS_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_REPORTS_KEY, JSON.stringify(SEED_REPORTS));
      return SEED_REPORTS;
    }
    return JSON.parse(raw);
  } catch {
    return SEED_REPORTS;
  }
}

export function saveReport(report: ScanReport): ScanReport[] {
  const current = loadReports();
  // Filter out any older duplicate with same target & type
  const updated = [report, ...current.filter(r => r.id !== report.id && r.target !== report.target)].slice(0, 200);
  try {
    localStorage.setItem(STORAGE_REPORTS_KEY, JSON.stringify(updated));
  } catch (err) {
    console.error('Failed to persist scan report to storage', err);
  }
  return updated;
}

export function updateReportAction(id: string, action: 'allowed' | 'blocked' | 'bypassed', reason?: string): ScanReport[] {
  const current = loadReports();
  const updated = current.map(r => {
    if (r.id === id) {
      return { ...r, actionTaken: action, bypassReason: reason || r.bypassReason };
    }
    return r;
  });
  try {
    localStorage.setItem(STORAGE_REPORTS_KEY, JSON.stringify(updated));
  } catch (err) {
    console.error('Failed to update report action', err);
  }
  return updated;
}

export function clearReports(): ScanReport[] {
  try {
    localStorage.setItem(STORAGE_REPORTS_KEY, JSON.stringify([]));
  } catch {}
  return [];
}

export function loadConfig(): DeltaShieldConfig {
  try {
    const raw = localStorage.getItem(STORAGE_CONFIG_KEY);
    if (!raw) return DEFAULT_CONFIG;
    const parsed = JSON.parse(raw);
    return {
      apiKey: typeof parsed.apiKey === 'string' ? parsed.apiKey : '',
      isKeyValid: Boolean(parsed.isKeyValid),
      detectionThreshold: typeof parsed.detectionThreshold === 'number' && !isNaN(parsed.detectionThreshold) ? parsed.detectionThreshold : 1,
      autoScanSites: parsed.autoScanSites !== false,
      autoScanDownloads: parsed.autoScanDownloads !== false,
      allowlist: Array.isArray(parsed.allowlist) ? parsed.allowlist : DEFAULT_CONFIG.allowlist,
      denylist: Array.isArray(parsed.denylist) ? parsed.denylist : DEFAULT_CONFIG.denylist,
      userGroup: parsed.userGroup || undefined,
      apiQuota: parsed.apiQuota || undefined,
    };
  } catch {
    return DEFAULT_CONFIG;
  }
}

export function saveConfig(config: DeltaShieldConfig): void {
  try {
    localStorage.setItem(STORAGE_CONFIG_KEY, JSON.stringify(config));
  } catch (err) {
    console.error('Failed to persist config', err);
  }
}
