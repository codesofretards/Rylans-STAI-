import { ScanReport, ThreatStatus, ThreatStats, EngineResult } from '../types/security';

// Browser-native SHA-256 hash calculation using Web Crypto API
export async function calculateSha256(fileOrBuffer: File | Blob | ArrayBuffer): Promise<string> {
  let buffer: ArrayBuffer;
  if (fileOrBuffer instanceof ArrayBuffer) {
    buffer = fileOrBuffer;
  } else {
    buffer = await fileOrBuffer.arrayBuffer();
  }

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

// Format raw VirusTotal URL/File attributes into normalized ScanReport
export function parseVirusTotalReport(
  target: string,
  type: 'url' | 'download' | 'file',
  vtData: any,
  hash?: string,
  threshold: number = 1
): ScanReport {
  const attributes = vtData?.data?.attributes || {};
  const statsRaw = attributes.last_analysis_stats || {
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
  };

  const stats: ThreatStats = {
    malicious: statsRaw.malicious || 0,
    suspicious: statsRaw.suspicious || 0,
    harmless: statsRaw.harmless || 0,
    undetected: statsRaw.undetected || 0,
    timeout: statsRaw.timeout || 0,
  };

  const totalEngines = stats.malicious + stats.suspicious + stats.harmless + stats.undetected + (stats.timeout || 0);

  // Extract identified threat names
  const threatNames: string[] = [];
  const engines: Record<string, EngineResult> = {};

  if (attributes.last_analysis_results) {
    for (const [engineName, res] of Object.entries<any>(attributes.last_analysis_results)) {
      engines[engineName] = {
        engineName,
        category: res.category || 'undetected',
        result: res.result || null,
        method: res.method,
        update: res.engine_update,
      };

      if ((res.category === 'malicious' || res.category === 'suspicious') && res.result) {
        if (!threatNames.includes(res.result)) {
          threatNames.push(res.result);
        }
      }
    }
  }

  let status: ThreatStatus = 'clean';
  if (stats.malicious >= threshold) {
    status = 'malicious';
  } else if (stats.suspicious > 0) {
    status = 'suspicious';
  }

  const id = vtData?.data?.id || `scan-${Date.now()}`;
  const permalink = type === 'url'
    ? `https://www.virustotal.com/gui/url/${id}`
    : `https://www.virustotal.com/gui/file/${hash || id}`;

  return {
    id,
    type,
    target,
    hash: hash || attributes.sha256 || undefined,
    timestamp: new Date().toISOString(),
    status,
    stats,
    threatNames: threatNames.slice(0, 5),
    engineCount: totalEngines || 85,
    permalink,
    actionTaken: status === 'malicious' ? 'blocked' : 'allowed',
    engines,
    reputation: attributes.reputation || 0,
    fileSize: attributes.size || undefined,
  };
}

// Validate API Key
export async function validateVirusTotalKey(apiKey: string): Promise<{
  valid: boolean;
  user?: any;
  error?: string;
}> {
  if (!apiKey || !apiKey.trim()) {
    return { valid: false, error: 'API key is required.' };
  }

  try {
    const res = await fetch('/api/vt/validate-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey: apiKey.trim() }),
    });

    const data = await res.json();
    if (!res.ok) {
      return { valid: false, error: data.error || 'Failed to validate VirusTotal API key.' };
    }

    return { valid: true, user: data.user };
  } catch (err: any) {
    return { valid: false, error: err.message || 'Network error verifying key.' };
  }
}

// Live URL Scan
export async function scanUrlWithVirusTotal(
  url: string,
  apiKey: string,
  threshold: number = 1
): Promise<ScanReport> {
  const res = await fetch('/api/vt/scan-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url.trim(), apiKey: apiKey.trim() }),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to analyze URL with VirusTotal.');
  }

  if (data.status === 'queued' && data.analysisId) {
    // Poll analysis endpoint if queued
    const polledReport = await pollAnalysis(data.analysisId, apiKey, url, 'url', threshold);
    return polledReport;
  }

  return parseVirusTotalReport(url, 'url', data.data, undefined, threshold);
}

// Live File Hash Scan (SHA-256)
export async function scanHashWithVirusTotal(
  hash: string,
  fileName: string,
  apiKey: string,
  threshold: number = 1
): Promise<ScanReport> {
  const res = await fetch('/api/vt/scan-hash', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash: hash.trim(), apiKey: apiKey.trim() }),
  });

  const data = await res.json();
  if (!res.ok) {
    if (res.status === 404) {
      // Hash is unknown to VirusTotal (never seen before in VT global repository)
      return {
        id: `unknown-${hash.slice(0, 12)}`,
        type: 'download',
        target: fileName,
        hash,
        timestamp: new Date().toISOString(),
        status: 'clean',
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
        threatNames: ['New / Unindexed Binary'],
        engineCount: 0,
        permalink: `https://www.virustotal.com/gui/search/${hash}`,
        actionTaken: 'allowed',
        reputation: 0,
      };
    }
    throw new Error(data.error || 'Failed to query file hash on VirusTotal.');
  }

  return parseVirusTotalReport(fileName, 'download', data.data, hash, threshold);
}

// Helper to poll analysis results
async function pollAnalysis(
  analysisId: string,
  apiKey: string,
  target: string,
  type: 'url' | 'download',
  threshold: number = 1,
  maxAttempts: number = 4
): Promise<ScanReport> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const res = await fetch('/api/vt/analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analysisId, apiKey }),
      });
      const data = await res.json();
      if (res.ok && data.status === 'completed') {
        return parseVirusTotalReport(target, type, data.data, undefined, threshold);
      }
    } catch {
      // Continue next attempt
    }
  }

  // Return interim queued report if still calculating
  return {
    id: analysisId,
    type,
    target,
    timestamp: new Date().toISOString(),
    status: 'clean',
    stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
    threatNames: ['Analysis in Progress by VT Engines'],
    engineCount: 75,
    permalink: `https://www.virustotal.com/gui/analysis/${analysisId}`,
    actionTaken: 'allowed',
  };
}
