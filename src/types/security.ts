export type ThreatStatus = 'clean' | 'suspicious' | 'malicious' | 'scanning' | 'error';
export type ScanType = 'url' | 'download' | 'file';
export type ActionTaken = 'allowed' | 'blocked' | 'bypassed';

export interface ThreatStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout?: number;
}

export interface EngineResult {
  engineName: string;
  category: 'malicious' | 'suspicious' | 'harmless' | 'undetected';
  result?: string | null;
  method?: string;
  update?: string;
}

export interface ScanReport {
  id: string;
  type: ScanType;
  target: string; // URL or filename
  hash?: string; // SHA-256 hash
  timestamp: string;
  status: ThreatStatus;
  stats: ThreatStats;
  threatNames: string[];
  engineCount: number;
  permalink?: string;
  actionTaken: ActionTaken;
  bypassReason?: string;
  engines?: Record<string, EngineResult>;
  reputation?: number;
  fileSize?: number;
}

export interface DeltaShieldConfig {
  apiKey: string;
  isKeyValid: boolean;
  userEmail?: string;
  userGroup?: string;
  apiQuota?: {
    dailyAllowed?: number;
    dailyUsed?: number;
    hourlyAllowed?: number;
    hourlyUsed?: number;
  };
  detectionThreshold: number; // minimum malicious engines to trigger intercept (default 1)
  autoScanSites: boolean;
  autoScanDownloads: boolean;
  allowlist: string[];
  denylist: string[];
}
