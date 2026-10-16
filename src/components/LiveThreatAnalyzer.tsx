import React, { useState, useRef } from 'react';
import { Globe, FileUp, ShieldAlert, ShieldCheck, AlertCircle, Loader2, ArrowRight, Key, Sparkles } from 'lucide-react';
import { calculateSha256, scanUrlWithVirusTotal, scanHashWithVirusTotal } from '../services/virusTotalService';
import { ScanReport, DeltaShieldConfig } from '../types/security';

interface LiveThreatAnalyzerProps {
  config: DeltaShieldConfig;
  onScanComplete: (report: ScanReport) => void;
  onOpenConfig: () => void;
  onPreviewIntercept: (report: ScanReport) => void;
}

export const LiveThreatAnalyzer: React.FC<LiveThreatAnalyzerProps> = ({
  config,
  onScanComplete,
  onOpenConfig,
  onPreviewIntercept,
}) => {
  const [activeMode, setActiveMode] = useState<'url' | 'file'>('url');
  const [urlInput, setUrlInput] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [latestReport, setLatestReport] = useState<ScanReport | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Pre-set security benchmark test samples
  const testSamples = [
    {
      label: 'Clean Domain (Wikipedia)',
      type: 'url' as const,
      value: 'https://www.wikipedia.org',
    },
    {
      label: 'Simulated Phishing Domain',
      type: 'url' as const,
      value: 'http://auth-verify-portal-login.xyz/secure/session',
    },
    {
      label: 'EICAR Standard Antivirus Test Hash',
      type: 'hash' as const,
      value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      name: 'eicar.com.txt',
    },
    {
      label: 'Emotet Banking Trojan Hash',
      type: 'hash' as const,
      value: '4a309e4a3b1a8d5f3089d43506e938e260ffffeae9d1366b837c7684dd934448',
      name: 'emotet_dropper.bin',
    },
  ];

  const handleUrlScan = async (targetUrl?: string) => {
    const url = (targetUrl || urlInput).trim();
    if (!url) {
      setError('Please provide a URL to inspect.');
      return;
    }

    if (!config.apiKey) {
      setError('VirusTotal API key is required for live threat analysis.');
      onOpenConfig();
      return;
    }

    setIsScanning(true);
    setError(null);
    setLatestReport(null);

    try {
      const report = await scanUrlWithVirusTotal(url, config.apiKey, config.detectionThreshold);
      setLatestReport(report);
      onScanComplete(report);
    } catch (err: any) {
      setError(err.message || 'Scan failed.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      setFile(selected);
      setError(null);
      setLatestReport(null);

      try {
        const hash = await calculateSha256(selected);
        setFileHash(hash);
      } catch (err: any) {
        setError('Failed to compute file SHA-256 hash.');
      }
    }
  };

  const handleFileHashScan = async (targetHash?: string, targetName?: string) => {
    const hash = targetHash || fileHash;
    const name = targetName || file?.name || 'uploaded_payload.bin';

    if (!hash) {
      setError('Please select a file or specify a SHA-256 hash.');
      return;
    }

    if (!config.apiKey) {
      setError('VirusTotal API key is required for live threat analysis.');
      onOpenConfig();
      return;
    }

    setIsScanning(true);
    setError(null);
    setLatestReport(null);

    try {
      const report = await scanHashWithVirusTotal(hash, name, config.apiKey, config.detectionThreshold);
      setLatestReport(report);
      onScanComplete(report);
    } catch (err: any) {
      setError(err.message || 'Scan failed.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner if API Key is missing */}
      {!config.apiKey && (
        <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-900/50 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <div className="text-sm font-semibold text-amber-300">VirusTotal API Key Required</div>
              <p className="text-xs text-slate-300 mt-0.5">
                DeltaShield queries VirusTotal API v3 in real time. Please connect your free or enterprise API key to run live URL and file scans.
              </p>
            </div>
          </div>
          <button
            onClick={onOpenConfig}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-amber-600 hover:bg-amber-500 rounded-lg transition-colors shrink-0"
          >
            <Key className="w-3.5 h-3.5" />
            <span>Enter API Key</span>
          </button>
        </div>
      )}

      {/* Mode Selector Tabs */}
      <div className="flex items-center gap-2 p-1 bg-slate-900 border border-slate-800 rounded-lg max-w-md">
        <button
          onClick={() => { setActiveMode('url'); setError(null); }}
          className={`flex-1 flex items-center justify-center gap-2 py-2 text-xs font-medium rounded-md transition-colors ${
            activeMode === 'url' ? 'bg-cyan-950 text-cyan-200 border border-cyan-800/60 shadow-sm' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>Web URL Scanner</span>
        </button>
        <button
          onClick={() => { setActiveMode('file'); setError(null); }}
          className={`flex-1 flex items-center justify-center gap-2 py-2 text-xs font-medium rounded-md transition-colors ${
            activeMode === 'file' ? 'bg-cyan-950 text-cyan-200 border border-cyan-800/60 shadow-sm' : 'text-slate-400 hover:text-white'
          }`}
        >
          <FileUp className="w-4 h-4" />
          <span>Download & File Hash Analyzer</span>
        </button>
      </div>

      {/* Main Scan Workbench Card */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
        {activeMode === 'url' ? (
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Inspect Target URL via VirusTotal API v3
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="url"
                value={urlInput || ''}
                onChange={e => setUrlInput(e.target.value)}
                placeholder="https://example.com/login or http://suspicious-download.link/file.exe"
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 transition-colors"
                onKeyDown={e => { if (e.key === 'Enter') handleUrlScan(); }}
              />
              <button
                onClick={() => handleUrlScan()}
                disabled={isScanning}
                className="flex items-center justify-center gap-2 px-6 py-2.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg transition-colors shrink-0"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Analyzing Engines...</span>
                  </>
                ) : (
                  <>
                    <span>Execute Scan</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        ) : (
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Calculate Client-Side SHA-256 & Query VirusTotal
            </label>

            {/* Drag & drop box */}
            <div
              onClick={() => fileInputRef.current?.click()}
              className="p-8 border-2 border-dashed border-slate-800 hover:border-cyan-600/60 rounded-xl bg-slate-950/60 text-center cursor-pointer transition-colors"
            >
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileChange}
                className="hidden"
              />
              <FileUp className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
              <div className="text-sm font-medium text-slate-200">
                {file ? file.name : 'Click to select or drop any file to inspect'}
              </div>
              <div className="text-xs text-slate-500 mt-1">
                {file ? `${(file.size / 1024).toFixed(1)} KB` : 'Executable, archive, script, document or installer'}
              </div>
            </div>

            {fileHash && (
              <div className="mt-4 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="truncate">
                  <span className="text-slate-400 mr-2">SHA-256 Hash:</span>
                  <span className="font-mono text-cyan-300 select-all">{fileHash}</span>
                </div>
                <button
                  onClick={() => handleFileHashScan()}
                  disabled={isScanning}
                  className="px-4 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg transition-colors shrink-0"
                >
                  {isScanning ? 'Querying VT...' : 'Analyze Hash'}
                </button>
              </div>
            )}
          </div>
        )}

        {/* Security Benchmark Quick Test Buttons */}
        <div className="pt-4 border-t border-slate-800">
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-3">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Quick Threat Benchmark Samples (Click to execute immediately)</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {testSamples.map((sample, idx) => (
              <button
                key={idx}
                disabled={isScanning}
                onClick={() => {
                  if (sample.type === 'url') {
                    setUrlInput(sample.value);
                    handleUrlScan(sample.value);
                  } else {
                    setFileHash(sample.value);
                    handleFileHashScan(sample.value, sample.name);
                  }
                }}
                className="p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800/80 border border-slate-800/80 text-left text-xs text-slate-300 hover:text-white transition-colors flex items-center justify-between group"
              >
                <div>
                  <div className="font-medium">{sample.label}</div>
                  <div className="font-mono text-[11px] text-slate-500 truncate max-w-xs">{sample.value}</div>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors shrink-0 ml-2" />
              </button>
            ))}
          </div>
        </div>

        {/* Error message */}
        {error && (
          <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/50 text-xs text-red-300">
            {error}
          </div>
        )}
      </div>

      {/* Latest Report Verdict Card */}
      {latestReport && (
        <div className={`p-6 rounded-xl border ${
          latestReport.status === 'malicious'
            ? 'bg-red-950/20 border-red-900/60'
            : latestReport.status === 'suspicious'
            ? 'bg-amber-950/20 border-amber-900/60'
            : 'bg-emerald-950/20 border-emerald-900/60'
        }`}>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              {latestReport.status === 'malicious' ? (
                <ShieldAlert className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
              ) : (
                <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
              )}
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">
                    {latestReport.status === 'malicious'
                      ? 'Threat Detected by VirusTotal'
                      : 'Asset Verified Clean & Harmless'}
                  </h3>
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                    latestReport.status === 'malicious' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {latestReport.stats.malicious} / {latestReport.engineCount} Engines Flagged
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-mono mt-1 break-all">
                  {latestReport.target}
                </p>
                {latestReport.threatNames.length > 0 && (
                  <div className="flex items-center gap-2 text-xs text-red-400 mt-2 font-mono">
                    <span>Identified:</span>
                    <span>{latestReport.threatNames.join(' · ')}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3 shrink-0">
              {latestReport.status === 'malicious' && (
                <button
                  onClick={() => onPreviewIntercept(latestReport)}
                  className="px-4 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors whitespace-nowrap"
                >
                  Preview Intercept Shield
                </button>
              )}
              {latestReport.permalink && (
                <a
                  href={latestReport.permalink}
                  target="_blank"
                  rel="noreferrer"
                  className="px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap"
                >
                  VirusTotal Intel →
                </a>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
