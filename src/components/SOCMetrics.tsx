import React from 'react';
import { ShieldCheck, ShieldAlert, Download, Globe, Radio } from 'lucide-react';
import { ScanReport } from '../types/security';

interface SOCMetricsProps {
  reports: ScanReport[];
  isKeyValid: boolean;
  threshold: number;
}

export const SOCMetrics: React.FC<SOCMetricsProps> = ({ reports, isKeyValid, threshold }) => {
  const totalScans = reports.length;
  const maliciousReports = reports.filter(r => r.status === 'malicious');
  const cleanReports = reports.filter(r => r.status === 'clean');
  const suspiciousReports = reports.filter(r => r.status === 'suspicious');
  const urlScans = reports.filter(r => r.type === 'url').length;
  const downloadScans = reports.filter(r => r.type === 'download').length;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
      {/* 1. Total Scanned */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span>Total Inspected</span>
          <Radio className="w-3.5 h-3.5 text-cyan-400" />
        </div>
        <div className="text-2xl font-bold text-white font-mono tabular-nums">
          {totalScans}
        </div>
        <div className="flex items-center gap-2 mt-2 text-xs text-slate-400">
          <span>{urlScans} URLs</span>
          <span aria-hidden="true">·</span>
          <span>{downloadScans} Downloads</span>
        </div>
      </div>

      {/* 2. Malicious Interceptions */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span>Malicious Interceptions</span>
          <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
        </div>
        <div className="text-2xl font-bold text-red-400 font-mono tabular-nums">
          {maliciousReports.length}
        </div>
        <div className="flex items-center gap-2 mt-2 text-xs text-slate-400">
          <span>Blocked automatically</span>
          <span aria-hidden="true">·</span>
          <span>Shield active</span>
        </div>
      </div>

      {/* 3. Clean Assets */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span>Clean & Harmless</span>
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        </div>
        <div className="text-2xl font-bold text-emerald-400 font-mono tabular-nums">
          {cleanReports.length}
        </div>
        <div className="flex items-center gap-2 mt-2 text-xs text-slate-400">
          <span>Zero threat detections</span>
          <span aria-hidden="true">·</span>
          <span>Allowed</span>
        </div>
      </div>

      {/* 4. Suspicious Flags */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span>Suspicious Flags</span>
          <Globe className="w-3.5 h-3.5 text-amber-400" />
        </div>
        <div className="text-2xl font-bold text-amber-400 font-mono tabular-nums">
          {suspiciousReports.length}
        </div>
        <div className="flex items-center gap-2 mt-2 text-xs text-slate-400">
          <span>Threshold: {threshold}+ engines</span>
          <span aria-hidden="true">·</span>
          <span>Under review</span>
        </div>
      </div>

      {/* 5. VirusTotal API Status */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span>VirusTotal Engine</span>
          <Download className="w-3.5 h-3.5 text-cyan-400" />
        </div>
        <div className="text-sm font-semibold text-white mt-1">
          {isKeyValid ? (
            <span className="text-emerald-400">API v3 Operational</span>
          ) : (
            <span className="text-slate-300">Ready for API Key</span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-2 text-xs text-slate-400">
          <span>Multi-Engine Feeds</span>
          <span aria-hidden="true">·</span>
          <span>90+ AV Vendors</span>
        </div>
      </div>
    </div>
  );
};
