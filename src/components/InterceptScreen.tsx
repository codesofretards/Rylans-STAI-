import React, { useState } from 'react';
import { ShieldAlert, ArrowLeft, AlertTriangle, ExternalLink, ShieldCheck } from 'lucide-react';
import { ScanReport } from '../types/security';

interface InterceptScreenProps {
  report?: ScanReport | null;
  onReturnToSafety: () => void;
  onBypass: (reportId: string, reason: string) => void;
}

export const InterceptScreen: React.FC<InterceptScreenProps> = ({
  report,
  onReturnToSafety,
  onBypass,
}) => {
  const [showBypassModal, setShowBypassModal] = useState(false);
  const [bypassReason, setBypassReason] = useState('Testing in controlled environment');
  const [bypassedConfirmed, setBypassedConfirmed] = useState(false);

  // Default fallback sample if no specific report is passed
  const activeReport = report || {
    id: 'sample-intercept',
    type: 'url' as const,
    target: 'http://auth-verify-portal-login.xyz/secure/session',
    timestamp: new Date().toISOString(),
    status: 'malicious' as const,
    stats: { malicious: 19, suspicious: 3, harmless: 0, undetected: 68 },
    threatNames: ['Phishing.CredentialHarvester', 'Spam.MaliciousURL', 'PhishTank.Verified'],
    engineCount: 90,
    permalink: 'https://www.virustotal.com/gui/url/u-auth-verify-portal',
    actionTaken: 'blocked' as const,
  };

  const handleConfirmBypass = () => {
    onBypass(activeReport.id, bypassReason);
    setBypassedConfirmed(true);
    setShowBypassModal(false);
  };

  return (
    <div className="min-h-[70vh] flex items-center justify-center p-4">
      <div className="max-w-2xl w-full bg-slate-900 border border-red-900/60 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glow ambient background accent */}
        <div className="absolute top-0 right-0 w-64 h-64 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />

        {/* Brand & Intercept Header */}
        <div className="flex items-center gap-4 pb-6 border-b border-slate-800 mb-6">
          <div className="w-14 h-14 rounded-xl bg-red-950/80 border border-red-800 flex items-center justify-center text-red-400 shrink-0 shadow-inner">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-cyan-400 font-semibold mb-1">
              DeltaShield Real-Time Defense
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Threat Intercepted: Access Blocked
            </h1>
          </div>
        </div>

        {/* Target Resource Box */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 mb-6">
          <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">
            {activeReport.type === 'download' ? 'Dangerous Download Intercepted' : 'Malicious Destination URL'}
          </div>
          <div className="text-sm font-mono text-red-400 break-all select-all">
            {activeReport.target}
          </div>
          {activeReport.hash && (
            <div className="mt-2 text-xs font-mono text-slate-400 truncate">
              SHA-256: {activeReport.hash}
            </div>
          )}
        </div>

        {/* Threat Telemetry Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="text-xs text-slate-400 mb-1">VirusTotal Detection Ratio</div>
            <div className="text-2xl font-bold text-red-400 font-mono tabular-nums">
              {activeReport.stats.malicious} / {activeReport.engineCount} Engines
            </div>
            <div className="text-xs text-slate-400 mt-1">Confirmed High-Severity Threat</div>
          </div>
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="text-xs text-slate-400 mb-1">DeltaShield Policy Action</div>
            <div className="text-2xl font-bold text-slate-200">
              {bypassedConfirmed ? (
                <span className="text-amber-400">Bypass Granted</span>
              ) : (
                <span className="text-red-400">Connection Terminated</span>
              )}
            </div>
            <div className="text-xs text-slate-400 mt-1">Real-time gateway protection</div>
          </div>
        </div>

        {/* Identified Malware & Signatures */}
        <div className="mb-8">
          <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
            Identified Threat Signatures
          </div>
          <div className="flex flex-wrap gap-2">
            {activeReport.threatNames.map((threat, idx) => (
              <span
                key={idx}
                className="px-3 py-1 rounded bg-red-950/60 text-red-300 border border-red-850 text-xs font-mono"
              >
                {threat}
              </span>
            ))}
          </div>

          {activeReport.permalink && (
            <div className="mt-3">
              <a
                href={activeReport.permalink}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:underline"
              >
                <span>Inspect full VirusTotal intelligence report</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-3">
          <button
            onClick={onReturnToSafety}
            className="flex-1 flex items-center justify-center gap-2 px-6 py-3.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-xl transition-colors shadow-lg shadow-blue-900/30"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Safety (Recommended)</span>
          </button>
          <button
            onClick={() => setShowBypassModal(true)}
            className="px-6 py-3.5 text-xs font-semibold text-slate-400 hover:text-red-300 hover:bg-red-950/30 border border-slate-800 hover:border-red-900/50 rounded-xl transition-colors whitespace-nowrap"
          >
            I understand the risk (Bypass)
          </button>
        </div>

        {/* Bypass Confirmation Dialog */}
        {showBypassModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl">
              <div className="flex items-center gap-3 text-amber-400 mb-3">
                <AlertTriangle className="w-5 h-5 shrink-0" />
                <h3 className="text-sm font-bold text-white">Override DeltaShield Warning?</h3>
              </div>
              <p className="text-xs text-slate-300 mb-4 leading-relaxed">
                VirusTotal engines flagged this resource as malicious. Bypassing will allow execution and log an audit trail entry.
              </p>

              <div className="mb-4">
                <label className="block text-xs font-semibold text-slate-400 mb-1.5">
                  Audit Bypass Reason
                </label>
                <select
                  value={bypassReason || ''}
                  onChange={e => setBypassReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="Security testing in isolated sandbox">Security testing in isolated sandbox</option>
                  <option value="False positive verified by IT admin">False positive verified by IT admin</option>
                  <option value="Authorized developer payload inspection">Authorized developer payload inspection</option>
                  <option value="Explicit override by user">Explicit override by user</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-3">
                <button
                  onClick={() => setShowBypassModal(false)}
                  className="px-4 py-2 text-xs text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleConfirmBypass}
                  className="px-4 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors"
                >
                  Confirm & Bypass
                </button>
              </div>
            </div>
          </div>
        )}

        {bypassedConfirmed && (
          <div className="mt-4 p-3 rounded-lg bg-emerald-950/40 border border-emerald-900/60 text-xs text-emerald-300 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Audited temporary bypass recorded. In real extension, navigation proceeds for 15 minutes.</span>
          </div>
        )}
      </div>
    </div>
  );
};
