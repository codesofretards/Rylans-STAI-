import React from 'react';
import { X, ExternalLink, ShieldAlert, ShieldCheck, AlertTriangle, FileCode, Globe, Copy, Check } from 'lucide-react';
import { ScanReport } from '../types/security';

interface ReportDetailModalProps {
  report: ScanReport | null;
  onClose: () => void;
}

export const ReportDetailModal: React.FC<ReportDetailModalProps> = ({ report, onClose }) => {
  const [copied, setCopied] = React.useState(false);

  if (!report) return null;

  const handleCopyHash = () => {
    if (report.hash) {
      navigator.clipboard.writeText(report.hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const engineEntries = report.engines ? Object.entries(report.engines) : [];
  const detectedEngines = engineEntries.filter(([_, info]) => info.category === 'malicious' || info.category === 'suspicious');
  const cleanEngines = engineEntries.filter(([_, info]) => info.category === 'harmless' || info.category === 'undetected');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            {report.status === 'malicious' ? (
              <div className="w-8 h-8 rounded-lg bg-red-950/60 border border-red-800 flex items-center justify-center text-red-400">
                <ShieldAlert className="w-4 h-4" />
              </div>
            ) : report.status === 'suspicious' ? (
              <div className="w-8 h-8 rounded-lg bg-amber-950/60 border border-amber-800 flex items-center justify-center text-amber-400">
                <AlertTriangle className="w-4 h-4" />
              </div>
            ) : (
              <div className="w-8 h-8 rounded-lg bg-emerald-950/60 border border-emerald-800 flex items-center justify-center text-emerald-400">
                <ShieldCheck className="w-4 h-4" />
              </div>
            )}
            <div>
              <h2 className="text-base font-semibold text-white">VirusTotal Threat Analysis Report</h2>
              <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                <span>{report.type === 'download' ? 'Download Payload' : 'Web Navigation'}</span>
                <span aria-hidden="true">·</span>
                <span>{new Date(report.timestamp).toLocaleString()}</span>
                <span aria-hidden="true">·</span>
                <span className="capitalize">{report.actionTaken} by DeltaShield</span>
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Target details */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-xs text-slate-400 mb-1">Target Resource</div>
            <div className="flex items-center gap-2 text-sm text-slate-200 font-mono break-all">
              {report.type === 'download' ? <FileCode className="w-4 h-4 text-cyan-400 shrink-0" /> : <Globe className="w-4 h-4 text-cyan-400 shrink-0" />}
              <span>{report.target}</span>
            </div>

            {report.hash && (
              <div className="mt-3 pt-3 border-t border-slate-900 flex items-center justify-between text-xs">
                <div className="text-slate-400 truncate mr-2">
                  <span className="text-slate-500 mr-2">SHA-256:</span>
                  <span className="font-mono text-slate-300">{report.hash}</span>
                </div>
                <button
                  onClick={handleCopyHash}
                  className="flex items-center gap-1 px-2 py-1 text-slate-400 hover:text-white rounded bg-slate-900 hover:bg-slate-800 transition-colors shrink-0"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            )}
          </div>

          {/* Stats Bar */}
          <div className="grid grid-cols-4 gap-3 text-center">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400 mb-1">Malicious</div>
              <div className="text-xl font-bold text-red-400 font-mono tabular-nums">{report.stats.malicious}</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400 mb-1">Suspicious</div>
              <div className="text-xl font-bold text-amber-400 font-mono tabular-nums">{report.stats.suspicious}</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400 mb-1">Harmless</div>
              <div className="text-xl font-bold text-emerald-400 font-mono tabular-nums">{report.stats.harmless}</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400 mb-1">Undetected</div>
              <div className="text-xl font-bold text-slate-400 font-mono tabular-nums">{report.stats.undetected}</div>
            </div>
          </div>

          {/* Identified Signatures */}
          {report.threatNames && report.threatNames.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-300 mb-2">Detected Threat Signatures</div>
              <div className="flex flex-wrap gap-2 text-xs">
                {report.threatNames.map((name, idx) => (
                  <span
                    key={idx}
                    className="px-2.5 py-1 rounded bg-red-950/40 text-red-300 border border-red-900/40 font-mono"
                  >
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Bypass reason if audited */}
          {report.bypassReason && (
            <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/40 text-xs">
              <div className="font-semibold text-amber-300 mb-1">User Audit Bypass Recorded</div>
              <p className="text-slate-300">Reason provided: "{report.bypassReason}"</p>
            </div>
          )}

          {/* Engine Breakdown */}
          {detectedEngines.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-300 mb-2">
                Flagging Security Engines ({detectedEngines.length})
              </div>
              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-4 font-medium">Engine</th>
                      <th className="py-2.5 px-4 font-medium">Verdict</th>
                      <th className="py-2.5 px-4 font-medium">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {detectedEngines.map(([name, info]) => (
                      <tr key={name} className="hover:bg-slate-800/40">
                        <td className="py-2 px-4 text-white font-medium">{name}</td>
                        <td className="py-2 px-4 text-red-400 capitalize">{info.category}</td>
                        <td className="py-2 px-4 text-slate-300">{info.result || 'Flagged'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {cleanEngines.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-400 mb-2">
                Sample Passing Engines ({cleanEngines.length} verified)
              </div>
              <div className="flex flex-wrap gap-2 text-xs text-slate-400">
                {cleanEngines.slice(0, 16).map(([name]) => (
                  <span key={name} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="text-xs text-slate-400">
            Total engines queried: <span className="font-mono text-slate-200">{report.engineCount}</span>
          </div>
          <div className="flex items-center gap-3">
            {report.permalink && (
              <a
                href={report.permalink}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:underline"
              >
                <span>View on VirusTotal</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            )}
            <button
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
