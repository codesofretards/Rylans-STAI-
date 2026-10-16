import React, { useState } from 'react';
import { Search, Globe, Download, ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, Trash2, ArrowUpRight } from 'lucide-react';
import { ScanReport } from '../types/security';

interface ScanLedgerProps {
  reports: ScanReport[];
  onSelectReport: (report: ScanReport) => void;
  onClearReports: () => void;
  onOpenScanner: () => void;
}

export const ScanLedger: React.FC<ScanLedgerProps> = ({
  reports,
  onSelectReport,
  onClearReports,
  onOpenScanner,
}) => {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'malicious' | 'clean' | 'suspicious' | 'url' | 'download'>('all');

  const filteredReports = reports.filter(r => {
    // Category filter
    if (filter === 'malicious' && r.status !== 'malicious') return false;
    if (filter === 'clean' && r.status !== 'clean') return false;
    if (filter === 'suspicious' && r.status !== 'suspicious') return false;
    if (filter === 'url' && r.type !== 'url') return false;
    if (filter === 'download' && r.type !== 'download') return false;

    // Search query
    if (!search.trim()) return true;
    const query = search.toLowerCase();
    return (
      r.target.toLowerCase().includes(query) ||
      (r.hash && r.hash.toLowerCase().includes(query)) ||
      r.threatNames.some(t => t.toLowerCase().includes(query))
    );
  });

  return (
    <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
      {/* Table controls */}
      <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search || ''}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by target URL, filename, threat name, or hash..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors"
          />
        </div>

        {/* Filter segment tabs */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 overflow-x-auto">
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
              filter === 'all' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Logs ({reports.length})
          </button>
          <button
            onClick={() => setFilter('malicious')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
              filter === 'malicious' ? 'bg-red-950 text-red-200 border border-red-900/60 shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Malicious ({reports.filter(r => r.status === 'malicious').length})
          </button>
          <button
            onClick={() => setFilter('clean')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
              filter === 'clean' ? 'bg-emerald-950 text-emerald-200 border border-emerald-900/60 shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Clean ({reports.filter(r => r.status === 'clean').length})
          </button>
          <button
            onClick={() => setFilter('download')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
              filter === 'download' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Downloads ({reports.filter(r => r.type === 'download').length})
          </button>
        </div>

        {/* Clear action */}
        {reports.length > 0 && (
          <button
            onClick={onClearReports}
            className="flex items-center gap-1.5 px-3 py-2 text-xs text-slate-400 hover:text-red-400 rounded-lg hover:bg-slate-800/60 transition-colors whitespace-nowrap"
            title="Clear all scan history"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        )}
      </div>

      {/* High-density grid */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs text-left">
          <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
            <tr>
              <th className="py-3 px-4 font-medium">Type</th>
              <th className="py-3 px-4 font-medium">Target Resource</th>
              <th className="py-3 px-4 font-medium">VirusTotal Verdict</th>
              <th className="py-3 px-4 font-medium">Enforcement Action</th>
              <th className="py-3 px-4 font-medium text-right">Timestamp</th>
              <th className="py-3 px-4 font-medium text-right">Report</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredReports.map(report => (
              <tr
                key={report.id}
                onClick={() => onSelectReport(report)}
                className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
              >
                {/* Type */}
                <td className="py-3 px-4 whitespace-nowrap">
                  <div className="flex items-center gap-1.5 text-slate-300">
                    {report.type === 'download' ? (
                      <Download className="w-3.5 h-3.5 text-cyan-400" />
                    ) : (
                      <Globe className="w-3.5 h-3.5 text-slate-400" />
                    )}
                    <span className="capitalize">{report.type}</span>
                  </div>
                </td>

                {/* Target */}
                <td className="py-3 px-4">
                  <div className="max-w-md">
                    <div className="font-mono text-slate-200 truncate group-hover:text-cyan-300 transition-colors" title={report.target}>
                      {report.target}
                    </div>
                    {report.threatNames.length > 0 && (
                      <div className="flex items-center gap-1.5 text-xs text-red-400 mt-0.5 truncate">
                        <span>{report.threatNames.join(' · ')}</span>
                      </div>
                    )}
                  </div>
                </td>

                {/* VirusTotal Verdict */}
                <td className="py-3 px-4 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    {report.status === 'malicious' ? (
                      <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                    ) : report.status === 'suspicious' ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                    )}
                    <div>
                      <span className={`font-semibold ${
                        report.status === 'malicious'
                          ? 'text-red-400'
                          : report.status === 'suspicious'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}>
                        {report.status === 'malicious'
                          ? `${report.stats.malicious} / ${report.engineCount} Malicious`
                          : report.status === 'suspicious'
                          ? `${report.stats.suspicious} Suspicious`
                          : `0 / ${report.engineCount} Clean`}
                      </span>
                    </div>
                  </div>
                </td>

                {/* Enforcement Action */}
                <td className="py-3 px-4 whitespace-nowrap">
                  <div className="flex items-center gap-2 text-xs">
                    {report.actionTaken === 'blocked' ? (
                      <span className="text-red-400 font-medium">Intercepted & Blocked</span>
                    ) : report.actionTaken === 'bypassed' ? (
                      <span className="text-amber-400 font-medium">User Bypassed</span>
                    ) : (
                      <span className="text-emerald-400 font-medium">Passed Through</span>
                    )}
                  </div>
                </td>

                {/* Timestamp */}
                <td className="py-3 px-4 text-right whitespace-nowrap text-slate-400 font-mono tabular-nums">
                  {new Date(report.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </td>

                {/* Report link */}
                <td className="py-3 px-4 text-right whitespace-nowrap">
                  <button
                    onClick={e => {
                      e.stopPropagation();
                      onSelectReport(report);
                    }}
                    className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium"
                  >
                    <span>Inspect</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                </td>
              </tr>
            ))}

            {filteredReports.length === 0 && (
              <tr>
                <td colSpan={6} className="py-12 text-center">
                  <div className="text-slate-400 text-sm mb-2">No scan records matching your filter.</div>
                  <button
                    onClick={onOpenScanner}
                    className="px-4 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors inline-block"
                  >
                    Run Live Threat Scan
                  </button>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
