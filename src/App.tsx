import { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { SOCMetrics } from './components/SOCMetrics';
import { ScanLedger } from './components/ScanLedger';
import { LiveThreatAnalyzer } from './components/LiveThreatAnalyzer';
import { InterceptScreen } from './components/InterceptScreen';
import { ExtensionManager } from './components/ExtensionManager';
import { SecurityPolicies } from './components/SecurityPolicies';
import { ReportDetailModal } from './components/ReportDetailModal';
import { ConfigModal } from './components/ConfigModal';
import { ScanReport, DeltaShieldConfig } from './types/security';
import {
  loadReports,
  saveReport,
  updateReportAction,
  clearReports,
  loadConfig,
  saveConfig,
} from './services/storageService';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('feed');
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [config, setConfig] = useState<DeltaShieldConfig>(loadConfig());
  const [selectedReport, setSelectedReport] = useState<ScanReport | null>(null);
  const [interceptPreviewReport, setInterceptPreviewReport] = useState<ScanReport | null>(null);
  const [isConfigOpen, setIsConfigOpen] = useState<boolean>(false);

  // Initialize data on mount
  useEffect(() => {
    setReports(loadReports());
  }, []);

  const handleScanComplete = (newReport: ScanReport) => {
    const updated = saveReport(newReport);
    setReports(updated);
  };

  const handleClearReports = () => {
    const updated = clearReports();
    setReports(updated);
  };

  const handleUpdateConfig = (newConfig: DeltaShieldConfig) => {
    setConfig(newConfig);
    saveConfig(newConfig);
  };

  const handlePreviewIntercept = (report: ScanReport) => {
    setInterceptPreviewReport(report);
    setActiveTab('intercept');
  };

  const handleBypass = (reportId: string, reason: string) => {
    const updated = updateReportAction(reportId, 'bypassed', reason);
    setReports(updated);
  };

  const handleReturnToSafety = () => {
    setActiveTab('feed');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* 1. Header (Top Bar Contract) */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        apiKey={config.apiKey}
        isKeyValid={config.isKeyValid}
        onOpenConfig={() => setIsConfigOpen(true)}
      />

      {/* 2. Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 sm:py-8">
        {/* SOC Executive Telemetry Strip */}
        <SOCMetrics
          reports={reports}
          isKeyValid={config.isKeyValid}
          threshold={config.detectionThreshold}
        />

        {/* Tab Content Routing */}
        {activeTab === 'feed' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                  Live Threat & Intercept Feed
                </h1>
                <p className="text-xs sm:text-sm text-slate-400 mt-1">
                  Real-time ledger of web destinations and download payloads verified by VirusTotal API v3.
                </p>
              </div>
              <button
                onClick={() => setActiveTab('analyzer')}
                className="px-4 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors whitespace-nowrap self-start sm:self-auto"
              >
                Scan New Target
              </button>
            </div>

            <ScanLedger
              reports={reports}
              onSelectReport={setSelectedReport}
              onClearReports={handleClearReports}
              onOpenScanner={() => setActiveTab('analyzer')}
            />
          </div>
        )}

        {activeTab === 'analyzer' && (
          <div className="space-y-6">
            <div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                Live Threat Intelligence Workbench
              </h1>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Route any target website URL or calculate client-side file hashes to query 90+ VirusTotal antivirus engines.
              </p>
            </div>

            <LiveThreatAnalyzer
              config={config}
              onScanComplete={handleScanComplete}
              onOpenConfig={() => setIsConfigOpen(true)}
              onPreviewIntercept={handlePreviewIntercept}
            />
          </div>
        )}

        {activeTab === 'intercept' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                  DeltaShield Intercept Warning Screen
                </h1>
                <p className="text-xs sm:text-sm text-slate-400 mt-1">
                  Active gateway barrier displayed to users when a visited domain or download contains confirmed malicious threats.
                </p>
              </div>
              <button
                onClick={() => setActiveTab('feed')}
                className="px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors"
              >
                Back to Feed
              </button>
            </div>

            <InterceptScreen
              report={interceptPreviewReport || reports.find(r => r.status === 'malicious') || null}
              onReturnToSafety={handleReturnToSafety}
              onBypass={handleBypass}
            />
          </div>
        )}

        {activeTab === 'extension' && (
          <div className="space-y-6">
            <div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                Chrome Extension Package & Deployment
              </h1>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Download the complete Manifest V3 Chrome extension bundle and load it directly into your browser.
              </p>
            </div>

            <ExtensionManager config={config} />
          </div>
        )}

        {activeTab === 'policies' && (
          <div className="space-y-6">
            <div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                Security Policies & VirusTotal API Configuration
              </h1>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Manage your threat detection sensitivity threshold, automated scan hooks, and domain rules.
              </p>
            </div>

            <SecurityPolicies
              config={config}
              onUpdateConfig={handleUpdateConfig}
            />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-6 px-6 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">DeltaShield</span>
            <span aria-hidden="true">·</span>
            <span>Automated Real-Time VirusTotal Threat Protection</span>
          </div>
          <div>
            <span>Manifest V3 Architecture</span>
            <span aria-hidden="true" className="mx-2">·</span>
            <span>Port 3000 Security Gateway</span>
          </div>
        </div>
      </footer>

      {/* Modals */}
      <ReportDetailModal
        report={selectedReport}
        onClose={() => setSelectedReport(null)}
      />

      <ConfigModal
        isOpen={isConfigOpen}
        onClose={() => setIsConfigOpen(false)}
        config={config}
        onSaveConfig={handleUpdateConfig}
      />
    </div>
  );
}
