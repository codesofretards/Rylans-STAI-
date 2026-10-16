import React, { useState } from 'react';
import { Key, Sliders, CheckCircle, AlertCircle, Shield, Globe, Plus, Trash2, Loader2 } from 'lucide-react';
import { DeltaShieldConfig } from '../types/security';
import { validateVirusTotalKey } from '../services/virusTotalService';

interface SecurityPoliciesProps {
  config: DeltaShieldConfig;
  onUpdateConfig: (newConfig: DeltaShieldConfig) => void;
}

export const SecurityPolicies: React.FC<SecurityPoliciesProps> = ({ config, onUpdateConfig }) => {
  const [apiKeyInput, setApiKeyInput] = useState<string>(config?.apiKey || '');
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<{ valid: boolean; message: string } | null>(null);

  const [newAllowDomain, setNewAllowDomain] = useState<string>('');
  const [newDenyDomain, setNewDenyDomain] = useState<string>('');

  React.useEffect(() => {
    setApiKeyInput(config?.apiKey || '');
  }, [config?.apiKey]);

  const handleTestAndSaveKey = async () => {
    if (!apiKeyInput.trim()) {
      setValidationResult({ valid: false, message: 'Please enter a VirusTotal API key.' });
      return;
    }

    setIsValidating(true);
    setValidationResult(null);

    const result = await validateVirusTotalKey(apiKeyInput.trim());
    setIsValidating(false);

    if (result.valid) {
      setValidationResult({ valid: true, message: 'VirusTotal API key verified successfully!' });
      onUpdateConfig({
        ...config,
        apiKey: apiKeyInput.trim(),
        isKeyValid: true,
        userGroup: result.user?.user_group || 'Public Free User',
        apiQuota: {
          dailyAllowed: result.user?.quotas?.api_requests_daily?.allowed,
          dailyUsed: result.user?.quotas?.api_requests_daily?.used,
          hourlyAllowed: result.user?.quotas?.api_requests_hourly?.allowed,
          hourlyUsed: result.user?.quotas?.api_requests_hourly?.used,
        }
      });
    } else {
      setValidationResult({ valid: false, message: result.error || 'Failed to validate API key.' });
      // Still save key so user can work with it if offline
      onUpdateConfig({
        ...config,
        apiKey: apiKeyInput.trim(),
        isKeyValid: false,
      });
    }
  };

  const handleThresholdChange = (val: number) => {
    onUpdateConfig({ ...config, detectionThreshold: val });
  };

  const handleToggleSites = () => {
    onUpdateConfig({ ...config, autoScanSites: !config.autoScanSites });
  };

  const handleToggleDownloads = () => {
    onUpdateConfig({ ...config, autoScanDownloads: !config.autoScanDownloads });
  };

  const handleAddAllowlist = () => {
    const clean = newAllowDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (clean && !config.allowlist.includes(clean)) {
      onUpdateConfig({ ...config, allowlist: [...config.allowlist, clean] });
      setNewAllowDomain('');
    }
  };

  const handleRemoveAllowlist = (domain: string) => {
    onUpdateConfig({ ...config, allowlist: config.allowlist.filter(d => d !== domain) });
  };

  const handleAddDenylist = () => {
    const clean = newDenyDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (clean && !config.denylist.includes(clean)) {
      onUpdateConfig({ ...config, denylist: [...config.denylist, clean] });
      setNewDenyDomain('');
    }
  };

  const handleRemoveDenylist = (domain: string) => {
    onUpdateConfig({ ...config, denylist: config.denylist.filter(d => d !== domain) });
  };

  return (
    <div className="space-y-8 max-w-4xl">
      {/* 1. VirusTotal API Key Configuration */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-2.5 mb-2">
          <Key className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold text-white">VirusTotal API Key (v3)</h2>
        </div>
        <p className="text-xs text-slate-400 mb-4 leading-relaxed">
          Provide your personal or enterprise VirusTotal API key. DeltaShield uses this key to query VT threat databases in real time. (Free public tier provides 4 requests/min and 500 requests/day).
        </p>

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="password"
            value={apiKeyInput || ''}
            onChange={e => setApiKeyInput(e.target.value)}
            placeholder="Enter 64-character VirusTotal API Key..."
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={handleTestAndSaveKey}
            disabled={isValidating}
            className="flex items-center justify-center gap-2 px-5 py-2.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg transition-colors shrink-0"
          >
            {isValidating ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Verifying...</span>
              </>
            ) : (
              <span>Test & Save Key</span>
            )}
          </button>
        </div>

        {validationResult && (
          <div className={`mt-3 p-3 rounded-lg text-xs flex items-center gap-2 ${
            validationResult.valid
              ? 'bg-emerald-950/40 border border-emerald-900/60 text-emerald-300'
              : 'bg-red-950/40 border border-red-900/60 text-red-300'
          }`}>
            {validationResult.valid ? <CheckCircle className="w-4 h-4 shrink-0" /> : <AlertCircle className="w-4 h-4 shrink-0" />}
            <span>{validationResult.message}</span>
          </div>
        )}

        {config.apiQuota && (
          <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <div className="text-slate-400">Account Type</div>
              <div className="font-semibold text-white mt-0.5">{config.userGroup || 'Standard'}</div>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <div className="text-slate-400">Daily Requests</div>
              <div className="font-semibold text-cyan-300 font-mono mt-0.5">
                {config.apiQuota.dailyUsed ?? 0} / {config.apiQuota.dailyAllowed ?? '∞'}
              </div>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <div className="text-slate-400">Hourly Requests</div>
              <div className="font-semibold text-cyan-300 font-mono mt-0.5">
                {config.apiQuota.hourlyUsed ?? 0} / {config.apiQuota.hourlyAllowed ?? '240'}
              </div>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <div className="text-slate-400">Real-time Gateway</div>
              <div className="font-semibold text-emerald-400 mt-0.5">Active</div>
            </div>
          </div>
        )}
      </div>

      {/* 2. Intercept Sensitivity & Rules */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-2.5 mb-2">
          <Sliders className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold text-white">Detection Sensitivity & Intercept Threshold</h2>
        </div>
        <p className="text-xs text-slate-400 mb-6 leading-relaxed">
          Configure how many antivirus vendors on VirusTotal must detect a threat before DeltaShield triggers the Intercept Shield.
        </p>

        {/* Threshold slider */}
        <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-300">
              Malicious Engines Threshold: <span className="text-cyan-400 font-mono">{config.detectionThreshold} Engine{config.detectionThreshold > 1 ? 's' : ''}</span>
            </span>
            <span className="text-xs text-slate-500">
              {config.detectionThreshold === 1 ? 'Strict Zero-Trust (Recommended)' : 'Conservative Threshold'}
            </span>
          </div>
          <input
            type="range"
            min="1"
            max="5"
            step="1"
            value={typeof config?.detectionThreshold === 'number' && !isNaN(config.detectionThreshold) ? config.detectionThreshold : 1}
            onChange={e => {
              const val = parseInt(e.target.value, 10);
              handleThresholdChange(isNaN(val) ? 1 : val);
            }}
            className="w-full accent-cyan-500 cursor-pointer"
          />
          <div className="flex justify-between text-[11px] text-slate-500 mt-1 font-mono">
            <span>1 (Strict)</span>
            <span>2</span>
            <span>3 (Balanced)</span>
            <span>4</span>
            <span>5 (Permissive)</span>
          </div>
        </div>

        {/* Toggles */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-white">Auto-Scan Visited Sites</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Check web destinations on navigation</div>
            </div>
            <button
              onClick={handleToggleSites}
              className={`w-11 h-6 rounded-full transition-colors relative ${
                config.autoScanSites ? 'bg-cyan-600' : 'bg-slate-800'
              }`}
            >
              <div className={`w-4 h-4 rounded-full bg-white transition-transform absolute top-1 ${
                config.autoScanSites ? 'right-1' : 'left-1'
              }`} />
            </button>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-white">Auto-Scan File Downloads</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Hash check incoming file downloads</div>
            </div>
            <button
              onClick={handleToggleDownloads}
              className={`w-11 h-6 rounded-full transition-colors relative ${
                config.autoScanDownloads ? 'bg-cyan-600' : 'bg-slate-800'
              }`}
            >
              <div className={`w-4 h-4 rounded-full bg-white transition-transform absolute top-1 ${
                config.autoScanDownloads ? 'right-1' : 'left-1'
              }`} />
            </button>
          </div>
        </div>
      </div>

      {/* 3. Domain Allowlist & Denylist */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Allowlist */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Trusted Domain Allowlist</h3>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Domains that always bypass inspection without querying VirusTotal.
          </p>

          <div className="flex gap-2 mb-3">
            <input
              type="text"
              value={newAllowDomain || ''}
              onChange={e => setNewAllowDomain(e.target.value)}
              placeholder="e.g. internal.company.net"
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              onKeyDown={e => { if (e.key === 'Enter') handleAddAllowlist(); }}
            />
            <button
              onClick={handleAddAllowlist}
              className="p-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>

          <div className="space-y-1 max-h-48 overflow-y-auto font-mono text-xs">
            {(config?.allowlist || []).map(domain => (
              <div key={domain} className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800/80">
                <span className="text-slate-300 truncate">{domain}</span>
                <button
                  onClick={() => handleRemoveAllowlist(domain)}
                  className="text-slate-500 hover:text-red-400 transition-colors ml-2"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Denylist */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-bold text-white">Custom Threat Denylist</h3>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Domains that DeltaShield blocks immediately without waiting for API queries.
          </p>

          <div className="flex gap-2 mb-3">
            <input
              type="text"
              value={newDenyDomain || ''}
              onChange={e => setNewDenyDomain(e.target.value)}
              placeholder="e.g. scam-phishing-test.org"
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              onKeyDown={e => { if (e.key === 'Enter') handleAddDenylist(); }}
            />
            <button
              onClick={handleAddDenylist}
              className="p-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>

          <div className="space-y-1 max-h-48 overflow-y-auto font-mono text-xs">
            {config.denylist.map(domain => (
              <div key={domain} className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800/80">
                <span className="text-slate-300 truncate">{domain}</span>
                <button
                  onClick={() => handleRemoveDenylist(domain)}
                  className="text-slate-500 hover:text-red-400 transition-colors ml-2"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
            {config.denylist.length === 0 && (
              <div className="text-slate-500 text-center py-4 text-xs font-sans">
                No custom domains in denylist
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
