import React, { useState } from 'react';
import { X, Key, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';
import { DeltaShieldConfig } from '../types/security';
import { validateVirusTotalKey } from '../services/virusTotalService';

interface ConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  config: DeltaShieldConfig;
  onSaveConfig: (newConfig: DeltaShieldConfig) => void;
}

export const ConfigModal: React.FC<ConfigModalProps> = ({
  isOpen,
  onClose,
  config,
  onSaveConfig,
}) => {
  const [apiKey, setApiKey] = useState<string>(config?.apiKey || '');
  const [isValidating, setIsValidating] = useState(false);
  const [status, setStatus] = useState<{ success?: boolean; message?: string } | null>(null);

  React.useEffect(() => {
    setApiKey(config?.apiKey || '');
    setStatus(null);
  }, [config?.apiKey, isOpen]);

  if (!isOpen) return null;

  const handleValidateAndSave = async () => {
    if (!apiKey.trim()) {
      setStatus({ success: false, message: 'Please enter a VirusTotal API key.' });
      return;
    }

    setIsValidating(true);
    setStatus(null);

    const result = await validateVirusTotalKey(apiKey.trim());
    setIsValidating(false);

    if (result.valid) {
      setStatus({ success: true, message: 'VirusTotal API key successfully validated!' });
      onSaveConfig({
        ...config,
        apiKey: apiKey.trim(),
        isKeyValid: true,
        userGroup: result.user?.user_group || 'Public Free User',
        apiQuota: {
          dailyAllowed: result.user?.quotas?.api_requests_daily?.allowed,
          dailyUsed: result.user?.quotas?.api_requests_daily?.used,
          hourlyAllowed: result.user?.quotas?.api_requests_hourly?.allowed,
          hourlyUsed: result.user?.quotas?.api_requests_hourly?.used,
        }
      });
      setTimeout(() => {
        onClose();
      }, 1000);
    } else {
      setStatus({ success: false, message: result.error || 'Failed to authenticate with VirusTotal.' });
      onSaveConfig({
        ...config,
        apiKey: apiKey.trim(),
        isKeyValid: false,
      });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2.5 mb-2">
          <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
            <Key className="w-4 h-4" />
          </div>
          <h2 className="text-base font-bold text-white">VirusTotal API Key (v3)</h2>
        </div>

        <p className="text-xs text-slate-300 mb-4 leading-relaxed">
          DeltaShield requires a VirusTotal API key to inspect visited URLs and download file hashes against 90+ threat engines. You can find your key at <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline">virustotal.com</a>.
        </p>

        <div className="mb-4">
          <label className="block text-xs font-semibold text-slate-400 mb-1.5">
            API Key (64 hex characters)
          </label>
          <input
            type="password"
            value={apiKey || ''}
            onChange={e => setApiKey(e.target.value)}
            placeholder="Paste your VirusTotal API key..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-white placeholder-slate-600 font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>

        {status && (
          <div className={`mb-4 p-3 rounded-lg text-xs flex items-center gap-2 ${
            status.success
              ? 'bg-emerald-950/40 border border-emerald-900/60 text-emerald-300'
              : 'bg-red-950/40 border border-red-900/60 text-red-300'
          }`}>
            {status.success ? <CheckCircle className="w-4 h-4 shrink-0" /> : <AlertCircle className="w-4 h-4 shrink-0" />}
            <span>{status.message}</span>
          </div>
        )}

        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleValidateAndSave}
            disabled={isValidating}
            className="flex items-center gap-2 px-5 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg transition-colors"
          >
            {isValidating ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Verifying with VT...</span>
              </>
            ) : (
              <span>Save & Connect</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
