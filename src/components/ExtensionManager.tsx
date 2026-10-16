import React, { useState } from 'react';
import { Download, FileCode, CheckCircle, FolderArchive, ArrowRight, Copy, Check } from 'lucide-react';
import {
  generateExtensionZip,
  MANIFEST_JSON,
  BACKGROUND_JS,
  POPUP_HTML,
  INTERCEPT_HTML,
  OPTIONS_HTML,
  EXTENSION_README,
} from '../extension/extensionSource';
import { DeltaShieldConfig } from '../types/security';

interface ExtensionManagerProps {
  config: DeltaShieldConfig;
}

export const ExtensionManager: React.FC<ExtensionManagerProps> = ({ config }) => {
  const [selectedFile, setSelectedFile] = useState<string>('manifest.json');
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [downloadSuccess, setDownloadSuccess] = useState<boolean>(false);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  const fileContents: Record<string, string> = {
    'manifest.json': JSON.stringify(MANIFEST_JSON, null, 2),
    'background.js': BACKGROUND_JS,
    'intercept.html': INTERCEPT_HTML,
    'popup.html': POPUP_HTML,
    'options.html': OPTIONS_HTML,
    'README.md': EXTENSION_README,
  };

  const handleDownloadZip = async () => {
    setIsExporting(true);
    setDownloadSuccess(false);

    try {
      const blob = await generateExtensionZip(config.apiKey);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'deltashield-extension-v1.0.0.zip';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 5000);
    } catch (err) {
      console.error('Failed to create extension zip', err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(fileContents[selectedFile] || '');
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="space-y-8">
      {/* Hero Action Card */}
      <div className="p-8 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-2">
            <FolderArchive className="w-4 h-4" />
            <span>Chrome Extension Manifest V3 Package</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-white">
            DeltaShield Browser Extension
          </h2>
          <p className="text-xs sm:text-sm text-slate-300 mt-2 max-w-xl leading-relaxed">
            Download the production-ready unpacked extension bundle configured for Google Chrome. Automatically intercepts visited web pages and downloads using your VirusTotal API key.
          </p>
          {config.apiKey && (
            <div className="flex items-center gap-2 mt-3 text-xs text-emerald-400">
              <CheckCircle className="w-4 h-4" />
              <span>Your configured VirusTotal key will be pre-packaged into this build</span>
            </div>
          )}
        </div>

        <div className="flex flex-col items-start sm:items-end gap-2 shrink-0">
          <button
            onClick={handleDownloadZip}
            disabled={isExporting}
            className="flex items-center gap-2.5 px-6 py-3.5 text-xs font-bold text-white bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-xl transition-all shadow-lg shadow-cyan-950/50 whitespace-nowrap"
          >
            <Download className="w-4 h-4" />
            <span>{isExporting ? 'Generating ZIP...' : 'Download Extension (.ZIP)'}</span>
          </button>
          {downloadSuccess && (
            <div className="text-xs text-emerald-400 flex items-center gap-1.5 mt-1">
              <CheckCircle className="w-3.5 h-3.5" />
              <span>deltashield-extension-v1.0.0.zip downloaded!</span>
            </div>
          )}
        </div>
      </div>

      {/* Installation Walkthrough Guide */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800">
        <h3 className="text-sm font-bold text-white mb-4">
          Chrome Installation Walkthrough (3 Steps)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-xs font-mono text-cyan-400 font-bold mb-1">STEP 01</div>
            <div className="text-sm font-semibold text-slate-200 mb-1">Unzip Archive</div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Click Download Extension (.ZIP) above, then extract the downloaded ZIP folder to a permanent local directory.
            </p>
          </div>
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-xs font-mono text-cyan-400 font-bold mb-1">STEP 02</div>
            <div className="text-sm font-semibold text-slate-200 mb-1">Open Chrome Extensions</div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Navigate to <code className="text-cyan-300 font-mono">chrome://extensions</code>, and toggle on <strong className="text-white">Developer mode</strong> in the top-right corner.
            </p>
          </div>
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-xs font-mono text-cyan-400 font-bold mb-1">STEP 03</div>
            <div className="text-sm font-semibold text-slate-200 mb-1">Load Unpacked</div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Click <strong className="text-white">Load unpacked</strong>, choose the unzipped folder containing manifest.json, and DeltaShield is live!
            </p>
          </div>
        </div>
      </div>

      {/* Codebase File Explorer */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Extension Source Explorer</h3>
          </div>
          <button
            onClick={handleCopyCode}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-400 hover:text-white bg-slate-950 hover:bg-slate-800 rounded-lg border border-slate-800 transition-colors"
          >
            {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedCode ? 'Copied' : 'Copy File'}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-slate-800">
          {/* File list sidebar */}
          <div className="p-2 space-y-1 bg-slate-950/60 font-mono text-xs">
            {Object.keys(fileContents).map(fileName => (
              <button
                key={fileName}
                onClick={() => setSelectedFile(fileName)}
                className={`w-full text-left px-3 py-2 rounded-lg flex items-center justify-between transition-colors ${
                  selectedFile === fileName
                    ? 'bg-slate-800 text-cyan-400 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <span>{fileName}</span>
                {selectedFile === fileName && <ArrowRight className="w-3.5 h-3.5" />}
              </button>
            ))}
          </div>

          {/* Code Viewer */}
          <div className="md:col-span-3 p-4 bg-slate-950 max-h-96 overflow-y-auto">
            <pre className="font-mono text-xs text-slate-300 whitespace-pre leading-relaxed select-all">
              {fileContents[selectedFile]}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
