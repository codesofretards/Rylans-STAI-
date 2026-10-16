import React from 'react';
import { Shield, Key } from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  apiKey: string;
  isKeyValid: boolean;
  onOpenConfig: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  apiKey,
  isKeyValid,
  onOpenConfig,
}) => {
  return (
    <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800 bg-slate-950/90 backdrop-blur sticky top-0 z-40">
      {/* Zone 1: Single text element wordmark */}
      <div 
        onClick={() => setActiveTab('feed')}
        className="flex items-center gap-2.5 cursor-pointer whitespace-nowrap shrink-0 group"
      >
        <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400 group-hover:border-cyan-500 transition-colors">
          <Shield className="w-4 h-4" />
        </div>
        <span className="text-base font-bold tracking-tight text-white">
          Delta<span className="text-cyan-400">Shield</span>
        </span>
      </div>

      {/* Zone 2: 4-5 clean single-line text navigation links */}
      <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
        <button
          onClick={() => setActiveTab('feed')}
          className={`whitespace-nowrap shrink-0 pb-1 border-b-2 transition-colors ${
            activeTab === 'feed'
              ? 'text-white border-cyan-400'
              : 'border-transparent hover:text-slate-200'
          }`}
        >
          Threat Feed
        </button>
        <button
          onClick={() => setActiveTab('analyzer')}
          className={`whitespace-nowrap shrink-0 pb-1 border-b-2 transition-colors ${
            activeTab === 'analyzer'
              ? 'text-white border-cyan-400'
              : 'border-transparent hover:text-slate-200'
          }`}
        >
          Live Threat Scanner
        </button>
        <button
          onClick={() => setActiveTab('intercept')}
          className={`whitespace-nowrap shrink-0 pb-1 border-b-2 transition-colors ${
            activeTab === 'intercept'
              ? 'text-white border-cyan-400'
              : 'border-transparent hover:text-slate-200'
          }`}
        >
          Intercept Shield
        </button>
        <button
          onClick={() => setActiveTab('extension')}
          className={`whitespace-nowrap shrink-0 pb-1 border-b-2 transition-colors ${
            activeTab === 'extension'
              ? 'text-white border-cyan-400'
              : 'border-transparent hover:text-slate-200'
          }`}
        >
          Extension Package
        </button>
        <button
          onClick={() => setActiveTab('policies')}
          className={`whitespace-nowrap shrink-0 pb-1 border-b-2 transition-colors ${
            activeTab === 'policies'
              ? 'text-white border-cyan-400'
              : 'border-transparent hover:text-slate-200'
          }`}
        >
          Security Policies
        </button>
      </nav>

      {/* Zone 3: 1 primary action */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onOpenConfig}
          className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 border ${
            apiKey && isKeyValid
              ? 'bg-slate-900 hover:bg-slate-800 text-emerald-400 border-emerald-900/60'
              : apiKey
              ? 'bg-slate-900 hover:bg-slate-800 text-cyan-300 border-slate-700'
              : 'bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-500'
          }`}
        >
          <Key className="w-3.5 h-3.5" />
          <span>{apiKey ? (isKeyValid ? 'VirusTotal Key Connected' : 'VirusTotal Key Saved') : 'Configure API Key'}</span>
        </button>
      </div>
    </header>
  );
};
