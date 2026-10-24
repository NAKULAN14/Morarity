import React from 'react';
import { Shield, Activity, Terminal, FolderClock, Layers, RefreshCw, Sparkles } from 'lucide-react';
import { BackendHealth } from '../types';

interface NavbarProps {
  activeTab: 'overview' | 'sqllab' | 'verify' | 'results' | 'reports' | 'architecture';
  setActiveTab: (tab: 'overview' | 'sqllab' | 'verify' | 'results' | 'reports' | 'architecture') => void;
  health: BackendHealth | null;
  healthLoading: boolean;
  onRefreshHealth: () => void;
  hasActiveResult: boolean;
  onOpenArchitecture?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  health,
  healthLoading,
  onRefreshHealth,
  hasActiveResult,
  onOpenArchitecture,
}) => {
  return (
    <header className="sticky top-0 z-50 bg-[#07090B]/90 backdrop-blur-md border-b border-[#222B30]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Identity */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setActiveTab('overview')}
              className="flex items-center gap-2.5 text-left group focus:outline-none"
            >
              <div className="w-8 h-8 rounded border border-[#222B30] bg-[#0C1013] flex items-center justify-center text-[#39E58C] group-hover:border-[#39E58C]/50 transition-colors">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold tracking-wider text-sm text-[#E8EEF0]">
                    MORIARTY
                  </span>
                  <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E]">
                    v0.1.0
                  </span>
                </div>
                <p className="text-[10px] text-[#536168] tracking-tight font-sans hidden sm:block">
                  Structural Security Patch Verification
                </p>
              </div>
            </button>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-1 sm:gap-2">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'overview'
                  ? 'bg-[#11171B] text-[#E8EEF0] border border-[#222B30]'
                  : 'text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Overview</span>
            </button>

            <button
              onClick={() => setActiveTab('sqllab')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'sqllab'
                  ? 'bg-[#1E1B4B] text-[#C084FC] border border-[#6366F1]/50'
                  : 'text-[#8B989E] hover:text-[#C084FC] hover:bg-[#0C1013]'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 text-[#C084FC]" />
              <span className="font-bold">SQL Security Lab</span>
            </button>

            <button
              onClick={() => setActiveTab('verify')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'verify'
                  ? 'bg-[#11171B] text-[#E8EEF0] border border-[#222B30]'
                  : 'text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>New Verification</span>
            </button>

            {hasActiveResult && (
              <button
                onClick={() => setActiveTab('results')}
                className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
                  activeTab === 'results'
                    ? 'bg-[#11171B] text-[#E8EEF0] border border-[#222B30]'
                    : 'text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
                }`}
              >
                <Shield className="w-3.5 h-3.5 text-[#39E58C]" />
                <span>Live Verdict</span>
              </button>
            )}

            <button
              onClick={() => setActiveTab('reports')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'reports'
                  ? 'bg-[#11171B] text-[#E8EEF0] border border-[#222B30]'
                  : 'text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
              }`}
            >
              <FolderClock className="w-3.5 h-3.5" />
              <span>Archive</span>
            </button>

            <button
              onClick={() => setActiveTab('architecture')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'architecture'
                  ? 'bg-[#11171B] text-[#39E58C] border border-[#39E58C]/40 font-bold'
                  : 'text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
              }`}
            >
              <Layers className="w-3.5 h-3.5 text-[#39E58C]" />
              <span>Architecture</span>
            </button>
          </nav>

          {/* Right Status & Tools */}
          <div className="flex items-center gap-3">
            {/* Backend Health Indicator */}
            <div className="flex items-center gap-2 pl-3 border-l border-[#222B30]">
              <div
                className={`w-2 h-2 rounded-full ${
                  healthLoading
                    ? 'bg-[#FFBE55] animate-ping'
                    : health
                    ? 'bg-[#39E58C] shadow-[0_0_8px_#39E58C]'
                    : 'bg-[#FF5B64] shadow-[0_0_8px_#FF5B64]'
                }`}
              />
              <div className="hidden sm:flex flex-col text-right">
                <span className="text-[10px] font-mono text-[#E8EEF0] leading-none">
                  {healthLoading ? 'CHECKING...' : health ? 'ENGINE ONLINE' : 'ENGINE OFFLINE'}
                </span>
                {health?.ping_ms !== undefined && (
                  <span className="text-[9px] font-mono text-[#536168] mt-0.5">
                    {health.ping_ms}ms • SQLite Sandbox
                  </span>
                )}
              </div>
              <button
                onClick={onRefreshHealth}
                disabled={healthLoading}
                className="p-1 rounded text-[#536168] hover:text-[#E8EEF0] hover:bg-[#11171B] transition-colors disabled:opacity-50"
                title="Refresh backend status"
              >
                <RefreshCw className={`w-3 h-3 ${healthLoading ? 'animate-spin' : ''}`} />
              </button>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
