import React from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  ArrowRight,
  Terminal,
  Cpu,
  Database,
  FileCode,
  FolderClock,
  Clock,
  Layers,
  Sparkles,
} from 'lucide-react';
import { Scenario, VerificationStats } from '../types';

interface OverviewWorkspaceProps {
  stats: VerificationStats | null;
  scenarios: Scenario[];
  onSelectScenario: (scenario: Scenario, autoRun?: boolean) => void;
  onNavigateVerify: () => void;
  onNavigateSqlLab?: () => void;
  onNavigateReports: () => void;
  onViewReport: (filename: string) => void;
  backendOnline: boolean;
}

export const OverviewWorkspace: React.FC<OverviewWorkspaceProps> = ({
  stats,
  scenarios,
  onSelectScenario,
  onNavigateVerify,
  onNavigateSqlLab,
  onNavigateReports,
  onViewReport,
  backendOnline,
}) => {
  return (
    <div className="space-y-10 py-2">
      {/* Editorial Hero Section */}
      <div className="relative overflow-hidden rounded-lg border border-[#222B30] bg-[#0C1013] p-8 sm:p-10">
        <div className="absolute inset-0 bg-tech-grid opacity-30 pointer-events-none" />

        <div className="relative z-10 max-w-4xl space-y-5">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#11171B] border border-[#222B30] text-xs font-mono text-[#8B989E]">
            <span className="w-2 h-2 rounded-full bg-[#39E58C]" />
            Moriarty 2.0 • ML-Guided Adaptive Verification & AST Patch Refinement
          </div>

          <h1 className="text-3xl sm:text-5xl font-mono font-bold tracking-tight text-[#E8EEF0] leading-tight">
            Don't trust the patch. <br />
            <span className="text-[#39E58C]">Challenge it.</span>
          </h1>

          <p className="text-sm sm:text-base text-[#8B989E] font-sans leading-relaxed max-w-2xl">
            Moriarty combines machine-learned query risk modeling with an adaptive verification agent.
            It identifies vulnerable SQL patterns, generates and refines security patches, dynamically challenges
            them against a 40-test attack catalog, and demands empirical proof before marking any fix verified.
          </p>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <button
              onClick={onNavigateVerify}
              className="px-5 py-2.5 rounded bg-[#39E58C] text-[#07090B] font-mono text-xs font-bold hover:bg-[#39E58C]/90 transition-all flex items-center gap-2 shadow-sm"
            >
              <Terminal className="w-4 h-4" />
              <span>Launch Verification Workstation</span>
            </button>

            {onNavigateSqlLab && (
              <button
                onClick={onNavigateSqlLab}
                className="px-5 py-2.5 rounded bg-[#1E1B4B] border border-[#6366F1]/60 text-[#C084FC] font-mono text-xs font-bold hover:bg-[#2E1065] transition-all flex items-center gap-2 shadow-sm"
              >
                <Sparkles className="w-4 h-4 text-[#C084FC]" />
                <span>SQL Security Lab (Continuous)</span>
              </button>
            )}

            <button
              onClick={onNavigateReports}
              className="px-4 py-2.5 rounded bg-[#11171B] border border-[#222B30] text-[#E8EEF0] font-mono text-xs hover:bg-[#151D22] transition-colors flex items-center gap-2"
            >
              <FolderClock className="w-4 h-4 text-[#8B989E]" />
              <span>Inspect Reports Archive</span>
            </button>
          </div>
        </div>
      </div>

      {/* Real Verification Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total runs */}
        <div className="border border-[#222B30] rounded p-4 bg-[#0C1013] space-y-1">
          <span className="text-xs font-mono text-[#536168]">TOTAL RUNS ON DISK</span>
          <div className="text-2xl sm:text-3xl font-mono font-bold text-[#E8EEF0]">
            {stats ? stats.total_verifications : '—'}
          </div>
          <span className="text-[11px] text-[#8B989E]">Audit reports logged</span>
        </div>

        {/* Verified */}
        <div className="border border-[#39E58C]/30 rounded p-4 bg-[#0B2418]/40 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-[#39E58C]">VERIFIED</span>
            <ShieldCheck className="w-4 h-4 text-[#39E58C]" />
          </div>
          <div className="text-2xl sm:text-3xl font-mono font-bold text-[#39E58C]">
            {stats ? stats.verified_count : '—'}
          </div>
          <span className="text-[11px] text-[#8B989E]">Proven remediations</span>
        </div>

        {/* Rejected */}
        <div className="border border-[#FF5B64]/30 rounded p-4 bg-[#2B1014]/40 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-[#FF5B64]">REJECTED</span>
            <ShieldAlert className="w-4 h-4 text-[#FF5B64]" />
          </div>
          <div className="text-2xl sm:text-3xl font-mono font-bold text-[#FF5B64]">
            {stats ? stats.rejected_count : '—'}
          </div>
          <span className="text-[11px] text-[#8B989E]">Disproved fixes</span>
        </div>

        {/* Inconclusive */}
        <div className="border border-[#FFBE55]/30 rounded p-4 bg-[#2A2010]/40 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-[#FFBE55]">INCONCLUSIVE</span>
            <AlertTriangle className="w-4 h-4 text-[#FFBE55]" />
          </div>
          <div className="text-2xl sm:text-3xl font-mono font-bold text-[#FFBE55]">
            {stats ? stats.inconclusive_count : '—'}
          </div>
          <span className="text-[11px] text-[#8B989E]">Honest uncertainty</span>
        </div>
      </div>

      {/* Preset Evaluation Scenarios */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-mono font-bold text-[#E8EEF0]">
              Evaluation Scenarios
            </h2>
            <p className="text-xs text-[#8B989E]">
              Demonstrates end-to-end adaptive verification across all three formal outcomes.
            </p>
          </div>
          <span className="text-xs font-mono text-[#536168] hidden sm:inline">
            5 Built-in Verification Testbeds
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((sc) => {
            const isVerif = sc.expected_verdict === 'VERIFIED';
            const isRej = sc.expected_verdict === 'REJECTED';

            return (
              <div
                key={sc.id}
                className="border border-[#222B30] rounded p-5 bg-[#0C1013] hover:border-[#324048] transition-all flex flex-col justify-between group"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                        isVerif
                          ? 'bg-[#0B2418] border-[#39E58C]/30 text-[#39E58C]'
                          : isRej
                          ? 'bg-[#2B1014] border-[#FF5B64]/30 text-[#FF5B64]'
                          : 'bg-[#2A2010] border-[#FFBE55]/30 text-[#FFBE55]'
                      }`}
                    >
                      EXPECTED: {sc.expected_verdict}
                    </span>
                    <span className="text-[10px] font-mono text-[#536168]">
                      {sc.vulnerability_type}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-sm font-mono font-semibold text-[#E8EEF0] group-hover:text-[#39E58C] transition-colors">
                      {sc.name}
                    </h3>
                    <p className="text-xs text-[#8B989E] font-sans mt-2 leading-relaxed">
                      {sc.description}
                    </p>
                  </div>
                </div>

                <div className="pt-4 mt-4 border-t border-[#222B30] flex items-center justify-between">
                  <button
                    onClick={() => onSelectScenario(sc, false)}
                    className="text-xs font-mono text-[#8B989E] hover:text-[#E8EEF0] transition-colors"
                  >
                    Load into Editor
                  </button>

                  <button
                    onClick={() => onSelectScenario(sc, true)}
                    className="px-3 py-1.5 rounded bg-[#11171B] border border-[#222B30] text-[#39E58C] text-xs font-mono font-medium hover:bg-[#39E58C] hover:text-[#07090B] transition-all flex items-center gap-1.5"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>Verify Now</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Verification Activity */}
      {stats && stats.recent_verifications && stats.recent_verifications.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-mono font-bold text-[#E8EEF0]">
                Recent Verification Activity
              </h2>
              <p className="text-xs text-[#8B989E]">
                Actual audit records pulled directly from the Moriarty reports storage.
              </p>
            </div>
            <button
              onClick={onNavigateReports}
              className="text-xs font-mono text-[#39E58C] hover:underline flex items-center gap-1"
            >
              <span>View All Reports</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="border border-[#222B30] rounded bg-[#0C1013] divide-y divide-[#222B30]">
            {stats.recent_verifications.slice(0, 4).map((report, idx) => {
              const isVerif = report.verdict === 'VERIFIED';
              const isRej = report.verdict === 'REJECTED';

              return (
                <div
                  key={idx}
                  className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-[#11171B]/50 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border mt-0.5 ${
                        isVerif
                          ? 'bg-[#0B2418] border-[#39E58C]/30 text-[#39E58C]'
                          : isRej
                          ? 'bg-[#2B1014] border-[#FF5B64]/30 text-[#FF5B64]'
                          : 'bg-[#2A2010] border-[#FFBE55]/30 text-[#FFBE55]'
                      }`}
                    >
                      {report.verdict}
                    </span>

                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-[#E8EEF0] font-medium">
                          {report.filename}
                        </span>
                        <span className="text-[10px] font-mono text-[#536168]">
                          Target: {report.target_type}
                        </span>
                      </div>
                      <p className="text-xs text-[#8B989E] font-sans truncate max-w-xl mt-0.5">
                        {report.summary}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 self-end sm:self-auto">
                    <span className="text-[11px] font-mono text-[#536168]">
                      {report.tests_run} tests run
                    </span>
                    <button
                      onClick={() => onViewReport(report.filename)}
                      className="px-2.5 py-1 text-xs font-mono rounded bg-[#11171B] border border-[#222B30] text-[#E8EEF0] hover:bg-[#151D22] transition-colors"
                    >
                      View Report
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
