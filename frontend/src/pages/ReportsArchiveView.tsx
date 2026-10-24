import React, { useState } from 'react';
import { FolderClock, ShieldCheck, ShieldAlert, AlertTriangle, Eye, RefreshCw, FileText, Download } from 'lucide-react';
import { ReportSummary, VerdictType } from '../types';

interface ReportsArchiveViewProps {
  reports: ReportSummary[];
  loading: boolean;
  onRefresh: () => void;
  onSelectReport: (filename: string) => void;
}

export const ReportsArchiveView: React.FC<ReportsArchiveViewProps> = ({
  reports,
  loading,
  onRefresh,
  onSelectReport,
}) => {
  const [filter, setFilter] = useState<'ALL' | VerdictType>('ALL');

  const filteredReports = reports.filter((r) => {
    if (filter === 'ALL') return true;
    return r.verdict === filter;
  });

  return (
    <div className="space-y-6 py-2">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#222B30] pb-4">
        <div>
          <h1 className="text-xl font-mono font-bold text-[#E8EEF0] flex items-center gap-2">
            <FolderClock className="w-5 h-5 text-[#39E58C]" />
            Verification Reports Archive
          </h1>
          <p className="text-xs text-[#8B989E] mt-0.5">
            Immutable JSON reports and audit ledgers generated from empirical verification sessions.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="px-3 py-1.5 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E] hover:text-[#E8EEF0] text-xs font-mono transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Archive</span>
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2">
        {(['ALL', 'VERIFIED', 'REJECTED', 'INCONCLUSIVE'] as const).map((v) => (
          <button
            key={v}
            onClick={() => setFilter(v)}
            className={`px-3 py-1 rounded text-xs font-mono transition-colors border ${
              filter === v
                ? 'bg-[#151D22] border-[#39E58C] text-[#E8EEF0]'
                : 'bg-[#0C1013] border-[#222B30] text-[#8B989E] hover:text-[#E8EEF0]'
            }`}
          >
            {v === 'ALL' ? 'All Reports' : v}
            <span className="ml-1.5 text-[10px] text-[#536168]">
              ({v === 'ALL' ? reports.length : reports.filter((r) => r.verdict === v).length})
            </span>
          </button>
        ))}
      </div>

      {/* Reports Table / Cards */}
      {filteredReports.length === 0 ? (
        <div className="border border-[#222B30] rounded p-12 bg-[#0C1013] text-center space-y-2">
          <FileText className="w-8 h-8 text-[#536168] mx-auto" />
          <h3 className="text-sm font-mono text-[#E8EEF0]">No reports match this filter</h3>
          <p className="text-xs text-[#8B989E]">Run a verification to generate audit reports on disk.</p>
        </div>
      ) : (
        <div className="border border-[#222B30] rounded bg-[#0C1013] divide-y divide-[#222B30] overflow-hidden">
          {filteredReports.map((report) => {
            const isVerif = report.verdict === 'VERIFIED';
            const isRej = report.verdict === 'REJECTED';

            return (
              <div
                key={report.filename}
                className="p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-[#11171B]/50 transition-colors"
              >
                <div className="flex items-start gap-4">
                  <div
                    className={`p-2 rounded border mt-0.5 ${
                      isVerif
                        ? 'bg-[#0B2418] border-[#39E58C]/30 text-[#39E58C]'
                        : isRej
                        ? 'bg-[#2B1014] border-[#FF5B64]/30 text-[#FF5B64]'
                        : 'bg-[#2A2010] border-[#FFBE55]/30 text-[#FFBE55]'
                    }`}
                  >
                    {isVerif ? (
                      <ShieldCheck className="w-5 h-5" />
                    ) : isRej ? (
                      <ShieldAlert className="w-5 h-5" />
                    ) : (
                      <AlertTriangle className="w-5 h-5" />
                    )}
                  </div>

                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className="text-xs font-mono font-bold text-[#E8EEF0]">
                        {report.filename}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          isVerif
                            ? 'bg-[#0B2418] border-[#39E58C]/30 text-[#39E58C]'
                            : isRej
                            ? 'bg-[#2B1014] border-[#FF5B64]/30 text-[#FF5B64]'
                            : 'bg-[#2A2010] border-[#FFBE55]/30 text-[#FFBE55]'
                        }`}
                      >
                        {report.verdict}
                      </span>
                      <span className="text-[10px] font-mono text-[#536168]">
                        Target: {report.target_type}
                      </span>
                    </div>

                    <p className="text-xs text-[#8B989E] font-sans line-clamp-2 max-w-3xl">
                      {report.summary}
                    </p>

                    <div className="flex flex-wrap items-center gap-4 pt-1 text-[11px] font-mono text-[#536168]">
                      <span>Provenance: <strong className="text-[#8B989E]">{report.target_provenance}</strong></span>
                      <span>Tests Executed: <strong className="text-[#8B989E]">{report.tests_run}</strong></span>
                      {report.stopping_reason && (
                        <span>Stopping Reason: <strong className="text-[#8B989E]">{report.stopping_reason}</strong></span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end md:self-auto flex-shrink-0">
                  <button
                    onClick={() => onSelectReport(report.filename)}
                    className="px-3.5 py-1.5 rounded bg-[#11171B] border border-[#222B30] text-[#E8EEF0] hover:bg-[#151D22] text-xs font-mono transition-colors flex items-center gap-1.5"
                  >
                    <Eye className="w-3.5 h-3.5 text-[#39E58C]" />
                    <span>Inspect Ledger</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
