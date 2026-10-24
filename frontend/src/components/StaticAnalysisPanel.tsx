import React from 'react';
import { FileCode, Shield, CheckCircle, AlertOctagon } from 'lucide-react';
import { AnalysisResult, PatchComparisonData } from '../types';

interface StaticAnalysisPanelProps {
  analysis?: AnalysisResult | null;
  patchComparison?: PatchComparisonData | null;
}

export const StaticAnalysisPanel: React.FC<StaticAnalysisPanelProps> = ({
  analysis,
  patchComparison,
}) => {
  if (!analysis) {
    return (
      <div className="border border-[#222B30] rounded p-8 bg-[#0C1013] text-center">
        <p className="text-xs font-mono text-[#536168]">No static analysis data available.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Patch comparison summary (if available) */}
      {patchComparison && (
        <div className="border border-[#222B30] rounded p-4 bg-[#0C1013]">
          <div className="flex items-center justify-between border-b border-[#222B30] pb-2.5">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-[#39E58C]" />
              <span className="text-xs font-mono font-bold text-[#E8EEF0]">
                AST Patch Comparison Result
              </span>
            </div>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                patchComparison.static_improvement_detected
                  ? 'bg-[#0B2418] border-[#39E58C]/30 text-[#39E58C]'
                  : 'bg-[#2B1014] border-[#FF5B64]/30 text-[#FF5B64]'
              }`}
            >
              Status: {patchComparison.status}
            </span>
          </div>

          <p className="text-xs text-[#E8EEF0] font-sans pt-3 leading-relaxed">
            {patchComparison.summary}
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3 pt-3 border-t border-[#222B30]/60 text-xs font-mono">
            <div>
              <span className="text-[#536168] block">Original Source Rules Triggered:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {patchComparison.original_rule_ids.length > 0 ? (
                  patchComparison.original_rule_ids.map(r => (
                    <span key={r} className="px-1.5 py-0.5 rounded bg-[#2B1014] text-[#FF5B64] border border-[#FF5B64]/30 text-[11px]">
                      {r}
                    </span>
                  ))
                ) : (
                  <span className="text-[#536168]">None detected</span>
                )}
              </div>
            </div>

            <div>
              <span className="text-[#536168] block">Patched Source Rules Triggered:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {patchComparison.patched_rule_ids.length > 0 ? (
                  patchComparison.patched_rule_ids.map(r => (
                    <span key={r} className="px-1.5 py-0.5 rounded bg-[#0B2418] text-[#39E58C] border border-[#39E58C]/30 text-[11px]">
                      {r}
                    </span>
                  ))
                ) : (
                  <span className="text-[#536168]">None detected</span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Analysis Findings */}
      <div className="border border-[#222B30] rounded p-4 bg-[#0C1013]">
        <div className="flex items-center justify-between border-b border-[#222B30] pb-2.5">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#8B989E]" />
            <span className="text-xs font-mono font-bold text-[#E8EEF0]">
              Static Rule Findings ({analysis.findings.length})
            </span>
          </div>
          <span className="text-[10px] font-mono text-[#536168]">
            Vulnerability: {analysis.vulnerability_type || 'NONE'}
          </span>
        </div>

        {analysis.findings.length > 0 ? (
          <div className="divide-y divide-[#222B30]/40 mt-2">
            {analysis.findings.map((finding, idx) => (
              <div key={idx} className="py-2.5 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono font-semibold text-[#E8EEF0]">
                    {finding.rule_id}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                        ? 'bg-[#2B1014] text-[#FF5B64]'
                        : 'bg-[#11171B] text-[#8B989E]'
                    }`}
                  >
                    {finding.severity}
                  </span>
                </div>
                <p className="text-xs text-[#8B989E] font-sans">{finding.message}</p>
                {finding.evidence && (
                  <code className="block text-[11px] font-mono text-[#39E58C] bg-[#07090B] p-1.5 rounded mt-1 border border-[#222B30]">
                    {finding.evidence}
                  </code>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs font-mono text-[#536168] pt-3">No static rule violations identified.</p>
        )}
      </div>

      {/* Security Invariants */}
      {analysis.security_invariants && analysis.security_invariants.length > 0 && (
        <div className="border border-[#222B30] rounded p-4 bg-[#0C1013]">
          <div className="flex items-center gap-2 border-b border-[#222B30] pb-2.5">
            <CheckCircle className="w-4 h-4 text-[#39E58C]" />
            <span className="text-xs font-mono font-bold text-[#E8EEF0]">
              Required Security Invariants
            </span>
          </div>
          <ul className="mt-3 space-y-2">
            {analysis.security_invariants.map((inv, idx) => (
              <li key={idx} className="flex items-start gap-2 text-xs text-[#8B989E]">
                <span className="text-[#39E58C] font-mono mt-0.5">•</span>
                <span>{inv}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
