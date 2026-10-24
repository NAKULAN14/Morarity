import React, { useState } from 'react';
import { Sparkles, CheckCircle2, AlertTriangle, ArrowRight, X, Code2 } from 'lucide-react';
import { PatchRefineResponse, PatchRefinementCandidate } from '../types';

interface PatchRefinementDrawerProps {
  refineResult: PatchRefineResponse | null;
  isOpen: boolean;
  onClose: () => void;
  onApplyCandidate: (code: string) => void;
}

export const PatchRefinementDrawer: React.FC<PatchRefinementDrawerProps> = ({
  refineResult,
  isOpen,
  onClose,
  onApplyCandidate,
}) => {
  if (!isOpen || !refineResult) return null;

  const [selectedAttempt, setSelectedAttempt] = useState<number>(
    refineResult.candidates.length > 0 ? refineResult.candidates[refineResult.candidates.length - 1].attempt : 1
  );

  const activeCandidate: PatchRefinementCandidate =
    refineResult.candidates.find((c) => c.attempt === selectedAttempt) || refineResult.candidates[0];

  const origRisk = refineResult.original_ml_analysis?.risk_score ?? 0.0;
  const refinedRisk = refineResult.final_ml_analysis?.risk_score ?? 0.0;
  const riskReductionPct = origRisk > 0 ? Math.max(0, Math.round(((origRisk - refinedRisk) / origRisk) * 100)) : 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-mono">
      <div className="bg-[#0C1013] border border-[#222B30] rounded-lg max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-[#222B30] bg-[#07090B] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-5 h-5 text-[#C084FC]" />
            <div>
              <h3 className="text-sm font-bold text-[#E8EEF0] flex items-center gap-2">
                AUTOMATED PATCH REFINEMENT LOOP
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#1E1B4B] border border-[#6366F1]/40 text-[#A5B4FC]">
                  {refineResult.attempts_made} / {refineResult.max_attempts} Bounded Iterations
                </span>
              </h3>
              <p className="text-[11px] text-[#8B989E]">
                Independent AST and ML classifier re-evaluation of candidate patches.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#11171B]"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Refinement Progression Summary */}
        <div className="p-4 bg-[#11171B] border-b border-[#222B30] flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-4">
            <div>
              <span className="text-[10px] text-[#536168] block">ORIGINAL ML RISK</span>
              <span className="font-bold text-[#FF5B64]">
                {Math.round(origRisk * 100)}% ({refineResult.original_ml_analysis?.risk_level})
              </span>
            </div>
            <ArrowRight className="w-4 h-4 text-[#536168]" />
            <div>
              <span className="text-[10px] text-[#536168] block">REFINED ML RISK</span>
              <span className="font-bold text-[#39E58C]">
                {Math.round(refinedRisk * 100)}% ({refineResult.final_ml_analysis?.risk_level})
              </span>
            </div>
            <div className="pl-2 border-l border-[#222B30]">
              <span className="text-[10px] text-[#536168] block">RISK REDUCTION</span>
              <span className="font-bold text-[#39E58C]">
                -{riskReductionPct}%
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] text-[#8B989E]">Status:</span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                refineResult.is_fully_refined
                  ? 'bg-[#0B2418] border-[#39E58C]/40 text-[#39E58C]'
                  : 'bg-[#2B1014] border-[#FF5B64]/40 text-[#FF5B64]'
              }`}
            >
              {refineResult.is_fully_refined ? 'FULLY REFINED' : 'PARTIALLY REFINED'}
            </span>
          </div>
        </div>

        {/* Candidates Stepper Bar */}
        <div className="flex border-b border-[#222B30] bg-[#07090B] overflow-x-auto">
          {refineResult.candidates.map((cand) => {
            const isSelected = cand.attempt === selectedAttempt;
            return (
              <button
                key={cand.attempt}
                onClick={() => setSelectedAttempt(cand.attempt)}
                className={`px-4 py-3 text-xs transition-colors border-r border-[#222B30] flex items-center gap-2 ${
                  isSelected
                    ? 'bg-[#11171B] text-[#E8EEF0] border-b-2 border-b-[#C084FC]'
                    : 'text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
                }`}
              >
                <span className="w-4 h-4 rounded-full bg-[#1E1B4B] border border-[#6366F1]/50 text-[#C084FC] text-[10px] flex items-center justify-center font-bold">
                  {cand.attempt}
                </span>
                <span>Candidate #{cand.attempt}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded border ${
                    cand.ml_risk_level === 'LOW'
                      ? 'bg-[#0B2418] text-[#39E58C] border-[#39E58C]/30'
                      : 'bg-[#2B1014] text-[#FF5B64] border-[#FF5B64]/30'
                  }`}
                >
                  {Math.round(cand.ml_risk_score * 100)}%
                </span>
              </button>
            );
          })}
        </div>

        {/* Candidate Detail View */}
        {activeCandidate && (
          <div className="p-4 overflow-y-auto flex-1 space-y-4">
            <div className="bg-[#07090B] border border-[#222B30] rounded p-3 space-y-2 text-xs">
              <span className="text-[10px] text-[#536168] block">EXPLANATION & ANALYSIS</span>
              <div className="text-[#E8EEF0] leading-relaxed">{activeCandidate.explanation}</div>

              {activeCandidate.unresolved_findings && activeCandidate.unresolved_findings.length > 0 && (
                <div className="pt-2 border-t border-[#222B30]">
                  <span className="text-[10px] text-[#FF5B64] block mb-1">Unresolved Residual Findings:</span>
                  <div className="flex flex-wrap gap-1">
                    {activeCandidate.unresolved_findings.map((f, i) => (
                      <span
                        key={i}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-[#2B1014] border border-[#FF5B64]/30 text-[#FF5B64]"
                      >
                        ⚠ {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Candidate Code */}
            <div className="space-y-1.5">
              <span className="text-xs text-[#8B989E] font-bold flex items-center gap-1.5">
                <Code2 className="w-3.5 h-3.5 text-[#39E58C]" />
                GENERATED CANDIDATE CODE #{activeCandidate.attempt}
              </span>
              <pre className="bg-[#07090B] border border-[#222B30] rounded p-3 text-xs text-[#E8EEF0] overflow-x-auto leading-relaxed max-h-[220px]">
                {activeCandidate.patch_code}
              </pre>
            </div>
          </div>
        )}

        {/* Footer Actions */}
        <div className="p-3 bg-[#07090B] border-t border-[#222B30] flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded bg-[#11171B] border border-[#222B30] text-xs text-[#8B989E] hover:text-[#E8EEF0]"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              if (activeCandidate) {
                onApplyCandidate(activeCandidate.patch_code);
                onClose();
              }
            }}
            className="px-4 py-1.5 rounded bg-[#39E58C] text-[#07090B] text-xs font-bold hover:bg-[#39E58C]/90 flex items-center gap-1.5"
          >
            <CheckCircle2 className="w-4 h-4" />
            <span>Apply Candidate #{activeCandidate?.attempt} to Patch Editor</span>
          </button>
        </div>
      </div>
    </div>
  );
};
