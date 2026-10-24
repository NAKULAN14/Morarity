import React from 'react';
import { Brain, Sparkles, ShieldAlert, AlertTriangle, Lightbulb, CheckCircle2, Lock } from 'lucide-react';
import { LLMReasoningResult } from '../types';

interface LLMReasoningCardProps {
  reasoning: LLMReasoningResult | null | undefined;
}

export const LLMReasoningCard: React.FC<LLMReasoningCardProps> = ({ reasoning }) => {
  if (!reasoning || (!reasoning.summary && reasoning.hypotheses.length === 0)) return null;

  const isFallback = reasoning.status === 'FALLBACK';
  const confidencePct = Math.round((reasoning.confidence || 0.85) * 100);

  return (
    <div className="bg-[#0C1013] border border-[#38BDF8]/40 rounded-lg p-4 font-mono space-y-3.5 shadow-lg shadow-[#38BDF8]/5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#222B30] pb-2.5">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-[#38BDF8]" />
          <span className="text-xs font-bold text-[#E8EEF0] tracking-wider">
            LLM SECURITY REASONING & HYPOTHESIS ENGINE
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#38BDF8]">
            {reasoning.model_name}
          </span>
          {reasoning.latency_ms > 0 && (
            <span className="text-[10px] text-[#536168]">
              {reasoning.latency_ms}ms
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] text-[#536168]">Confidence:</span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-[#0B2418] border border-[#39E58C]/40 text-[#39E58C] font-bold">
            {confidencePct}%
          </span>
          <span
            className={`text-[10px] px-2 py-0.5 rounded border ${
              isFallback
                ? 'bg-[#2A2010] text-[#FFBE55] border-[#FFBE55]/40'
                : 'bg-[#0B2418] text-[#39E58C] border-[#39E58C]/40'
            }`}
          >
            {reasoning.status}
          </span>
        </div>
      </div>

      {/* Summary */}
      <div className="text-xs text-[#E8EEF0] bg-[#07090B] p-3 rounded border border-[#222B30] leading-relaxed">
        <span className="text-[10px] text-[#38BDF8] font-bold block mb-1 flex items-center gap-1.5">
          <Sparkles className="w-3 h-3 text-[#38BDF8]" />
          TECHNICAL REASONING SYNTHESIS:
        </span>
        {reasoning.summary}
      </div>

      {/* Hypotheses & Recommended Categories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        {/* Hypotheses */}
        <div className="space-y-2 bg-[#07090B] p-3 rounded border border-[#222B30]">
          <span className="text-[10px] text-[#8B989E] font-bold block flex items-center gap-1.5">
            <Lightbulb className="w-3 h-3 text-[#FFBE55]" />
            SECURITY HYPOTHESES ({reasoning.hypotheses.length})
          </span>
          <div className="space-y-1.5">
            {reasoning.hypotheses.map((hyp, i) => (
              <div key={i} className="flex items-start gap-1.5 text-[11px] text-[#E8EEF0] leading-relaxed">
                <span className="text-[#38BDF8] select-none">▸</span>
                <span>{hyp}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recommended Test Categories */}
        <div className="space-y-2 bg-[#07090B] p-3 rounded border border-[#222B30]">
          <span className="text-[10px] text-[#8B989E] font-bold block flex items-center gap-1.5">
            <CheckCircle2 className="w-3 h-3 text-[#39E58C]" />
            RECOMMENDED PROBE CATEGORIES
          </span>
          <div className="flex flex-wrap gap-1.5">
            {reasoning.recommended_test_categories.map((cat, i) => (
              <span
                key={i}
                className="text-[10px] px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#38BDF8]"
              >
                {cat}
              </span>
            ))}
          </div>

          {/* Patch Concerns (if present) */}
          {reasoning.patch_concerns && reasoning.patch_concerns.length > 0 && (
            <div className="pt-2 border-t border-[#222B30] space-y-1">
              <span className="text-[10px] text-[#FF5B64] font-bold block flex items-center gap-1">
                <ShieldAlert className="w-3 h-3 text-[#FF5B64]" />
                PATCH RESIDUAL CONCERNS:
              </span>
              {reasoning.patch_concerns.map((concern, i) => (
                <div key={i} className="text-[11px] text-[#FF5B64]/90 flex items-start gap-1.5">
                  <span>•</span>
                  <span>{concern}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Advisory Boundary Footer */}
      <div className="flex items-center gap-2 text-[10px] text-[#536168] bg-[#07090B]/60 px-3 py-1.5 rounded border border-[#222B30]">
        <Lock className="w-3 h-3 flex-shrink-0 text-[#8B989E]" />
        <span>
          <strong className="text-[#8B989E]">Advisory Boundary:</strong> The LLM proposes hypotheses and suggests test challenges. It does not determine the final security verdict; all claims must be empirically proven in the controlled sandbox.
        </span>
      </div>
    </div>
  );
};
