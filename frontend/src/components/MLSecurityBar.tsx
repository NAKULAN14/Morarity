import React from 'react';
import { Cpu, ShieldCheck, ShieldAlert, Sparkles, ArrowRight, Brain, Zap } from 'lucide-react';
import { MLAnalysisResult } from '../types';

interface MLSecurityBarProps {
  originalML?: MLAnalysisResult | null;
  patchedML?: MLAnalysisResult | null;
  mode?: 'ml_guided' | 'rule_based' | string;
  className?: string;
}

export const MLSecurityBar: React.FC<MLSecurityBarProps> = ({
  originalML,
  patchedML,
  mode = 'ml_guided',
  className = '',
}) => {
  if (!originalML && !patchedML) return null;

  const getRiskColor = (level?: string) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return { text: 'text-[#FF5B64]', bg: 'bg-[#2B1014]', border: 'border-[#FF5B64]/40', bar: 'bg-[#FF5B64]' };
      case 'MEDIUM':
        return { text: 'text-[#FFBE55]', bg: 'bg-[#2A2010]', border: 'border-[#FFBE55]/40', bar: 'bg-[#FFBE55]' };
      default:
        return { text: 'text-[#39E58C]', bg: 'bg-[#0B2418]', border: 'border-[#39E58C]/40', bar: 'bg-[#39E58C]' };
    }
  };

  const origRisk = originalML ? originalML.risk_score : 0.0;
  const patchedRisk = patchedML ? patchedML.risk_score : 0.0;
  const origColor = getRiskColor(originalML?.risk_level);
  const patchColor = getRiskColor(patchedML?.risk_level);

  let reductionPct = 0;
  if (originalML && patchedML && origRisk > 0) {
    reductionPct = Math.max(0, Math.round(((origRisk - patchedRisk) / origRisk) * 100));
  }

  return (
    <div className={`bg-[#0C1013] border border-[#222B30] rounded p-4 space-y-3 font-mono ${className}`}>
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#222B30] pb-2.5">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-[#818CF8]" />
          <span className="text-xs font-bold text-[#E8EEF0] tracking-wide">
            ML-GUIDED SECURITY VERIFICATION ENGINE
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-[#1E1B4B] border border-[#6366F1]/40 text-[#A5B4FC]">
            TF-IDF (2-5) + Logistic Regression {originalML?.model_version || 'v1.0.0'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] text-[#536168]">PLANNER STRATEGY:</span>
          <span
            className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
              mode === 'ml_guided'
                ? 'bg-[#1E1B4B] border-[#818CF8]/50 text-[#C7D2FE]'
                : 'bg-[#11171B] border-[#222B30] text-[#8B989E]'
            }`}
          >
            {mode === 'ml_guided' ? 'ML_GUIDED_ADAPTIVE' : 'RULE_BASED'}
          </span>
        </div>
      </div>

      {/* Side-by-side Risk Comparison Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {/* Original Code ML Risk */}
        {originalML && (
          <div className="bg-[#07090B] border border-[#222B30] rounded p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-[#8B989E]">ORIGINAL SOURCE RISK</span>
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded border ${origColor.bg} ${origColor.border} ${origColor.text}`}
              >
                {originalML.risk_level} ({Math.round(origRisk * 100)}%)
              </span>
            </div>

            {/* Probability Progress Bar */}
            <div className="w-full bg-[#11171B] h-1.5 rounded-full overflow-hidden border border-[#222B30]">
              <div
                className={`h-full ${origColor.bar} transition-all duration-500`}
                style={{ width: `${Math.round(origRisk * 100)}%` }}
              />
            </div>

            {/* Detected Features */}
            {originalML.detected_features && originalML.detected_features.length > 0 && (
              <div className="pt-1 flex flex-wrap gap-1">
                {originalML.detected_features.map((feat, i) => (
                  <span
                    key={i}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-[#11171B] text-[#FF5B64] border border-[#FF5B64]/30"
                  >
                    {feat}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Patched Code ML Risk */}
        {patchedML && (
          <div className="bg-[#07090B] border border-[#222B30] rounded p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-[#8B989E]">REMEDIATED PATCH RISK</span>
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded border ${patchColor.bg} ${patchColor.border} ${patchColor.text}`}
              >
                {patchedML.risk_level} ({Math.round(patchedRisk * 100)}%)
              </span>
            </div>

            {/* Probability Progress Bar */}
            <div className="w-full bg-[#11171B] h-1.5 rounded-full overflow-hidden border border-[#222B30]">
              <div
                className={`h-full ${patchColor.bar} transition-all duration-500`}
                style={{ width: `${Math.round(patchedRisk * 100)}%` }}
              />
            </div>

            {/* Detected Features */}
            {patchedML.detected_features && patchedML.detected_features.length > 0 && (
              <div className="pt-1 flex flex-wrap gap-1">
                {patchedML.detected_features.map((feat, i) => (
                  <span
                    key={i}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-[#11171B] text-[#39E58C] border border-[#39E58C]/30"
                  >
                    {feat}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Risk Delta & Recommended Categories */}
        <div className="bg-[#07090B] border border-[#222B30] rounded p-3 space-y-2 md:col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-[#8B989E]">MEASURED REMEDIATION DELTA</span>
            {originalML && patchedML && (
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                  reductionPct > 0
                    ? 'bg-[#0B2418] border-[#39E58C]/40 text-[#39E58C]'
                    : 'bg-[#2B1014] border-[#FF5B64]/40 text-[#FF5B64]'
                }`}
              >
                {reductionPct > 0 ? `-${reductionPct}% RISK` : 'NO REDUCTION'}
              </span>
            )}
          </div>

          {/* Test Categories Prioritized */}
          {originalML?.recommended_test_categories && originalML.recommended_test_categories.length > 0 && (
            <div className="space-y-1">
              <span className="text-[10px] text-[#536168] block">PRIORITIZED TEST CATEGORIES:</span>
              <div className="flex flex-wrap gap-1">
                {originalML.recommended_test_categories.map((cat, i) => (
                  <span
                    key={i}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-[#11171B] text-[#38BDF8] border border-[#38BDF8]/30"
                  >
                    {cat}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
