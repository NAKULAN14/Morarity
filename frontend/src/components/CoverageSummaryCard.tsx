import React from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  HelpCircle,
  AlertTriangle,
  Info,
  Layers,
  Activity,
  Award,
} from 'lucide-react';
import { VerificationCoverage } from '../types';

interface CoverageSummaryCardProps {
  coverage?: VerificationCoverage | null;
  budgetPreset?: string;
}

export const CoverageSummaryCard: React.FC<CoverageSummaryCardProps> = ({
  coverage,
  budgetPreset,
}) => {
  if (!coverage) return null;

  const pct = coverage.coverage_percentage || 0;

  return (
    <div className="bg-[#0C1013] border border-[#222B30] rounded p-4 space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222B30] pb-3">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#39E58C]" />
          <span className="text-xs font-mono font-bold text-[#E8EEF0]">
            ADAPTIVE VERIFICATION COVERAGE & INVARIANT TRACKING
          </span>
          {budgetPreset && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#11171B] border border-[#39E58C]/40 text-[#39E58C] uppercase">
              Budget: {budgetPreset}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-[#8B989E]">
            Category Coverage:
          </span>
          <span className="text-xs font-mono font-bold text-[#39E58C]">
            {pct}%
          </span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-[#11171B] border border-[#222B30] rounded-full h-2 overflow-hidden">
        <div
          className="bg-gradient-to-r from-[#38BDF8] via-[#39E58C] to-[#10B981] h-full transition-all duration-500 rounded-full"
          style={{ width: `${Math.min(100, Math.max(5, pct))}%` }}
        />
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 text-center font-mono">
        {/* Available */}
        <div className="p-2.5 rounded bg-[#07090B] border border-[#222B30]">
          <span className="text-[10px] text-[#536168] block">CATALOG TESTS</span>
          <span className="text-base font-bold text-[#E8EEF0]">
            {coverage.tests_available}
          </span>
          <span className="text-[9px] text-[#8B989E] block mt-0.5">12 Categories</span>
        </div>

        {/* Executed */}
        <div className="p-2.5 rounded bg-[#07090B] border border-[#222B30]">
          <span className="text-[10px] text-[#536168] block">EXECUTED</span>
          <span className="text-base font-bold text-[#38BDF8]">
            {coverage.tests_executed}
          </span>
          <span className="text-[9px] text-[#8B989E] block mt-0.5">Under Budget</span>
        </div>

        {/* Passed */}
        <div className="p-2.5 rounded bg-[#0B2418]/60 border border-[#39E58C]/40">
          <span className="text-[10px] text-[#39E58C]/80 block">PASSED</span>
          <span className="text-base font-bold text-[#39E58C]">
            {coverage.tests_passed}
          </span>
          <span className="text-[9px] text-[#39E58C]/80 block mt-0.5">Neutralized</span>
        </div>

        {/* Failed */}
        <div className={`p-2.5 rounded border ${
          coverage.tests_failed > 0
            ? 'bg-[#2B1014]/60 border-[#FF5B64]/60 text-[#FF5B64]'
            : 'bg-[#07090B] border-[#222B30] text-[#536168]'
        }`}>
          <span className="text-[10px] block">FAILED</span>
          <span className="text-base font-bold">
            {coverage.tests_failed}
          </span>
          <span className="text-[9px] block mt-0.5">
            {coverage.tests_failed > 0 ? 'Exploitable' : 'Zero Leaks'}
          </span>
        </div>

        {/* Inconclusive */}
        <div className="p-2.5 rounded bg-[#07090B] border border-[#222B30]">
          <span className="text-[10px] text-[#536168] block">INCONCLUSIVE</span>
          <span className="text-base font-bold text-[#FFBE55]">
            {coverage.tests_inconclusive}
          </span>
          <span className="text-[9px] text-[#8B989E] block mt-0.5">Ambiguous</span>
        </div>

        {/* Not Applicable */}
        <div
          className="p-2.5 rounded bg-[#07090B] border border-[#222B30] relative group cursor-help"
          title="Stacked queries (semicolon delimited) are not supported by Python sqlite3 driver API and are strictly tracked as not applicable rather than falsely passed."
        >
          <div className="flex items-center justify-center gap-1">
            <span className="text-[10px] text-[#8B989E]">NOT APPLICABLE</span>
            <Info className="w-2.5 h-2.5 text-[#536168]" />
          </div>
          <span className="text-base font-bold text-[#8B989E]">
            {coverage.tests_not_applicable}
          </span>
          <span className="text-[9px] text-[#536168] block mt-0.5">Driver Limit</span>
        </div>
      </div>

      {/* Categories & Invariants Lists */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
        {/* Covered Categories */}
        <div className="p-3 rounded bg-[#07090B] border border-[#222B30] space-y-2">
          <div className="flex items-center justify-between text-[#8B989E]">
            <span className="font-bold flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-[#39E58C]" />
              COVERED TEST CATEGORIES ({coverage.categories_covered.length})
            </span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {coverage.categories_covered.map((cat, idx) => (
              <span
                key={idx}
                className="px-2 py-0.5 rounded bg-[#0B2418] border border-[#39E58C]/40 text-[#39E58C] text-[10px]"
              >
                ✓ {cat}
              </span>
            ))}
            {coverage.categories_covered.length === 0 && (
              <span className="text-[#536168] text-[11px]">No categories covered yet.</span>
            )}
          </div>
        </div>

        {/* Invariants Verified */}
        <div className="p-3 rounded bg-[#07090B] border border-[#222B30] space-y-2">
          <div className="flex items-center justify-between text-[#8B989E]">
            <span className="font-bold flex items-center gap-1.5">
              <Award className="w-3.5 h-3.5 text-[#A78BFA]" />
              INVARIANTS EMPIRICALLY CONFIRMED ({coverage.invariants_verified.length})
            </span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {coverage.invariants_verified.map((inv, idx) => (
              <span
                key={idx}
                className="px-2 py-0.5 rounded bg-[#1A132F] border border-[#A78BFA]/40 text-[#C4B5FD] text-[10px]"
              >
                ★ {inv}
              </span>
            ))}
            {coverage.invariants_verified.length === 0 && (
              <span className="text-[#536168] text-[11px]">No invariants confirmed yet.</span>
            )}
          </div>
        </div>
      </div>

      {/* Remaining Gaps Alert if any */}
      {coverage.remaining_coverage_gaps && coverage.remaining_coverage_gaps.length > 0 && (
        <div className="p-2.5 rounded bg-[#11171B] border border-[#222B30] text-[11px] font-mono text-[#8B989E] flex flex-wrap items-center gap-2">
          <span className="text-[#FB923C] font-semibold">REMAINING COVERAGE GAPS (Under current budget):</span>
          {coverage.remaining_coverage_gaps.map((gap, i) => (
            <span key={i} className="px-1.5 py-0.5 rounded bg-[#07090B] border border-[#222B30] text-[#8B989E]">
              {gap}
            </span>
          ))}
          <span className="text-[10px] text-[#536168] ml-auto">
            Expand budget to Standard (15) or Thorough (30) to test remaining categories.
          </span>
        </div>
      )}
    </div>
  );
};
