import React from 'react';
import { ChevronRight, ArrowRight, CheckCircle2, XCircle, AlertCircle, PlayCircle, ShieldCheck } from 'lucide-react';
import { DecisionTraceStep } from '../types';

interface DecisionTraceTimelineProps {
  decisionTrace: DecisionTraceStep[];
}

export const DecisionTraceTimeline: React.FC<DecisionTraceTimelineProps> = ({ decisionTrace }) => {
  if (!decisionTrace || decisionTrace.length === 0) {
    return (
      <div className="border border-[#222B30] rounded p-8 bg-[#0C1013] text-center">
        <p className="text-xs font-mono text-[#536168]">No agent decision trace steps available for this run.</p>
      </div>
    );
  }

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'RUN_TEST':
        return (
          <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#E8EEF0]">
            <PlayCircle className="w-3 h-3 text-[#39E58C]" /> RUN_TEST
          </span>
        );
      case 'STOP_VERIFIED':
        return (
          <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-[#0B2418] border border-[#39E58C]/40 text-[#39E58C]">
            <ShieldCheck className="w-3 h-3" /> STOP_VERIFIED
          </span>
        );
      case 'STOP_REJECTED':
        return (
          <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-[#2B1014] border border-[#FF5B64]/40 text-[#FF5B64]">
            <XCircle className="w-3 h-3" /> STOP_REJECTED
          </span>
        );
      case 'STOP_INCONCLUSIVE':
      case 'STOP_FOR_INVESTIGATION':
        return (
          <span className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-[#2A2010] border border-[#FFBE55]/40 text-[#FFBE55]">
            <AlertCircle className="w-3 h-3" /> {action}
          </span>
        );
      default:
        return (
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E]">
            {action}
          </span>
        );
    }
  };

  const getOutcomeBadge = (outcome?: string | null) => {
    if (!outcome) return null;
    switch (outcome) {
      case 'PASS':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#0B2418] border border-[#39E58C]/30 text-[#39E58C]">
            <CheckCircle2 className="w-3 h-3" /> PASS
          </span>
        );
      case 'FAIL':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#2B1014] border border-[#FF5B64]/30 text-[#FF5B64]">
            <XCircle className="w-3 h-3" /> FAIL
          </span>
        );
      case 'ERROR':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#2A2010] border border-[#FFBE55]/30 text-[#FFBE55]">
            <AlertCircle className="w-3 h-3" /> ERROR
          </span>
        );
      default:
        return (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E]">
            {outcome}
          </span>
        );
    }
  };

  return (
    <div className="space-y-3">
      {decisionTrace.map((step, idx) => {
        const isLast = idx === decisionTrace.length - 1;
        const isStop = step.action.startsWith('STOP');

        return (
          <div
            key={idx}
            className={`border rounded p-4 transition-all ${
              isStop
                ? step.action === 'STOP_VERIFIED'
                  ? 'border-[#39E58C]/30 bg-[#0B2418]/30'
                  : step.action === 'STOP_REJECTED'
                  ? 'border-[#FF5B64]/30 bg-[#2B1014]/30'
                  : 'border-[#FFBE55]/30 bg-[#2A2010]/30'
                : 'border-[#222B30] bg-[#0C1013]'
            }`}
          >
            {/* Header row */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222B30]/60 pb-2.5">
              <div className="flex items-center gap-2.5">
                <span className="w-6 h-6 rounded bg-[#11171B] border border-[#222B30] flex items-center justify-center text-xs font-mono font-bold text-[#8B989E]">
                  {step.step}
                </span>
                {getActionBadge(step.action)}
                {step.strategy && (
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#151D22] text-[#8B989E] border border-[#222B30]">
                    Strategy: <strong className="text-[#E8EEF0]">{step.strategy}</strong>
                  </span>
                )}
              </div>

              <div className="flex items-center gap-2">
                {step.test_outcome && getOutcomeBadge(step.test_outcome)}
                {step.evidence_id && (
                  <span className="text-[10px] font-mono text-[#536168]">
                    Evidence: {step.evidence_id.substring(0, 8)}...
                  </span>
                )}
              </div>
            </div>

            {/* Test Payload (if executed) */}
            {step.test_input && (
              <div className="mt-3 px-3 py-2 rounded bg-[#07090B] border border-[#222B30] flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-mono text-[#536168] flex items-center gap-1">
                  <ArrowRight className="w-3 h-3 text-[#39E58C]" /> Probe Payload:
                </span>
                <code className="text-xs font-mono text-[#39E58C] bg-[#0C1013] px-2 py-0.5 rounded border border-[#222B30]">
                  {step.test_input}
                </code>
              </div>
            )}

            {/* Agent Reasoning */}
            <div className="mt-3 space-y-1">
              <div className="text-[11px] font-mono text-[#536168] uppercase tracking-wider">
                Agent Reasoning & Hypothesis Challenge:
              </div>
              <p className="text-xs text-[#E8EEF0] leading-relaxed font-sans">
                {step.reason}
              </p>
            </div>

            {/* Stopping reason if final */}
            {step.stop_reason && (
              <div className="mt-2.5 pt-2 border-t border-[#222B30]/40 flex items-center gap-2 text-xs font-mono">
                <span className="text-[#536168]">Conclusion Criterion:</span>
                <span className="text-[#8B989E]">{step.stop_reason}</span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
