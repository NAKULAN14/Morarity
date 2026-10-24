import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Cpu, Crosshair, CheckCircle2 } from 'lucide-react';
import { VerdictType } from '../types';

interface VerdictBannerProps {
  verdict: VerdictType;
  summary: string;
  verificationId: string;
  targetType?: string | null;
  targetProvenance?: string | null;
  verificationScope?: string | null;
  stoppingReason?: string | null;
  submittedSourceExecuted?: boolean | null;
  dynamicVerificationPerformed?: boolean | null;
}

export const VerdictBanner: React.FC<VerdictBannerProps> = ({
  verdict,
  summary,
  verificationId,
  targetType,
  targetProvenance,
  verificationScope,
  stoppingReason,
  submittedSourceExecuted,
  dynamicVerificationPerformed,
}) => {
  const isVerified = verdict === 'VERIFIED';
  const isRejected = verdict === 'REJECTED';
  const isInconclusive = verdict === 'INCONCLUSIVE';

  const config = {
    VERIFIED: {
      title: 'VERIFIED',
      subtitle: 'The available evidence supports that the vulnerability has been successfully remediated.',
      textColor: 'text-[#39E58C]',
      bgColor: 'bg-[#0B2418]',
      borderColor: 'border-[#39E58C]/40',
      badgeBg: 'bg-[#39E58C]/10',
      badgeBorder: 'border-[#39E58C]/30',
      Icon: ShieldCheck,
      statement: 'Empirical challenge disproved exploitability & confirmed parameter separation.',
    },
    REJECTED: {
      title: 'REJECTED',
      subtitle: 'The verification found evidence that the patch does not adequately prevent the vulnerability.',
      textColor: 'text-[#FF5B64]',
      bgColor: 'bg-[#2B1014]',
      borderColor: 'border-[#FF5B64]/40',
      badgeBg: 'bg-[#FF5B64]/10',
      badgeBorder: 'border-[#FF5B64]/30',
      Icon: ShieldAlert,
      statement: 'Security claim disproved: test payloads altered query logic or leaked records.',
    },
    INCONCLUSIVE: {
      title: 'INCONCLUSIVE',
      subtitle: 'The available evidence is insufficient to establish whether the patch is effective.',
      textColor: 'text-[#FFBE55]',
      bgColor: 'bg-[#2A2010]',
      borderColor: 'border-[#FFBE55]/40',
      badgeBg: 'bg-[#FFBE55]/10',
      badgeBorder: 'border-[#FFBE55]/30',
      Icon: AlertTriangle,
      statement: 'Preserving uncertainty: missing real runtime target, broken functionality, or AST parsing limits.',
    },
  }[verdict];

  const CurrentIcon = config.Icon;

  return (
    <div
      className={`relative overflow-hidden rounded border ${config.borderColor} ${config.bgColor} p-6 sm:p-7 transition-all`}
    >
      {/* Precision grid highlight effect */}
      <div className="absolute inset-0 bg-tech-dots opacity-20 pointer-events-none" />

      <div className="relative z-10">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          {/* Main Verdict Badge & Statement */}
          <div className="flex items-start gap-4 sm:gap-5">
            <div
              className={`p-3.5 rounded border ${config.badgeBorder} ${config.badgeBg} ${config.textColor} flex-shrink-0 mt-0.5`}
            >
              <CurrentIcon className="w-8 h-8" />
            </div>

            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-3">
                <span className={`text-2xl sm:text-3xl font-mono font-bold tracking-wider ${config.textColor}`}>
                  {config.title}
                </span>

                <span
                  className={`text-xs font-mono font-medium px-2.5 py-0.5 rounded border ${config.badgeBorder} ${config.badgeBg} ${config.textColor}`}
                >
                  {isVerified && 'Remediation Proven'}
                  {isRejected && 'Exploit Succeeded'}
                  {isInconclusive && 'Honest Uncertainty'}
                </span>

                <span className="text-xs font-mono text-[#8B989E]">
                  ID: <span className="text-[#E8EEF0]">{verificationId}</span>
                </span>
              </div>

              <p className="text-sm font-medium text-[#E8EEF0] leading-relaxed max-w-3xl">
                {config.subtitle}
              </p>

              <p className="text-xs text-[#8B989E] font-sans pt-1">
                {summary}
              </p>
            </div>
          </div>

          {/* Verification Scope & Provenance Metadata Card */}
          <div className="lg:w-80 flex-shrink-0 bg-[#07090B]/60 border border-[#222B30] rounded p-3.5 text-xs font-mono space-y-2">
            <div className="flex items-center justify-between border-b border-[#222B30] pb-1.5">
              <span className="text-[#536168] flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-[#8B989E]" /> Target Type
              </span>
              <span className="text-[#E8EEF0] truncate max-w-[170px]">
                {targetType || 'SUBMITTED_SOURCE_ENV'}
              </span>
            </div>

            <div className="flex items-center justify-between border-b border-[#222B30] pb-1.5">
              <span className="text-[#536168] flex items-center gap-1.5">
                <Crosshair className="w-3.5 h-3.5 text-[#8B989E]" /> Provenance
              </span>
              <span className={`truncate max-w-[170px] ${targetProvenance?.includes('MATCH') || targetProvenance?.includes('RESTRICTED') ? 'text-[#39E58C]' : 'text-[#FFBE55]'}`}>
                {targetProvenance || 'RESTRICTED_SOURCE_ENV'}
              </span>
            </div>

            <div className="flex items-center justify-between border-b border-[#222B30] pb-1.5">
              <span className="text-[#536168] flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-[#8B989E]" /> Source Executed
              </span>
              <span className={submittedSourceExecuted ? 'text-[#39E58C]' : 'text-[#8B989E]'}>
                {submittedSourceExecuted ? 'YES (Isolated SQLite)' : 'NO (Demonstration Only)'}
              </span>
            </div>

            {stoppingReason && (
              <div className="pt-0.5">
                <span className="text-[10px] text-[#536168] block">Stopping Reason</span>
                <span className="text-[11px] text-[#8B989E] truncate block font-sans">
                  {stoppingReason}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Scope Note */}
        {verificationScope && (
          <div className="mt-4 pt-3 border-t border-[#222B30]/60 flex flex-wrap items-center justify-between gap-2 text-[11px] text-[#536168] font-mono">
            <div>
              <span className="text-[#8B989E]">Scope:</span> {verificationScope}
            </div>
            <div className="text-[#8B989E]">
              {dynamicVerificationPerformed ? '• Real Dynamic Verification' : '• Static & Demonstration Fixture'}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
