import React, { useState } from 'react';
import { ShieldCheck, ShieldX, ChevronDown, ChevronUp, Database, FileCode, CheckCircle, XCircle } from 'lucide-react';
import { Evidence } from '../types';

interface EvidenceLedgerViewProps {
  evidenceList: Evidence[];
}

export const EvidenceLedgerView: React.FC<EvidenceLedgerViewProps> = ({ evidenceList }) => {
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedIds(prev => ({ ...prev, [id]: !prev[id] }));
  };

  if (!evidenceList || evidenceList.length === 0) {
    return (
      <div className="border border-[#222B30] rounded p-8 bg-[#0C1013] text-center">
        <p className="text-xs font-mono text-[#536168]">No evidence items recorded in ledger.</p>
      </div>
    );
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'REAL_APPLICATION_VERIFICATION':
        return <Database className="w-3.5 h-3.5 text-[#39E58C]" />;
      case 'STATIC_ANALYSIS':
        return <FileCode className="w-3.5 h-3.5 text-[#8B989E]" />;
      default:
        return <Database className="w-3.5 h-3.5 text-[#FFBE55]" />;
    }
  };

  return (
    <div className="space-y-3">
      {evidenceList.map((item) => {
        const isExpanded = !!expandedIds[item.evidence_id];
        const obs = item.observed || {};

        return (
          <div
            key={item.evidence_id}
            className="border border-[#222B30] rounded bg-[#0C1013] overflow-hidden transition-all"
          >
            {/* Header / Summary Bar */}
            <div
              onClick={() => toggleExpand(item.evidence_id)}
              className="flex items-center justify-between px-4 py-3 bg-[#07090B]/60 cursor-pointer hover:bg-[#11171B] transition-colors border-b border-[#222B30]/60"
            >
              <div className="flex items-center gap-3">
                <div className="p-1.5 rounded bg-[#11171B] border border-[#222B30]">
                  {getCategoryIcon(item.category)}
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-[#E8EEF0]">
                      {item.test_id}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E]">
                      {item.category}
                    </span>
                  </div>
                  <p className="text-xs text-[#8B989E] font-sans truncate max-w-xl">
                    {item.description}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                {/* Supports verification badge */}
                {item.supports_verification ? (
                  <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-[#0B2418] border border-[#39E58C]/40 text-[#39E58C]">
                    <ShieldCheck className="w-3 h-3" /> VERIFYING EVIDENCE
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#536168]">
                    <ShieldX className="w-3 h-3" /> NON-VERIFYING
                  </span>
                )}

                <button className="text-[#8B989E] p-1">
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Quick Properties Bar */}
            <div className="px-4 py-2 bg-[#07090B]/30 flex flex-wrap items-center gap-4 text-xs font-mono border-b border-[#222B30]/30">
              {obs.payload !== undefined && (
                <div className="flex items-center gap-1">
                  <span className="text-[#536168]">Payload:</span>
                  <code className="text-[#39E58C] bg-[#11171B] px-1.5 py-0.5 rounded text-[11px]">
                    {obs.payload || "''"}
                  </code>
                </div>
              )}

              {obs.baseline_exploitable !== undefined && (
                <div className="flex items-center gap-1">
                  <span className="text-[#536168]">Baseline Exploitable:</span>
                  <span className={obs.baseline_exploitable ? 'text-[#39E58C]' : 'text-[#FFBE55]'}>
                    {obs.baseline_exploitable ? 'TRUE' : 'FALSE'}
                  </span>
                </div>
              )}

              {obs.patch_blocks_payload !== undefined && (
                <div className="flex items-center gap-1">
                  <span className="text-[#536168]">Patch Blocks:</span>
                  <span className={obs.patch_blocks_payload ? 'text-[#39E58C]' : 'text-[#FF5B64]'}>
                    {obs.patch_blocks_payload ? 'TRUE' : 'FALSE'}
                  </span>
                </div>
              )}

              {obs.functionality_intact !== undefined && (
                <div className="flex items-center gap-1">
                  <span className="text-[#536168]">Functionality:</span>
                  <span className={obs.functionality_intact ? 'text-[#39E58C]' : 'text-[#FFBE55]'}>
                    {obs.functionality_intact ? 'PRESERVED' : 'FAILED'}
                  </span>
                </div>
              )}

              {obs.target_provenance && (
                <div className="flex items-center gap-1">
                  <span className="text-[#536168]">Provenance:</span>
                  <span className="text-[#E8EEF0]">{obs.target_provenance}</span>
                </div>
              )}
            </div>

            {/* Expandable Technical Details */}
            {isExpanded && (
              <div className="p-4 bg-[#07090B] border-t border-[#222B30] space-y-3">
                <div className="text-[11px] font-mono text-[#536168] uppercase tracking-wider">
                  Raw Observed Evidence Schema (Audit Ledger)
                </div>
                <pre className="text-xs font-mono text-[#8B989E] bg-[#0C1013] p-3 rounded border border-[#222B30] overflow-x-auto leading-relaxed">
                  {JSON.stringify(obs, null, 2)}
                </pre>
                <div className="text-[10px] font-mono text-[#536168]">
                  Evidence UUID: {item.evidence_id} • Timestamp: {item.timestamp || 'N/A'}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
