import React from 'react';
import { X, Layers, ShieldCheck, Database, Cpu, Terminal, CheckCircle2, ArrowRight } from 'lucide-react';

interface ArchitectureModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ArchitectureModal: React.FC<ArchitectureModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#07090B]/80 backdrop-blur-sm">
      <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto bg-[#0C1013] border border-[#222B30] rounded-lg shadow-2xl p-6 sm:p-7 text-[#E8EEF0]">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#222B30] pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-[#11171B] border border-[#222B30] text-[#39E58C]">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-mono font-bold text-[#E8EEF0]">
                Moriarty Architectural Pipeline
              </h2>
              <p className="text-xs text-[#8B989E]">
                Adaptive AI Structural Security Patch Verification
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#11171B] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="py-5 space-y-6 text-xs leading-relaxed">
          {/* Mission Box */}
          <div className="p-4 rounded bg-[#07090B] border border-[#222B30] font-mono">
            <span className="text-[#39E58C] font-semibold block mb-1">Central Operating Principle:</span>
            <p className="text-[#8B989E] font-sans text-xs">
              "An adaptive security verification agent that tries to disprove the claim that a vulnerability
              has been fixed before allowing that claim to be marked verified."
            </p>
          </div>

          {/* Step Pipeline */}
          <div className="space-y-3 font-mono">
            <div className="p-3.5 rounded bg-[#11171B] border border-[#222B30] flex items-start gap-3">
              <span className="w-5 h-5 rounded bg-[#07090B] border border-[#222B30] flex items-center justify-center text-[11px] font-bold text-[#39E58C] flex-shrink-0 mt-0.5">
                1
              </span>
              <div>
                <strong className="text-[#E8EEF0]">AST Static Analyzer & Invariant Generator</strong>
                <p className="text-[#8B989E] font-sans text-xs mt-0.5">
                  Parses original and patched Python code into Abstract Syntax Trees. Identifies concatenation, f-strings,
                  or parameterized queries. Formulates required security invariants.
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded bg-[#11171B] border border-[#222B30] flex items-start gap-3">
              <span className="w-5 h-5 rounded bg-[#07090B] border border-[#222B30] flex items-center justify-center text-[11px] font-bold text-[#39E58C] flex-shrink-0 mt-0.5">
                2
              </span>
              <div>
                <strong className="text-[#E8EEF0]">Finding-Aware Agent Planner</strong>
                <p className="text-[#8B989E] font-sans text-xs mt-0.5">
                  Selects active verification strategies (boolean tautologies, delimiter injection, administrative bypasses).
                  Adapts next probes based on actual runtime observations.
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded bg-[#11171B] border border-[#222B30] flex items-start gap-3">
              <span className="w-5 h-5 rounded bg-[#07090B] border border-[#222B30] flex items-center justify-center text-[11px] font-bold text-[#39E58C] flex-shrink-0 mt-0.5">
                3
              </span>
              <div>
                <strong className="text-[#E8EEF0]">Isolated Local Execution & Target Provenance</strong>
                <p className="text-[#8B989E] font-sans text-xs mt-0.5">
                  Safely compiles submitted source into an isolated execution target against an in-memory SQLite database.
                  Verifies that the executed runtime object corresponds to submitted source.
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded bg-[#11171B] border border-[#222B30] flex items-start gap-3">
              <span className="w-5 h-5 rounded bg-[#07090B] border border-[#222B30] flex items-center justify-center text-[11px] font-bold text-[#39E58C] flex-shrink-0 mt-0.5">
                4
              </span>
              <div>
                <strong className="text-[#E8EEF0]">Forensic Evidence Ledger</strong>
                <p className="text-[#8B989E] font-sans text-xs mt-0.5">
                  Records empirical observations with strict integrity validation. Distinguishes real application execution
                  from simulated fixtures. Only rigorously validated items support verification.
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded bg-[#11171B] border border-[#222B30] flex items-start gap-3">
              <span className="w-5 h-5 rounded bg-[#07090B] border border-[#222B30] flex items-center justify-center text-[11px] font-bold text-[#39E58C] flex-shrink-0 mt-0.5">
                5
              </span>
              <div>
                <strong className="text-[#E8EEF0]">Rigorous Verdict Engine</strong>
                <p className="text-[#8B989E] font-sans text-xs mt-0.5">
                  Computes VERIFIED, REJECTED, or INCONCLUSIVE with an explicit targeted scope statement.
                  Prevents false safety claims and enforces uncertainty preservation.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-[#222B30] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-mono rounded bg-[#11171B] border border-[#222B30] text-[#E8EEF0] hover:bg-[#151D22] transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
