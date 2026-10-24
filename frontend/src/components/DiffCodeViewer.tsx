import React, { useState } from 'react';
import { Copy, Check, Code, AlertTriangle, ShieldCheck } from 'lucide-react';

interface DiffCodeViewerProps {
  originalSource: string;
  patchedSource: string;
  originalFindings?: string[];
  patchedFindings?: string[];
}

export const DiffCodeViewer: React.FC<DiffCodeViewerProps> = ({
  originalSource,
  patchedSource,
  originalFindings = [],
  patchedFindings = [],
}) => {
  const [copiedOriginal, setCopiedOriginal] = useState(false);
  const [copiedPatched, setCopiedPatched] = useState(false);

  const copyToClipboard = (text: string, isOriginal: boolean) => {
    navigator.clipboard.writeText(text);
    if (isOriginal) {
      setCopiedOriginal(true);
      setTimeout(() => setCopiedOriginal(false), 2000);
    } else {
      setCopiedPatched(true);
      setTimeout(() => setCopiedPatched(false), 2000);
    }
  };

  const renderCodeLines = (code: string, isVulnerable: boolean) => {
    const lines = code.trim().split('\n');
    return lines.map((line, index) => {
      const lineNum = index + 1;
      const hasUnsafeSql = isVulnerable && (line.includes('+') || line.includes('f"') || line.includes("f'"));
      const hasSafeParam = !isVulnerable && line.includes('?');

      return (
        <div
          key={index}
          className={`flex items-start text-xs font-mono leading-5 hover:bg-[#11171B] ${
            hasUnsafeSql
              ? 'bg-[#2B1014]/30 text-[#FF5B64]'
              : hasSafeParam
              ? 'bg-[#0B2418]/30 text-[#39E58C]'
              : 'text-[#E8EEF0]'
          }`}
        >
          <span className="w-10 text-right pr-3 select-none text-[#536168] bg-[#07090B]/40 flex-shrink-0">
            {lineNum}
          </span>
          <span className="px-2 overflow-x-auto whitespace-pre">{line}</span>
        </div>
      );
    });
  };

  return (
    <div className="border border-[#222B30] rounded bg-[#0C1013] overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#07090B] border-b border-[#222B30] text-xs">
        <div className="flex items-center gap-2">
          <Code className="w-4 h-4 text-[#8B989E]" />
          <span className="font-mono font-medium text-[#E8EEF0]">
            Differential Source Inspection
          </span>
          <span className="text-[#536168] hidden sm:inline">• Python / SQLite AST Comparison</span>
        </div>
        <div className="text-[11px] font-mono text-[#536168]">
          Side-by-Side Target Provenance Review
        </div>
      </div>

      {/* Code Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-[#222B30]">
        {/* Left: Vulnerable Baseline */}
        <div className="flex flex-col bg-[#07090B]/60">
          <div className="flex items-center justify-between px-4 py-2 border-b border-[#222B30] bg-[#11171B]/50">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#FF5B64]" />
              <span className="text-xs font-mono font-semibold text-[#FF5B64]">
                VULNERABLE BASELINE
              </span>
              {originalFindings.length > 0 && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#FF5B64]/10 border border-[#FF5B64]/30 text-[#FF5B64]">
                  {originalFindings.join(', ')}
                </span>
              )}
            </div>
            <button
              onClick={() => copyToClipboard(originalSource, true)}
              className="p-1 text-[#8B989E] hover:text-[#E8EEF0] transition-colors"
              title="Copy vulnerable source"
            >
              {copiedOriginal ? <Check className="w-3.5 h-3.5 text-[#39E58C]" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          <div className="p-3 overflow-x-auto min-h-[220px] max-h-[360px] font-mono">
            {renderCodeLines(originalSource, true)}
          </div>
        </div>

        {/* Right: Patched Implementation */}
        <div className="flex flex-col bg-[#07090B]/60">
          <div className="flex items-center justify-between px-4 py-2 border-b border-[#222B30] bg-[#11171B]/50">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#39E58C]" />
              <span className="text-xs font-mono font-semibold text-[#39E58C]">
                PATCHED IMPLEMENTATION
              </span>
              {patchedFindings.length > 0 && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#39E58C]/10 border border-[#39E58C]/30 text-[#39E58C]">
                  {patchedFindings.join(', ')}
                </span>
              )}
            </div>
            <button
              onClick={() => copyToClipboard(patchedSource, false)}
              className="p-1 text-[#8B989E] hover:text-[#E8EEF0] transition-colors"
              title="Copy patched source"
            >
              {copiedPatched ? <Check className="w-3.5 h-3.5 text-[#39E58C]" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          <div className="p-3 overflow-x-auto min-h-[220px] max-h-[360px] font-mono">
            {renderCodeLines(patchedSource, false)}
          </div>
        </div>
      </div>
    </div>
  );
};
