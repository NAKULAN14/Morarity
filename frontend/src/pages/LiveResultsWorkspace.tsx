import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Code,
  Activity,
  Database,
  FileCode,
  Download,
  Copy,
  Check,
  RotateCcw,
  CheckCircle2,
  Terminal,
  FileJson,
} from 'lucide-react';
import { VerificationResponse } from '../types';
import { VerdictBanner } from '../components/VerdictBanner';
import { DiffCodeViewer } from '../components/DiffCodeViewer';
import { DecisionTraceTimeline } from '../components/DecisionTraceTimeline';
import { EvidenceLedgerView } from '../components/EvidenceLedgerView';
import { TestsExecutedList } from '../components/TestsExecutedList';
import { StaticAnalysisPanel } from '../components/StaticAnalysisPanel';
import { CoverageSummaryCard } from '../components/CoverageSummaryCard';
import { MLSecurityBar } from '../components/MLSecurityBar';

interface LiveResultsWorkspaceProps {
  response: VerificationResponse;
  originalSource: string;
  patchedSource: string;
  onNewVerification: () => void;
}

export const LiveResultsWorkspace: React.FC<LiveResultsWorkspaceProps> = ({
  response,
  originalSource,
  patchedSource,
  onNewVerification,
}) => {
  const [activeTab, setActiveTab] = useState<'trace' | 'diff' | 'evidence' | 'tests' | 'analysis' | 'json'>('trace');
  const [copiedJson, setCopiedJson] = useState(false);

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(response, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(response, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `moriarty_report_${response.verification_id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6 py-2">
      {/* Top action row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[#39E58C]" />
          <span className="font-mono text-xs text-[#8B989E]">
            Verification Session: <strong className="text-[#E8EEF0]">{response.verification_id}</strong>
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyJson}
            className="px-3 py-1.5 rounded bg-[#11171B] border border-[#222B30] text-xs font-mono text-[#8B989E] hover:text-[#E8EEF0] transition-colors flex items-center gap-1.5"
            title="Copy verification report JSON"
          >
            {copiedJson ? <Check className="w-3.5 h-3.5 text-[#39E58C]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy JSON</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="px-3 py-1.5 rounded bg-[#11171B] border border-[#222B30] text-xs font-mono text-[#8B989E] hover:text-[#E8EEF0] transition-colors flex items-center gap-1.5"
            title="Download formal JSON audit report"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Report</span>
          </button>

          <button
            onClick={onNewVerification}
            className="px-3.5 py-1.5 rounded bg-[#39E58C] text-[#07090B] text-xs font-mono font-bold hover:bg-[#39E58C]/90 transition-all flex items-center gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>New Verification</span>
          </button>
        </div>
      </div>

      {/* Prominent Verdict Banner */}
      <VerdictBanner
        verdict={response.verdict}
        summary={response.summary}
        verificationId={response.verification_id}
        targetType={response.target_type}
        targetProvenance={response.target_provenance}
        verificationScope={response.verification_scope}
        stoppingReason={response.stopping_reason}
        submittedSourceExecuted={response.submitted_source_executed}
        dynamicVerificationPerformed={response.dynamic_verification_performed}
      />

      {/* ML Risk & Security Bar */}
      {(response.original_ml_analysis || response.patched_ml_analysis) && (
        <MLSecurityBar
          originalML={response.original_ml_analysis}
          patchedML={response.patched_ml_analysis}
          mode={response.ml_guided_mode ? 'ml_guided' : 'rule_based'}
        />
      )}

      {/* Coverage & Invariant Tracking Card */}
      {response.coverage && (
        <CoverageSummaryCard coverage={response.coverage} />
      )}

      {/* Forensic Inspection Tabs */}
      <div className="border-b border-[#222B30] flex flex-wrap gap-1 sm:gap-2">
        <button
          onClick={() => setActiveTab('trace')}
          className={`px-3.5 py-2 text-xs font-mono font-medium transition-colors border-b-2 flex items-center gap-1.5 ${
            activeTab === 'trace'
              ? 'border-[#39E58C] text-[#E8EEF0] bg-[#11171B]/60'
              : 'border-transparent text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Decision Trace ({response.decision_trace?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('diff')}
          className={`px-3.5 py-2 text-xs font-mono font-medium transition-colors border-b-2 flex items-center gap-1.5 ${
            activeTab === 'diff'
              ? 'border-[#39E58C] text-[#E8EEF0] bg-[#11171B]/60'
              : 'border-transparent text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
          }`}
        >
          <Code className="w-3.5 h-3.5" />
          <span>Differential Source Code</span>
        </button>

        <button
          onClick={() => setActiveTab('evidence')}
          className={`px-3.5 py-2 text-xs font-mono font-medium transition-colors border-b-2 flex items-center gap-1.5 ${
            activeTab === 'evidence'
              ? 'border-[#39E58C] text-[#E8EEF0] bg-[#11171B]/60'
              : 'border-transparent text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Evidence Ledger ({response.evidence?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('tests')}
          className={`px-3.5 py-2 text-xs font-mono font-medium transition-colors border-b-2 flex items-center gap-1.5 ${
            activeTab === 'tests'
              ? 'border-[#39E58C] text-[#E8EEF0] bg-[#11171B]/60'
              : 'border-transparent text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
          }`}
        >
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>Executed Probes ({response.tests_executed?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('analysis')}
          className={`px-3.5 py-2 text-xs font-mono font-medium transition-colors border-b-2 flex items-center gap-1.5 ${
            activeTab === 'analysis'
              ? 'border-[#39E58C] text-[#E8EEF0] bg-[#11171B]/60'
              : 'border-transparent text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Static AST Analysis</span>
        </button>

        <button
          onClick={() => setActiveTab('json')}
          className={`px-3.5 py-2 text-xs font-mono font-medium transition-colors border-b-2 flex items-center gap-1.5 ${
            activeTab === 'json'
              ? 'border-[#39E58C] text-[#E8EEF0] bg-[#11171B]/60'
              : 'border-transparent text-[#8B989E] hover:text-[#E8EEF0] hover:bg-[#0C1013]'
          }`}
        >
          <FileJson className="w-3.5 h-3.5" />
          <span>Raw Report JSON</span>
        </button>
      </div>

      {/* Tab Panels */}
      <div className="pt-2">
        {activeTab === 'trace' && (
          <DecisionTraceTimeline decisionTrace={response.decision_trace || []} />
        )}

        {activeTab === 'diff' && (
          <DiffCodeViewer
            originalSource={originalSource}
            patchedSource={patchedSource}
            originalFindings={response.patch_comparison?.original_rule_ids || []}
            patchedFindings={response.patch_comparison?.patched_rule_ids || []}
          />
        )}

        {activeTab === 'evidence' && (
          <EvidenceLedgerView evidenceList={response.evidence || []} />
        )}

        {activeTab === 'tests' && (
          <TestsExecutedList tests={response.tests_executed || []} />
        )}

        {activeTab === 'analysis' && (
          <StaticAnalysisPanel
            analysis={response.analysis}
            patchComparison={response.patch_comparison}
          />
        )}

        {activeTab === 'json' && (
          <div className="border border-[#222B30] rounded bg-[#0C1013] p-4">
            <div className="flex items-center justify-between border-b border-[#222B30] pb-2 mb-3">
              <span className="text-xs font-mono text-[#8B989E]">Complete Moriarty Audit Schema</span>
              <button
                onClick={handleCopyJson}
                className="text-xs font-mono text-[#39E58C] hover:underline flex items-center gap-1"
              >
                {copiedJson ? 'Copied to Clipboard' : 'Copy Full JSON'}
              </button>
            </div>
            <pre className="text-xs font-mono text-[#8B989E] bg-[#07090B] p-4 rounded border border-[#222B30] overflow-x-auto max-h-[500px]">
              {JSON.stringify(response, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* Limitations Disclaimer Box */}
      {response.limitations && response.limitations.length > 0 && (
        <div className="p-4 rounded bg-[#0C1013] border border-[#222B30] space-y-2 text-xs">
          <div className="font-mono font-semibold text-[#8B989E] uppercase tracking-wider flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-[#FFBE55]" />
            Verification Limitations & Integrity Boundaries
          </div>
          <ul className="space-y-1 text-[#536168] font-sans">
            {response.limitations.map((lim, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-[#8B989E] font-mono mt-0.5">•</span>
                <span>{lim}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
