import React, { useState, useEffect } from 'react';
import {
  Play,
  RotateCcw,
  Cpu,
  Layers,
  Terminal,
  AlertOctagon,
  CheckCircle2,
  FileCode,
  Shield,
  HelpCircle,
} from 'lucide-react';
import { Scenario, VerificationRequest } from '../types';

interface NewVerificationWorkspaceProps {
  scenarios: Scenario[];
  selectedScenario: Scenario | null;
  onSelectScenario: (scenario: Scenario) => void;
  onSubmitVerification: (request: VerificationRequest) => void;
  isVerifying: boolean;
  errorMessage: string | null;
  backendOnline: boolean;
}

export const NewVerificationWorkspace: React.FC<NewVerificationWorkspaceProps> = ({
  scenarios,
  selectedScenario,
  onSelectScenario,
  onSubmitVerification,
  isVerifying,
  errorMessage,
  backendOnline,
}) => {
  const [originalSource, setOriginalSource] = useState<string>('');
  const [patchedSource, setPatchedSource] = useState<string>('');
  const [targetType, setTargetType] = useState<string>('SUBMITTED_SOURCE_EXECUTION');
  const [maxTests, setMaxTests] = useState<number>(3);
  const [activeScenarioId, setActiveScenarioId] = useState<string>('');

  // Synchronize when selectedScenario changes externally
  useEffect(() => {
    if (selectedScenario) {
      setOriginalSource(selectedScenario.original_source);
      setPatchedSource(selectedScenario.patched_source);
      setActiveScenarioId(selectedScenario.id);
      if (selectedScenario.default_mode === 'fixture_only') {
        setTargetType('CONTROLLED_FIXTURE');
      } else {
        setTargetType('SUBMITTED_SOURCE_EXECUTION');
      }
    } else if (scenarios.length > 0 && !originalSource) {
      // Default to first scenario
      const first = scenarios[0];
      setOriginalSource(first.original_source);
      setPatchedSource(first.patched_source);
      setActiveScenarioId(first.id);
    }
  }, [selectedScenario, scenarios]);

  const handleScenarioChange = (scenarioId: string) => {
    const sc = scenarios.find((s) => s.id === scenarioId);
    if (sc) {
      onSelectScenario(sc);
    }
  };

  const handleResetToCurrentScenario = () => {
    const sc = scenarios.find((s) => s.id === activeScenarioId);
    if (sc) {
      setOriginalSource(sc.original_source);
      setPatchedSource(sc.patched_source);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!originalSource.trim() || !patchedSource.trim()) return;

    onSubmitVerification({
      original_source: originalSource,
      patched_source: patchedSource,
      scenario: activeScenarioId,
      target_type: targetType,
      execute_submitted_source: targetType !== 'CONTROLLED_FIXTURE',
      max_tests: maxTests,
    });
  };

  return (
    <div className="space-y-6 py-2">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#222B30] pb-4">
        <div>
          <h1 className="text-xl font-mono font-bold text-[#E8EEF0] flex items-center gap-2">
            <Terminal className="w-5 h-5 text-[#39E58C]" />
            New Security Patch Verification
          </h1>
          <p className="text-xs text-[#8B989E] mt-0.5">
            Configure vulnerable baseline and patched code to initiate an empirical disproof challenge.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleResetToCurrentScenario}
            className="px-3 py-1.5 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E] hover:text-[#E8EEF0] text-xs font-mono transition-colors flex items-center gap-1.5"
            title="Reset editors to selected scenario default source code"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Editors</span>
          </button>
        </div>
      </div>

      {/* Scenario Presets Pill Bar */}
      <div className="space-y-2">
        <label className="text-xs font-mono text-[#536168] uppercase tracking-wider block">
          Preset Verification Scenarios:
        </label>
        <div className="flex flex-wrap gap-2">
          {scenarios.map((sc) => {
            const isSelected = activeScenarioId === sc.id;
            const isVerif = sc.expected_verdict === 'VERIFIED';
            const isRej = sc.expected_verdict === 'REJECTED';

            return (
              <button
                key={sc.id}
                type="button"
                onClick={() => handleScenarioChange(sc.id)}
                className={`px-3 py-2 rounded text-xs font-mono transition-all text-left flex items-center gap-2 border ${
                  isSelected
                    ? 'bg-[#151D22] border-[#39E58C] text-[#E8EEF0] shadow-sm'
                    : 'bg-[#0C1013] border-[#222B30] text-[#8B989E] hover:border-[#324048] hover:text-[#E8EEF0]'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    isVerif ? 'bg-[#39E58C]' : isRej ? 'bg-[#FF5B64]' : 'bg-[#FFBE55]'
                  }`}
                />
                <span className="font-medium">{sc.name.split(':')[0]}</span>
                <span className="text-[10px] text-[#536168]">
                  ({sc.expected_verdict})
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Verification Parameters & Options */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded bg-[#0C1013] border border-[#222B30] text-xs font-mono">
        {/* Target Type */}
        <div className="space-y-1.5">
          <label className="text-[#8B989E] flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-[#39E58C]" /> Target Execution Mode:
          </label>
          <select
            value={targetType}
            onChange={(e) => setTargetType(e.target.value)}
            className="w-full bg-[#07090B] border border-[#222B30] rounded px-3 py-2 text-xs text-[#E8EEF0] font-mono focus:outline-none focus:border-[#39E58C]"
          >
            <option value="SUBMITTED_SOURCE_EXECUTION">
              Isolated Submitted-Source Sandbox (RESTRICTED_SOURCE_ENV)
            </option>
            <option value="REAL_LOCAL_APPLICATION">
              Registered Scenario Application (REGISTERED_SCENARIO_MATCH)
            </option>
            <option value="CONTROLLED_FIXTURE">
              Controlled In-Memory Demonstration (FIXTURE ONLY)
            </option>
          </select>
        </div>

        {/* Vulnerability Class */}
        <div className="space-y-1.5">
          <label className="text-[#8B989E] flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-[#39E58C]" /> Vulnerability Class:
          </label>
          <input
            type="text"
            disabled
            value="SQL_INJECTION (SQLite AST & Invariants)"
            className="w-full bg-[#07090B]/60 border border-[#222B30] rounded px-3 py-2 text-xs text-[#8B989E] font-mono cursor-not-allowed"
          />
        </div>

        {/* Max Tests Budget */}
        <div className="space-y-1.5">
          <label className="text-[#8B989E] flex items-center justify-between">
            <span>Agent Test Budget:</span>
            <span className="text-[#39E58C] font-bold">{maxTests} tests max</span>
          </label>
          <div className="flex items-center gap-3 pt-1.5">
            <input
              type="range"
              min="1"
              max="5"
              value={maxTests}
              onChange={(e) => setMaxTests(parseInt(e.target.value, 10))}
              className="w-full accent-[#39E58C] cursor-pointer"
            />
          </div>
        </div>
      </div>

      {/* Error message banner if any */}
      {errorMessage && (
        <div className="p-4 rounded bg-[#2B1014]/60 border border-[#FF5B64]/50 text-xs font-mono text-[#FF5B64] flex items-start gap-2.5">
          <AlertOctagon className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-bold block">Verification Error:</span>
            <span className="text-[#E8EEF0] font-sans">{errorMessage}</span>
          </div>
        </div>
      )}

      {/* Dual Code Editors (Vulnerable vs Patched) */}
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: Original / Vulnerable Code */}
          <div className="flex flex-col border border-[#222B30] rounded bg-[#0C1013] overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 bg-[#07090B] border-b border-[#222B30]">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#FF5B64]" />
                <span className="text-xs font-mono font-bold text-[#FF5B64]">
                  BASELINE / VULNERABLE SOURCE
                </span>
              </div>
              <span className="text-[10px] font-mono text-[#536168]">
                Python 3 / SQLite Function
              </span>
            </div>

            <textarea
              value={originalSource}
              onChange={(e) => setOriginalSource(e.target.value)}
              placeholder="Paste original vulnerable Python function here..."
              rows={14}
              className="w-full bg-[#07090B]/60 p-4 font-mono text-xs text-[#E8EEF0] leading-relaxed resize-y focus:outline-none focus:bg-[#07090B] border-none"
              spellCheck={false}
              required
            />
          </div>

          {/* Right: Patched Implementation */}
          <div className="flex flex-col border border-[#222B30] rounded bg-[#0C1013] overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 bg-[#07090B] border-b border-[#222B30]">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#39E58C]" />
                <span className="text-xs font-mono font-bold text-[#39E58C]">
                  CANDIDATE PATCHED SOURCE
                </span>
              </div>
              <span className="text-[10px] font-mono text-[#536168]">
                Under Adaptive Verification
              </span>
            </div>

            <textarea
              value={patchedSource}
              onChange={(e) => setPatchedSource(e.target.value)}
              placeholder="Paste candidate patched Python function here..."
              rows={14}
              className="w-full bg-[#07090B]/60 p-4 font-mono text-xs text-[#E8EEF0] leading-relaxed resize-y focus:outline-none focus:bg-[#07090B] border-none"
              spellCheck={false}
              required
            />
          </div>
        </div>

        {/* Submit Execution Button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded bg-[#0C1013] border border-[#222B30]">
          <div className="text-xs text-[#8B989E] font-sans">
            <span className="text-[#39E58C] font-mono font-semibold">Integrity Protocol:</span>{' '}
            The agent will analyze AST structures, verify provenance, and probe for residual SQL injection.
          </div>

          <button
            type="submit"
            disabled={isVerifying || !backendOnline}
            className={`px-6 py-3 rounded font-mono text-xs font-bold transition-all flex items-center justify-center gap-2 min-w-[220px] ${
              isVerifying
                ? 'bg-[#151D22] text-[#8B989E] border border-[#222B30] cursor-wait'
                : !backendOnline
                ? 'bg-[#2B1014] text-[#FF5B64] border border-[#FF5B64]/30 cursor-not-allowed'
                : 'bg-[#39E58C] text-[#07090B] hover:bg-[#39E58C]/90 shadow-subtle-glow-verified cursor-pointer'
            }`}
          >
            {isVerifying ? (
              <>
                <div className="w-4 h-4 border-2 border-[#39E58C] border-t-transparent rounded-full animate-spin" />
                <span>Agent Verifying...</span>
              </>
            ) : !backendOnline ? (
              <span>Engine Offline (Start Backend)</span>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Execute Verification</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
