import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  RotateCcw,
  Sparkles,
  Copy,
  Check,
  Clock,
  Layers,
  Code2,
  Cpu,
  History,
  FileCode,
  Zap,
  Sliders,
  X,
  BookOpen,
  Filter,
  Network,
} from 'lucide-react';
import {
  BudgetPreset,
  CatalogResponse,
  LabContinuousMode,
  LabStatus,
  SQLAnalysisResult,
  GeneratedPatch,
  LabRevisionEntry,
  VerificationResponse,
  VerdictType,
  PatchRefineResponse,
  PlannerComparisonResult,
} from '../types';
import {
  analyzeSqlInput,
  generateSqlPatch,
  verifyLabPatch,
  continuousEvaluate,
  getCatalog,
  refineSqlPatch,
  comparePlanners,
} from '../services/api';
import { VerdictBanner } from '../components/VerdictBanner';
import { DiffCodeViewer } from '../components/DiffCodeViewer';
import { EvidenceLedgerView } from '../components/EvidenceLedgerView';
import { DecisionTraceTimeline } from '../components/DecisionTraceTimeline';
import { TestsExecutedList } from '../components/TestsExecutedList';
import { CoverageSummaryCard } from '../components/CoverageSummaryCard';
import { MLSecurityBar } from '../components/MLSecurityBar';
import { PatchRefinementDrawer } from '../components/PatchRefinementDrawer';
import { PlannerBenchmarkModal } from '../components/PlannerBenchmarkModal';
import { LLMReasoningCard } from '../components/LLMReasoningCard';
import { EvidenceGraphView } from '../components/EvidenceGraphView';

const PRESETS = [
  {
    id: 'raw_sql',
    name: 'Raw SQL: Unparameterized Filter',
    type: 'RAW_SQL',
    code: "SELECT id, username, role, email FROM users WHERE username = 'admin'",
    description: "Raw SQL query with unquoted/quoted string literal in WHERE clause.",
  },
  {
    id: 'py_concat',
    name: 'Python: String Concatenation',
    type: 'PYTHON_CODE',
    code: `def get_user_by_username(cursor, username: str):
    query = "SELECT id, username, role, email FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()`,
    description: "Deliberately unsafe query construction using string concatenation.",
  },
  {
    id: 'py_fstring',
    name: 'Python: F-String Interpolation',
    type: 'PYTHON_CODE',
    code: `def get_user_by_username(cursor, username: str):
    query = f"SELECT id, username, role, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()`,
    description: "Python 3 f-string interpolating user input directly into SQL syntax.",
  },
  {
    id: 'py_flawed_patch',
    name: 'Python: Incomplete Sanitizer (Will be REJECTED)',
    type: 'PYTHON_CODE',
    code: `def get_user_by_username(cursor, username: str):
    sanitized = username.replace('--', '')
    query = "SELECT id, username, role, email FROM users WHERE username = '" + sanitized + "'"
    cursor.execute(query)
    return cursor.fetchall()`,
    description: "Naive filter stripping '--' while leaving quotes exploitable.",
  },
];

interface SqlSecurityLabWorkspaceProps {
  backendOnline: boolean;
}

export const SqlSecurityLabWorkspace: React.FC<SqlSecurityLabWorkspaceProps> = ({
  backendOnline,
}) => {
  // Inputs & Revisions
  const [sourceCode, setSourceCode] = useState<string>(PRESETS[1].code);
  const [candidatePatch, setCandidatePatch] = useState<string>('');
  const [sourceRevision, setSourceRevision] = useState<number>(1);
  const [patchRevision, setPatchRevision] = useState<number>(1);

  // Modes & Status
  const [mode, setMode] = useState<LabContinuousMode>('manual');
  const [status, setStatus] = useState<LabStatus>('IDLE');
  const [isStale, setIsStale] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<'editor' | 'diff'>('editor');

  // Results
  const [analysisResult, setAnalysisResult] = useState<SQLAnalysisResult | null>(null);
  const [generatedPatchResult, setGeneratedPatchResult] = useState<GeneratedPatch | null>(null);
  const [verificationResponse, setVerificationResponse] = useState<VerificationResponse | null>(null);
  const [showEvidenceGraph, setShowEvidenceGraph] = useState<boolean>(false);
  const [revisionHistory, setRevisionHistory] = useState<LabRevisionEntry[]>([]);

  // Adaptive Budget & Catalog States
  const [budgetPreset, setBudgetPreset] = useState<BudgetPreset>('quick');
  const [customMaxTests, setCustomMaxTests] = useState<number>(10);
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [showCatalogModal, setShowCatalogModal] = useState<boolean>(false);
  const [catalogSearch, setCatalogSearch] = useState<string>('');
  const [selectedCatalogCategory, setSelectedCatalogCategory] = useState<string>('ALL');

  // Loading & UI States
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [copiedPatch, setCopiedPatch] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const debounceTimerRef = useRef<any>(null);

  // Handle Source Code Change
  const handleSourceChange = (val: string) => {
    setSourceCode(val);
    setSourceRevision((prev) => prev + 1);
    if (verificationResponse) {
      setIsStale(true);
      setStatus('STALE');
    }
  };

  // Handle Candidate Patch Change
  const handlePatchChange = (val: string) => {
    setCandidatePatch(val);
    setPatchRevision((prev) => prev + 1);
    if (verificationResponse) {
      setIsStale(true);
      setStatus('STALE');
    }
  };

  // Load Preset
  const handleLoadPreset = (preset: typeof PRESETS[0]) => {
    setSourceCode(preset.code);
    setCandidatePatch('');
    setAnalysisResult(null);
    setGeneratedPatchResult(null);
    setVerificationResponse(null);
    setIsStale(false);
    setStatus('IDLE');
    setSourceRevision((prev) => prev + 1);
    setPatchRevision(1);
  };

  // 1. Manual Analyze
  const handleAnalyze = async () => {
    if (!sourceCode.trim()) return;
    setIsAnalyzing(true);
    setErrorMessage(null);
    setStatus('ANALYZING');
    try {
      const res = await analyzeSqlInput(sourceCode);
      setAnalysisResult(res);
      if (res.is_vulnerable) {
        setStatus('VULNERABILITY_DETECTED');
      } else {
        setStatus('SAFE');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Analysis failed.');
      setStatus('ERROR');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // 2. Manual Generate Patch
  const handleGeneratePatch = async () => {
    if (!sourceCode.trim()) return;
    setIsGenerating(true);
    setErrorMessage(null);
    setStatus('PATCH_GENERATING');
    try {
      const patchRes = await generateSqlPatch(sourceCode);
      setGeneratedPatchResult(patchRes);
      setCandidatePatch(patchRes.patched_code);
      setPatchRevision((prev) => prev + 1);

      // Re-analyze if not already analyzed
      if (!analysisResult) {
        const anaRes = await analyzeSqlInput(sourceCode);
        setAnalysisResult(anaRes);
      }
      setStatus('VULNERABILITY_DETECTED');
    } catch (err: any) {
      setErrorMessage(err.message || 'Patch generation failed.');
      setStatus('ERROR');
    } finally {
      setIsGenerating(false);
    }
  };

  // 3. Manual Verify
  const handleVerify = async () => {
    if (!sourceCode.trim() || !candidatePatch.trim()) return;
    setIsVerifying(true);
    setErrorMessage(null);
    setStatus('VERIFYING');

    const curSourceRev = sourceRevision;
    const curPatchRev = patchRevision;

    try {
      const verifRes = await verifyLabPatch({
        original_source: sourceCode,
        candidate_patch: candidatePatch,
        source_revision: curSourceRev,
        patch_revision: curPatchRev,
        budget_preset: budgetPreset,
        max_tests: budgetPreset === 'custom' ? customMaxTests : undefined,
      });

      setVerificationResponse(verifRes);
      setIsStale(false);
      setStatus(verifRes.verdict);

      // Append to Revision History
      const newEntry: LabRevisionEntry = {
        id: verifRes.verification_id,
        timestamp: new Date().toLocaleTimeString(),
        sourceRevision: curSourceRev,
        patchRevision: curPatchRev,
        status: verifRes.verdict,
        verdict: verifRes.verdict,
        testsRun: verifRes.tests_executed.length,
        summary: verifRes.summary,
      };
      setRevisionHistory((prev) => [newEntry, ...prev.slice(0, 9)]);
    } catch (err: any) {
      setErrorMessage(err.message || 'Verification execution failed.');
      setStatus('ERROR');
    } finally {
      setIsVerifying(false);
    }
  };

  // Copy Candidate Patch
  const handleCopyPatch = () => {
    if (!candidatePatch) return;
    navigator.clipboard.writeText(candidatePatch);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  // Reset to Original Generated Patch
  const handleResetToGenerated = () => {
    if (generatedPatchResult) {
      setCandidatePatch(generatedPatchResult.patched_code);
      setPatchRevision((prev) => prev + 1);
      setIsStale(true);
      setStatus('STALE');
    }
  };

  // ML Patch Refinement Loop States & Action
  const [refineResult, setRefineResult] = useState<PatchRefineResponse | null>(null);
  const [isRefining, setIsRefining] = useState<boolean>(false);
  const [showRefineDrawer, setShowRefineDrawer] = useState<boolean>(false);

  // Planner Comparison Benchmark States & Action
  const [benchmarkResult, setBenchmarkResult] = useState<PlannerComparisonResult | null>(null);
  const [isBenchmarking, setIsBenchmarking] = useState<boolean>(false);
  const [showBenchmarkModal, setShowBenchmarkModal] = useState<boolean>(false);

  const handleRefinePatch = async () => {
    if (!sourceCode.trim()) return;
    setIsRefining(true);
    setErrorMessage(null);
    try {
      const res = await refineSqlPatch({
        original_source: sourceCode,
        current_patch: candidatePatch || sourceCode,
        max_attempts: 3,
      });
      setRefineResult(res);
      setShowRefineDrawer(true);
      if (res.final_patch) {
        setCandidatePatch(res.final_patch);
        setPatchRevision((prev) => prev + 1);
        setIsStale(true);
        setStatus('STALE');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Patch refinement failed.');
    } finally {
      setIsRefining(false);
    }
  };

  const handleComparePlanners = async () => {
    setIsBenchmarking(true);
    setShowBenchmarkModal(true);
    setErrorMessage(null);
    try {
      const res = await comparePlanners({
        original_source: sourceCode,
        patched_source: candidatePatch || sourceCode,
        budget_preset: budgetPreset,
      });
      setBenchmarkResult(res);
    } catch (err: any) {
      setErrorMessage(err.message || 'Planner benchmark failed.');
    } finally {
      setIsBenchmarking(false);
    }
  };

  // Fetch SQL injection test catalog on mount
  useEffect(() => {
    getCatalog()
      .then((data: any) => setCatalog(data))
      .catch((err: any) => console.error('Failed to load SQL test catalog', err));
  }, []);

  // Debounced Continuous Evaluation Effect
  useEffect(() => {
    if (mode === 'manual' || !sourceCode.trim()) return;

    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }

    const delay = mode === 'auto_verify' ? 1400 : 900;

    debounceTimerRef.current = setTimeout(async () => {
      try {
        if (mode === 'auto_analyze') {
          setIsAnalyzing(true);
          setStatus('ANALYZING');
          const ana = await analyzeSqlInput(sourceCode);
          setAnalysisResult(ana);
          if (ana.is_vulnerable) {
            setStatus('VULNERABILITY_DETECTED');
            // Auto generate patch if empty
            if (!candidatePatch.trim()) {
              const p = await generateSqlPatch(sourceCode);
              setGeneratedPatchResult(p);
              setCandidatePatch(p.patched_code);
              setPatchRevision((rev) => rev + 1);
            }
          } else {
            setStatus('SAFE');
          }
          setIsAnalyzing(false);
        } else if (mode === 'auto_verify') {
          setIsVerifying(true);
          setStatus('VERIFYING');
          const evalRes = await continuousEvaluate({
            source_code: sourceCode,
            patch_code: candidatePatch || undefined,
            source_revision: sourceRevision,
            patch_revision: patchRevision,
            auto_verify: true,
            budget_preset: budgetPreset,
            max_tests: budgetPreset === 'custom' ? customMaxTests : undefined,
          });

          setAnalysisResult(evalRes.analysis);
          if (evalRes.generated_patch && !candidatePatch) {
            setGeneratedPatchResult(evalRes.generated_patch);
            setCandidatePatch(evalRes.generated_patch.patched_code);
          }
          if (evalRes.verification_result) {
            setVerificationResponse(evalRes.verification_result);
            setIsStale(false);
            setStatus(evalRes.verification_result.verdict);

            const newEntry: LabRevisionEntry = {
              id: evalRes.verification_result.verification_id,
              timestamp: new Date().toLocaleTimeString(),
              sourceRevision: sourceRevision,
              patchRevision: patchRevision,
              status: evalRes.verification_result.verdict,
              verdict: evalRes.verification_result.verdict,
              testsRun: evalRes.verification_result.tests_executed.length,
              summary: evalRes.verification_result.summary,
            };
            setRevisionHistory((prev) => [newEntry, ...prev.slice(0, 9)]);
          } else if (evalRes.analysis.is_vulnerable) {
            setStatus('VULNERABILITY_DETECTED');
          } else {
            setStatus('SAFE');
          }
          setIsVerifying(false);
        }
      } catch (err: any) {
        setErrorMessage(err.message || 'Continuous evaluation encountered an error.');
        setStatus('ERROR');
        setIsAnalyzing(false);
        setIsVerifying(false);
      }
    }, delay);

    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
    };
  }, [sourceCode, mode]);

  // Helper for status badge styling
  const getStatusBadge = () => {
    switch (status) {
      case 'ANALYZING':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#1E293B] text-[#38BDF8] border border-[#38BDF8]/40 animate-pulse flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 animate-spin" />
            ANALYZING INPUT...
          </span>
        );
      case 'VULNERABILITY_DETECTED':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#2B1014] text-[#FF5B64] border border-[#FF5B64]/50 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5" />
            VULNERABILITY DETECTED
          </span>
        );
      case 'PATCH_GENERATING':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#2E1065] text-[#C084FC] border border-[#C084FC]/40 animate-pulse flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 animate-spin" />
            GENERATING AST PATCH...
          </span>
        );
      case 'VERIFYING':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#0C4A6E] text-[#38BDF8] border border-[#38BDF8]/50 animate-pulse flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 animate-bounce" />
            DIFFERENTIAL VERIFYING...
          </span>
        );
      case 'VERIFIED':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#0B2418] text-[#39E58C] border border-[#39E58C]/50 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" />
            VERIFIED SECURE
          </span>
        );
      case 'REJECTED':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#2B1014] text-[#FF5B64] border border-[#FF5B64]/50 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5" />
            PATCH REJECTED
          </span>
        );
      case 'INCONCLUSIVE':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#2A2010] text-[#FFBE55] border border-[#FFBE55]/50 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            INCONCLUSIVE
          </span>
        );
      case 'STALE':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#2D1B00] text-[#FB923C] border border-[#FB923C]/50 flex items-center gap-1.5 animate-pulse">
            <Clock className="w-3.5 h-3.5" />
            VERDICT STALE (MODIFIED)
          </span>
        );
      case 'SAFE':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#0B2418] text-[#39E58C] border border-[#39E58C]/40 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" />
            STATIC / PARAMETERIZED
          </span>
        );
      case 'ERROR':
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#2B1014] text-[#FF5B64] border border-[#FF5B64]/40 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            ERROR
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-[#11171B] text-[#8B989E] border border-[#222B30] flex items-center gap-1.5">
            <Code2 className="w-3.5 h-3.5" />
            IDLE / READY
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Continuous Evaluation Controls */}
      <div className="bg-[#0C1013] border border-[#222B30] rounded p-5 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded bg-[#11171B] border border-[#222B30] flex items-center justify-center text-[#39E58C]">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-lg font-mono font-bold tracking-wider text-[#E8EEF0]">
                  SQL SECURITY LAB
                </h1>
                <span className="px-1.5 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[10px] font-mono text-[#8B989E]">
                  CONTINUOUS WORKBENCH
                </span>
              </div>
              <p className="text-xs text-[#8B989E] mt-0.5">
                Continuous SQL Injection Detection, Deterministic AST Parameterization & Differential Patch Verification
              </p>
            </div>
          </div>
        </div>

        {/* Continuous Mode Selector & Status */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center bg-[#07090B] border border-[#222B30] rounded p-1">
            <button
              onClick={() => setMode('manual')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                mode === 'manual'
                  ? 'bg-[#11171B] text-[#E8EEF0] border border-[#222B30]'
                  : 'text-[#8B989E] hover:text-[#E8EEF0]'
              }`}
            >
              Manual
            </button>
            <button
              onClick={() => setMode('auto_analyze')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors flex items-center gap-1 ${
                mode === 'auto_analyze'
                  ? 'bg-[#11171B] text-[#38BDF8] border border-[#38BDF8]/40'
                  : 'text-[#8B989E] hover:text-[#38BDF8]'
              }`}
            >
              <Cpu className="w-3 h-3" />
              Auto-Analyze
            </button>
            <button
              onClick={() => setMode('auto_verify')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors flex items-center gap-1 ${
                mode === 'auto_verify'
                  ? 'bg-[#11171B] text-[#39E58C] border border-[#39E58C]/40'
                  : 'text-[#8B989E] hover:text-[#39E58C]'
              }`}
            >
              <Zap className="w-3 h-3 text-[#39E58C]" />
              Auto-Verify
            </button>
          </div>

          {getStatusBadge()}
        </div>
      </div>

      {/* Preset Scenarios Selector */}
      <div className="bg-[#0C1013] border border-[#222B30] rounded p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono text-[#8B989E] uppercase tracking-wider flex items-center gap-1.5">
            <FileCode className="w-3.5 h-3.5 text-[#39E58C]" />
            Quick Presets / Test Inputs
          </span>
          <span className="text-[11px] font-mono text-[#536168]">
            Click to populate dual-editor with known vulnerability structures
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {PRESETS.map((p) => (
            <button
              key={p.id}
              onClick={() => handleLoadPreset(p)}
              className="text-left p-2.5 rounded bg-[#07090B] border border-[#222B30] hover:border-[#39E58C]/50 hover:bg-[#11171B] transition-colors group"
            >
              <div className="text-xs font-mono font-medium text-[#E8EEF0] group-hover:text-[#39E58C] flex items-center justify-between">
                <span>{p.name}</span>
              </div>
              <p className="text-[11px] text-[#536168] mt-1 line-clamp-1">{p.description}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Stale Verdict Alert Banner */}
      {isStale && verificationResponse && (
        <div className="bg-[#2D1B00] border border-[#FB923C]/50 rounded p-3.5 text-xs font-mono text-[#FB923C] flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-[#FB923C]" />
            <div>
              <span className="font-bold">VERDICT STALE (Source Rev #{sourceRevision}, Patch Rev #{patchRevision}):</span>{' '}
              Source code or candidate patch has been modified since the last empirical verification.
              Previous verdict ({verificationResponse.verdict}) is invalidated until re-tested.
            </div>
          </div>
          <button
            onClick={handleVerify}
            disabled={isVerifying || !backendOnline}
            className="px-3 py-1 rounded bg-[#FB923C]/20 border border-[#FB923C]/40 text-[#FB923C] hover:bg-[#FB923C]/30 text-xs font-mono transition-colors flex items-center gap-1"
          >
            <Play className="w-3 h-3 fill-current" />
            Re-Verify
          </button>
        </div>
      )}

      {/* Verification Budget Selector & Catalog Action Bar */}
      <div className="bg-[#0C1013] border border-[#222B30] rounded p-3.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <Sliders className="w-3.5 h-3.5 text-[#39E58C]" />
            <span className="text-xs font-mono font-bold text-[#E8EEF0]">
              VERIFICATION BUDGET:
            </span>
          </div>

          <div className="flex items-center bg-[#07090B] border border-[#222B30] rounded p-0.5">
            <button
              onClick={() => setBudgetPreset('quick')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                budgetPreset === 'quick'
                  ? 'bg-[#11171B] text-[#39E58C] border border-[#39E58C]/40 font-bold'
                  : 'text-[#8B989E] hover:text-[#E8EEF0]'
              }`}
              title="Quick: Up to 5 tests across initial delimiter and tautology probes"
            >
              Quick (5 max)
            </button>
            <button
              onClick={() => setBudgetPreset('standard')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                budgetPreset === 'standard'
                  ? 'bg-[#11171B] text-[#38BDF8] border border-[#38BDF8]/40 font-bold'
                  : 'text-[#8B989E] hover:text-[#E8EEF0]'
              }`}
              title="Standard: Up to 15 tests covering multiple core dialect categories"
            >
              Standard (15 max)
            </button>
            <button
              onClick={() => setBudgetPreset('thorough')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                budgetPreset === 'thorough'
                  ? 'bg-[#11171B] text-[#C084FC] border border-[#C084FC]/40 font-bold'
                  : 'text-[#8B989E] hover:text-[#E8EEF0]'
              }`}
              title="Thorough: Up to 30 tests covering all 11 executable categories"
            >
              Thorough (30 max)
            </button>
            <button
              onClick={() => setBudgetPreset('custom')}
              className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
                budgetPreset === 'custom'
                  ? 'bg-[#11171B] text-[#FFBE55] border border-[#FFBE55]/40 font-bold'
                  : 'text-[#8B989E] hover:text-[#E8EEF0]'
              }`}
              title="Custom: User-defined upper test bound"
            >
              Custom
            </button>
          </div>

          {budgetPreset === 'custom' && (
            <div className="flex items-center gap-1.5 bg-[#07090B] border border-[#222B30] rounded px-2 py-0.5">
              <span className="text-[11px] font-mono text-[#536168]">Limit:</span>
              <input
                type="number"
                min={1}
                max={50}
                value={customMaxTests}
                onChange={(e) => setCustomMaxTests(Math.max(1, Math.min(50, parseInt(e.target.value) || 1)))}
                className="w-12 bg-transparent text-xs font-mono text-[#E8EEF0] focus:outline-none text-center"
              />
              <span className="text-[11px] font-mono text-[#536168]">tests</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleComparePlanners}
            disabled={isBenchmarking || !backendOnline}
            className="px-3 py-1.5 rounded bg-[#1E1B4B] border border-[#6366F1]/50 hover:border-[#818CF8] text-xs font-mono text-[#A5B4FC] flex items-center gap-1.5 transition-colors disabled:opacity-50"
            title="Benchmark Rule-Based vs ML-Guided Planners side-by-side"
          >
            <Cpu className={`w-3.5 h-3.5 ${isBenchmarking ? 'animate-spin' : ''}`} />
            <span>Compare Planners (Rule vs ML)</span>
          </button>

          <button
            onClick={() => setShowCatalogModal(true)}
            className="px-3 py-1.5 rounded bg-[#11171B] border border-[#222B30] hover:border-[#38BDF8]/50 text-xs font-mono text-[#38BDF8] flex items-center gap-1.5 transition-colors"
          >
            <BookOpen className="w-3.5 h-3.5 text-[#38BDF8]" />
            <span>Inspect SQL Test Catalog ({catalog?.total_tests || 40} Cases)</span>
          </button>
        </div>
      </div>

      {/* ML-Guided Security Risk Analysis Bar */}
      <MLSecurityBar
        originalML={verificationResponse?.original_ml_analysis || analysisResult?.ml_analysis}
        patchedML={verificationResponse?.patched_ml_analysis || generatedPatchResult?.ml_analysis}
        mode={verificationResponse?.ml_guided_mode ? 'ml_guided' : 'rule_based'}
      />

      {/* LLM Security Reasoning Card */}
      <LLMReasoningCard
        reasoning={verificationResponse?.llm_reasoning || analysisResult?.llm_reasoning}
      />

      {/* 2. Dual Split Editor: Source vs Candidate Patch */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Left: Source Implementation */}
        <div className="bg-[#0C1013] border border-[#222B30] rounded flex flex-col">
          <div className="p-3 border-b border-[#222B30] bg-[#07090B]/60 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-[#E8EEF0]">SOURCE IMPLEMENTATION</span>
              <span className="px-1.5 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[10px] font-mono text-[#38BDF8]">
                Rev #{sourceRevision}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono text-[#536168]">
                {sourceCode.split('\n').length} lines • {sourceCode.length} chars
              </span>
            </div>
          </div>

          <div className="p-3 flex-1 flex flex-col">
            <textarea
              value={sourceCode}
              onChange={(e) => handleSourceChange(e.target.value)}
              placeholder="Paste raw SQL (e.g. SELECT * FROM users WHERE username = 'admin') or Python database function..."
              rows={12}
              className="w-full flex-1 bg-[#07090B] border border-[#222B30] focus:border-[#39E58C]/50 rounded p-3 text-xs font-mono text-[#E8EEF0] resize-y focus:outline-none leading-relaxed"
              spellCheck={false}
            />

            <div className="mt-3 flex items-center justify-between gap-2 pt-2 border-t border-[#222B30]/50">
              <span className="text-[11px] text-[#536168] font-mono">
                Accepts Raw SQL or Python DB query functions
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing || !backendOnline}
                  className="px-3 py-1.5 rounded bg-[#11171B] border border-[#222B30] hover:border-[#38BDF8]/50 text-xs font-mono text-[#38BDF8] flex items-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  <Cpu className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
                  <span>Analyze</span>
                </button>
                <button
                  onClick={handleGeneratePatch}
                  disabled={isGenerating || !backendOnline}
                  className="px-3 py-1.5 rounded bg-[#1E1B4B] border border-[#6366F1]/50 hover:border-[#818CF8] text-xs font-mono text-[#A5B4FC] flex items-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
                  <span>Generate Patch</span>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Candidate Security Patch */}
        <div className="bg-[#0C1013] border border-[#222B30] rounded flex flex-col">
          <div className="p-3 border-b border-[#222B30] bg-[#07090B]/60 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-[#E8EEF0]">CANDIDATE SECURITY PATCH</span>
              <span className="px-1.5 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[10px] font-mono text-[#C084FC]">
                Rev #{patchRevision}
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#2B1014] border border-[#FF5B64]/40 text-[#FF5B64]">
                UNVERIFIED CANDIDATE
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setViewMode(viewMode === 'editor' ? 'diff' : 'editor')}
                className="px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[11px] font-mono text-[#8B989E] hover:text-[#E8EEF0]"
              >
                {viewMode === 'editor' ? 'Show Diff' : 'Show Code'}
              </button>
              <button
                onClick={handleCopyPatch}
                disabled={!candidatePatch}
                className="p-1 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E] hover:text-[#E8EEF0] disabled:opacity-30"
                title="Copy Patch"
              >
                {copiedPatch ? <Check className="w-3.5 h-3.5 text-[#39E58C]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="p-3 flex-1 flex flex-col">
            {viewMode === 'editor' ? (
              <textarea
                value={candidatePatch}
                onChange={(e) => handlePatchChange(e.target.value)}
                placeholder="Candidate patch will be generated here using deterministic AST parameterization. You can freely edit this candidate to test flawed patches or manual variants..."
                rows={12}
                className="w-full flex-1 bg-[#07090B] border border-[#222B30] focus:border-[#C084FC]/50 rounded p-3 text-xs font-mono text-[#E8EEF0] resize-y focus:outline-none leading-relaxed"
                spellCheck={false}
              />
            ) : (
              <div className="flex-1 overflow-auto max-h-[300px]">
                <DiffCodeViewer
                  originalSource={sourceCode}
                  patchedSource={candidatePatch || sourceCode}
                />
              </div>
            )}

            <div className="mt-3 flex items-center justify-between gap-2 pt-2 border-t border-[#222B30]/50">
              <div className="flex items-center gap-2">
                {generatedPatchResult && (
                  <button
                    onClick={handleResetToGenerated}
                    className="text-[11px] font-mono text-[#8B989E] hover:text-[#E8EEF0] flex items-center gap-1"
                  >
                    <RotateCcw className="w-3 h-3" />
                    Reset
                  </button>
                )}
                <button
                  onClick={handleRefinePatch}
                  disabled={isRefining || !sourceCode.trim() || !backendOnline}
                  className="px-2.5 py-1 rounded bg-[#1E1B4B] border border-[#6366F1]/50 hover:border-[#818CF8] text-[11px] font-mono text-[#A5B4FC] flex items-center gap-1.5 transition-colors disabled:opacity-40"
                  title="Refine patch iteratively (up to 3 bounded attempts) with ML validation"
                >
                  <Sparkles className={`w-3 h-3 ${isRefining ? 'animate-spin' : ''}`} />
                  <span>{isRefining ? 'Refining...' : 'Refine with ML'}</span>
                </button>
              </div>
              <button
                onClick={handleVerify}
                disabled={isVerifying || !candidatePatch.trim() || !backendOnline}
                className="px-4 py-1.5 rounded bg-[#0B2418] border border-[#39E58C]/50 hover:bg-[#39E58C]/20 text-xs font-mono font-medium text-[#39E58C] flex items-center gap-1.5 transition-colors disabled:opacity-40"
              >
                <Play className={`w-3.5 h-3.5 fill-current ${isVerifying ? 'animate-pulse' : ''}`} />
                <span>{isVerifying ? 'Verifying with Moriarty...' : 'Verify Patch with Moriarty'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Analysis Findings & Invariants Card */}
      {analysisResult && (
        <div className="bg-[#0C1013] border border-[#222B30] rounded p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-[#222B30] pb-3">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#38BDF8]" />
              <span className="text-xs font-mono font-bold text-[#E8EEF0]">
                ANALYSIS FINDINGS & ATTACK SURFACE
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E]">
                Target: {analysisResult.detected_table || 'users'} table • Param: {analysisResult.detected_parameters.join(', ') || 'username'}
              </span>
            </div>
            <div>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  analysisResult.severity === 'HIGH' || analysisResult.severity === 'CRITICAL'
                    ? 'bg-[#2B1014] text-[#FF5B64] border-[#FF5B64]/40'
                    : 'bg-[#0B2418] text-[#39E58C] border-[#39E58C]/40'
                }`}
              >
                Severity: {analysisResult.severity}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs font-mono">
            {/* Summary & Findings */}
            <div className="space-y-2 lg:col-span-1">
              <span className="text-[#8B989E] font-medium block">SUMMARY:</span>
              <p className="text-[#E8EEF0] bg-[#07090B] p-2.5 rounded border border-[#222B30]">
                {analysisResult.summary}
              </p>
              {analysisResult.findings.map((f, i) => (
                <div key={i} className="p-2 rounded bg-[#11171B] border border-[#222B30] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[#38BDF8] font-bold">{f.rule_id}</span>
                    <span className="text-[10px] text-[#8B989E]">Rule</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E]">{f.message}</p>
                </div>
              ))}
            </div>

            {/* Probe Payloads */}
            <div className="space-y-2 lg:col-span-1">
              <span className="text-[#8B989E] font-medium block">EMPIRICAL PROBE PAYLOADS:</span>
              <div className="bg-[#07090B] p-2.5 rounded border border-[#222B30] space-y-1.5">
                {analysisResult.potential_payloads.length > 0 ? (
                  analysisResult.potential_payloads.map((payload, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-[11px] text-[#FF5B64]">
                      <span className="text-[#536168] select-none">[{idx + 1}]</span>
                      <code className="bg-[#11171B] px-1.5 py-0.5 rounded border border-[#222B30] flex-1 overflow-x-auto">
                        {payload}
                      </code>
                    </div>
                  ))
                ) : (
                  <span className="text-[11px] text-[#536168]">
                    No immediate attack payloads indicated for static query.
                  </span>
                )}
              </div>
            </div>

            {/* Security Invariants */}
            <div className="space-y-2 lg:col-span-1">
              <span className="text-[#8B989E] font-medium block">REQUIRED SECURITY INVARIANTS:</span>
              <div className="bg-[#07090B] p-2.5 rounded border border-[#222B30] space-y-2">
                {analysisResult.security_invariants.map((inv, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-[11px] text-[#E8EEF0]">
                    <span className="text-[#39E58C] font-bold select-none">✓</span>
                    <span>{inv}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 4. Patch Generation Rationale & Mechanics */}
      {generatedPatchResult && (
        <div className="bg-[#0C1013] border border-[#222B30] rounded p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-[#222B30] pb-2.5">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#C084FC]" />
              <span className="text-xs font-mono font-bold text-[#E8EEF0]">
                PATCH SPECIFICATION & TECHNIQUE
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#C084FC]">
                Method: {generatedPatchResult.generation_method}
              </span>
            </div>
            <span className="text-[10px] font-mono text-[#8B989E]">
              {generatedPatchResult.technique}
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1.5">
              <span className="text-[#8B989E] font-medium">TECHNICAL EXPLANATION:</span>
              <p className="text-[#E8EEF0] bg-[#07090B] p-2.5 rounded border border-[#222B30] leading-relaxed">
                {generatedPatchResult.technical_explanation}
              </p>
            </div>
            <div className="space-y-1.5">
              <span className="text-[#8B989E] font-medium">INVARIANTS ENFORCED:</span>
              <div className="bg-[#07090B] p-2.5 rounded border border-[#222B30] space-y-1.5">
                {generatedPatchResult.invariants_enforced.map((inv, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-[11px] text-[#39E58C]">
                    <span>•</span>
                    <span className="text-[#E8EEF0]">{inv}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. Empirical Verification Results */}
      {verificationResponse && (
        <div className="space-y-4">
          <div className="border-t border-[#222B30] pt-4 flex flex-wrap items-center justify-between gap-3 mb-2">
            <h2 className="text-sm font-mono font-bold text-[#E8EEF0] flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#39E58C]" />
              EMPIRICAL VERIFICATION EVIDENCE & TRACE
            </h2>

            <div className="flex items-center gap-2 bg-[#07090B] p-1 rounded border border-[#222B30]">
              <button
                onClick={() => setShowEvidenceGraph(false)}
                className={`px-3 py-1 rounded text-xs font-mono transition-colors flex items-center gap-1.5 ${
                  !showEvidenceGraph
                    ? 'bg-[#11171B] text-[#39E58C] border border-[#39E58C]/40 font-bold'
                    : 'text-[#8B989E] hover:text-[#E8EEF0]'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Test Traces & Ledger</span>
              </button>
              <button
                onClick={() => setShowEvidenceGraph(true)}
                className={`px-3 py-1 rounded text-xs font-mono transition-colors flex items-center gap-1.5 ${
                  showEvidenceGraph
                    ? 'bg-[#11171B] text-[#38BDF8] border border-[#38BDF8]/40 font-bold'
                    : 'text-[#8B989E] hover:text-[#E8EEF0]'
                }`}
              >
                <Network className="w-3.5 h-3.5" />
                <span>Evidence Graph (DAG)</span>
              </button>
            </div>
          </div>

          {/* Verdict Banner */}
          <VerdictBanner
            verdict={verificationResponse.verdict}
            summary={verificationResponse.summary}
            verificationId={verificationResponse.verification_id}
            targetType={verificationResponse.target_type}
            targetProvenance={verificationResponse.target_provenance}
            verificationScope={verificationResponse.verification_scope}
            stoppingReason={verificationResponse.stopping_reason}
            submittedSourceExecuted={verificationResponse.submitted_source_executed}
            dynamicVerificationPerformed={verificationResponse.dynamic_verification_performed}
          />

          {showEvidenceGraph ? (
            <EvidenceGraphView graphData={verificationResponse.evidence_graph} />
          ) : (
            <>
              {/* Verification Coverage Summary Card */}
              {verificationResponse.coverage && (
                <CoverageSummaryCard
                  coverage={verificationResponse.coverage}
                  budgetPreset={budgetPreset}
                />
              )}

              {/* Tests Executed List */}
              {verificationResponse.tests_executed && verificationResponse.tests_executed.length > 0 && (
                <div className="bg-[#0C1013] border border-[#222B30] rounded p-4">
                  <h3 className="text-xs font-mono font-bold text-[#E8EEF0] mb-3 flex items-center gap-2">
                    <Layers className="w-3.5 h-3.5 text-[#39E58C]" />
                    PROBE TESTS EXECUTED ({verificationResponse.tests_executed.length})
                  </h3>
                  <TestsExecutedList tests={verificationResponse.tests_executed} />
                </div>
              )}

              {/* Decision Trace Timeline */}
              {verificationResponse.decision_trace && verificationResponse.decision_trace.length > 0 && (
                <div className="bg-[#0C1013] border border-[#222B30] rounded p-4">
                  <h3 className="text-xs font-mono font-bold text-[#E8EEF0] mb-3 flex items-center gap-2">
                    <History className="w-3.5 h-3.5 text-[#38BDF8]" />
                    AGENT DECISION TRACE
                  </h3>
                  <DecisionTraceTimeline decisionTrace={verificationResponse.decision_trace} />
                </div>
              )}

              {/* Evidence Ledger */}
              {verificationResponse.evidence && verificationResponse.evidence.length > 0 && (
                <div className="bg-[#0C1013] border border-[#222B30] rounded p-4">
                  <h3 className="text-xs font-mono font-bold text-[#E8EEF0] mb-3 flex items-center gap-2">
                    <ShieldCheck className="w-3.5 h-3.5 text-[#39E58C]" />
                    RECORDED EVIDENCE LEDGER ({verificationResponse.evidence.length})
                  </h3>
                  <EvidenceLedgerView evidenceList={verificationResponse.evidence} />
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* 6. Revision History Log */}
      {revisionHistory.length > 0 && (
        <div className="bg-[#0C1013] border border-[#222B30] rounded p-4">
          <div className="flex items-center justify-between border-b border-[#222B30] pb-2.5 mb-3">
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-[#8B989E]" />
              <span className="text-xs font-mono font-bold text-[#E8EEF0]">
                SESSION REVISION HISTORY
              </span>
            </div>
            <span className="text-[11px] font-mono text-[#536168]">
              {revisionHistory.length} evaluation runs recorded
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-[#222B30] text-[#536168]">
                  <th className="pb-2 font-medium">TIME</th>
                  <th className="pb-2 font-medium">REVISION</th>
                  <th className="pb-2 font-medium">VERDICT</th>
                  <th className="pb-2 font-medium">TESTS</th>
                  <th className="pb-2 font-medium">SUMMARY</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#222B30]/40">
                {revisionHistory.map((entry, idx) => (
                  <tr key={idx} className="hover:bg-[#11171B]/50 transition-colors">
                    <td className="py-2.5 text-[#8B989E]">{entry.timestamp}</td>
                    <td className="py-2.5">
                      <span className="text-[#38BDF8]">Src #{entry.sourceRevision}</span>
                      <span className="text-[#536168]"> / </span>
                      <span className="text-[#C084FC]">Patch #{entry.patchRevision}</span>
                    </td>
                    <td className="py-2.5">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          entry.verdict === 'VERIFIED'
                            ? 'bg-[#0B2418] text-[#39E58C] border border-[#39E58C]/40'
                            : entry.verdict === 'REJECTED'
                            ? 'bg-[#2B1014] text-[#FF5B64] border border-[#FF5B64]/40'
                            : 'bg-[#2A2010] text-[#FFBE55] border border-[#FFBE55]/40'
                        }`}
                      >
                        {entry.verdict || entry.status}
                      </span>
                    </td>
                    <td className="py-2.5 text-[#8B989E]">{entry.testsRun ?? 0} probes</td>
                    <td className="py-2.5 text-[#536168] max-w-xs truncate" title={entry.summary}>
                      {entry.summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Error Message Alert */}
      {errorMessage && (
        <div className="bg-[#2B1014] border border-[#FF5B64]/50 rounded p-3 text-xs font-mono text-[#FF5B64] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* 7. Catalog Inspection Modal */}
      {showCatalogModal && catalog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-[#0C1013] border border-[#222B30] rounded-lg max-w-5xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-[#222B30] bg-[#07090B] flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <BookOpen className="w-5 h-5 text-[#38BDF8]" />
                <div>
                  <h3 className="text-sm font-mono font-bold text-[#E8EEF0] flex items-center gap-2">
                    STRUCTURED SQL INJECTION TEST CATALOG
                    <span className="text-[10px] px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#39E58C]">
                      {catalog.total_tests} Test Cases Across {catalog.categories.length} Categories
                    </span>
                  </h3>
                  <p className="text-[11px] text-[#8B989E]">
                    Organized by query context, security invariant, and SQLite driver execution support.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowCatalogModal(false)}
                className="p-1.5 rounded hover:bg-[#11171B] text-[#8B989E] hover:text-[#E8EEF0] transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Filter Bar */}
            <div className="p-3 border-b border-[#222B30] bg-[#0A0D10] flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 flex-1 max-w-md">
                <input
                  type="text"
                  placeholder="Search test ID, invariant, payload, or description..."
                  value={catalogSearch}
                  onChange={(e) => setCatalogSearch(e.target.value)}
                  className="w-full bg-[#07090B] border border-[#222B30] focus:border-[#38BDF8]/50 rounded px-3 py-1.5 text-xs font-mono text-[#E8EEF0] focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-[#536168]" />
                <select
                  value={selectedCatalogCategory}
                  onChange={(e) => setSelectedCatalogCategory(e.target.value)}
                  className="bg-[#07090B] border border-[#222B30] text-xs font-mono text-[#E8EEF0] rounded px-2.5 py-1.5 focus:outline-none"
                >
                  <option value="ALL">All Categories ({catalog.categories.length})</option>
                  {catalog.categories.map((c, i) => (
                    <option key={i} value={c.name}>
                      {c.name} ({c.total_tests})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Catalog Table */}
            <div className="flex-1 overflow-auto p-4">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[#222B30] text-[#536168]">
                      <th className="pb-2.5 font-medium">TEST ID</th>
                      <th className="pb-2.5 font-medium">CATEGORY</th>
                      <th className="pb-2.5 font-medium">SECURITY INVARIANT</th>
                      <th className="pb-2.5 font-medium">PROBE PAYLOAD</th>
                      <th className="pb-2.5 font-medium">SQLITE EXECUTION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#222B30]/40">
                    {catalog.tests
                      .filter((t) => {
                        const matchCat =
                          selectedCatalogCategory === 'ALL' || t.category === selectedCatalogCategory;
                        const matchSearch =
                          !catalogSearch ||
                          t.test_id.toLowerCase().includes(catalogSearch.toLowerCase()) ||
                          t.name.toLowerCase().includes(catalogSearch.toLowerCase()) ||
                          t.security_invariant.toLowerCase().includes(catalogSearch.toLowerCase()) ||
                          t.payload.toLowerCase().includes(catalogSearch.toLowerCase()) ||
                          t.description.toLowerCase().includes(catalogSearch.toLowerCase());
                        return matchCat && matchSearch;
                      })
                      .map((test) => {
                        const isSupported = test.execution_support === 'SUPPORTED';
                        return (
                          <tr key={test.test_id} className="hover:bg-[#11171B]/50 transition-colors">
                            <td className="py-2.5 font-bold text-[#38BDF8] whitespace-nowrap">
                              {test.test_id}
                            </td>
                            <td className="py-2.5 text-[#E8EEF0] whitespace-nowrap">
                              {test.category}
                            </td>
                            <td className="py-2.5 text-[#A78BFA] text-[11px] max-w-xs truncate" title={test.security_invariant}>
                              {test.security_invariant}
                            </td>
                            <td className="py-2.5">
                              <code className="px-1.5 py-0.5 rounded bg-[#07090B] border border-[#222B30] text-[#39E58C] text-[11px]">
                                {test.payload}
                              </code>
                            </td>
                            <td className="py-2.5 whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] border ${
                                  isSupported
                                    ? 'bg-[#0B2418] border-[#39E58C]/40 text-[#39E58C]'
                                    : 'bg-[#2A2010] border-[#FFBE55]/40 text-[#FFBE55]'
                                }`}
                                title={
                                  isSupported
                                    ? 'Directly executable dynamically in Python SQLite environment'
                                    : 'Stacked queries not supported by Python sqlite3 cursor.execute() driver API; tracked as not applicable rather than false pass'
                                }
                              >
                                {test.execution_support}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-3 border-t border-[#222B30] bg-[#07090B] flex items-center justify-between text-xs font-mono text-[#536168]">
              <span>
                37 Dynamic SQLite Tests • 3 Driver-Restricted Tests (Stacked Queries)
              </span>
              <button
                onClick={() => setShowCatalogModal(false)}
                className="px-3 py-1 rounded bg-[#11171B] border border-[#222B30] text-[#E8EEF0] hover:bg-[#151D22]"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
      {/* 8. Patch Refinement Candidate Drawer */}
      <PatchRefinementDrawer
        refineResult={refineResult}
        isOpen={showRefineDrawer}
        onClose={() => setShowRefineDrawer(false)}
        onApplyCandidate={(code) => {
          setCandidatePatch(code);
          setPatchRevision((p) => p + 1);
          setIsStale(true);
          setStatus('STALE');
        }}
      />

      {/* 9. Planner Benchmark Comparison Modal */}
      <PlannerBenchmarkModal
        comparison={benchmarkResult}
        isOpen={showBenchmarkModal}
        onClose={() => setShowBenchmarkModal(false)}
        isLoading={isBenchmarking}
      />
    </div>
  );
};
