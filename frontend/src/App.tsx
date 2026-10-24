import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { OverviewWorkspace } from './pages/OverviewWorkspace';
import { NewVerificationWorkspace } from './pages/NewVerificationWorkspace';
import { LiveResultsWorkspace } from './pages/LiveResultsWorkspace';
import { ReportsArchiveView } from './pages/ReportsArchiveView';
import { ArchitectureModal } from './components/ArchitectureModal';
import {
  checkBackendHealth,
  getScenarios,
  getVerificationStats,
  getReports,
  getReportDetail,
  verifyPatch,
} from './services/api';
import {
  BackendHealth,
  ReportSummary,
  Scenario,
  VerificationRequest,
  VerificationResponse,
  VerificationStats,
} from './types';
import { AlertCircle, RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'verify' | 'results' | 'reports'>('overview');
  const [backendHealth, setBackendHealth] = useState<BackendHealth | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(false);
  const [stats, setStats] = useState<VerificationStats | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<Scenario | null>(null);

  const [currentResponse, setCurrentResponse] = useState<VerificationResponse | null>(null);
  const [currentOriginalSource, setCurrentOriginalSource] = useState<string>('');
  const [currentPatchedSource, setCurrentPatchedSource] = useState<string>('');

  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [reportsLoading, setReportsLoading] = useState<boolean>(false);

  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isArchitectureModalOpen, setIsArchitectureModalOpen] = useState<boolean>(false);

  // 1. Initial Data Fetch
  const loadInitialData = useCallback(async () => {
    setHealthLoading(true);
    try {
      const health = await checkBackendHealth();
      setBackendHealth(health);

      const [scList, statsData, reportsData] = await Promise.all([
        getScenarios(),
        getVerificationStats(),
        getReports(),
      ]);

      setScenarios(scList);
      if (scList.length > 0 && !selectedScenario) {
        setSelectedScenario(scList[0]);
      }
      setStats(statsData);
      setReports(reportsData);
    } catch (err: any) {
      setBackendHealth(null);
      setErrorMessage(err.message || 'Cannot reach Moriarty verification backend.');
    } finally {
      setHealthLoading(false);
    }
  }, [selectedScenario]);

  useEffect(() => {
    loadInitialData();

    // Check health every 15 seconds
    const interval = setInterval(async () => {
      try {
        const health = await checkBackendHealth();
        setBackendHealth(health);
      } catch {
        setBackendHealth(null);
      }
    }, 15000);

    return () => clearInterval(interval);
  }, [loadInitialData]);

  // 2. Refresh Reports & Stats
  const refreshReportsAndStats = async () => {
    setReportsLoading(true);
    try {
      const [statsData, reportsData] = await Promise.all([
        getVerificationStats(),
        getReports(),
      ]);
      setStats(statsData);
      setReports(reportsData);
    } catch (err) {
      console.error('Error refreshing reports:', err);
    } finally {
      setReportsLoading(false);
    }
  };

  // 3. Handle Scenario Selection
  const handleSelectScenario = (scenario: Scenario, autoRun: boolean = false) => {
    setSelectedScenario(scenario);
    setCurrentOriginalSource(scenario.original_source);
    setCurrentPatchedSource(scenario.patched_source);

    if (autoRun) {
      handleSubmitVerification({
        original_source: scenario.original_source,
        patched_source: scenario.patched_source,
        scenario: scenario.id,
        target_type: scenario.default_mode === 'fixture_only' ? 'CONTROLLED_FIXTURE' : 'SUBMITTED_SOURCE_EXECUTION',
        execute_submitted_source: scenario.default_mode !== 'fixture_only',
        max_tests: 3,
      });
    } else {
      setActiveTab('verify');
    }
  };

  // 4. Submit Verification Execution
  const handleSubmitVerification = async (request: VerificationRequest) => {
    setIsVerifying(true);
    setErrorMessage(null);
    if (request.original_source) setCurrentOriginalSource(request.original_source);
    if (request.patched_source) setCurrentPatchedSource(request.patched_source);

    try {
      const response = await verifyPatch(request);
      setCurrentResponse(response);
      setActiveTab('results');
      // Refresh historical reports and stats in background
      refreshReportsAndStats();
    } catch (err: any) {
      setErrorMessage(err.message || 'Verification execution failed.');
    } finally {
      setIsVerifying(false);
    }
  };

  // 5. Inspect Selected Report from Archive
  const handleSelectReport = async (filename: string) => {
    try {
      const detail = await getReportDetail(filename);
      // Map report JSON back into VerificationResponse schema
      const mappedResponse: VerificationResponse = {
        verification_id: detail.verification_id || filename.replace('.json', ''),
        verdict: detail.verdict || 'INCONCLUSIVE',
        summary: detail.verdict_summary || detail.summary || '',
        analysis: detail.analysis || {
          supported: true,
          vulnerability_type: 'SQL_INJECTION',
          findings: [],
          security_invariants: [],
          summary: '',
        },
        tests_executed: (detail.tests || []).map((t: any) => ({
          test_id: t.test_id || 'PROBE',
          passed: t.passed ?? false,
          outcome: t.outcome || (t.passed ? 'PASS' : 'FAIL'),
          details: t.details || '',
          execution_time_ms: t.execution_time_ms,
          error: t.error,
          baseline_exploitable: t.baseline_exploitable,
          patch_blocks_payload: t.patch_blocks_payload,
          functionality_intact: t.functionality_intact,
        })),
        evidence: detail.evidence || [],
        limitations: detail.limitations || [],
        verification_scope: detail.verification_scope,
        dynamic_verification_performed: detail.dynamic_verification_performed,
        target_type: detail.target_type,
        target_provenance: detail.target_provenance,
        submitted_source_executed: detail.submitted_source_executed,
        source_runtime_match: detail.source_runtime_match,
        final_action: detail.agent?.final_action,
        stopping_reason: detail.agent?.stopping_reason,
        decision_trace: detail.agent?.decision_trace,
        patch_comparison: detail.patch_comparison,
      };

      setCurrentResponse(mappedResponse);
      setActiveTab('results');
    } catch (err: any) {
      alert(`Could not load report: ${err.message}`);
    }
  };

  return (
    <div className="min-h-screen bg-[#07090B] text-[#E8EEF0] flex flex-col font-sans">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        health={backendHealth}
        healthLoading={healthLoading}
        onRefreshHealth={loadInitialData}
        hasActiveResult={currentResponse !== null}
        onOpenArchitecture={() => setIsArchitectureModalOpen(true)}
      />

      {/* Backend Offline Warning Banner */}
      {!backendHealth && (
        <div className="bg-[#2B1014] border-b border-[#FF5B64]/30 px-4 py-2.5 text-xs font-mono text-[#FF5B64] flex items-center justify-between">
          <div className="flex items-center gap-2 max-w-4xl mx-auto w-full">
            <AlertCircle className="w-4 h-4 flex-shrink-0 text-[#FF5B64]" />
            <span>
              Moriarty Backend Engine is offline at <code className="bg-[#07090B] px-1 py-0.5 rounded">http://127.0.0.1:8000</code>.
              Start backend with: <code className="text-[#E8EEF0]">scripts/start_backend.bat</code> or <code className="text-[#E8EEF0]">uvicorn --app-dir backend app.main:app</code>.
            </span>
          </div>
          <button
            onClick={loadInitialData}
            disabled={healthLoading}
            className="flex items-center gap-1 text-[11px] hover:underline"
          >
            <RefreshCw className={`w-3 h-3 ${healthLoading ? 'animate-spin' : ''}`} />
            <span>Retry</span>
          </button>
        </div>
      )}

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && (
          <OverviewWorkspace
            stats={stats}
            scenarios={scenarios}
            onSelectScenario={handleSelectScenario}
            onNavigateVerify={() => setActiveTab('verify')}
            onNavigateReports={() => setActiveTab('reports')}
            onViewReport={handleSelectReport}
            backendOnline={backendHealth !== null}
          />
        )}

        {activeTab === 'verify' && (
          <NewVerificationWorkspace
            scenarios={scenarios}
            selectedScenario={selectedScenario}
            onSelectScenario={(s) => setSelectedScenario(s)}
            onSubmitVerification={handleSubmitVerification}
            isVerifying={isVerifying}
            errorMessage={errorMessage}
            backendOnline={backendHealth !== null}
          />
        )}

        {activeTab === 'results' && currentResponse && (
          <LiveResultsWorkspace
            response={currentResponse}
            originalSource={currentOriginalSource}
            patchedSource={currentPatchedSource}
            onNewVerification={() => setActiveTab('verify')}
          />
        )}

        {activeTab === 'reports' && (
          <ReportsArchiveView
            reports={reports}
            loading={reportsLoading}
            onRefresh={refreshReportsAndStats}
            onSelectReport={handleSelectReport}
          />
        )}
      </main>

      {/* Forensic Architecture Modal */}
      <ArchitectureModal
        isOpen={isArchitectureModalOpen}
        onClose={() => setIsArchitectureModalOpen(false)}
      />

      {/* Workstation Footer */}
      <footer className="border-t border-[#222B30] bg-[#07090B] py-4 text-xs font-mono text-[#536168]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            MORIARTY WORKSTATION • Structural Security Patch Verification
          </div>
          <div>
            Honest Verification Engine • Three-Outcome Model (VERIFIED / REJECTED / INCONCLUSIVE)
          </div>
        </div>
      </footer>
    </div>
  );
};
