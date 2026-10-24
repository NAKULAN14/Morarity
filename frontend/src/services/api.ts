import {
  BackendHealth,
  BudgetPreset,
  CatalogResponse,
  ComprehensiveBenchmarkResponse,
  GeneratedPatch,
  PatchRefineRequest,
  PatchRefineResponse,
  PlannerComparisonResult,
  ReportSummary,
  Scenario,
  SQLAnalysisResult,
  VerificationRequest,
  VerificationResponse,
  VerificationStats,
} from '../types';

const API_BASE = '/api';

export class ApiError extends Error {
  status?: number;
  details?: any;

  constructor(message: string, status?: number, details?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

export async function checkBackendHealth(): Promise<BackendHealth> {
  const start = performance.now();
  try {
    const res = await fetch(`${API_BASE}/health`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const ping_ms = Math.round(performance.now() - start);

    if (!res.ok) {
      throw new ApiError(`Health check failed: HTTP ${res.status}`, res.status);
    }
    const data = await res.json();
    return { ...data, ping_ms };
  } catch (err: any) {
    throw new ApiError(
      err.message || 'Cannot connect to Moriarty verification backend at http://127.0.0.1:8000',
      err.status || 0
    );
  }
}

export async function getScenarios(): Promise<Scenario[]> {
  const res = await fetch(`${API_BASE}/scenarios`);
  if (!res.ok) {
    throw new ApiError(`Failed to load scenarios: HTTP ${res.status}`, res.status);
  }
  return res.json();
}

export async function verifyPatch(request: VerificationRequest): Promise<VerificationResponse> {
  const res = await fetch(`${API_BASE}/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    let errorDetail = `Verification request failed with HTTP ${res.status}`;
    try {
      const errorJson = await res.json();
      if (errorJson.detail) {
        errorDetail = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
      }
    } catch {
      // ignore
    }
    throw new ApiError(errorDetail, res.status);
  }

  return res.json();
}

export async function getReports(): Promise<ReportSummary[]> {
  const res = await fetch(`${API_BASE}/reports`);
  if (!res.ok) {
    throw new ApiError(`Failed to fetch reports: HTTP ${res.status}`, res.status);
  }
  return res.json();
}

export async function getReportDetail(filename: string): Promise<any> {
  const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(filename)}`);
  if (!res.ok) {
    throw new ApiError(`Failed to fetch report '${filename}': HTTP ${res.status}`, res.status);
  }
  return res.json();
}

export async function getVerificationStats(): Promise<VerificationStats> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) {
    throw new ApiError(`Failed to fetch verification stats: HTTP ${res.status}`, res.status);
  }
  return res.json();
}

export async function analyzeSqlInput(inputText: string, inputType: string = 'auto'): Promise<SQLAnalysisResult> {
  const res = await fetch(`${API_BASE}/lab/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ input_text: inputText, input_type: inputType }),
  });

  if (!res.ok) {
    let errorDetail = `SQL Analysis failed with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.detail) errorDetail = err.detail;
    } catch {}
    throw new ApiError(errorDetail, res.status);
  }

  return res.json();
}

export async function generateSqlPatch(
  inputText: string,
  inputType: string = 'auto',
  paramName?: string
): Promise<GeneratedPatch> {
  const res = await fetch(`${API_BASE}/lab/generate-patch`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ input_text: inputText, input_type: inputType, param_name: paramName }),
  });

  if (!res.ok) {
    let errorDetail = `Patch generation failed with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.detail) errorDetail = err.detail;
    } catch {}
    throw new ApiError(errorDetail, res.status);
  }

  return res.json();
}

export async function verifyLabPatch(request: {
  original_source: string;
  candidate_patch: string;
  budget_preset?: BudgetPreset | null;
  max_tests?: number;
  source_revision?: number;
  patch_revision?: number;
  input_kind?: string;
}): Promise<VerificationResponse> {
  const res = await fetch(`${API_BASE}/lab/verify-patch`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    let errorDetail = `Lab verification failed with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.detail) errorDetail = err.detail;
    } catch {}
    throw new ApiError(errorDetail, res.status);
  }

  return res.json();
}

export async function continuousEvaluate(request: {
  source_code: string;
  patch_code?: string;
  source_revision?: number;
  patch_revision?: number;
  auto_verify?: boolean;
  max_tests?: number;
  budget_preset?: BudgetPreset | null;
}): Promise<any> {
  const res = await fetch(`${API_BASE}/lab/evaluate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    let errorDetail = `Continuous evaluation failed with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.detail) errorDetail = err.detail;
    } catch {}
    throw new ApiError(errorDetail, res.status);
  }

  return res.json();
}

export async function getCatalog(): Promise<CatalogResponse> {
  const res = await fetch(`${API_BASE}/catalog`);
  if (!res.ok) {
    throw new ApiError(`Failed to fetch catalog: HTTP ${res.status}`, res.status);
  }
  return res.json();
}

export async function refineSqlPatch(
  request: PatchRefineRequest
): Promise<PatchRefineResponse> {
  const res = await fetch(`${API_BASE}/lab/refine-patch`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    let errorDetail = `Patch refinement failed with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.detail) errorDetail = err.detail;
    } catch {}
    throw new ApiError(errorDetail, res.status);
  }

  return res.json();
}

export async function comparePlanners(request: {
  scenario?: string;
  original_source?: string;
  patched_source?: string;
  budget_preset?: BudgetPreset | null;
  max_tests?: number;
}): Promise<PlannerComparisonResult> {
  const res = await fetch(`${API_BASE}/lab/compare-planners`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    let errorDetail = `Planner comparison failed with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.detail) errorDetail = err.detail;
    } catch {}
    throw new ApiError(errorDetail, res.status);
  }

  return res.json();
}

export async function getComprehensiveBenchmark(
  budget: number = 5
): Promise<ComprehensiveBenchmarkResponse> {
  const res = await fetch(`${API_BASE}/planner/benchmark?budget=${budget}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!res.ok) {
    let errorDetail = `Comprehensive benchmark failed with HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.detail) errorDetail = err.detail;
    } catch {}
    throw new ApiError(errorDetail, res.status);
  }

  return res.json();
}
