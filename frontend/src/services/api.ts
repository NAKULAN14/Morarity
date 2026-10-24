import {
  BackendHealth,
  ReportSummary,
  Scenario,
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
