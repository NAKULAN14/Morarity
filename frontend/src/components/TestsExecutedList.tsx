import React from 'react';
import { CheckCircle2, XCircle, Clock, Database, ArrowRight } from 'lucide-react';
import { TestResult } from '../types';

interface TestsExecutedListProps {
  tests: TestResult[];
}

export const TestsExecutedList: React.FC<TestsExecutedListProps> = ({ tests }) => {
  if (!tests || tests.length === 0) {
    return (
      <div className="border border-[#222B30] rounded p-8 bg-[#0C1013] text-center">
        <p className="text-xs font-mono text-[#536168]">No dynamic tests were executed in this verification run.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {tests.map((test, index) => {
        const isPass = test.passed;

        return (
          <div
            key={test.test_id || index}
            className={`border rounded p-4 bg-[#0C1013] transition-all ${
              isPass ? 'border-[#222B30]' : 'border-[#FF5B64]/40 bg-[#2B1014]/20'
            }`}
          >
            {/* Header row */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222B30]/60 pb-2.5">
              <div className="flex items-center gap-2.5">
                <div
                  className={`p-1.5 rounded ${
                    isPass ? 'bg-[#0B2418] text-[#39E58C]' : 'bg-[#2B1014] text-[#FF5B64]'
                  }`}
                >
                  {isPass ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-[#E8EEF0]">
                      {test.test_id}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        isPass
                          ? 'bg-[#0B2418] border-[#39E58C]/30 text-[#39E58C]'
                          : 'bg-[#2B1014] border-[#FF5B64]/30 text-[#FF5B64]'
                      }`}
                    >
                      {test.outcome}
                    </span>
                  </div>
                </div>
              </div>

              {test.execution_time_ms !== undefined && test.execution_time_ms !== null && (
                <div className="flex items-center gap-1 text-xs font-mono text-[#8B989E]">
                  <Clock className="w-3.5 h-3.5 text-[#536168]" />
                  <span>{test.execution_time_ms} ms</span>
                </div>
              )}
            </div>

            {/* Test Details */}
            <div className="mt-3 space-y-2">
              <p className="text-xs text-[#E8EEF0] font-sans leading-relaxed">
                {test.details}
              </p>

              {/* Invariant flags */}
              <div className="flex flex-wrap items-center gap-3 pt-1 text-xs font-mono">
                {test.baseline_exploitable !== undefined && (
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] ${
                      test.baseline_exploitable
                        ? 'bg-[#0B2418] border border-[#39E58C]/30 text-[#39E58C]'
                        : 'bg-[#2A2010] border border-[#FFBE55]/30 text-[#FFBE55]'
                    }`}
                  >
                    Baseline Exploitable: {test.baseline_exploitable ? 'YES' : 'NO'}
                  </span>
                )}

                {test.patch_blocks_payload !== undefined && (
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] ${
                      test.patch_blocks_payload
                        ? 'bg-[#0B2418] border border-[#39E58C]/30 text-[#39E58C]'
                        : 'bg-[#2B1014] border border-[#FF5B64]/30 text-[#FF5B64]'
                    }`}
                  >
                    Patch Blocks Payload: {test.patch_blocks_payload ? 'YES' : 'NO'}
                  </span>
                )}

                {test.functionality_intact !== undefined && (
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] ${
                      test.functionality_intact
                        ? 'bg-[#0B2418] border border-[#39E58C]/30 text-[#39E58C]'
                        : 'bg-[#2A2010] border border-[#FFBE55]/30 text-[#FFBE55]'
                    }`}
                  >
                    Functionality Intact: {test.functionality_intact ? 'YES' : 'NO'}
                  </span>
                )}
              </div>

              {test.error && (
                <div className="mt-2 p-2.5 rounded bg-[#2B1014]/50 border border-[#FF5B64]/40 text-xs font-mono text-[#FF5B64]">
                  Error: {test.error}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};
