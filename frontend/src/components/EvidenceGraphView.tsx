import React, { useState } from 'react';
import {
  Network,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Cpu,
  Brain,
  Zap,
  Layers,
  FileCode,
  ArrowRight,
  Info,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { EvidenceGraphData, EvidenceGraphNode, EvidenceGraphEdge } from '../types';

interface EvidenceGraphViewProps {
  graphData: EvidenceGraphData | null | undefined;
}

export const EvidenceGraphView: React.FC<EvidenceGraphViewProps> = ({ graphData }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="bg-[#0C1013] border border-[#222B30] rounded p-8 text-center text-xs font-mono text-[#536168]">
        No evidence graph available for this verification run.
      </div>
    );
  }

  const selectedNode = selectedNodeId
    ? graphData.nodes.find((n) => n.id === selectedNodeId)
    : graphData.nodes[graphData.nodes.length - 1]; // Default to Verdict

  // Find incoming and outgoing edges for the selected node
  const incomingEdges = graphData.edges.filter((e) => e.target === selectedNode?.id);
  const outgoingEdges = graphData.edges.filter((e) => e.source === selectedNode?.id);

  const getNodeColor = (type: string, status: string) => {
    if (status === 'VERIFIED') return 'border-[#39E58C] bg-[#0B2418]/60 text-[#39E58C]';
    if (status === 'REJECTED') return 'border-[#FF5B64] bg-[#2B1014]/60 text-[#FF5B64]';
    if (status === 'INCONCLUSIVE') return 'border-[#FFBE55] bg-[#2A2010]/60 text-[#FFBE55]';
    if (status === 'CONFIRMED') return 'border-[#39E58C]/60 bg-[#0B2418]/40 text-[#39E58C]';
    if (status === 'CONTRADICTED') return 'border-[#FF5B64]/60 bg-[#2B1014]/40 text-[#FF5B64]';
    if (type === 'LLM_HYPOTHESIS') return 'border-[#38BDF8]/60 bg-[#082F49]/40 text-[#38BDF8]';
    if (type === 'ML_RISK') return 'border-[#C084FC]/60 bg-[#2E1065]/40 text-[#C084FC]';
    if (type === 'CANDIDATE_PATCH') return 'border-[#A855F7]/60 bg-[#3B0764]/40 text-[#C084FC]';
    return 'border-[#222B30] bg-[#11171B] text-[#E8EEF0]';
  };

  const getNodeIcon = (type: string, status: string) => {
    switch (type) {
      case 'SOURCE':
        return <FileCode className="w-3.5 h-3.5 text-[#38BDF8]" />;
      case 'PARSED_STRUCTURE':
        return <Layers className="w-3.5 h-3.5 text-[#8B989E]" />;
      case 'SECURITY_FINDING':
        return <ShieldAlert className="w-3.5 h-3.5 text-[#FF5B64]" />;
      case 'ML_RISK':
        return <Zap className="w-3.5 h-3.5 text-[#C084FC]" />;
      case 'LLM_HYPOTHESIS':
        return <Brain className="w-3.5 h-3.5 text-[#38BDF8]" />;
      case 'TEST_DECISION':
        return <Cpu className="w-3.5 h-3.5 text-[#FFBE55]" />;
      case 'TEST_EXECUTION':
        return <Layers className="w-3.5 h-3.5 text-[#38BDF8]" />;
      case 'EVIDENCE_RECORD':
        return status === 'CONFIRMED' ? (
          <CheckCircle2 className="w-3.5 h-3.5 text-[#39E58C]" />
        ) : (
          <XCircle className="w-3.5 h-3.5 text-[#FF5B64]" />
        );
      case 'CANDIDATE_PATCH':
        return <Shield className="w-3.5 h-3.5 text-[#C084FC]" />;
      case 'VERDICT':
        return status === 'VERIFIED' ? (
          <ShieldCheck className="w-3.5 h-3.5 text-[#39E58C]" />
        ) : status === 'REJECTED' ? (
          <ShieldAlert className="w-3.5 h-3.5 text-[#FF5B64]" />
        ) : (
          <AlertTriangle className="w-3.5 h-3.5 text-[#FFBE55]" />
        );
      default:
        return <Network className="w-3.5 h-3.5 text-[#8B989E]" />;
    }
  };

  // Group nodes by pipeline layer
  const layers = [
    { title: '1. Input & AST Structure', types: ['SOURCE', 'PARSED_STRUCTURE', 'SECURITY_FINDING'] },
    { title: '2. Advisory Signals (ML & LLM)', types: ['ML_RISK', 'LLM_HYPOTHESIS'] },
    { title: '3. Test Decisions & Probes', types: ['TEST_DECISION', 'TEST_EXECUTION'] },
    { title: '4. Evidence Ledger & Patch', types: ['EVIDENCE_RECORD', 'CANDIDATE_PATCH'] },
    { title: '5. Formal Verdict', types: ['VERDICT'] },
  ];

  return (
    <div className="bg-[#0C1013] border border-[#222B30] rounded-lg p-4 font-mono space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#222B30] pb-3">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-[#39E58C]" />
          <span className="text-xs font-bold text-[#E8EEF0] tracking-wider">
            VERIFICATION EVIDENCE GRAPH
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#39E58C]">
            {graphData.nodes.length} Nodes • {graphData.edges.length} Edges
          </span>
        </div>
        <p className="text-[11px] text-[#8B989E]">
          Click any node to inspect provenance, relations, and verification trail.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Graph Visual Pipeline (2 Cols) */}
        <div className="lg:col-span-2 space-y-4">
          {layers.map((layer, idx) => {
            const layerNodes = graphData.nodes.filter((n) => layer.types.includes(n.type));
            if (layerNodes.length === 0) return null;

            return (
              <div key={idx} className="space-y-1.5 bg-[#07090B] p-3 rounded border border-[#222B30]">
                <div className="flex items-center justify-between text-[10px] text-[#536168] font-bold">
                  <span>{layer.title.toUpperCase()}</span>
                  <span>{layerNodes.length} node{layerNodes.length > 1 ? 's' : ''}</span>
                </div>

                <div className="flex flex-wrap gap-2 pt-1">
                  {layerNodes.map((node) => {
                    const isSelected = selectedNode?.id === node.id;
                    const colorClasses = getNodeColor(node.type, node.status);

                    return (
                      <button
                        key={node.id}
                        onClick={() => setSelectedNodeId(node.id)}
                        className={`text-left p-2 rounded border transition-all flex items-center gap-2 text-xs ${colorClasses} ${
                          isSelected
                            ? 'ring-2 ring-[#39E58C] shadow-[0_0_10px_rgba(57,229,140,0.2)]'
                            : 'hover:border-[#8B989E]'
                        }`}
                      >
                        {getNodeIcon(node.type, node.status)}
                        <div className="leading-tight">
                          <span className="block font-bold truncate max-w-[200px]">{node.label}</span>
                          <span className="text-[9px] uppercase tracking-wider opacity-70">
                            {node.status}
                          </span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Node Detail Panel (1 Col) */}
        <div className="lg:col-span-1 bg-[#07090B] border border-[#222B30] rounded p-3.5 flex flex-col justify-between space-y-3">
          {selectedNode ? (
            <div className="space-y-3 text-xs">
              <div className="border-b border-[#222B30] pb-2 flex items-center justify-between">
                <span className="text-[10px] text-[#536168] uppercase">NODE INSPECTOR</span>
                <span
                  className={`text-[9px] px-2 py-0.5 rounded border uppercase font-bold ${getNodeColor(
                    selectedNode.type,
                    selectedNode.status
                  )}`}
                >
                  {selectedNode.status}
                </span>
              </div>

              <div>
                <h4 className="font-bold text-[#E8EEF0] flex items-center gap-1.5 text-xs">
                  {getNodeIcon(selectedNode.type, selectedNode.status)}
                  <span>{selectedNode.label}</span>
                </h4>
                <span className="text-[10px] text-[#8B989E] font-mono mt-0.5 block">
                  ID: <code className="text-[#38BDF8]">{selectedNode.id}</code> • Type: {selectedNode.type}
                </span>
              </div>

              {selectedNode.code_location && (
                <div className="text-[11px] text-[#8B989E]">
                  Code Ref: <code className="text-[#E8EEF0]">{selectedNode.code_location}</code>
                </div>
              )}

              {/* Node Details Attributes */}
              {Object.keys(selectedNode.details).length > 0 && (
                <div className="space-y-1 bg-[#0C1013] p-2.5 rounded border border-[#222B30]">
                  <span className="text-[10px] text-[#536168] block font-bold">ATTRIBUTES:</span>
                  <div className="space-y-1 text-[11px] overflow-x-auto">
                    {Object.entries(selectedNode.details).map(([k, v]) => (
                      <div key={k} className="flex items-start justify-between gap-2">
                        <span className="text-[#8B989E]">{k}:</span>
                        <span className="text-[#E8EEF0] font-mono text-right truncate max-w-[160px]">
                          {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Connected Edges */}
              <div className="space-y-1.5 pt-1">
                <span className="text-[10px] text-[#536168] block font-bold">GRAPH CONNECTIONS:</span>
                <div className="space-y-1 text-[10px]">
                  {incomingEdges.map((e, idx) => (
                    <div key={idx} className="flex items-center gap-1 text-[#8B989E] bg-[#11171B] p-1 rounded">
                      <span className="text-[#38BDF8] truncate max-w-[80px]">{e.source}</span>
                      <ArrowRight className="w-2.5 h-2.5 text-[#536168]" />
                      <span className="text-[#39E58C] font-bold">{e.relation}</span>
                    </div>
                  ))}
                  {outgoingEdges.map((e, idx) => (
                    <div key={idx} className="flex items-center gap-1 text-[#8B989E] bg-[#11171B] p-1 rounded">
                      <span className="text-[#39E58C] font-bold">{e.relation}</span>
                      <ArrowRight className="w-2.5 h-2.5 text-[#536168]" />
                      <span className="text-[#38BDF8] truncate max-w-[80px]">{e.target}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center text-xs text-[#536168] my-auto">
              Select a node to inspect provenance and verification trace.
            </div>
          )}

          <div className="border-t border-[#222B30] pt-2 text-[10px] text-[#536168] flex items-center gap-1">
            <Info className="w-3 h-3 text-[#39E58C]" />
            <span>Traceability Graph ensures no verdict is made without recorded evidence.</span>
          </div>
        </div>
      </div>
    </div>
  );
};
