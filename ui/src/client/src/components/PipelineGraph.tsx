import {
  AlertCircle,
  CheckCircle2,
  Circle,
  Clock3,
  FileWarning,
  LoaderCircle,
  Timer
} from 'lucide-react';
import type { CSSProperties, ReactElement } from 'react';
import type { NodeState, RunNode } from '../api';

type PipelineGraphProps = {
  nodes: RunNode[];
  selectedNodeId?: string | null;
  onSelectNode?: (nodeId: string) => void;
};

const preferredStages = [
  ['decompile'],
  ['parse', 'manifest-facts'],
  ['taint', 'manifest-misconfig'],
  ['report']
];

const stateIcon: Record<NodeState, ReactElement> = {
  QUEUED: <Clock3 size={14} aria-hidden="true" />,
  RUNNING: <LoaderCircle size={14} aria-hidden="true" className="spin" />,
  COMPLETED: <CheckCircle2 size={14} aria-hidden="true" />,
  FAILED: <AlertCircle size={14} aria-hidden="true" />
};

function formatDuration(durationMs?: number | null): string | null {
  if (durationMs == null) {
    return null;
  }
  if (durationMs < 1000) {
    return `${durationMs} ms`;
  }
  const seconds = durationMs / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m ${remainder}s`;
}

function buildStages(nodes: RunNode[]): RunNode[][] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const used = new Set<string>();
  const stages = preferredStages
    .map((ids) =>
      ids
        .map((id) => byId.get(id))
        .filter((node): node is RunNode => {
          if (!node) {
            return false;
          }
          used.add(node.id);
          return true;
        })
    )
    .filter((stage) => stage.length > 0);

  const remaining = nodes.filter((node) => !used.has(node.id));
  if (remaining.length > 0) {
    stages.push(remaining);
  }

  return stages;
}

function metricSummary(node: RunNode): string | null {
  if (node.id !== 'taint' && Object.keys(node.metrics ?? {}).length === 0) {
    return null;
  }

  const ruleCount = node.metrics?.ruleCount;
  const parts = Object.entries(node.metrics ?? {})
    .slice(0, 3)
    .map(([key, value]) => `${key}: ${String(value)}`);

  if (node.id === 'taint' && ruleCount == null && parts.length === 0) {
    return 'Aggregate taint analyzer node';
  }

  return parts.length > 0 ? parts.join(' · ') : null;
}

function NodeCard({
  node,
  selected,
  selectable,
  onSelectNode
}: {
  node: RunNode;
  selected: boolean;
  selectable: boolean;
  onSelectNode?: (nodeId: string) => void;
}) {
  const duration = formatDuration(node.durationMs);
  const content = (
    <>
      <span className="graph-node-topline">
        <span className="graph-node-label">{node.label}</span>
        <span className={`status-badge compact ${node.state.toLowerCase()}`}>
          {stateIcon[node.state]}
          {node.state}
        </span>
      </span>
      {node.message ? <span className="graph-node-message">{node.message}</span> : null}
      <span className="graph-node-facts">
        {duration ? (
          <span>
            <Timer size={14} aria-hidden="true" />
            {duration}
          </span>
        ) : null}
        {node.kind === 'analyzer' || node.findingCount > 0 ? (
          <span>
            <FileWarning size={14} aria-hidden="true" />
            {node.findingCount} finding{node.findingCount === 1 ? '' : 's'}
          </span>
        ) : null}
        {!duration && node.kind !== 'analyzer' && node.findingCount === 0 ? (
          <span>
            <Circle size={13} aria-hidden="true" />
            {node.kind}
          </span>
        ) : null}
      </span>
      {metricSummary(node) ? <span className="graph-node-metrics">{metricSummary(node)}</span> : null}
      {node.error ? <span className="graph-node-error">{node.error.message}</span> : null}
    </>
  );

  if (selectable) {
    return (
      <button
        type="button"
        className={`graph-node ${node.state.toLowerCase()} ${selected ? 'selected' : ''}`}
        onClick={() => onSelectNode?.(node.id)}
        aria-pressed={selected}
      >
        {content}
      </button>
    );
  }

  return <div className={`graph-node ${node.state.toLowerCase()}`}>{content}</div>;
}

export function PipelineGraph({ nodes, selectedNodeId, onSelectNode }: PipelineGraphProps) {
  const stages = buildStages(nodes);

  if (nodes.length === 0) {
    return (
      <div className="empty-state graph-empty">
        <Circle size={22} aria-hidden="true" />
        <span>Pipeline status has not been reported yet</span>
      </div>
    );
  }

  return (
    <div className="pipeline-graph" aria-label="Scan pipeline graph">
      <svg className="pipeline-lines" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        <path d="M18 50 C27 50 27 32 36 32" />
        <path d="M18 50 C27 50 27 68 36 68" />
        <path d="M46 32 C55 32 55 32 64 32" />
        <path d="M46 68 C55 68 55 68 64 68" />
        <path d="M74 32 C83 32 83 50 92 50" />
        <path d="M74 68 C83 68 83 50 92 50" />
      </svg>

      <div className="pipeline-stages" style={{ '--stage-count': stages.length } as CSSProperties}>
        {stages.map((stage, index) => (
          <div className="pipeline-stage" key={stage.map((node) => node.id).join(':')}>
            <span className="stage-label">Stage {index + 1}</span>
            {stage.map((node) => (
              <NodeCard
                key={node.id}
                node={node}
                selected={selectedNodeId === node.id}
                selectable={Boolean(onSelectNode)}
                onSelectNode={onSelectNode}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
