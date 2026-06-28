import {
  AlertCircle,
  CheckCircle2,
  Circle,
  Clock3,
  FileWarning,
  LoaderCircle,
  Timer
} from 'lucide-react';
import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react';
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
  ['report'],
  ['ai-triage']
];

const stateIcon: Record<NodeState, ReactElement> = {
  QUEUED: <Clock3 size={14} aria-hidden="true" />,
  RUNNING: <LoaderCircle size={14} aria-hidden="true" className="spin" />,
  COMPLETED: <CheckCircle2 size={14} aria-hidden="true" />,
  FAILED: <AlertCircle size={14} aria-hidden="true" />
};

type LinePair = {
  from: string;
  to: string;
};

type GraphLine = {
  id: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
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

function buildLinePairs(stages: RunNode[][]): LinePair[] {
  const pairs: LinePair[] = [];

  for (let index = 0; index < stages.length - 1; index += 1) {
    const fromStage = stages[index];
    const toStage = stages[index + 1];

    if (fromStage.length === 1) {
      for (const toNode of toStage) {
        pairs.push({ from: fromStage[0].id, to: toNode.id });
      }
      continue;
    }

    if (toStage.length === 1) {
      for (const fromNode of fromStage) {
        pairs.push({ from: fromNode.id, to: toStage[0].id });
      }
      continue;
    }

    for (let nodeIndex = 0; nodeIndex < Math.min(fromStage.length, toStage.length); nodeIndex += 1) {
      pairs.push({ from: fromStage[nodeIndex].id, to: toStage[nodeIndex].id });
    }
  }

  return pairs;
}

function ruleLabel(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }

  const candidate = value as Record<string, unknown>;
  for (const key of ['rule', 'ruleId', 'id'] as const) {
    const field = candidate[key];
    if (typeof field === 'string' && field.length > 0) {
      return field;
    }
  }

  return null;
}

function metricSummary(node: RunNode): string | null {
  if (node.id !== 'taint' && Object.keys(node.metrics ?? {}).length === 0) {
    return null;
  }

  const ruleCount = node.metrics?.ruleCount;

  if (node.id === 'taint') {
    const rules = Array.isArray(node.metrics?.rules) ? node.metrics.rules : null;
    if (rules && rules.length > 0) {
      const labels = rules
        .map(ruleLabel)
        .filter((label): label is string => Boolean(label));
      if (labels.length > 0) {
        const suffix = labels.length !== rules.length ? ` (+${rules.length - labels.length} more)` : '';
        return `Rules: ${labels.join(', ')}${suffix}`;
      }
    }

    if (typeof ruleCount === 'number') {
      return `Rules: ${ruleCount}`;
    }

    return 'Aggregate taint analyzer node';
  }

  const parts = Object.entries(node.metrics ?? {})
    .slice(0, 3)
    .map(([key, value]) => `${key}: ${String(value)}`);

  return parts.length > 0 ? parts.join(' · ') : null;
}

function NodeCard({
  node,
  nodeRef,
  selected,
  selectable,
  onSelectNode
}: {
  node: RunNode;
  nodeRef: (element: HTMLElement | null) => void;
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
        ref={nodeRef}
        className={`graph-node ${node.state.toLowerCase()} ${selected ? 'selected' : ''}`}
        onClick={() => onSelectNode?.(node.id)}
        aria-pressed={selected}
      >
        {content}
      </button>
    );
  }

  return (
    <div ref={nodeRef} className={`graph-node ${node.state.toLowerCase()}`}>
      {content}
    </div>
  );
}

export function PipelineGraph({ nodes, selectedNodeId, onSelectNode }: PipelineGraphProps) {
  const graphRef = useRef<HTMLDivElement | null>(null);
  const nodeRefs = useRef(new Map<string, HTMLElement>());
  const [lines, setLines] = useState<GraphLine[]>([]);
  const stages = useMemo(() => buildStages(nodes), [nodes]);
  const linePairs = useMemo(() => buildLinePairs(stages), [stages]);

  const setNodeRef = useCallback((nodeId: string, element: HTMLElement | null) => {
    if (element) {
      nodeRefs.current.set(nodeId, element);
    } else {
      nodeRefs.current.delete(nodeId);
    }
  }, []);

  useLayoutEffect(() => {
    const currentGraphElement = graphRef.current;
    if (!currentGraphElement) {
      setLines([]);
      return undefined;
    }
    const graphElement = currentGraphElement;

    function updateLines() {
      const graphRect = graphElement.getBoundingClientRect();
      const nextLines = linePairs.flatMap((pair) => {
        const fromElement = nodeRefs.current.get(pair.from);
        const toElement = nodeRefs.current.get(pair.to);
        if (!fromElement || !toElement) {
          return [];
        }

        const fromRect = fromElement.getBoundingClientRect();
        const toRect = toElement.getBoundingClientRect();
        return [
          {
            id: `${pair.from}:${pair.to}`,
            x1: fromRect.right - graphRect.left,
            y1: fromRect.top + fromRect.height / 2 - graphRect.top,
            x2: toRect.left - graphRect.left,
            y2: toRect.top + toRect.height / 2 - graphRect.top
          }
        ];
      });

      setLines(nextLines);
    }

    updateLines();

    const resizeObserver = new ResizeObserver(updateLines);
    resizeObserver.observe(graphElement);
    for (const element of nodeRefs.current.values()) {
      resizeObserver.observe(element);
    }
    window.addEventListener('resize', updateLines);

    return () => {
      resizeObserver.disconnect();
      window.removeEventListener('resize', updateLines);
    };
  }, [linePairs]);

  if (nodes.length === 0) {
    return (
      <div className="empty-state graph-empty">
        <Circle size={22} aria-hidden="true" />
        <span>Pipeline status has not been reported yet</span>
      </div>
    );
  }

  return (
    <div className="pipeline-graph" ref={graphRef} aria-label="Scan pipeline graph">
      <svg className="pipeline-lines" aria-hidden="true">
        {lines.map((line) => (
          <line key={line.id} x1={line.x1} y1={line.y1} x2={line.x2} y2={line.y2} />
        ))}
      </svg>

      <div className="pipeline-stages" style={{ '--stage-count': stages.length } as CSSProperties}>
        {stages.map((stage, index) => (
          <div className="pipeline-stage" key={stage.map((node) => node.id).join(':')}>
            <span className="stage-label">Stage {index + 1}</span>
            {stage.map((node) => (
              <NodeCard
                key={node.id}
                node={node}
                nodeRef={(element) => setNodeRef(node.id, element)}
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
