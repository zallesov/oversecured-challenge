import { ArrowLeft, Download, ExternalLink, RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, ApiError, upsertById, type Finding, type Run, type RunNode } from '../api';
import { FindingTable } from './FindingTable';
import { PipelineGraph } from './PipelineGraph';

type RunDetailProps = {
  runId: string | null;
  onRunUpdated?: (run: Run) => void;
  onGoToRuns?: () => void;
};

function formatDuration(durationMs?: number | null): string {
  if (durationMs == null) {
    return 'Pending';
  }
  if (durationMs < 1000) {
    return `${durationMs} ms`;
  }
  const seconds = Math.round(durationMs / 1000);
  const minutes = Math.floor(seconds / 60);
  return minutes > 0 ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'Unexpected error';
}

export function RunDetail({ runId, onRunUpdated, onGoToRuns }: RunDetailProps) {
  const [run, setRun] = useState<Run | null>(null);
  const [nodes, setNodes] = useState<RunNode[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reportBusy, setReportBusy] = useState<'html' | 'sarif' | 'ai-triage' | null>(null);
  const refreshInFlight = useRef(false);
  const onRunUpdatedRef = useRef(onRunUpdated);
  onRunUpdatedRef.current = onRunUpdated;

  const refresh = useCallback(async () => {
    if (!runId) {
      return;
    }
    if (refreshInFlight.current) {
      return;
    }

    refreshInFlight.current = true;
    setError(null);
    try {
      const [nextRun, nextNodes, nextFindings] = await Promise.all([
        api.getRun(runId),
        api.getRunNodes(runId),
        api.getRunFindings(runId),
      ]);
      setRun(nextRun);
      setNodes(nextNodes);
      setFindings(nextFindings);
      onRunUpdatedRef.current?.(nextRun);
    } finally {
      refreshInFlight.current = false;
    }
  }, [runId]);

  // Snapshot + realtime subscriptions
  useEffect(() => {
    if (!runId) {
      setRun(null);
      setNodes([]);
      setFindings([]);
      return;
    }

    let cancelled = false;

    // Pending unsubscribe functions — called on cleanup even if subscribe resolves after unmount
    const unsubs: Array<() => Promise<void>> = [];

    setLoading(true);
    setError(null);

    async function init() {
      try {
        // Snapshot
        const [nextRun, nextNodes, nextFindings] = await Promise.all([
          api.getRun(runId as string),
          api.getRunNodes(runId as string),
          api.getRunFindings(runId as string),
        ]);
        if (cancelled) return;
        setRun(nextRun);
        setNodes(nextNodes);
        setFindings(nextFindings);
        onRunUpdatedRef.current?.(nextRun);
      } catch (nextError: unknown) {
        if (!cancelled) {
          setError(errorMessage(nextError));
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }

      if (cancelled) return;

      // Subscribe — each subscribe call returns an unsub; handle cancelled-before-resolved
      const runUnsub = api.subscribeRun(runId as string, (updatedRun) => {
        if (cancelled) return;
        setRun(updatedRun);
        onRunUpdatedRef.current?.(updatedRun);
      });
      runUnsub
        .then((fn) => {
          if (cancelled) {
            void fn();
          } else {
            unsubs.push(fn);
          }
        })
        .catch((e: unknown) => {
          if (!cancelled) setError(errorMessage(e));
        });

      const nodesUnsub = api.subscribeNodes(runId as string, (action, node) => {
        if (cancelled) return;
        setNodes((prev) => upsertById(prev, node, action));
      });
      nodesUnsub
        .then((fn) => {
          if (cancelled) {
            void fn();
          } else {
            unsubs.push(fn);
          }
        })
        .catch((e: unknown) => {
          if (!cancelled) setError(errorMessage(e));
        });

      const findingsUnsub = api.subscribeFindings(runId as string, (action, finding) => {
        if (cancelled) return;
        setFindings((prev) => upsertById(prev, finding, action));
      });
      findingsUnsub
        .then((fn) => {
          if (cancelled) {
            void fn();
          } else {
            unsubs.push(fn);
          }
        })
        .catch((e: unknown) => {
          if (!cancelled) setError(errorMessage(e));
        });
    }

    void init();

    return () => {
      cancelled = true;
      for (const fn of unsubs) {
        void fn();
      }
    };
  }, [runId]);

  const selectedNode = useMemo(
    () => nodes.find((node) => node.id === selectedNodeId) ?? null,
    [nodes, selectedNodeId]
  );

  async function openReport(kind: 'html' | 'sarif' | 'ai-triage') {
    if (!runId) {
      return;
    }
    setReportBusy(kind);
    setError(null);
    try {
      const blob = await api.getReport(runId, kind);
      const url = window.URL.createObjectURL(blob);
      if (kind === 'html' || kind === 'ai-triage') {
        window.open(url, '_blank', 'noopener,noreferrer');
      } else {
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `${run?.apkFilename ?? 'scan'}-${runId}.sarif`;
        anchor.click();
      }
      window.setTimeout(() => window.URL.revokeObjectURL(url), 60_000);
    } catch (nextError) {
      setError(errorMessage(nextError));
    } finally {
      setReportBusy(null);
    }
  }

  if (!runId) {
    return (
      <section className="panel detail-placeholder">
        <h2>Select a scan</h2>
        <p>Upload an APK or choose a scan from the list to inspect pipeline status and findings.</p>
      </section>
    );
  }

  return (
    <div className="run-detail">
      <section className="panel detail-summary" aria-labelledby="run-detail-heading">
        <div className="panel-heading detail-heading">
          <div>
            <h2 id="run-detail-heading">{run?.apkFilename ?? 'Loading scan'}</h2>
            <p>{run?.message ?? (loading ? 'Loading scan status' : 'No status message')}</p>
          </div>
          <div className="detail-actions">
            {onGoToRuns ? (
              <button className="secondary-button" type="button" onClick={onGoToRuns}>
                <ArrowLeft size={16} aria-hidden="true" />
                All scans
              </button>
            ) : null}
            <button className="icon-button" type="button" onClick={refresh} disabled={loading} title="Refresh scan">
              <RefreshCw size={17} aria-hidden="true" />
              <span className="sr-only">Refresh scan</span>
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => openReport('html')}
              disabled={!run || reportBusy !== null}
            >
              <ExternalLink size={16} aria-hidden="true" />
              HTML
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => openReport('sarif')}
              disabled={!run || reportBusy !== null}
            >
              <Download size={16} aria-hidden="true" />
              SARIF
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => openReport('ai-triage')}
              disabled={!run || reportBusy !== null}
              title="AI triage verdicts and fixes"
            >
              <ExternalLink size={16} aria-hidden="true" />
              AI Triage
            </button>
          </div>
        </div>

        <div className="summary-grid">
          <div>
            <span>Status</span>
            <strong className={`status-text ${run?.status?.toLowerCase() ?? ''}`}>{run?.status ?? 'Loading'}</strong>
          </div>
          <div>
            <span>Duration</span>
            <strong>{formatDuration(run?.durationMs)}</strong>
          </div>
          <div>
            <span>Findings</span>
            <strong>{findings.length}</strong>
          </div>
          <div>
            <span>Workflow</span>
            <strong>{run?.workflowId ?? 'Pending'}</strong>
          </div>
        </div>

        {error ? <div className="inline-alert">{error}</div> : null}
      </section>

      <section className="panel graph-panel" aria-labelledby="pipeline-heading">
        <div className="panel-heading">
          <div>
            <h2 id="pipeline-heading">Pipeline</h2>
            <p>{selectedNode ? `Selected ${selectedNode.label}` : 'Node status and analyzer output'}</p>
          </div>
        </div>
        <PipelineGraph nodes={nodes} selectedNodeId={selectedNodeId} onSelectNode={setSelectedNodeId} />
        {selectedNode ? (
          <div className="node-inspector">
            <button type="button" onClick={() => setSelectedNodeId(null)}>
              Clear selection
            </button>
            <span>{selectedNode.message ?? 'No node message'}</span>
          </div>
        ) : null}
      </section>

      <FindingTable findings={findings} selectedNodeId={selectedNodeId} />
    </div>
  );
}
