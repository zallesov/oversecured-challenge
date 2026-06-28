import { AlertCircle, CheckCircle2, Clock3, LoaderCircle, Smartphone } from 'lucide-react';
import type { ReactElement } from 'react';
import type { Run, RunStatus } from '../api';

type RunListProps = {
  runs: Run[];
  selectedRunId: string | null;
  loading: boolean;
  onSelectRun: (id: string) => void;
};

const statusIcon: Record<RunStatus, ReactElement> = {
  QUEUED: <Clock3 size={15} aria-hidden="true" />,
  RUNNING: <LoaderCircle size={15} aria-hidden="true" className="spin" />,
  COMPLETED: <CheckCircle2 size={15} aria-hidden="true" />,
  FAILED: <AlertCircle size={15} aria-hidden="true" />
};

function formatTime(value?: string | null): string {
  if (!value) {
    return 'Not started';
  }
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(new Date(value));
}

function formatSize(bytes?: number): string {
  if (!bytes) {
    return '';
  }
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function RunList({ runs, selectedRunId, loading, onSelectRun }: RunListProps) {
  return (
    <section className="panel run-list-panel" aria-labelledby="runs-heading">
      <div className="panel-heading">
        <div>
          <h2 id="runs-heading">Scans</h2>
          <p>{loading ? 'Refreshing scans' : `${runs.length} scan${runs.length === 1 ? '' : 's'}`}</p>
        </div>
      </div>

      {runs.length === 0 ? (
        <div className="empty-state">
          <Smartphone size={22} aria-hidden="true" />
          <span>No scans yet</span>
        </div>
      ) : (
        <div className="run-list" role="list">
          {runs.map((run) => (
            <button
              className={`run-list-item ${run.id === selectedRunId ? 'selected' : ''}`}
              key={run.id}
              type="button"
              onClick={() => onSelectRun(run.id)}
              aria-pressed={run.id === selectedRunId}
            >
              <span className="run-list-main">
                <span className="run-name">{run.apkFilename}</span>
                <span className="run-meta">
                  {formatTime(run.createdAt ?? run.startedAt)}
                  {formatSize(run.apkSizeBytes) ? ` · ${formatSize(run.apkSizeBytes)}` : ''}
                </span>
              </span>
              <span className={`status-badge ${run.status.toLowerCase()}`}>
                {statusIcon[run.status]}
                {run.status}
              </span>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}
