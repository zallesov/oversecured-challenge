import { Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { Finding } from '../api';

type FindingTableProps = {
  findings: Finding[];
  selectedNodeId?: string | null;
};

const severityRank: Record<string, number> = {
  CRITICAL: 0,
  ERROR: 1,
  HIGH: 2,
  WARNING: 3,
  MEDIUM: 4,
  LOW: 5,
  NOTE: 6,
  INFO: 7
};

function location(file?: string | null, line?: number | null): string {
  if (!file) {
    return 'No location';
  }
  return line ? `${file}:${line}` : file;
}

// Triage messages are stored as "[verdict, confidence X] rationale" — the prefix is shown in its
// own columns, so strip it for the message cell.
function cleanMessage(message: string): string {
  return message.replace(/^\[[^\]]*\]\s*/, '');
}

function formatConfidence(confidence?: number | null): string {
  if (confidence == null) {
    return '—';
  }
  return `${Math.round(confidence * 100)}%`;
}

export function FindingTable({ findings, selectedNodeId }: FindingTableProps) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('ALL');

  const severityOptions = useMemo(
    () => ['ALL', ...Array.from(new Set(findings.map((finding) => finding.severity))).sort()],
    [findings]
  );

  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return findings
      .filter((finding) => (selectedNodeId ? finding.nodeId === selectedNodeId : true))
      .filter((finding) => (severity === 'ALL' ? true : finding.severity === severity))
      .filter((finding) => {
        if (!normalizedQuery) {
          return true;
        }
        return [
          finding.message,
          finding.ruleId,
          finding.vulnerabilityClass,
          finding.analyzer,
          finding.fix,
          finding.sourceFile,
          finding.sinkFile
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery));
      })
      .sort((a, b) => {
        const severityDelta = (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
        if (severityDelta !== 0) {
          return severityDelta;
        }
        return (a.ruleId ?? '').localeCompare(b.ruleId ?? '');
      });
  }, [findings, query, selectedNodeId, severity]);

  // Show the triage-specific columns (verdict/confidence/fix) when every visible finding is from
  // the AI triage step; otherwise the generic rule/message layout.
  const triageView = filtered.length > 0 && filtered.every((finding) => finding.analyzer === 'ai-triage');

  return (
    <section className="panel findings-panel" aria-labelledby="findings-heading">
      <div className="panel-heading findings-heading">
        <div>
          <h2 id="findings-heading">{triageView ? 'AI Triage Findings' : 'Findings'}</h2>
          <p>
            {filtered.length} shown
            {selectedNodeId ? ` for ${selectedNodeId}` : ''}
          </p>
        </div>
        <div className="finding-tools">
          <label className="search-field">
            <Search size={16} aria-hidden="true" />
            <span className="sr-only">Search findings</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search findings"
            />
          </label>
          <label className="select-field">
            <span className="sr-only">Filter by severity</span>
            <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
              {severityOptions.map((option) => (
                <option key={option} value={option}>
                  {option === 'ALL' ? 'All severities' : option}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state">No findings match the current view</div>
      ) : triageView ? (
        <div className="finding-table" role="table" aria-label="AI triage findings">
          <div className="finding-row finding-header triage" role="row">
            <span role="columnheader">Severity</span>
            <span role="columnheader">Verdict</span>
            <span role="columnheader">Confidence</span>
            <span role="columnheader">Message</span>
            <span role="columnheader">Fix</span>
          </div>
          {filtered.map((finding) => (
            <details className="finding-row finding-item triage" key={finding.id}>
              <summary>
                <span className={`severity-pill ${String(finding.severity).toLowerCase()}`}>
                  {finding.severity}
                </span>
                <span className={`verdict-pill ${String(finding.verdict ?? '').toLowerCase()}`}>
                  {finding.verdict ?? '—'}
                </span>
                <span className="finding-confidence">{formatConfidence(finding.confidence)}</span>
                <span className="finding-message">
                  {finding.verdict ? cleanMessage(finding.message) : finding.message}
                </span>
                <span className="finding-fix">{finding.fix ?? '—'}</span>
              </summary>
              <div className="finding-details">
                <dl>
                  <div>
                    <dt>Rule</dt>
                    <dd>{finding.ruleId ?? 'Not specified'}</dd>
                  </div>
                  <div>
                    <dt>Location</dt>
                    <dd>{location(finding.sourceFile, finding.sourceLine)}</dd>
                  </div>
                  <div>
                    <dt>CWE</dt>
                    <dd>{finding.cwe ?? 'Not mapped'}</dd>
                  </div>
                  <div>
                    <dt>OWASP Mobile</dt>
                    <dd>{finding.owaspMobile ?? 'Not mapped'}</dd>
                  </div>
                </dl>
              </div>
            </details>
          ))}
        </div>
      ) : (
        <div className="finding-table" role="table" aria-label="Security findings">
          <div className="finding-row finding-header" role="row">
            <span role="columnheader">Severity</span>
            <span role="columnheader">Rule</span>
            <span role="columnheader">Message</span>
          </div>
          {filtered.map((finding) => (
            <details className="finding-row finding-item" key={finding.id}>
              <summary>
                <span className={`severity-pill ${String(finding.severity).toLowerCase()}`}>
                  {finding.severity}
                </span>
                <span className="finding-rule">
                  {finding.ruleId ?? finding.vulnerabilityClass ?? finding.analyzer}
                </span>
                <span className="finding-message">{finding.message}</span>
              </summary>
              <div className="finding-details">
                <dl>
                  <div>
                    <dt>Analyzer</dt>
                    <dd>{finding.analyzer}</dd>
                  </div>
                  <div>
                    <dt>Class</dt>
                    <dd>{finding.vulnerabilityClass ?? 'Not specified'}</dd>
                  </div>
                  <div>
                    <dt>Source</dt>
                    <dd>{location(finding.sourceFile, finding.sourceLine)}</dd>
                  </div>
                  <div>
                    <dt>Sink</dt>
                    <dd>{location(finding.sinkFile, finding.sinkLine)}</dd>
                  </div>
                  <div>
                    <dt>CWE</dt>
                    <dd>{finding.cwe ?? 'Not mapped'}</dd>
                  </div>
                  <div>
                    <dt>OWASP Mobile</dt>
                    <dd>{finding.owaspMobile ?? 'Not mapped'}</dd>
                  </div>
                </dl>
              </div>
            </details>
          ))}
        </div>
      )}
    </section>
  );
}
