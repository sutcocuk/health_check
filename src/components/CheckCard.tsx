import { useState } from 'react';
import type { HealthCheck, CheckStatus } from '../data/checks';
import { runSearch, parseSeverity, severityToStatus } from '../services/splunkApi';

interface Props {
  check: HealthCheck;
  onStatusChange: (id: string, status: CheckStatus) => void;
}

const SOURCE_LABEL: Record<string, string> = {
  monitoring_console: 'MC', health_assistant: 'HA', smt: 'SMT', ps_assessment: 'PS',
};
const SOURCE_CLS: Record<string, string> = {
  monitoring_console: 'source-mc', health_assistant: 'source-ha',
  smt: 'source-smt', ps_assessment: 'source-ps',
};
const STATUS_TEXT: Record<CheckStatus, string> = {
  unknown: '— N/A', pass: '✓ PASS', warn: '⚠ WARN', fail: '✕ FAIL', info: 'ℹ INFO',
};
const ICON_SYMBOL: Record<CheckStatus, string> = {
  unknown: '·', pass: '✓', warn: '⚠', fail: '✕', info: 'ℹ',
};

export default function CheckCard({ check, onStatusChange }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [copied,   setCopied]   = useState(false);
  const [running,  setRunning]  = useState(false);
  const [lastRun,  setLastRun]  = useState<string | null>(null);
  const [flash,    setFlash]    = useState(false);

  const handleRun = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setRunning(true);
    try {
      const result = await runSearch(check.search, 20);
      const sev    = parseSeverity(result);
      onStatusChange(check.id, severityToStatus(sev));
    } catch {
      onStatusChange(check.id, 'unknown');
    }
    setRunning(false);
    setLastRun(new Date().toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    setFlash(true);
    setTimeout(() => setFlash(false), 800);
  };

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(check.search).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  const s = check.status;
  const flashColors: Record<CheckStatus, string> = {
    fail: '#c0392b40', warn: '#e67e2240', pass: '#27ae6040', info: '#2980b940', unknown: 'transparent',
  };

  return (
    <>
      <div
        className={`check-row row-${s}`}
        onClick={() => setExpanded(v => !v)}
        style={flash ? { background: flashColors[s] } : {}}
      >
        {/* Icon */}
        <div className={`row-icon icon-${s}`}>{ICON_SYMBOL[s]}</div>

        {/* Body */}
        <div className="row-body">
          <div className="row-title">
            {check.title}
            {check.checkNumber && (
              <span className="check-num-badge" style={{ marginLeft: 6 }}>{check.checkNumber}</span>
            )}
          </div>
          <div className="row-desc">{check.description}</div>
          {check.tags.length > 0 && (
            <div className="row-tags">
              {check.tags.map(t => <span key={t} className="row-tag">{t}</span>)}
            </div>
          )}
        </div>

        {/* Right */}
        <div className="row-right" onClick={e => e.stopPropagation()}>
          <span className={`check-source-badge ${SOURCE_CLS[check.source]}`}>
            {SOURCE_LABEL[check.source]}
          </span>

          <div className={`status-pill sp-${s}`}>
            <span>{STATUS_TEXT[s]}</span>
            {lastRun && <span className="pill-time">{lastRun}</span>}
          </div>

          <button className="btn-run" onClick={handleRun} disabled={running}>
            {running ? '⏳' : '▶ Run'}
          </button>

          <button className="btn-spl" onClick={e => { e.stopPropagation(); setExpanded(v => !v); }}>
            SPL {expanded ? '▴' : '▾'}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="row-detail">
          {check.failureText && (
            <div>
              <div className="detail-label">Failure Condition</div>
              <div className="detail-failure">{check.failureText}</div>
            </div>
          )}
          {check.suggestedAction && (
            <div>
              <div className="detail-label">Suggested Action</div>
              <div className="detail-action">{check.suggestedAction}</div>
            </div>
          )}
          <div className="spl-wrap">
            <div className="detail-label">SPL Query</div>
            <button className={`btn-copy${copied ? ' copied' : ''}`} onClick={handleCopy}>
              {copied ? 'Copied!' : 'Copy'}
            </button>
            <pre className="spl-code">{check.search}</pre>
          </div>
          {(check.applicableTo || check.docLink) && (
            <div style={{ display: 'flex', gap: 12, fontSize: 11 }}>
              {check.applicableTo && (
                <span className="detail-text">Applies to: <strong style={{ color: '#9090c0' }}>{check.applicableTo}</strong></span>
              )}
              {check.docLink && (
                <a href={check.docLink.startsWith('http') ? check.docLink : '#'}
                  target="_blank" rel="noreferrer"
                  style={{ color: '#4a7cff', textDecoration: 'none' }}>
                  {check.docTitle || 'Documentation'} →
                </a>
              )}
            </div>
          )}
        </div>
      )}
    </>
  );
}
