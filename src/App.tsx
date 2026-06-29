import { useState, useCallback } from 'react';
import type { Category, CheckStatus, CheckResult } from './data/checks';
import { checks as initialChecks, CATEGORIES } from './data/checks';
import CategoryView from './components/CategoryView';
import Overview from './components/Overview';
import { runSearch, parseSeverity, severityToStatus } from './services/splunkApi';
import { generatePdf } from './services/pdfExport';

const CATEGORY_ICONS: Record<string, string> = {
  Overview:               '⊞',
  Security:               '🔒',
  'System and Environment': '🖥️',
  'Data Collection':      '📥',
  'Data Indexing':        '🗄️',
  'Data Search':          '🔍',
  'Splunk Miscellaneous': '⚙️',
  'Upgrade Readiness':    '🚀',
};

type RunState = 'idle' | 'running' | 'done';

function HealthScoreGauge({ score, color }: { score: number; color: string }) {
  const r = 34;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  return (
    <div className="health-score-box">
      <div className="score-ring-wrap">
        <svg width="80" height="80" viewBox="0 0 80 80">
          <circle cx="40" cy="40" r={r} fill="none" stroke="#1e2235" strokeWidth="8" />
          <circle cx="40" cy="40" r={r} fill="none" stroke={color} strokeWidth="8"
            strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" />
        </svg>
        <div className="score-ring-num" style={{ color }}>{score}</div>
      </div>
      <div className="score-label">Health Score</div>
      <div className="score-status" style={{ color }}>
        {score >= 80 ? '● Gezond' : score >= 50 ? '● Stabiel' : '● Kritiek'}
      </div>
    </div>
  );
}

export default function App() {
  const [activeCategory, setActiveCategory] = useState<Category>('Overview');
  const [checks, setChecks] = useState(initialChecks);
  const [runState, setRunState] = useState<RunState>('idle');
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [currentCheck, setCurrentCheck] = useState('');
  const [lastRunTime, setLastRunTime] = useState<string | null>(null);

  const handleStatusChange = (id: string, status: CheckStatus, result?: CheckResult) => {
    setChecks(prev => prev.map(c => c.id === id ? { ...c, status, result } : c));
  };

  const handleRunAll = useCallback(async () => {
    setRunState('running');
    setProgress({ done: 0, total: checks.length });
    const updated = [...checks];
    for (let i = 0; i < updated.length; i++) {
      const check = updated[i];
      setCurrentCheck(check.title);
      setProgress({ done: i, total: updated.length });
      try {
        const result = await runSearch(check.search, 8);
        const sev = parseSeverity(result, check.search);
        updated[i] = { ...check, status: severityToStatus(sev), result: result ?? undefined };
        setChecks([...updated]);
      } catch {
        updated[i] = { ...check, status: 'unknown' };
      }
    }
    setProgress({ done: updated.length, total: updated.length });
    setCurrentCheck('');
    setRunState('done');
    setLastRunTime(new Date().toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' }));
  }, [checks]);

  const handleExportPdf = () => generatePdf(checks, window.location.host);

  const handleExportCsv = () => {
    const csv = [
      'id,title,category,status,source,tags',
      ...checks.map(c =>
        [c.id, c.title, c.category, c.status, c.source, c.tags.join(';')]
          .map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')
      ),
    ].join('\n');
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })),
      download: `splunk-health-check-${new Date().toISOString().slice(0, 10)}.csv`,
    });
    a.click();
  };

  // Health score: (pass*1 + warn*0.5) / ran checks * 100
  const ran   = checks.filter(c => c.status !== 'unknown');
  const pass  = checks.filter(c => c.status === 'pass').length;
  const warn  = checks.filter(c => c.status === 'warn').length;
  const fail  = checks.filter(c => c.status === 'fail').length;
  const info  = checks.filter(c => c.status === 'info').length;
  const score = ran.length > 0
    ? Math.round((pass + warn * 0.5) / ran.length * 100)
    : 0;
  const scoreColor = score >= 80 ? '#52c41a' : score >= 50 ? '#ffa940' : '#ff6b6b';

  const pct = progress.total > 0 ? Math.round(progress.done / progress.total * 100) : 0;

  const catBadge = (cat: Category) => {
    const cc = checks.filter(c => c.category === cat);
    const f  = cc.filter(c => c.status === 'fail').length;
    const w  = cc.filter(c => c.status === 'warn').length;
    const p  = cc.filter(c => c.status === 'pass').length;
    if (f > 0) return { count: f, cls: 'nav-badge-fail' };
    if (w > 0) return { count: w, cls: 'nav-badge-warn' };
    if (p === cc.length && cc.length > 0) return { count: p, cls: 'nav-badge-ok' };
    return null;
  };

  return (
    <div className="app-layout">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-title">Health Check</div>
          <div className="sidebar-logo-sub">Splunk Platform</div>
        </div>

        <HealthScoreGauge score={score} color={scoreColor} />

        <nav className="sidebar-nav">
          {CATEGORIES.map(cat => {
            const badge = cat !== 'Overview' ? catBadge(cat) : null;
            return (
              <div key={cat} className={`nav-item${activeCategory === cat ? ' active' : ''}`}
                onClick={() => setActiveCategory(cat)}>
                <span className="nav-item-icon">{CATEGORY_ICONS[cat]}</span>
                <span>{cat}</span>
                {badge && <span className={`nav-item-badge ${badge.cls}`}>{badge.count}</span>}
              </div>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          {/* Summary */}
          {ran.length > 0 && (
            <div className="sidebar-summary">
              {fail > 0 && <span className="c-fail" style={{ fontWeight: 600 }}>{fail} fail</span>}
              {warn > 0 && <span className="c-warn" style={{ fontWeight: 600 }}>{warn} warn</span>}
              {pass > 0 && <span className="c-pass" style={{ fontWeight: 600 }}>{pass} pass</span>}
              {info > 0 && <span className="c-info" style={{ fontWeight: 600 }}>{info} info</span>}
            </div>
          )}

          {/* Progress */}
          {runState === 'running' && (
            <div className="run-progress">
              <div className="run-progress-row">
                <span>Bezig… {progress.done}/{progress.total}</span>
                <span>{pct}%</span>
              </div>
              <div className="run-progress-track">
                <div className="run-progress-fill" style={{ width: `${pct}%` }} />
              </div>
              <div className="run-progress-check">{currentCheck}</div>
            </div>
          )}

          {lastRunTime && runState !== 'running' && (
            <div className="sidebar-run-info">Laatste run: {lastRunTime} · {checks.length} checks</div>
          )}

          <button className="btn-run-all" onClick={handleRunAll} disabled={runState === 'running'}>
            {runState === 'running' ? `⏳ Bezig (${pct}%)` : '▶  Run alle checks'}
          </button>
          <button className="btn-pdf" onClick={handleExportPdf}>📄 Export PDF rapport</button>
          <button className="btn-csv" onClick={handleExportCsv}>↓ Export CSV</button>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="main-content">
        {activeCategory === 'Overview'
          ? <Overview checks={checks} onNavigate={setActiveCategory} />
          : <CategoryView
              category={activeCategory}
              checks={checks.filter(c => c.category === activeCategory)}
              onStatusChange={handleStatusChange}
            />
        }
      </main>
    </div>
  );
}
