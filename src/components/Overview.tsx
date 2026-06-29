import type { HealthCheck, Category } from '../data/checks';
import { CATEGORIES } from '../data/checks';

interface Props {
  checks: HealthCheck[];
  onNavigate: (cat: Category) => void;
}

const CAT_ICONS: Record<string, string> = {
  Security:               '🔒',
  'System and Environment': '🖥️',
  'Data Collection':      '📥',
  'Data Indexing':        '🗄️',
  'Data Search':          '🔍',
  'Splunk Miscellaneous': '⚙️',
  'Upgrade Readiness':    '🚀',
};

function DonutChart({ pass, warn, fail, info, unk, total }: {
  pass: number; warn: number; fail: number; info: number; unk: number; total: number;
}) {
  const r = 44;
  const circ = 2 * Math.PI * r;
  const pct = (n: number) => (n / total) * circ;

  const segments = [
    { color: '#27ae60', value: pass },
    { color: '#e67e22', value: warn },
    { color: '#c0392b', value: fail },
    { color: '#2980b9', value: info },
    { color: '#2a3050', value: unk },
  ];

  let offset = 0;
  const arcs = segments.map(s => {
    const len = pct(s.value);
    const arc = { color: s.color, offset, len };
    offset += len;
    return arc;
  });

  const ran   = pass + warn + fail + info;
  const score = ran > 0 ? Math.round((pass + warn * 0.5) / ran * 100) : 0;
  const scoreColor = score >= 80 ? '#52c41a' : score >= 50 ? '#ffa940' : '#ff6b6b';

  return (
    <div className="donut-wrap">
      <svg width="110" height="110" viewBox="0 0 110 110">
        <circle cx="55" cy="55" r={r} fill="none" stroke="#1e2235" strokeWidth="14" />
        {arcs.filter(a => a.len > 0).map((arc, i) => (
          <circle key={i} cx="55" cy="55" r={r} fill="none"
            stroke={arc.color} strokeWidth="14"
            strokeDasharray={`${arc.len} ${circ - arc.len}`}
            strokeDashoffset={-arc.offset}
          />
        ))}
      </svg>
      <div className="donut-center">
        <div className="donut-pct" style={{ color: scoreColor }}>{score}%</div>
        <div className="donut-sub">gezond</div>
      </div>
    </div>
  );
}

function CatStatusDot({ checks }: { checks: HealthCheck[] }) {
  const f = checks.filter(c => c.status === 'fail').length;
  const w = checks.filter(c => c.status === 'warn').length;
  const p = checks.filter(c => c.status === 'pass').length;
  if (f > 0) return <div className="cat-dot cat-dot-fail" />;
  if (w > 0) return <div className="cat-dot cat-dot-warn" />;
  if (p > 0) return <div className="cat-dot cat-dot-pass" />;
  return <div className="cat-dot cat-dot-unk" />;
}

export default function Overview({ checks, onNavigate }: Props) {
  const total = checks.length;
  const fail  = checks.filter(c => c.status === 'fail').length;
  const warn  = checks.filter(c => c.status === 'warn').length;
  const pass  = checks.filter(c => c.status === 'pass').length;
  const info  = checks.filter(c => c.status === 'info').length;
  const unk   = checks.filter(c => c.status === 'unknown').length;

  const cats = CATEGORIES.filter(c => c !== 'Overview');

  const issues = checks
    .filter(c => c.status === 'fail' || c.status === 'warn')
    .sort((a, b) => {
      const ord = { fail: 0, warn: 1 };
      return (ord[a.status as 'fail'|'warn'] ?? 2) - (ord[b.status as 'fail'|'warn'] ?? 2);
    })
    .slice(0, 8);

  const SOURCE_LABEL: Record<string, string> = {
    monitoring_console: 'MC', health_assistant: 'HA', smt: 'SMT', ps_assessment: 'PS',
  };
  const SOURCE_CLS: Record<string, string> = {
    monitoring_console: 'source-mc', health_assistant: 'source-ha', smt: 'source-smt', ps_assessment: 'source-ps',
  };

  return (
    <div className="overview-wrap">
      <div className="page-header">
        <div className="page-title">Splunk Health Check — Overview</div>
        <div className="page-sub">{total} checks · Host: {window.location.host}</div>
      </div>

      {/* Stat pills */}
      <div className="stat-pills">
        <div className="stat-pill pill-fail"><div className="stat-num c-fail">{fail}</div><div className="stat-lbl">Fail</div></div>
        <div className="stat-pill pill-warn"><div className="stat-num c-warn">{warn}</div><div className="stat-lbl">Warn</div></div>
        <div className="stat-pill pill-pass"><div className="stat-num c-pass">{pass}</div><div className="stat-lbl">Pass</div></div>
        <div className="stat-pill pill-info"><div className="stat-num c-info">{info}</div><div className="stat-lbl">Info</div></div>
        <div className="stat-pill pill-unk"><div className="stat-num c-unk">{unk}</div><div className="stat-lbl">N/A</div></div>
      </div>

      {/* Donut + legend */}
      <div className="donut-row">
        <DonutChart pass={pass} warn={warn} fail={fail} info={info} unk={unk} total={total} />
        <div className="donut-legend">
          <div className="legend-item"><div className="legend-dot" style={{ background: '#27ae60' }} /><span>{pass} Pass</span></div>
          <div className="legend-item"><div className="legend-dot" style={{ background: '#e67e22' }} /><span>{warn} Warn</span></div>
          <div className="legend-item"><div className="legend-dot" style={{ background: '#c0392b' }} /><span>{fail} Fail</span></div>
          <div className="legend-item"><div className="legend-dot" style={{ background: '#2980b9' }} /><span>{info} Info</span></div>
          <div className="legend-item"><div className="legend-dot" style={{ background: '#2a3050' }} /><span>{unk} N/A</span></div>
        </div>
        <div className="source-badges">
          <div className="source-badges-title">Bronnen</div>
          <div className="source-badges-row">
            <span className="check-source-badge source-mc">MC — Monitoring Console</span>
            <span className="check-source-badge source-ha">HA — Health Assistant</span>
            <span className="check-source-badge source-smt">SMT — SMT Health App</span>
            <span className="check-source-badge source-ps">PS — PS Assessment</span>
          </div>
        </div>
      </div>

      {/* Category grid */}
      <div className="section-header">Per categorie</div>
      <div className="cat-grid">
        {cats.map(cat => {
          const cc  = checks.filter(c => c.category === cat);
          const cf  = cc.filter(c => c.status === 'fail').length;
          const cw  = cc.filter(c => c.status === 'warn').length;
          const cp  = cc.filter(c => c.status === 'pass').length;
          const ci  = cc.filter(c => c.status === 'info').length;
          const cu  = cc.filter(c => c.status === 'unknown').length;
          const tot = cc.length || 1;
          return (
            <div key={cat} className="cat-card" onClick={() => onNavigate(cat)}>
              <div className="cat-card-top">
                <span className="cat-icon">{CAT_ICONS[cat]}</span>
                <CatStatusDot checks={cc} />
              </div>
              <div className="cat-name">{cat}</div>
              <div className="cat-total">{cc.length} checks</div>
              <div className="bar-stack">
                {cf > 0 && <div className="bar-seg bar-seg-fail" style={{ flex: cf }} />}
                {cw > 0 && <div className="bar-seg bar-seg-warn" style={{ flex: cw }} />}
                {cp > 0 && <div className="bar-seg bar-seg-pass" style={{ flex: cp }} />}
                {ci > 0 && <div className="bar-seg bar-seg-info" style={{ flex: ci }} />}
                {cu > 0 && <div className="bar-seg bar-seg-unk"  style={{ flex: cu }} />}
                {cf + cw + cp + ci + cu === 0 && <div className="bar-seg bar-seg-unk" style={{ flex: 1 }} />}
              </div>
              <div className="cat-nums">
                {cf > 0 && <span className="c-fail">{cf} fail</span>}
                {cw > 0 && <span className="c-warn">{cw} warn</span>}
                {cp > 0 && <span className="c-pass">{cp} pass</span>}
                {ci > 0 && <span className="c-info">{ci} info</span>}
                {cf + cw + cp + ci === 0 && <span className="c-unk">{cu} N/A</span>}
              </div>
            </div>
          );
        })}
      </div>

      {/* Critical findings */}
      {issues.length > 0 && (
        <>
          <div className="section-header">Kritieke bevindingen</div>
          <div className="findings-list">
            {issues.map(check => (
              <div
                key={check.id}
                className={`check-row row-${check.status}`}
                onClick={() => onNavigate(check.category)}
              >
                <div className={`row-icon icon-${check.status}`}>
                  {check.status === 'fail' ? '✕' : '⚠'}
                </div>
                <div className="row-body">
                  <div className="row-title">{check.title}</div>
                  <div className="row-desc">{check.description}</div>
                </div>
                <div className="row-right">
                  <span className={`check-source-badge ${SOURCE_CLS[check.source]}`}>
                    {SOURCE_LABEL[check.source]}
                  </span>
                  <span className={`status-pill sp-${check.status}`}>
                    {check.status === 'fail' ? 'FAIL' : 'WARN'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
