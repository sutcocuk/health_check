import { useState } from 'react';
import type { Category, HealthCheck, CheckStatus, CheckResult } from '../data/checks';
import CheckCard from './CheckCard';

interface Props {
  category: Category;
  checks: HealthCheck[];
  onStatusChange: (id: string, status: CheckStatus, result?: CheckResult) => void;
}

const CAT_ICONS: Record<string, string> = {
  Security: '🔒', 'System and Environment': '🖥️',
  'Data Collection': '📥', 'Data Indexing': '🗄️',
  'Data Search': '🔍', 'Splunk Miscellaneous': '⚙️', 'Upgrade Readiness': '🚀',
};

type Filter = 'all' | CheckStatus;

export default function CategoryView({ category, checks, onStatusChange }: Props) {
  const [filter, setFilter] = useState<Filter>('all');
  const [search, setSearch] = useState('');

  const fail  = checks.filter(c => c.status === 'fail').length;
  const warn  = checks.filter(c => c.status === 'warn').length;
  const pass  = checks.filter(c => c.status === 'pass').length;
  const info  = checks.filter(c => c.status === 'info').length;
  const unk   = checks.filter(c => c.status === 'unknown').length;
  const error = checks.filter(c => c.status === 'error').length;

  const filtered = checks.filter(c => {
    if (filter !== 'all' && c.status !== filter) return false;
    if (search) {
      const q = search.toLowerCase();
      return c.title.toLowerCase().includes(q) || c.description.toLowerCase().includes(q) || c.tags.some(t => t.includes(q));
    }
    return true;
  });

  const chips: { key: Filter; label: string; count: number; cls: string }[] = [
    { key: 'all',     label: 'Alle',    count: checks.length, cls: 'chip-all'   },
    { key: 'fail',    label: '✕ Fail',  count: fail,  cls: 'chip-fail'  },
    { key: 'warn',    label: '⚠ Warn',  count: warn,  cls: 'chip-warn'  },
    { key: 'pass',    label: '✓ Pass',  count: pass,  cls: 'chip-pass'  },
    { key: 'info',    label: 'ℹ Info',  count: info,  cls: 'chip-info'  },
    { key: 'unknown', label: '— N/A',   count: unk,   cls: 'chip-unk'   },
    { key: 'error',   label: '✕ Error', count: error, cls: 'chip-error' },
  ];

  return (
    <div className="cat-view">
      <div className="cat-view-header">
        <div className="cat-view-title">
          <span>{CAT_ICONS[category]}</span>
          <span>{category}</span>
        </div>
        <div className="cat-view-stats">
          {chips.map(chip => (
            <button key={chip.key}
              className={`cat-stat-chip ${chip.cls}${filter === chip.key ? ' active' : ''}`}
              onClick={() => setFilter(chip.key)}
              style={{ opacity: filter !== chip.key && chip.key !== 'all' && chip.count === 0 ? 0.3 : 1 }}
            >
              {chip.label} ({chip.count})
            </button>
          ))}
          <div className="cat-search">
            <input placeholder="Zoek checks…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>
        </div>
      </div>

      <div className="checks-list">
        {filtered.length === 0 && (
          <div style={{ color: '#4a5580', textAlign: 'center', padding: '40px 0', fontSize: 13 }}>
            Geen checks gevonden
          </div>
        )}
        {filtered.map(check => (
          <CheckCard key={check.id} check={check} onStatusChange={onStatusChange} />
        ))}
      </div>
    </div>
  );
}
