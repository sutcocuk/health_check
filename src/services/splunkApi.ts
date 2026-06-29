export interface SplunkResult {
  fields: { name: string }[];
  rows: string[][];
}

function getCsrfToken(): string {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name && name.startsWith('splunkweb_csrf_token')) {
      return decodeURIComponent(value || '');
    }
  }
  return '';
}

function getSplunkBase(): string {
  // Works both standalone (/static/app/...) and in Splunk page context
  const loc = window.location;
  return `${loc.protocol}//${loc.host}`;
}

function prepareSpl(spl: string): string {
  return spl
    .replace(/\$rest_scope\$/g, 'splunk_server=*')
    .replace(/`dmc_set_index_internal`/g, 'index=_internal')
    .replace(/`dmc_set_index_metrics`/g, 'index=_metrics')
    .replace(/\$earliest\$/g, '-24h')
    .replace(/\$latest\$/g, 'now')
    .replace(/\$field1\.earliest\$/g, '-24h')
    .replace(/\$field1\.latest\$/g, 'now')
    .replace(/\$instance\$/g, '*')
    .replace(/\$machine\$/g, '*')
    .replace(/\$search_head\$/g, '*');
}

export async function runSearch(spl: string, timeout = 30): Promise<SplunkResult | null> {
  const base = getSplunkBase();
  const csrfToken = getCsrfToken();
  const preparedSpl = prepareSpl(spl);

  const searchStr = preparedSpl.trimStart().startsWith('|')
    ? preparedSpl
    : `search ${preparedSpl}`;

  try {
    const body = new URLSearchParams({
      search: searchStr,
      output_mode: 'json',
      exec_mode: 'oneshot',
      count: '100',
      timeout: String(timeout),
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), (timeout + 5) * 1000);

    const url = `${base}/en-US/splunkd/__raw/services/search/jobs/export`;
    console.log('[HealthCheck] POST', url, { csrfToken: csrfToken ? '✓' : '✗ MISSING' });

    const resp = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Splunk-Form-Key': csrfToken,
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: body.toString(),
    });
    clearTimeout(timer);

    console.log('[HealthCheck] response status:', resp.status);
    if (!resp.ok) {
      console.error('[HealthCheck] request failed:', resp.status, resp.statusText);
      return null;
    }

    const text = await resp.text();
    const lines = text.trim().split('\n').filter(Boolean);

    let fields: { name: string }[] = [];
    const rows: string[][] = [];

    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (obj.preview === true) continue;
        if (obj.fields) fields = obj.fields;
        if (obj.result) {
          if (fields.length === 0) {
            fields = Object.keys(obj.result).map(name => ({ name }));
          }
          const row = fields.map((f) => String(obj.result[f.name] ?? ''));
          rows.push(row);
        }
      } catch {
        // skip malformed lines
      }
    }

    return { fields, rows };
  } catch {
    return null;
  }
}

const DMC_PATTERNS = ['dmc_group', 'inputlookup dmc_', 'dmc_set_index', 'dmc_forwarder'];

function usesDmc(spl: string): boolean {
  const lower = spl.toLowerCase();
  return DMC_PATTERNS.some(p => lower.includes(p));
}

export function parseSeverity(result: SplunkResult | null, spl = ''): number {
  if (!result) return -1;

  if (result.rows.length === 0) {
    // No results from a DMC-dependent search → unknown (DMC not configured)
    if (usesDmc(spl)) return -1;
    // No results from any other search → no problems found → pass
    return 0;
  }

  const sevIdx = result.fields.findIndex((f) => f.name === 'severity_level');

  // Results but no severity_level field → data found (warn)
  if (sevIdx === -1) return 2;

  let maxSev = 0;
  for (const row of result.rows) {
    const val = parseFloat(row[sevIdx] || '0');
    if (!isNaN(val) && val > maxSev) maxSev = val;
  }
  return maxSev;
}

export function severityToStatus(sev: number): import('../data/checks').CheckStatus {
  if (sev === 3) return 'fail';
  if (sev === 2) return 'warn';
  if (sev === 1) return 'info';
  if (sev === 0) return 'pass';
  return 'unknown';
}
