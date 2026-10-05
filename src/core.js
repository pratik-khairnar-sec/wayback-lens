/* Wayback Lens - shared core: query builder, parser, classifier, icons.
 * Exposed as the global `WB`. Author: Pratik (https://github.com/pratik-khairnar-sec) */
(function (g) {
  'use strict';

  const CDX = 'https://web.archive.org/cdx/search/cdx';

  const MODES = {
    domain:    { label: 'Main domain',     hint: 'Every archived path on this host',        icon: 'globe'   },
    wildcard:  { label: 'All subdomains',  hint: 'The host plus every subdomain',           icon: 'network' },
    path:      { label: 'This path',       hint: 'Everything beneath the current path',     icon: 'folder'  },
    sensitive: { label: 'Sensitive files', hint: 'Backups, dumps, keys, configs, logs',     icon: 'lock'    },
    js:        { label: 'JavaScript',      hint: 'Old bundles leak endpoints and secrets',  icon: 'code'    },
    params:    { label: 'With parameters', hint: 'Query-string URLs worth fuzzing',         icon: 'sliders' },
  };

  /* ---------- target parsing ---------- */
  function parseTarget(input) {
    let s = String(input || '').trim();
    if (!s) return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
    let u;
    try { u = new URL(s); } catch { return null; }
    if (!/^https?:$/.test(u.protocol) || !u.hostname.includes('.')) return null;
    const host = u.hostname.toLowerCase();
    return {
      host,
      root: host.replace(/^www\./, ''),
      origin: u.origin,
      path: u.pathname.replace(/\/+$/, ''),
    };
  }

  /* ---------- CDX query ---------- */
  function buildQuery(mode, input, opts = {}) {
    const t = typeof input === 'string' ? parseTarget(input) : input;
    if (!t || !MODES[mode]) return null;
    const p = new URLSearchParams();

    if (mode === 'domain') {
      p.set('url', t.host + '/*');
    } else if (mode === 'path') {
      p.set('url', t.origin + t.path);
      p.set('matchType', 'prefix');
    } else {
      p.set('url', t.root);
      p.set('matchType', 'domain');
      if (mode === 'sensitive') p.append('filter', `original:.*\\.(${sensitiveExt()})(\\?.*)?$`);
      if (mode === 'js')        p.append('filter', 'original:.*\\.m?js(\\?.*)?$');
      if (mode === 'params')    p.append('filter', 'original:.*\\?.*=.*');
    }
    if (opts.liveOnly) p.append('filter', 'statuscode:200');
    p.set('fl', 'timestamp,original,statuscode,mimetype');
    p.set('collapse', 'urlkey');
    p.set('output', 'text');
    p.set('limit', String(opts.limit || 100000));
    return `${CDX}?${p.toString()}`;
  }

  /* ---------- classification ---------- */
  const CAT_META = {
    secrets:  { label: 'Keys and secrets',     risk: 3 },
    database: { label: 'Databases and dumps',  risk: 3 },
    backups:  { label: 'Backups and archives', risk: 2 },
    config:   { label: 'Config files',         risk: 2 },
    logs:     { label: 'Logs',                 risk: 2 },
    docs:     { label: 'Documents',            risk: 1 },
    binaries: { label: 'Binaries and scripts', risk: 1 },
    scripts:  { label: 'JavaScript',           risk: 1 },
    data:     { label: 'JSON and XML',         risk: 1 },
    other:    { label: 'Other',                risk: 0 },
  };
  const STATUS_META = {
    '200': 'Found (200)', '3xx': 'Redirects (3xx)', '404': 'Not found (404)',
    '4xx': 'Other client errors', '5xx': 'Server errors', none: 'No status',
  };
  const EXT_CAT = {};
  const add = (cat, list) => list.split(' ').forEach(e => (EXT_CAT[e] = cat));
  add('secrets',  'env pem key crt pub asc secret htpasswd npmrc kdbx');
  add('database', 'sql db sqlite mdb');
  add('backups',  'bak backup old orig swp tmp zip tar gz tgz 7z rar cache');
  add('config',   'yml yaml ini config conf properties');
  add('logs',     'log');
  add('docs',     'pdf doc docx xls xlsx pptx csv txt md md5');
  add('binaries', 'exe dll bin apk msi dmg iso img deb rpm sh bat');
  add('scripts',  'js mjs map');
  add('data',     'json xml');
  const sensitiveExt = () => Object.keys(EXT_CAT).filter(e => e !== 'js' && e !== 'mjs').concat('git').join('|');
  const RISK_EXT = { bak: 3, backup: 3, old: 3, orig: 3, swp: 3, pub: 1, crt: 1, asc: 1, map: 2 };

  const URL_RE = /^https?:\/\/([^\/?#]+)([^?#]*)(\?[^#]*)?/i;

  function enrich(r) {
    const m = URL_RE.exec(r.url);
    r.host   = m ? m[1].toLowerCase().replace(/:\d+$/, '') : '';
    r.path   = m ? m[2] : '';
    r.query  = m && m[3] ? m[3] : '';
    r.year   = r.ts ? r.ts.slice(0, 4) : '';
    r.hasParams = r.query.includes('=');
    const base = r.path.split('/').pop().toLowerCase();
    const ext  = base.includes('.') ? base.split('.').pop() : '';
    let cat = EXT_CAT[ext] || 'other';
    let risk = RISK_EXT[ext] ?? CAT_META[cat].risk;
    if (/(^|\/)\.git(\/|$)/i.test(r.path) || base.startsWith('.env') ||
        /^(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.htpasswd)$/.test(base) || base.startsWith('wp-config')) { cat = 'secrets'; risk = 3; }
    r.cat = cat;
    r.risk = risk;
    const st = r.status || '-';
    r.sg = st === '200' ? '200' : st === '404' ? '404' : st[0] === '3' ? '3xx' : st[0] === '4' ? '4xx' : st[0] === '5' ? '5xx' : 'none';
    return r;
  }

  function parse(text) {
    const out = [];
    for (const line of text.split('\n')) {
      if (!line) continue;
      const [ts, url, status, mime] = line.split(' ');
      if (url) out.push(enrich({ ts, url, status: status || '-', mime: mime || '' }));
    }
    return out;
  }

  const snapshotUrl = r => `https://web.archive.org/web/${r.ts}/${r.url}`;
  const isHttp = s => /^https?:\/\//i.test(s);

  /* ---------- exports ---------- */
  const csvCell = v => `"${String(v).replace(/"/g, '""')}"`;
  function serialize(rows, format) {
    if (format === 'json') return JSON.stringify(rows.map(r => ({
      url: r.url, host: r.host, category: r.cat, risk: r.risk, status: r.status, mime: r.mime, archived: r.ts,
    })), null, 2);
    if (format === 'csv') return ['url,host,category,risk,status,mime,archived']
      .concat(rows.map(r => [r.url, r.host, r.cat, r.risk, r.status, r.mime, r.ts].map(csvCell).join(','))).join('\n');
    if (format === 'hosts') return [...new Set(rows.map(r => r.host))].sort().join('\n');
    return rows.map(r => r.url).join('\n');
  }

  /* ---------- icon sprite (inline: no CDN, works offline) ---------- */
  const ICONS = {
    globe:   '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3.2 3.4 3.2 14.6 0 18M12 3c-3.2 3.4-3.2 14.6 0 18"/>',
    network: '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5H5v5M12 11.5h7v5"/>',
    folder:  '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    lock:    '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    code:    '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 6l-3 12"/>',
    sliders: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    copy:    '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
    ext:     '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    clock:   '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    down:    '<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>',
    search:  '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.2-4.2"/>',
    link:    '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    stop:    '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    retry:   '<path d="M20 12a8 8 0 1 1-2.5-5.8M20 4v5h-5"/>',
  };
  function injectIcons() {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0" style="position:absolute" aria-hidden="true">' +
      Object.entries(ICONS).map(([k, v]) => `<symbol id="i-${k}" viewBox="0 0 24 24">${v}</symbol>`).join('') + '</svg>';
    document.body.insertAdjacentHTML('afterbegin', svg);
  }
  function icon(name) {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('class', 'i');
    s.setAttribute('aria-hidden', 'true');
    const u = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    u.setAttribute('href', '#i-' + name);
    s.appendChild(u);
    return s;
  }

  g.WB = { MODES, CAT_META, STATUS_META, parseTarget, buildQuery, parse, snapshotUrl, isHttp, serialize, injectIcons, icon };
})(globalThis);
