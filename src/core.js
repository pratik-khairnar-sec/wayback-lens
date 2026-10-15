/* Wayback Lens - shared core: query builder, parser, classifier, parameter mining, CLI pipelines, OSINT pivots, icons.
 * Version 2.0.0
 * Exposed as the global `WB`. Author: Pratik (https://github.com/pratik-khairnar-sec) */
(function (g) {
  'use strict';

  const CDX = 'https://web.archive.org/cdx/search/cdx';

  const MODES = {
    domain:    { label: 'Main domain',     hint: 'Every archived path on this host',            icon: 'globe'     },
    wildcard:  { label: 'All subdomains',  hint: 'The host plus every subdomain',               icon: 'network'   },
    path:      { label: 'This path',       hint: 'Everything beneath the current path',         icon: 'folder'    },
    api:       { label: 'APIs & Swagger',  hint: 'REST endpoints, GraphQL, Swagger/OpenAPI',    icon: 'zap'       },
    sensitive: { label: 'Sensitive files', hint: 'Backups, dumps, keys, configs, logs',         icon: 'lock'      },
    js:        { label: 'JavaScript',      hint: 'Old bundles leak endpoints and secrets',      icon: 'code'      },
    params:    { label: 'With parameters', hint: 'Query-string URLs worth fuzzing',             icon: 'sliders'   },
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
      if (mode === 'api')       p.append('filter', 'original:.*(api/|graphql|swagger|openapi|api-docs|/v[0-9]+/|rest/).*');
    }
    if (opts.liveOnly) p.append('filter', 'statuscode:200');
    p.set('fl', 'timestamp,original,statuscode,mimetype');
    p.set('collapse', 'urlkey');
    p.set('output', 'text');
    p.set('limit', String(opts.limit || 100000));
    return `${CDX}?${p.toString()}`;
  }

  /* ---------- classification & heuristics ---------- */
  const CAT_META = {
    secrets:  { label: 'Keys and secrets',     risk: 3 },
    database: { label: 'Databases and dumps',  risk: 3 },
    api:      { label: 'APIs and Swagger',     risk: 2 },
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

  /* Vulnerability parameter archetypes for high-impact fuzzing */
  const VULN_PARAM_PATTERNS = {
    ssrf: /^(url|dest|destination|redirect|uri|path|next|return|return_to|target|domain|rurl|link|src|feed|host|port|to|out|view|dir|show|navigation|open|val|callback|window|data|reference|site|html)$/i,
    lfi:  /^(file|document|folder|root|page|include|doc|pdf|read|template|layout|cat|action|board|date|detail|download|prefix|filename|module)$/i,
    sqli: /^(id|user_id|uid|account|order_id|role|query|search|key|no|num|select|where|sort|filter|order|column|row|group|report|tbl|table)$/i,
    auth: /^(token|api_key|apikey|secret|jwt|access_token|auth|signature|sig|bearer|hash|code|passwd|password|pass|admin|credential|session|sid)$/i,
  };

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

    // API & Swagger Detection
    const isApi = /(^|\/)(api|graphql|swagger|openapi|api-docs|rest|v[0-9]+)(\/|$|\.)/i.test(r.path) ||
                  /swagger\.(json|yaml)|openapi\.(json|yaml)/i.test(base);
    r.isApi = isApi;
    if (isApi && (cat === 'other' || cat === 'data')) cat = 'api';

    let risk = RISK_EXT[ext] ?? CAT_META[cat].risk;
    if (/(^|\/)\.git(\/|$)/i.test(r.path) || base.startsWith('.env') ||
        /^(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.htpasswd)$/.test(base) || base.startsWith('wp-config')) {
      cat = 'secrets'; risk = 3;
    }
    r.cat = cat;
    r.risk = risk;
    const st = r.status || '-';
    r.sg = st === '200' ? '200' : st === '404' ? '404' : st[0] === '3' ? '3xx' : st[0] === '4' ? '4xx' : st[0] === '5' ? '5xx' : 'none';

    // Query Parameter Mining & Vulnerability Classification
    r.params = [];
    r.vulnTypes = [];
    if (r.hasParams) {
      const q = r.query.replace(/^\?/, '');
      for (const pair of q.split('&')) {
        const k = pair.split('=')[0]?.trim();
        if (k) {
          const lk = k.toLowerCase();
          if (!r.params.includes(lk)) r.params.push(lk);
          for (const [vtype, re] of Object.entries(VULN_PARAM_PATTERNS)) {
            if (re.test(lk) && !r.vulnTypes.includes(vtype)) {
              r.vulnTypes.push(vtype);
            }
          }
        }
      }
    }
    r.hasVulnParam = r.vulnTypes.length > 0;
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

  function extractParams(rows) {
    const counts = new Map();
    const types = new Map();
    for (const r of rows) {
      if (!r.params) continue;
      for (const p of r.params) {
        counts.set(p, (counts.get(p) || 0) + 1);
        if (!types.has(p)) {
          const matched = [];
          for (const [vtype, re] of Object.entries(VULN_PARAM_PATTERNS)) {
            if (re.test(p)) matched.push(vtype);
          }
          types.set(p, matched);
        }
      }
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => ({ name, count, vulnTypes: types.get(name) || [] }));
  }

  const snapshotUrl = r => `https://web.archive.org/web/${r.ts}/${r.url}`;
  const isHttp = s => /^https?:\/\//i.test(s);

  /* ---------- CLI Command Pipelines ---------- */
  function getCliPipelines(host) {
    const cleanHost = (host || 'target.com').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    return [
      {
        id: 'nuclei',
        name: 'Nuclei Vulnerability Scan',
        desc: 'Scan discovered archived URLs for known CVEs and high-severity misconfigurations.',
        cmd: `nuclei -l wayback-${cleanHost}-urls.txt -t cves/,vulnerabilities/ -es info -rate-limit 150`,
      },
      {
        id: 'ffuf',
        name: 'FFuF Parameter Fuzzing',
        desc: 'Fuzz endpoints with extracted high-risk query parameter wordlists.',
        cmd: `ffuf -w wayback-${cleanHost}-params.txt -u "https://${cleanHost}/?FUZZ=FUZZ" -mc 200,301,302,401,403`,
      },
      {
        id: 'httpx',
        name: 'HTTPx Live Verification & Tech Stack',
        desc: 'Probe extracted subdomains for live HTTP 200, titles, and technologies.',
        cmd: `httpx -l wayback-${cleanHost}-hosts.txt -title -status-code -tech-detect -follow-redirects`,
      },
      {
        id: 'dalfox',
        name: 'Dalfox XSS Scanner',
        desc: 'Test parameterized archived URLs for Reflected and DOM XSS.',
        cmd: `dalfox file wayback-${cleanHost}-urls.txt --silence --mass`,
      },
      {
        id: 'sqlmap',
        name: 'SQLmap Automated Injection',
        desc: 'Automated SQL injection audit on all endpoints containing parameters.',
        cmd: `sqlmap -m wayback-${cleanHost}-urls.txt --batch --dbs --random-agent`,
      },
      {
        id: 'arjun',
        name: 'Arjun Parameter Discovery',
        desc: 'Find hidden HTTP parameters on target host using passive archive wordlists.',
        cmd: `arjun -u "https://${cleanHost}" --passive wayback`,
      },
    ];
  }

  /* ---------- OSINT Pivots ---------- */
  function getOsintPivots(host) {
    const cleanHost = (host || 'target.com').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    return [
      { name: 'Shodan', icon: 'crosshair', url: `https://www.shodan.io/search?query=hostname%3A${encodeURIComponent(cleanHost)}`, desc: 'Open ports, SSL certs, exposed services' },
      { name: 'Crt.sh', icon: 'shield', url: `https://crt.sh/?q=%25.${encodeURIComponent(cleanHost)}`, desc: 'Certificate Transparency certificate history' },
      { name: 'URLScan.io', icon: 'search', url: `https://urlscan.io/search/#${encodeURIComponent(cleanHost)}`, desc: 'Automated page scans & DOM tech stack' },
      { name: 'VirusTotal', icon: 'shield', url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(cleanHost)}`, desc: 'Malware & historical DNS records' },
      { name: 'AlienVault OTX', icon: 'network', url: `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(cleanHost)}`, desc: 'Open Threat Exchange threat intelligence' },
      { name: 'Google Dork: Secrets', icon: 'lock', url: `https://www.google.com/search?q=site%3A${encodeURIComponent(cleanHost)}+ext%3Aenv+OR+ext%3Asql+OR+ext%3Akey+OR+ext%3Abak`, desc: 'Find exposed .env, .sql, and private keys' },
      { name: 'Google Dork: Subdomains', icon: 'globe', url: `https://www.google.com/search?q=site%3A*.${encodeURIComponent(cleanHost)}+-site%3Awww.${encodeURIComponent(cleanHost)}`, desc: 'Discover non-standard subdomains' },
      { name: 'Wayback Calendar', icon: 'calendar', url: `https://web.archive.org/web/*/${encodeURIComponent(cleanHost)}`, desc: 'Visual timeline of historical snapshot dates' },
    ];
  }

  /* ---------- exports ---------- */
  const csvCell = v => `"${String(v).replace(/"/g, '""')}"`;
  function serialize(rows, format) {
    if (format === 'json') return JSON.stringify(rows.map(r => ({
      url: r.url, host: r.host, category: r.cat, risk: r.risk, status: r.status, mime: r.mime, archived: r.ts,
      isApi: r.isApi, params: r.params, vulnTypes: r.vulnTypes
    })), null, 2);
    if (format === 'csv') return ['url,host,category,risk,status,mime,archived,is_api,vuln_params']
      .concat(rows.map(r => [r.url, r.host, r.cat, r.risk, r.status, r.mime, r.ts, r.isApi ? 'yes' : 'no', (r.vulnTypes || []).join(';')].map(csvCell).join(','))).join('\n');
    if (format === 'hosts') return [...new Set(rows.map(r => r.host))].sort().join('\n');
    if (format === 'params') {
      const pList = extractParams(rows).map(p => p.name);
      return pList.join('\n');
    }
    return rows.map(r => r.url).join('\n');
  }

  /* ---------- icon sprite (inline: no CDN, works offline) ---------- */
  const ICONS = {
    globe:     '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3.2 3.4 3.2 14.6 0 18M12 3c-3.2 3.4-3.2 14.6 0 18"/>',
    network:   '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5H5v5M12 11.5h7v5"/>',
    folder:    '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    lock:      '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    code:      '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 6l-3 12"/>',
    sliders:   '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    copy:      '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
    ext:       '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    clock:     '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    down:      '<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>',
    search:    '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.2-4.2"/>',
    link:      '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    stop:      '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    retry:     '<path d="M20 12a8 8 0 1 1-2.5-5.8M20 4v5h-5"/>',
    zap:       '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    terminal:  '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    crosshair: '<circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/>',
    shield:    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    calendar:  '<rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/>',
    close:     '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    check:     '<polyline points="20 6 9 17 4 12"/>',
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

  g.WB = {
    MODES,
    CAT_META,
    STATUS_META,
    VULN_PARAM_PATTERNS,
    parseTarget,
    buildQuery,
    parse,
    enrich,
    extractParams,
    getCliPipelines,
    getOsintPivots,
    snapshotUrl,
    isHttp,
    serialize,
    injectIcons,
    icon
  };
})(globalThis);
