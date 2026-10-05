document.addEventListener('DOMContentLoaded', () => {
  WB.injectIcons();
  const $ = id => document.getElementById(id);
  const P = new URLSearchParams(location.search);
  const mode = P.get('mode'), targetRaw = P.get('target') || '';
  const opts = { liveOnly: P.get('live') === '1', limit: Number(P.get('limit')) || 100000 };
  const target = WB.parseTarget(targetRaw);
  const query = WB.buildQuery(mode, target, opts);
  const PAGE = 300, TIMEOUT_MS = 90000;

  const S = { all: [], view: [], cats: new Set(), status: new Set(), liveOnly: false, host: null, q: '', rx: false, params: false, sort: 'risk', shown: PAGE };
  let ctl, vctl, timedOut = false;
  const LIVE_CAP = 500, LIVE_WORKERS = 8, LIVE_TIMEOUT = 8000;

  /* ---------- header ---------- */
  document.title = `${target ? target.root : 'Results'} - Wayback Lens`;
  $('modeName').textContent = WB.MODES[mode]?.label || 'Scan';
  $('host').textContent = target ? (mode === 'path' ? target.origin + target.path : target.root) : '';
  $('qline').textContent = query ? decodeURIComponent(query.replace('https://web.archive.org/cdx/search/cdx?', 'cdx?')) : '';

  function toast(msg) {
    const t = $('toast'); t.textContent = msg; t.classList.add('show');
    clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 2200);
  }
  const copy = async (text, msg) => { try { await navigator.clipboard.writeText(text); toast(msg); } catch { toast('Copy blocked by the browser.'); } };
  $('copyQ').addEventListener('click', () => query && copy(query, 'Request URL copied'));

  /* ---------- fetching (streamed, cancellable, with a timeout) ---------- */
  function setStatus(kind, text) {
    const el = $('status');
    el.className = 'status ' + kind;
    $('statusText').textContent = text;
    $('cancel').hidden = kind !== '';
    $('retry').hidden = kind !== 'fail';
  }

  async function load() {
    if (!query) { setStatus('fail', 'That target is not a valid domain or URL. Reopen the extension and try again.'); return; }
    setStatus('', 'Contacting the Wayback Machine');
    ctl = new AbortController(); timedOut = false;
    const timer = setTimeout(() => { timedOut = true; ctl.abort(); }, TIMEOUT_MS);
    const t0 = performance.now();
    try {
      const res = await fetch(query, { signal: ctl.signal });
      if (res.status === 429) throw new Error('The Wayback Machine is rate-limiting you. Wait a minute, then retry.');
      if (!res.ok) throw new Error(`The Wayback Machine returned HTTP ${res.status}. Retry shortly, or narrow the scope.`);
      const reader = res.body.getReader(), dec = new TextDecoder();
      let text = '', lines = 0, last = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = dec.decode(value, { stream: true });
        text += chunk;
        for (let i = chunk.indexOf('\n'); i !== -1; i = chunk.indexOf('\n', i + 1)) lines++;
        if (performance.now() - last > 150) { setStatus('', `Receiving archived URLs: ${lines.toLocaleString()} so far`); last = performance.now(); }
      }
      S.all = WB.parse(text);
      const secs = ((performance.now() - t0) / 1000).toFixed(1);
      if (!S.all.length) { setStatus('done', `No archived URLs found (${secs} s).`); showEmpty('Nothing archived for this scope', 'Try All subdomains, a shorter path, or switch off the 200-only filter.'); return; }
      const capped = S.all.length >= opts.limit ? ` Capped at ${opts.limit.toLocaleString()}; raise the limit in the popup for more.` : '';
      setStatus('done', `Loaded ${S.all.length.toLocaleString()} URLs in ${secs} s.${capped}`);
      init();
    } catch (e) {
      const msg = timedOut ? 'Timed out after 90 s. Use a narrower scope or a lower limit.'
        : e.name === 'AbortError' ? 'Cancelled.'
        : e instanceof TypeError ? 'Could not reach web.archive.org. Check your connection, then retry.'
        : e.message;
      setStatus('fail', msg);
    } finally { clearTimeout(timer); }
  }
  $('cancel').addEventListener('click', () => { ctl && ctl.abort(); vctl && vctl.abort(); });
  $('retry').addEventListener('click', load);

  /* ---------- facets ---------- */
  function counts(key) { const m = new Map(); for (const r of S.all) m.set(r[key], (m.get(r[key]) || 0) + 1); return m; }
  function facetButton(label, n, pressed, onClick, extra = {}) {
    const li = document.createElement('li'), b = document.createElement('button');
    b.setAttribute('aria-pressed', String(pressed));
    if (extra.risk != null) { const rk = document.createElement('i'); rk.className = 'rk r' + extra.risk; b.append(rk); }
    const l = document.createElement('span'); l.className = 'l' + (extra.mono ? ' m' : ''); l.textContent = label; l.title = label;
    const c = document.createElement('span'); c.className = 'n'; c.textContent = n.toLocaleString();
    b.append(l, c); b.addEventListener('click', onClick); li.append(b); return li;
  }
  function renderFacets() {
    const cats = $('cats'); cats.replaceChildren();
    [...counts('cat')].sort((a, b) => WB.CAT_META[b[0]].risk - WB.CAT_META[a[0]].risk || b[1] - a[1]).forEach(([k, n]) =>
      cats.append(facetButton(WB.CAT_META[k].label, n, S.cats.has(k), () => { S.cats.has(k) ? S.cats.delete(k) : S.cats.add(k); apply(); }, { risk: WB.CAT_META[k].risk })));
    const sts = $('statuses'); sts.replaceChildren();
    const sc = counts('sg');
    ['200', '3xx', '404', '4xx', '5xx', 'none'].filter(k => sc.has(k)).forEach(k =>
      sts.append(facetButton(WB.STATUS_META[k], sc.get(k), S.status.has(k), () => { S.status.has(k) ? S.status.delete(k) : S.status.add(k); apply(); })));
    const hosts = $('hosts'); hosts.replaceChildren();
    [...counts('host')].sort((a, b) => b[1] - a[1]).slice(0, 25).forEach(([h, n]) =>
      hosts.append(facetButton(h, n, S.host === h, () => { S.host = S.host === h ? null : h; apply(); }, { mono: true })));
  }

  /* ---------- filter, sort, render ---------- */
  const sorters = {
    risk: (a, b) => b.risk - a.risk || (a.url < b.url ? -1 : 1),
    new: (a, b) => (a.ts < b.ts ? 1 : -1),
    old: (a, b) => (a.ts > b.ts ? 1 : -1),
    az: (a, b) => (a.url < b.url ? -1 : 1),
  };
  function apply(resetPage = true) {
    let test = null, bad = false;
    if (S.q) {
      if (S.rx) { try { const re = new RegExp(S.q, 'i'); test = r => re.test(r.url); } catch { bad = true; } }
      else { const needle = S.q.toLowerCase(); test = r => r.url.toLowerCase().includes(needle); }
    }
    document.querySelector('.search').classList.toggle('bad', bad);
    S.view = S.all.filter(r =>
      (!S.cats.size || S.cats.has(r.cat)) && (!S.status.size || S.status.has(r.sg)) && (!S.liveOnly || (r.live >= 200 && r.live < 300)) && (!S.host || r.host === S.host) && (!S.params || r.hasParams) && (!test || test(r)));
    $('only200').checked = S.status.size === 1 && S.status.has('200');
    const rst = $('resetFilters');
    if (rst) rst.hidden = !(S.cats.size || S.status.size || S.host || S.q || S.params || S.liveOnly);
    S.view.sort(sorters[S.sort]);
    if (resetPage) S.shown = PAGE;
    renderFacets(); renderList();
  }

  function row(r) {
    const li = document.createElement('li'); li.className = 'row r' + r.risk;
    const rail = document.createElement('span'); rail.className = 'rail';
    const a = document.createElement('a'); a.className = 'u';
    if (WB.isHttp(r.url)) { a.href = WB.snapshotUrl(r); a.target = '_blank'; a.rel = 'noopener noreferrer'; }
    a.title = 'Open the archived snapshot';
    for (const [cls, txt] of [['h', r.host], ['p', r.path || '/'], ['s', r.query]]) { if (!txt) continue; const s = document.createElement('span'); s.className = cls; s.textContent = txt; a.append(s); }
    const tag = document.createElement('span'); tag.className = 'tag'; tag.textContent = WB.CAT_META[r.cat].label;
    const meta = document.createElement('span'); meta.className = 'meta';
    const st = document.createElement('span'); st.className = 'st-' + r.status[0]; st.textContent = r.status;
    meta.append(`${r.year} `, st);
    if (r.live !== undefined) {
      const lv = document.createElement('span'); lv.className = 'live st-' + String(r.live)[0];
      lv.textContent = r.live === 0 ? 'live: no reply' : `live ${r.live}`; meta.append(lv);
    }
    const acts = document.createElement('span'); acts.className = 'acts';
    const cp = document.createElement('button'); cp.title = 'Copy URL'; cp.setAttribute('aria-label', 'Copy URL'); cp.append(WB.icon('copy'));
    cp.addEventListener('click', () => copy(r.url, 'URL copied'));
    acts.append(cp);
    if (WB.isHttp(r.url)) {
      const lv = document.createElement('a'); lv.href = r.url; lv.target = '_blank'; lv.rel = 'noopener noreferrer';
      lv.title = 'Open the live URL (authorized targets only)'; lv.setAttribute('aria-label', 'Open live URL'); lv.append(WB.icon('ext')); acts.append(lv);
    }
    li.append(rail, a, tag, meta, acts); return li;
  }

  function renderList() {
    const list = $('list'); list.replaceChildren();
    const slice = S.view.slice(0, S.shown), frag = document.createDocumentFragment();
    for (const r of slice) frag.append(row(r));
    list.append(frag);
    $('count').textContent = `${S.view.length.toLocaleString()} of ${S.all.length.toLocaleString()} URLs`;
    const left = S.view.length - slice.length, more = $('more');
    more.hidden = left <= 0; more.textContent = `Show ${Math.min(PAGE, left).toLocaleString()} more (${left.toLocaleString()} remaining)`;
    list.hidden = !S.view.length;
    if (S.view.length) $('empty').hidden = true; else showEmpty('No URLs match these filters', 'Clear a file type, host or search term to widen the list.');
  }
  function showEmpty(title, body) {
    const e = $('empty'); e.hidden = false; e.replaceChildren();
    const b = document.createElement('b'); b.textContent = title; e.append(b, body);
  }

  /* ---------- wiring ---------- */
  function init() {
    $('stats').hidden = false; $('app').hidden = false;
    $('sTotal').textContent = S.all.length.toLocaleString();
    $('sHosts').textContent = new Set(S.all.map(r => r.host)).size.toLocaleString();
    $('sParams').textContent = S.all.filter(r => r.hasParams).length.toLocaleString();
    $('sRisk').textContent = S.all.filter(r => r.risk >= 3).length.toLocaleString();
    apply();
  }
  let deb;
  $('q').addEventListener('input', e => { clearTimeout(deb); deb = setTimeout(() => { S.q = e.target.value.trim(); apply(); }, 120); });
  $('rx').addEventListener('click', e => { S.rx = !S.rx; e.currentTarget.setAttribute('aria-pressed', String(S.rx)); apply(); });
  $('onlyParams').addEventListener('change', e => { S.params = e.target.checked; apply(); });
  $('only200').addEventListener('change', e => { S.status = e.target.checked ? new Set(['200']) : new Set(); apply(); });
  $('liveOnly').addEventListener('change', e => { S.liveOnly = e.target.checked; apply(); });
  $('resetFilters')?.addEventListener('click', () => {
    S.cats.clear(); S.status.clear(); S.host = null; S.q = ''; $('q').value = '';
    S.params = false; $('onlyParams').checked = false; $('only200').checked = false;
    S.liveOnly = false; const lo = $('liveOnly'); if (lo) lo.checked = false;
    apply();
  });
  window.addEventListener('keydown', e => {
    const active = document.activeElement;
    if (e.key === '/' && active !== $('q') && !['INPUT', 'TEXTAREA', 'SELECT'].includes(active?.tagName)) {
      e.preventDefault();
      $('q').focus();
      $('q').select();
    } else if (e.key === 'Escape' && active === $('q')) {
      if ($('q').value) { $('q').value = ''; S.q = ''; apply(); }
      $('q').blur();
    }
  });
  $('verify').addEventListener('click', verifyLive);
  $('sort').addEventListener('change', e => { S.sort = e.target.value; apply(); });
  $('more').addEventListener('click', () => { S.shown += PAGE; renderList(); });

  document.querySelector('.exports').addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b || !b.dataset.exp || !S.view.length) return;
    const fmt = b.dataset.exp, body = WB.serialize(S.view, fmt === 'copy' ? 'txt' : fmt);
    if (fmt === 'copy') return copy(body, `${S.view.length.toLocaleString()} URLs copied`);
    const ext = fmt === 'hosts' ? 'txt' : fmt;
    const mime = { json: 'application/json', csv: 'text/csv' }[fmt] || 'text/plain';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([body], { type: mime + ';charset=utf-8' }));
    a.download = `wayback-${target.root}-${mode}${fmt === 'hosts' ? '-hosts' : ''}-${new Date().toISOString().slice(0, 10)}.${ext}`;
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    toast(`Saved ${a.download}`);
  });

  /* ---------- live verification (optional, user-initiated) ---------- */
  async function probe(url, signal) {
    const t = new AbortController(), onAbort = () => t.abort(), timer = setTimeout(() => t.abort(), LIVE_TIMEOUT);
    signal.addEventListener('abort', onAbort);
    const init = { redirect: 'follow', credentials: 'omit', cache: 'no-store', signal: t.signal };
    try {
      let res = await fetch(url, { ...init, method: 'HEAD' });
      if (res.status === 405 || res.status === 501) { res = await fetch(url, { ...init, method: 'GET' }); try { res.body && res.body.cancel(); } catch {} }
      return res.status;
    } catch { return signal.aborted ? undefined : 0; }
    finally { clearTimeout(timer); signal.removeEventListener('abort', onAbort); }
  }

  async function verifyLive() {
    const rows = S.view.filter(r => WB.isHttp(r.url)).slice(0, LIVE_CAP);
    if (!rows.length) return;
    const origins = ['https://*/*', 'http://*/*'];
    let ok = false;
    try { ok = (await chrome.permissions.contains({ origins })) || (await chrome.permissions.request({ origins })); } catch {}
    if (!ok) { toast('Permission is needed to check live URLs.'); return; }
    const hosts = new Set(rows.map(r => r.host)).size;
    if (!confirm(`Send ${rows.length} HEAD requests to ${hosts} host(s)?\n\nThe highest-risk URLs in the current view are checked first. Only do this for targets that are in scope or that you are authorized to test.`)) return;

    vctl = new AbortController();
    let next = 0, done = 0;
    setStatus('', `Verifying live URLs: 0 of ${rows.length}`);
    const worker = async () => {
      while (next < rows.length && !vctl.signal.aborted) {
        const r = rows[next++]; r.live = await probe(r.url, vctl.signal);
        if (++done % 10 === 0) setStatus('', `Verifying live URLs: ${done} of ${rows.length}`);
      }
    };
    await Promise.all(Array.from({ length: LIVE_WORKERS }, worker));
    const stopped = vctl.signal.aborted; vctl = null;
    const alive = rows.filter(r => r.live >= 200 && r.live < 300).length;
    setStatus('done', `${stopped ? 'Stopped. ' : ''}Checked ${done} URLs: ${alive} responded with 2xx. Archived status is from the capture; "live" is what the server says now.`);
    $('liveWrap').hidden = false;
    renderList();
  }

  load();
});
