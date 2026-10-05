document.addEventListener('DOMContentLoaded', async () => {
  WB.injectIcons();
  const $ = id => document.getElementById(id);
  const input = $('target'), scope = $('scope'), modesEl = $('modes'), qprev = $('qprev');
  const live = $('live'), limit = $('limit'), recentEl = $('recent'), toast = $('toast');
  const DEFAULT_PREVIEW = qprev.textContent;
  const store = chrome.storage.local;

  /* scan buttons (generated from WB.MODES so popup and results never drift apart) */
  for (const [key, m] of Object.entries(WB.MODES)) {
    const b = document.createElement('button');
    b.className = 'mode';
    b.dataset.mode = key;
    b.append(WB.icon(m.icon));
    const t = document.createElement('span');
    t.innerHTML = `<b></b><small></small>`;
    t.querySelector('b').textContent = m.label;
    t.querySelector('small').textContent = m.hint;
    b.append(t);
    b.addEventListener('click', () => run(key));
    for (const ev of ['mouseenter', 'focus']) b.addEventListener(ev, () => preview(key));
    for (const ev of ['mouseleave', 'blur'])  b.addEventListener(ev, () => (qprev.textContent = DEFAULT_PREVIEW));
    modesEl.append(b);
  }

  const opts = () => ({ liveOnly: live.checked, limit: Number(limit.value) });

  function preview(mode) {
    const q = WB.buildQuery(mode, input.value, opts());
    qprev.textContent = q ? decodeURIComponent(q.replace('https://web.archive.org/cdx/search/cdx?', 'cdx?')) : 'Enter a valid domain or URL first.';
  }

  function refreshScope() {
    const t = WB.parseTarget(input.value);
    scope.textContent = t ? t.root : (input.value.trim() ? 'invalid' : '');
    scope.classList.toggle('bad', !t && !!input.value.trim());
  }

  function warn(msg) {
    toast.textContent = msg; toast.classList.add('show');
    clearTimeout(warn.t); warn.t = setTimeout(() => toast.classList.remove('show'), 2600);
  }

  async function run(mode) {
    const t = WB.parseTarget(input.value);
    if (!t) { warn('Enter a valid domain or URL, for example example.com.'); input.focus(); return; }
    const { recent = [] } = await store.get('recent');
    await store.set({ recent: [t.root, ...recent.filter(r => r !== t.root)].slice(0, 5), opts: opts() });
    const params = new URLSearchParams({ mode, target: input.value.trim(), limit: limit.value });
    if (live.checked) params.set('live', '1');
    await chrome.tabs.create({ url: chrome.runtime.getURL('results.html?' + params) });
    window.close();
  }

  /* state restore */
  const { opts: saved = {}, recent = [] } = await store.get(['opts', 'recent']);
  live.checked = !!saved.liveOnly;
  if (saved.limit) limit.value = String(saved.limit);
  if (recent.length) {
    recentEl.hidden = false;
    for (const r of recent) {
      const b = document.createElement('button');
      b.textContent = r;
      b.addEventListener('click', () => { input.value = r; refreshScope(); input.focus(); });
      recentEl.append(b);
    }
  }
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const url = tabs[0]?.url;
    if (url && /^https?:/.test(url)) input.value = url;
    refreshScope();
  });

  input.addEventListener('input', refreshScope);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') run('domain'); });
  input.focus();
  input.select();
});
