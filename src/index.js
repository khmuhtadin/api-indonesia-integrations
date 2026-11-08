// API Indonesia integrations for Notion and Linear.
// Cloudflare Worker, plain JavaScript, no build step.

const API_BASE = 'https://use.apiindonesia.id/api/v1';
const NOTION_VERSION = '2022-06-28';
const DB_TITLE = 'Hari Libur Indonesia';
const LABEL_NAME = 'Holiday';
const SESSION_COOKIE = 'aii_s';
const SESSION_TTL = 60 * 60 * 24; // 1 day

const TYPE_LABEL = {
  nasional: 'Libur nasional',
  keagamaan: 'Libur keagamaan',
  cuti_bersama: 'Cuti bersama',
};

// ---------- small helpers ----------

const now = () => Math.floor(Date.now() / 1000);

function wibDate(offsetDays = 0) {
  const d = new Date(Date.now() + 7 * 3600 * 1000 + offsetDays * 86400 * 1000);
  return d.toISOString().slice(0, 10);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function b64(buf) {
  let s = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function unb64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
const b64url = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));

function randomId(bytes = 24) {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- crypto: AES-GCM for stored tokens/keys, HMAC for the session cookie ----------

async function aesKey(env) {
  return crypto.subtle.importKey('raw', unb64(env.ENC_KEY), 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encrypt(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), new TextEncoder().encode(text));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return b64(out);
}
async function decrypt(env, data) {
  const raw = unb64(data);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, await aesKey(env), raw.slice(12));
  return new TextDecoder().decode(pt);
}
async function hmacKey(env) {
  const material = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('session:' + env.ENC_KEY));
  return crypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function makeSession(env, kind, id) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ k: kind, id, exp: now() + SESSION_TTL })));
  const sig = b64url(await crypto.subtle.sign('HMAC', await hmacKey(env), new TextEncoder().encode(payload)));
  return `${payload}.${sig}`;
}
async function readSession(env, request, kind) {
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`));
  if (!m) return null;
  const [payload, sig] = m[1].split('.');
  if (!payload || !sig) return null;
  const ok = await crypto.subtle.verify('HMAC', await hmacKey(env), unb64url(sig), new TextEncoder().encode(payload));
  if (!ok) return null;
  const data = JSON.parse(new TextDecoder().decode(unb64url(payload)));
  if (data.exp < now() || data.k !== kind) return null;
  return data.id;
}
function sessionCookie(value, maxAge = SESSION_TTL) {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

// ---------- API Indonesia ----------

async function fetchHolidays(apiKey, year) {
  const res = await fetch(`${API_BASE}/libur?tahun=${year}`, { headers: { 'x-api-key': apiKey, 'user-agent': 'api-indonesia-integrations' } });
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* ignore */
  }
  if (!res.ok || !body || body.success === false) {
    const msg = body?.error?.message || body?.message || `HTTP ${res.status}`;
    const err = new Error(`API Indonesia: ${msg}`);
    err.status = res.status;
    throw err;
  }
  return (body.data || []).filter((h) => h.is_active !== 0);
}

// ---------- HTML ----------

const CSS = `
*{box-sizing:border-box}body{margin:0;font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#1d1d1f;background:#fafafa}
main{max-width:720px;margin:0 auto;padding:40px 20px 80px}
header{display:flex;align-items:center;gap:12px;margin-bottom:24px}header img{width:40px;height:40px}
header a{color:inherit;text-decoration:none;font-weight:600}
h1{font-size:28px;line-height:1.25;margin:0 0 8px}h2{font-size:20px;margin:32px 0 8px}
.card{background:#fff;border:1px solid #e5e5e5;border-radius:10px;padding:20px;margin:20px 0}
label{display:block;font-weight:600;margin:12px 0 6px}
input[type=text],input[type=password],select{width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:8px;font:inherit}
button,.btn{display:inline-block;background:#ff4f00;color:#fff;border:0;border-radius:8px;padding:10px 18px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;margin-top:14px}
button.secondary{background:#fff;color:#1d1d1f;border:1px solid #ccc}
.muted{color:#666;font-size:14px}.ok{color:#137333}.err{color:#b3261e}
code{background:#f0f0f0;padding:1px 5px;border-radius:4px;font-size:14px}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}
footer{margin-top:48px;font-size:14px;color:#666}footer a{color:#666}
.radio{display:flex;gap:8px;align-items:center;font-weight:400;margin:6px 0}
`;

function page(title, body, status = 200, headers = {}) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><link rel="icon" href="https://apiindonesia.id/logo.svg"><style>${CSS}</style></head><body><main>
<header><img src="https://apiindonesia.id/logo.svg" alt=""><a href="/">API Indonesia integrations</a></header>
${body}
<footer><a href="/notion">Notion</a> · <a href="/linear">Linear</a> · <a href="/privacy">Privacy</a> · <a href="https://apiindonesia.id/terms">Terms</a> · <a href="https://github.com/khmuhtadin/api-indonesia-integrations">Source code</a> · Support: <a href="mailto:contactmuhtadin@gmail.com">contactmuhtadin@gmail.com</a></footer>
</main></body></html>`;
  return new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8', ...headers } });
}

function errorPage(message, back = '/') {
  return page('Something went wrong', `<h1>Something went wrong</h1><p class="err">${esc(message)}</p><p><a href="${esc(back)}">Go back</a></p>`, 400);
}

function redirect(location, headers = {}) {
  return new Response(null, { status: 302, headers: { location, ...headers } });
}

const KEY_HELP = `<p class="muted">You need an API Indonesia key. Create one at <a href="https://dashboard.apiindonesia.id/register">dashboard.apiindonesia.id</a> (new accounts get a one-time 3,000 credit bonus, no card needed). Each successful API Indonesia request costs 2 credits (Rp2). The key is stored encrypted and is only used to read holiday data for your workspace.</p>`;

function homePage() {
  return page(
    'API Indonesia integrations',
    `<h1>API Indonesia integrations</h1>
<p>Small, open source integrations that bring Indonesian public holidays and cuti bersama (joint leave days, from the SKB 3 Menteri) into the tools your team already uses. Data comes from <a href="https://apiindonesia.id">API Indonesia</a>.</p>
<div class="card"><h2 style="margin-top:0">Notion</h2><p>Creates a "Hari Libur Indonesia" database in a page you choose and fills it with this year's and next year's holidays. New dates are added daily.</p><a class="btn" href="/notion">Set up Notion</a></div>
<div class="card"><h2 style="margin-top:0">Linear</h2><p>Creates an issue, labelled "Holiday", in a team you choose for each Indonesian public holiday or cuti bersama day coming up in the next 14 days (or another window you pick).</p><a class="btn" href="/linear">Set up Linear</a></div>`
  );
}

function notionPage() {
  return page(
    'API Indonesia for Notion',
    `<h1>API Indonesia for Notion</h1>
<p>Keep a "Hari Libur Indonesia" database in your Notion workspace with every Indonesian public holiday and cuti bersama day for the current and next year. Rows come from the official SKB 3 Menteri list served by <a href="https://apiindonesia.id">API Indonesia</a>, and new dates are added automatically once a day.</p>
<div class="card"><h2 style="margin-top:0">Connect</h2>
<form method="post" action="/notion/connect">
<label for="k">Your API Indonesia key</label>
<input id="k" name="api_key" type="password" placeholder="aip_live_..." autocomplete="off" required>
<button type="submit">Connect to Notion</button></form>${KEY_HELP}</div>
<h2>How it works</h2>
<ol>
<li>Paste your API Indonesia key and click <b>Connect to Notion</b>.</li>
<li>In the Notion screen, choose the page where the database should live (you can create an empty page such as "Team calendar" first).</li>
<li>Back here, pick that page. The integration creates a database called <b>Hari Libur Indonesia</b> inside it and fills it.</li>
<li>Once a day the integration checks for new dates (for example when next year's SKB is published) and adds rows that are missing. Existing rows are never edited or deleted, so you can add your own notes.</li>
</ol>
<h2>Database columns</h2>
<table><tr><th>Column</th><th>Content</th></tr>
<tr><td>Nama</td><td>Holiday name, e.g. "Idulfitri 1448 H"</td></tr>
<tr><td>Tanggal</td><td>Date</td></tr>
<tr><td>Jenis</td><td>Libur nasional, Libur keagamaan or Cuti bersama</td></tr>
<tr><td>Cuti Bersama</td><td>Checkbox, ticked for joint leave days</td></tr>
<tr><td>Tahun</td><td>Year</td></tr>
<tr><td>Sumber</td><td>Source decree, e.g. skb-3-menteri-2027</td></tr>
<tr><td>ID</td><td>Stable API Indonesia id used to avoid duplicates</td></tr></table>
<h2>Cost</h2><p>The integration calls the API Indonesia holiday endpoint with your key: two requests per daily check (current and next year), so about 4 credits (Rp4) a day.</p>
<h2>Disconnect</h2><p>Remove "API Indonesia" in Notion under Settings → Connections. When the next sync finds the access token no longer works, all stored data for your workspace is deleted. You can also email <a href="mailto:contactmuhtadin@gmail.com">contactmuhtadin@gmail.com</a> to have it deleted right away. The database in your workspace stays yours.</p>`
  );
}

function linearPage() {
  return page(
    'API Indonesia for Linear',
    `<h1>API Indonesia for Linear</h1>
<p>Plan sprints around Indonesian public holidays and cuti bersama. The integration creates a Linear issue, labelled "Holiday", in the team you pick for every holiday coming up in the next 14 days (7, 30 or 60 days also available). Each issue has the holiday date as its due date. Data comes from the official SKB 3 Menteri list served by <a href="https://apiindonesia.id">API Indonesia</a>.</p>
<div class="card"><h2 style="margin-top:0">Connect</h2>
<form method="post" action="/linear/connect">
<label for="k">Your API Indonesia key</label>
<input id="k" name="api_key" type="password" placeholder="aip_live_..." autocomplete="off" required>
<button type="submit">Connect to Linear</button></form>${KEY_HELP}</div>
<h2>How it works</h2>
<ol>
<li>Paste your API Indonesia key and click <b>Connect to Linear</b>, then approve access in Linear.</li>
<li>Pick the team that should receive holiday issues and how far ahead to look.</li>
<li>The integration uses an existing "Holiday" label (team or workspace) or creates one if it does not exist, then creates one issue per upcoming holiday, for example "Hari libur: Idulfitri 1448 H (Wed, 10 Mar 2027)".</li>
<li>It checks once a day. Each holiday gets one issue only, so nothing is duplicated, and issues are never edited or closed by the integration.</li>
</ol>
<h2>Permissions</h2><p>The app asks for Linear's <code>read</code> and <code>write</code> scopes: read to list your teams and labels, write to create the "Holiday" label and the issues. Actions appear as made by the API Indonesia app.</p>
<h2>Cost</h2><p>Usually one API Indonesia request per day (two around the turn of the year), so 2 to 4 credits (Rp2 to Rp4) a day on your key.</p>
<h2>Disconnect</h2><p>Use the Disconnect button on the setup page, or revoke "API Indonesia" in Linear under Settings → Applications. Disconnecting deletes the stored tokens and your key. Issues already created stay in your workspace.</p>`
  );
}

function privacyPage() {
  return page(
    'Privacy',
    `<h1>Privacy</h1>
<p class="muted">Applies to the API Indonesia integrations for Notion and Linear at integrations.apiindonesia.id. Operated by Khaisa Studio (Khairul Muhtadin), Indonesia. Last updated 8 November 2026.</p>
<h2>What we store</h2>
<ul>
<li>Your API Indonesia key, encrypted (AES-GCM, with a key held only as a Cloudflare Worker secret).</li>
<li>The OAuth access token (and refresh token, for Linear) from Notion or Linear, encrypted the same way.</li>
<li>Workspace identifiers and names, the id of the Notion page and database or the Linear team and label you picked, and the ids of rows or issues the integration created, so it does not create duplicates.</li>
<li>Timestamps of the last sync and the last error message, if any.</li>
</ul>
<h2>What we do not store</h2>
<p>We do not read or store the content of your Notion pages or Linear issues beyond what is listed above. Notion is asked for no user information. We do not use cookies other than a short-lived session cookie for the setup page, and we do not use analytics or trackers on these pages.</p>
<h2>How data is used</h2>
<p>Only to fetch Indonesian holiday data from API Indonesia with your key and write it to the database or team you picked. Requests to API Indonesia are billed to your key (2 credits per successful request) and are covered by the <a href="https://apiindonesia.id/privacy">API Indonesia privacy policy</a>. Data is stored in Cloudflare (Workers and D1).</p>
<h2>How to disconnect and delete your data</h2>
<ul>
<li>Notion: remove "API Indonesia" under Settings → Connections. On the next sync the token stops working and we delete everything stored for that workspace.</li>
<li>Linear: click Disconnect on the setup page (deletes immediately) or revoke the app under Settings → Applications (deleted on the next sync).</li>
<li>Or email <a href="mailto:contactmuhtadin@gmail.com">contactmuhtadin@gmail.com</a> and we will delete it manually.</li>
</ul>
<p>Content the integration already created in your workspace (database rows, issues) stays there and is yours to keep or delete.</p>
<h2>Source code</h2><p>The integration is open source: <a href="https://github.com/khmuhtadin/api-indonesia-integrations">github.com/khmuhtadin/api-indonesia-integrations</a>.</p>`
  );
}

// ---------- shared connect step (validates key, stores pending state) ----------

async function startConnect(request, env, kind) {
  const form = await request.formData();
  const apiKey = String(form.get('api_key') || '').trim();
  if (!/^aip_(live|test)_[A-Za-z0-9_-]{8,}$/.test(apiKey)) return errorPage('That does not look like an API Indonesia key (it starts with aip_live_).', `/${kind}`);
  try {
    await fetchHolidays(apiKey, wibDate().slice(0, 4));
  } catch (e) {
    return errorPage(`Could not use this key: ${e.message}`, `/${kind}`);
  }
  const state = randomId();
  await env.DB.prepare('INSERT INTO pending (state, kind, api_key_enc, created_at) VALUES (?, ?, ?, ?)')
    .bind(state, kind, await encrypt(env, apiKey), now())
    .run();
  const redirectUri = `${env.BASE_URL}/${kind}/callback`;
  if (kind === 'notion') {
    const u = new URL('https://api.notion.com/v1/oauth/authorize');
    u.searchParams.set('client_id', env.NOTION_CLIENT_ID);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('owner', 'user');
    u.searchParams.set('redirect_uri', redirectUri);
    u.searchParams.set('state', state);
    return redirect(u.toString());
  }
  const u = new URL('https://linear.app/oauth/authorize');
  u.searchParams.set('client_id', env.LINEAR_CLIENT_ID);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('scope', 'read,write');
  u.searchParams.set('actor', 'app');
  u.searchParams.set('prompt', 'consent');
  u.searchParams.set('state', state);
  return redirect(u.toString());
}

async function takePending(env, state, kind) {
  if (!state) return null;
  const row = await env.DB.prepare('SELECT * FROM pending WHERE state = ? AND kind = ?').bind(state, kind).first();
  if (!row) return null;
  await env.DB.prepare('DELETE FROM pending WHERE state = ?').bind(state).run();
  if (row.created_at < now() - 3600) return null;
  return row;
}

// ---------- Notion ----------

async function notionApi(token, method, path, body) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch(`https://api.notion.com/v1${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, 'notion-version': NOTION_VERSION, 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 429 && attempt < 2) {
      await sleep(1000 * (Number(res.headers.get('retry-after')) || 1));
      continue;
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(`Notion: ${data.message || res.status}`);
      err.status = res.status;
      err.code = data.code;
      throw err;
    }
    return data;
  }
}

async function notionCallback(request, env) {
  const url = new URL(request.url);
  if (url.searchParams.get('error')) return errorPage(`Notion did not grant access (${url.searchParams.get('error')}).`, '/notion');
  const pending = await takePending(env, url.searchParams.get('state'), 'notion');
  if (!pending) return errorPage('This connect link expired. Please start again.', '/notion');
  const res = await fetch('https://api.notion.com/v1/oauth/token', {
    method: 'POST',
    headers: { authorization: 'Basic ' + btoa(`${env.NOTION_CLIENT_ID}:${env.NOTION_CLIENT_SECRET}`), 'content-type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code: url.searchParams.get('code'), redirect_uri: `${env.BASE_URL}/notion/callback` }),
  });
  const tok = await res.json().catch(() => ({}));
  if (!res.ok || !tok.access_token) return errorPage(`Notion token exchange failed: ${tok.error || res.status}`, '/notion');
  const id = tok.bot_id;
  const existing = await env.DB.prepare('SELECT database_id, page_id FROM notion_installs WHERE id = ?').bind(id).first();
  await env.DB.prepare(
    `INSERT INTO notion_installs (id, workspace_id, workspace_name, access_token_enc, api_key_enc, page_id, database_id, backlog, last_sync, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
     ON CONFLICT(id) DO UPDATE SET workspace_id=excluded.workspace_id, workspace_name=excluded.workspace_name,
       access_token_enc=excluded.access_token_enc, api_key_enc=excluded.api_key_enc, backlog=1, last_error=NULL`
  )
    .bind(id, tok.workspace_id || null, tok.workspace_name || null, await encrypt(env, tok.access_token), pending.api_key_enc, existing?.page_id || null, existing?.database_id || null, now())
    .run();
  return redirect('/notion/setup', { 'set-cookie': sessionCookie(await makeSession(env, 'notion', id)) });
}

function pageTitle(p) {
  for (const prop of Object.values(p.properties || {})) {
    if (prop.type === 'title') return (prop.title || []).map((t) => t.plain_text).join('') || 'Untitled';
  }
  return 'Untitled';
}

async function notionSetupGet(request, env) {
  const id = await readSession(env, request, 'notion');
  if (!id) return redirect('/notion');
  const inst = await env.DB.prepare('SELECT * FROM notion_installs WHERE id = ?').bind(id).first();
  if (!inst) return redirect('/notion');
  const token = await decrypt(env, inst.access_token_enc);
  if (inst.database_id) {
    const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM notion_rows WHERE install_id = ?').bind(id).first();
    return page(
      'API Indonesia for Notion: connected',
      `<h1>Connected to ${esc(inst.workspace_name || 'Notion')}</h1>
<p class="ok">The <b>${DB_TITLE}</b> database is set up with ${count.n} holiday rows.</p>
<p><a class="btn" href="https://www.notion.so/${esc(inst.database_id.replace(/-/g, ''))}" target="_blank" rel="noopener">Open the database in Notion</a></p>
${inst.backlog ? '<p>Some rows are still being added. They will appear within the next sync, or you can run it now.</p>' : ''}
${inst.last_error ? `<p class="err">Last error: ${esc(inst.last_error)}</p>` : ''}
<form method="post" action="/notion/sync"><button type="submit" class="secondary">Sync now</button></form>
<p class="muted">The integration checks for new dates once a day. To disconnect, remove "API Indonesia" in Notion under Settings → Connections.</p>`
    );
  }
  let pages = [];
  try {
    const r = await notionApi(token, 'POST', '/search', { filter: { property: 'object', value: 'page' }, page_size: 50 });
    pages = (r.results || []).filter((p) => p.parent?.type !== 'database_id');
  } catch (e) {
    return errorPage(e.message, '/notion');
  }
  if (!pages.length) {
    return page(
      'Pick a page',
      `<h1>No page shared yet</h1><p>The integration needs access to one page to create the database in. <a href="/notion">Connect again</a> and choose a page in the Notion screen (create an empty page first if you like).</p>`
    );
  }
  const options = pages
    .map((p, i) => `<label class="radio"><input type="radio" name="page_id" value="${esc(p.id)}" ${i === 0 ? 'checked' : ''}> ${esc(pageTitle(p))}</label>`)
    .join('');
  return page(
    'Pick a page',
    `<h1>Where should the database go?</h1><p>Pick the page that will hold the <b>${DB_TITLE}</b> database.</p>
<form method="post" action="/notion/setup" class="card">${options}<button type="submit">Create database</button></form>`
  );
}

const NOTION_PROPS = {
  Nama: { title: {} },
  Tanggal: { date: {} },
  Jenis: {
    select: {
      options: [
        { name: 'Libur nasional', color: 'red' },
        { name: 'Libur keagamaan', color: 'green' },
        { name: 'Cuti bersama', color: 'blue' },
      ],
    },
  },
  'Cuti Bersama': { checkbox: {} },
  Tahun: { number: { format: 'number' } },
  Sumber: { rich_text: {} },
  ID: { rich_text: {} },
};

async function notionSetupPost(request, env, ctx) {
  const id = await readSession(env, request, 'notion');
  if (!id) return redirect('/notion');
  const inst = await env.DB.prepare('SELECT * FROM notion_installs WHERE id = ?').bind(id).first();
  if (!inst) return redirect('/notion');
  const form = await request.formData();
  const pageId = String(form.get('page_id') || '');
  if (!pageId) return redirect('/notion/setup');
  const token = await decrypt(env, inst.access_token_enc);
  let db;
  try {
    db = await notionApi(token, 'POST', '/databases', {
      parent: { type: 'page_id', page_id: pageId },
      title: [{ type: 'text', text: { content: DB_TITLE } }],
      icon: { type: 'emoji', emoji: '📅' },
      properties: NOTION_PROPS,
    });
  } catch (e) {
    return errorPage(e.message, '/notion/setup');
  }
  await env.DB.prepare('UPDATE notion_installs SET page_id = ?, database_id = ?, backlog = 1 WHERE id = ?').bind(pageId, db.id, id).run();
  await env.DB.prepare('DELETE FROM notion_rows WHERE install_id = ?').bind(id).run();
  const fresh = await env.DB.prepare('SELECT * FROM notion_installs WHERE id = ?').bind(id).first();
  await syncNotion(env, fresh, 40);
  return redirect('/notion/setup');
}

async function notionSyncPost(request, env) {
  const id = await readSession(env, request, 'notion');
  if (!id) return redirect('/notion');
  const inst = await env.DB.prepare('SELECT * FROM notion_installs WHERE id = ?').bind(id).first();
  if (inst?.database_id) await syncNotion(env, inst, 40);
  return redirect('/notion/setup');
}

function notionRow(h) {
  return {
    Nama: { title: [{ text: { content: h.name } }] },
    Tanggal: { date: { start: h.date } },
    Jenis: { select: { name: TYPE_LABEL[h.type] || h.type } },
    'Cuti Bersama': { checkbox: !!h.is_joint_leave || h.type === 'cuti_bersama' },
    Tahun: { number: Number(h.year || h.date.slice(0, 4)) },
    Sumber: { rich_text: [{ text: { content: h.source || '' } }] },
    ID: { rich_text: [{ text: { content: h.id } }] },
  };
}

// Returns number of subrequests used.
async function syncNotion(env, inst, budget) {
  let used = 0;
  try {
    const apiKey = await decrypt(env, inst.api_key_enc);
    const token = await decrypt(env, inst.access_token_enc);
    const y = Number(wibDate().slice(0, 4));
    const holidays = [];
    for (const year of [y, y + 1]) {
      used++;
      holidays.push(...(await fetchHolidays(apiKey, year)));
    }
    const done = new Set(
      (await env.DB.prepare('SELECT holiday_id FROM notion_rows WHERE install_id = ?').bind(inst.id).all()).results.map((r) => r.holiday_id)
    );
    const todo = holidays.filter((h) => !done.has(h.id)).sort((a, b) => a.date.localeCompare(b.date));
    let created = 0;
    for (const h of todo) {
      if (used >= budget) break;
      used++;
      const p = await notionApi(token, 'POST', '/pages', { parent: { database_id: inst.database_id }, properties: notionRow(h) });
      await env.DB.prepare('INSERT OR IGNORE INTO notion_rows (install_id, holiday_id, page_id) VALUES (?, ?, ?)').bind(inst.id, h.id, p.id).run();
      created++;
      await sleep(340); // stay under Notion's ~3 requests/second
    }
    const backlog = todo.length > created ? 1 : 0;
    await env.DB.prepare('UPDATE notion_installs SET backlog = ?, last_sync = ?, last_error = NULL WHERE id = ?').bind(backlog, now(), inst.id).run();
  } catch (e) {
    if (e.status === 401 || e.code === 'unauthorized') {
      // Access was removed in Notion: delete everything we hold for this workspace.
      await env.DB.batch([
        env.DB.prepare('DELETE FROM notion_rows WHERE install_id = ?').bind(inst.id),
        env.DB.prepare('DELETE FROM notion_installs WHERE id = ?').bind(inst.id),
      ]);
    } else if (e.code === 'object_not_found') {
      await env.DB.batch([
        env.DB.prepare('UPDATE notion_installs SET database_id = NULL, backlog = 0, last_sync = ?, last_error = ? WHERE id = ?').bind(now(), 'Database not found. Reconnect to create a new one.', inst.id),
        env.DB.prepare('DELETE FROM notion_rows WHERE install_id = ?').bind(inst.id),
      ]);
    } else {
      await env.DB.prepare('UPDATE notion_installs SET last_sync = ?, last_error = ? WHERE id = ?').bind(now(), String(e.message).slice(0, 300), inst.id).run();
    }
  }
  return used;
}

// ---------- Linear ----------

async function linearGql(token, query, variables = {}) {
  const res = await fetch('https://api.linear.app/graphql', {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables }),
  });
  const data = await res.json().catch(() => ({}));
  const authErr = res.status === 401 || (data.errors || []).some((er) => er.extensions?.code === 'AUTHENTICATION_ERROR');
  if (authErr) {
    const err = new Error('Linear: authentication failed');
    err.status = 401;
    throw err;
  }
  if (!res.ok || data.errors) throw new Error(`Linear: ${(data.errors || []).map((er) => er.message).join('; ') || res.status}`);
  return data.data;
}

async function linearTokenRequest(env, params) {
  const res = await fetch('https://api.linear.app/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: env.LINEAR_CLIENT_ID, client_secret: env.LINEAR_CLIENT_SECRET, ...params }),
  });
  const tok = await res.json().catch(() => ({}));
  if (!res.ok || !tok.access_token) {
    const err = new Error(`Linear token request failed: ${tok.error || res.status}`);
    err.status = res.status === 400 || res.status === 401 ? 401 : res.status;
    throw err;
  }
  return tok;
}

// Returns a valid access token, refreshing it if needed.
async function linearToken(env, inst) {
  if (inst.refresh_token_enc && inst.expires_at && inst.expires_at - 300 < now()) {
    const tok = await linearTokenRequest(env, { grant_type: 'refresh_token', refresh_token: await decrypt(env, inst.refresh_token_enc) });
    await env.DB.prepare('UPDATE linear_installs SET access_token_enc = ?, refresh_token_enc = ?, expires_at = ? WHERE id = ?')
      .bind(
        await encrypt(env, tok.access_token),
        tok.refresh_token ? await encrypt(env, tok.refresh_token) : inst.refresh_token_enc,
        tok.expires_in ? now() + Number(tok.expires_in) : null,
        inst.id
      )
      .run();
    return tok.access_token;
  }
  return decrypt(env, inst.access_token_enc);
}

async function linearCallback(request, env) {
  const url = new URL(request.url);
  if (url.searchParams.get('error')) return errorPage(`Linear did not grant access (${url.searchParams.get('error')}).`, '/linear');
  const pending = await takePending(env, url.searchParams.get('state'), 'linear');
  if (!pending) return errorPage('This connect link expired. Please start again.', '/linear');
  let tok;
  try {
    tok = await linearTokenRequest(env, { grant_type: 'authorization_code', code: url.searchParams.get('code'), redirect_uri: `${env.BASE_URL}/linear/callback` });
  } catch (e) {
    return errorPage(e.message, '/linear');
  }
  let org;
  try {
    org = (await linearGql(tok.access_token, '{ organization { id name urlKey } }')).organization;
  } catch (e) {
    return errorPage(e.message, '/linear');
  }
  await env.DB.prepare(
    `INSERT INTO linear_installs (id, org_name, org_key, access_token_enc, refresh_token_enc, expires_at, api_key_enc, backlog, last_sync, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
     ON CONFLICT(id) DO UPDATE SET org_name=excluded.org_name, org_key=excluded.org_key, access_token_enc=excluded.access_token_enc,
       refresh_token_enc=excluded.refresh_token_enc, expires_at=excluded.expires_at, api_key_enc=excluded.api_key_enc, backlog=1, last_error=NULL`
  )
    .bind(
      org.id,
      org.name,
      org.urlKey,
      await encrypt(env, tok.access_token),
      tok.refresh_token ? await encrypt(env, tok.refresh_token) : null,
      tok.expires_in ? now() + Number(tok.expires_in) : null,
      pending.api_key_enc,
      now()
    )
    .run();
  return redirect('/linear/setup', { 'set-cookie': sessionCookie(await makeSession(env, 'linear', org.id)) });
}

async function linearSetupGet(request, env) {
  const id = await readSession(env, request, 'linear');
  if (!id) return redirect('/linear');
  const inst = await env.DB.prepare('SELECT * FROM linear_installs WHERE id = ?').bind(id).first();
  if (!inst) return redirect('/linear');
  let teams;
  try {
    teams = (await linearGql(await linearToken(env, inst), '{ teams(first: 100) { nodes { id name key } } }')).teams.nodes;
  } catch (e) {
    return errorPage(e.message, '/linear');
  }
  const issues = (
    await env.DB.prepare('SELECT issue_identifier FROM linear_issues WHERE install_id = ? AND issue_identifier IS NOT NULL ORDER BY rowid DESC LIMIT 20').bind(id).all()
  ).results;
  const teamOpts = teams.map((t) => `<option value="${esc(t.id)}" ${t.id === inst.team_id ? 'selected' : ''}>${esc(t.name)} (${esc(t.key)})</option>`).join('');
  const dayOpts = [7, 14, 30, 60].map((d) => `<option value="${d}" ${d === inst.days_ahead ? 'selected' : ''}>${d} days</option>`).join('');
  const status = inst.team_id
    ? `<p class="ok">Active for team <b>${esc(inst.team_name)}</b>, looking ${inst.days_ahead} days ahead. Last check: ${inst.last_sync ? new Date(inst.last_sync * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : 'not yet'}.</p>
${issues.length ? `<p>Issues created: ${issues.map((i) => `<a href="https://linear.app/${esc(inst.org_key)}/issue/${esc(i.issue_identifier)}" target="_blank" rel="noopener">${esc(i.issue_identifier)}</a>`).join(', ')}</p>` : '<p>No holiday falls inside the window yet. Issues will appear automatically when one does.</p>'}
${inst.last_error ? `<p class="err">Last error: ${esc(inst.last_error)}</p>` : ''}`
    : '<p>Pick a team to finish setup.</p>';
  return page(
    'API Indonesia for Linear: setup',
    `<h1>Connected to ${esc(inst.org_name)}</h1>${status}
<form method="post" action="/linear/setup" class="card">
<label for="team">Team for holiday issues</label><select id="team" name="team_id">${teamOpts}</select>
<label for="days">Create issues for holidays in the next</label><select id="days" name="days">${dayOpts}</select>
<button type="submit">Save and check now</button></form>
<form method="post" action="/linear/disconnect"><button type="submit" class="secondary">Disconnect and delete my data</button></form>`
  );
}

async function ensureLabel(token, teamId) {
  const q = await linearGql(
    token,
    `query($teamId: String!) { team(id: $teamId) { labels(first: 250) { nodes { id name } } }
       issueLabels(first: 250, filter: { team: { null: true } }) { nodes { id name } } }`,
    { teamId }
  );
  const all = [...(q.team?.labels?.nodes || []), ...(q.issueLabels?.nodes || [])];
  const hit = all.find((l) => l.name.toLowerCase() === LABEL_NAME.toLowerCase());
  if (hit) return hit.id;
  const create = (input) =>
    linearGql(token, `mutation($input: IssueLabelCreateInput!) { issueLabelCreate(input: $input) { success issueLabel { id } } }`, {
      input: { name: LABEL_NAME, color: '#FF4F00', ...input },
    });
  let c;
  try {
    c = await create({ teamId });
  } catch (e) {
    console.error('team label create failed', e.message);
    c = await create({});
  }
  return c.issueLabelCreate.issueLabel.id;
}

async function linearSetupPost(request, env) {
  const id = await readSession(env, request, 'linear');
  if (!id) return redirect('/linear');
  const inst = await env.DB.prepare('SELECT * FROM linear_installs WHERE id = ?').bind(id).first();
  if (!inst) return redirect('/linear');
  const form = await request.formData();
  const teamId = String(form.get('team_id') || '');
  const days = [7, 14, 30, 60].includes(Number(form.get('days'))) ? Number(form.get('days')) : 14;
  let step = 'token';
  try {
    const token = await linearToken(env, inst);
    step = 'team';
    const team = (await linearGql(token, 'query($id: String!) { team(id: $id) { id name } }', { id: teamId })).team;
    step = 'label';
    const labelId = await ensureLabel(token, team.id);
    await env.DB.prepare('UPDATE linear_installs SET team_id = ?, team_name = ?, label_id = ?, days_ahead = ?, backlog = 1 WHERE id = ?')
      .bind(team.id, team.name, labelId, days, id)
      .run();
  } catch (e) {
    console.error('linear setup failed at', step, e.message);
    return errorPage(`${e.message} (step: ${step})`, '/linear/setup');
  }
  const fresh = await env.DB.prepare('SELECT * FROM linear_installs WHERE id = ?').bind(id).first();
  await syncLinear(env, fresh, 40);
  return redirect('/linear/setup');
}

async function linearDisconnect(request, env) {
  const id = await readSession(env, request, 'linear');
  if (!id) return redirect('/linear');
  const inst = await env.DB.prepare('SELECT * FROM linear_installs WHERE id = ?').bind(id).first();
  if (inst) {
    try {
      const token = await decrypt(env, inst.access_token_enc);
      await fetch('https://api.linear.app/oauth/revoke', {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }),
      });
    } catch {
      /* best effort */
    }
    await env.DB.batch([
      env.DB.prepare('DELETE FROM linear_issues WHERE install_id = ?').bind(id),
      env.DB.prepare('DELETE FROM linear_installs WHERE id = ?').bind(id),
    ]);
  }
  return page('Disconnected', '<h1>Disconnected</h1><p>Your tokens, API key and setup for this Linear workspace were deleted. Issues already created stay in Linear.</p>', 200, {
    'set-cookie': sessionCookie('', 0),
  });
}

function fmtDate(iso) {
  const d = new Date(iso + 'T00:00:00Z');
  return d.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

function issueBody(h) {
  const kind = TYPE_LABEL[h.type] || h.type;
  return [
    h.type === 'cuti_bersama'
      ? `**${fmtDate(h.date)}** is a cuti bersama day in Indonesia: **${h.name}**.`
      : `**${fmtDate(h.date)}** is an Indonesian public holiday: **${h.name}** (${kind.toLowerCase()}).`,
    '',
    h.type === 'cuti_bersama'
      ? 'This is a cuti bersama (joint leave) day set by the SKB 3 Menteri. Many companies and government offices close, so plan reviews, releases and on-call around it.'
      : 'Offices and banks in Indonesia are closed. Plan reviews, releases and on-call around it.',
    '',
    `Source: ${h.source || 'SKB 3 Menteri'} via [API Indonesia](https://apiindonesia.id).`,
    '',
    '_Created automatically by the API Indonesia integration. Close or delete this issue whenever you like; it will not be recreated._',
  ].join('\n');
}

async function syncLinear(env, inst, budget) {
  let used = 0;
  try {
    const token = await linearToken(env, inst);
    used++;
    const apiKey = await decrypt(env, inst.api_key_enc);
    const start = wibDate();
    const end = wibDate(inst.days_ahead);
    const years = [...new Set([start.slice(0, 4), end.slice(0, 4)])];
    const holidays = [];
    for (const y of years) {
      used++;
      holidays.push(...(await fetchHolidays(apiKey, y)));
    }
    const done = new Set(
      (await env.DB.prepare('SELECT holiday_id FROM linear_issues WHERE install_id = ?').bind(inst.id).all()).results.map((r) => r.holiday_id)
    );
    const todo = holidays.filter((h) => h.date >= start && h.date <= end && !done.has(h.id)).sort((a, b) => a.date.localeCompare(b.date));
    let created = 0;
    for (const h of todo) {
      if (used >= budget) break;
      used++;
      const r = await linearGql(
        token,
        `mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier } } }`,
        {
          input: {
            teamId: inst.team_id,
            title: `Hari libur: ${h.name} (${fmtDate(h.date)})`,
            description: issueBody(h),
            dueDate: h.date,
            labelIds: inst.label_id ? [inst.label_id] : [],
          },
        }
      );
      const issue = r.issueCreate.issue;
      await env.DB.prepare('INSERT OR IGNORE INTO linear_issues (install_id, holiday_id, issue_id, issue_identifier) VALUES (?, ?, ?, ?)')
        .bind(inst.id, h.id, issue.id, issue.identifier)
        .run();
      created++;
    }
    const backlog = todo.length > created ? 1 : 0;
    await env.DB.prepare('UPDATE linear_installs SET backlog = ?, last_sync = ?, last_error = NULL WHERE id = ?').bind(backlog, now(), inst.id).run();
  } catch (e) {
    if (e.status === 401) {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM linear_issues WHERE install_id = ?').bind(inst.id),
        env.DB.prepare('DELETE FROM linear_installs WHERE id = ?').bind(inst.id),
      ]);
    } else {
      await env.DB.prepare('UPDATE linear_installs SET last_sync = ?, last_error = ? WHERE id = ?').bind(now(), String(e.message).slice(0, 300), inst.id).run();
    }
  }
  return used;
}

// ---------- scheduled ----------

async function runScheduled(env) {
  let budget = Number(env.SUBREQ_BUDGET || 45);
  const cutoff = now() - 23 * 3600;
  await env.DB.prepare('DELETE FROM pending WHERE created_at < ?').bind(now() - 3600).run();
  const notion = (
    await env.DB.prepare('SELECT * FROM notion_installs WHERE database_id IS NOT NULL AND (backlog = 1 OR last_sync < ?) ORDER BY last_sync LIMIT 50').bind(cutoff).all()
  ).results;
  const linear = (
    await env.DB.prepare('SELECT * FROM linear_installs WHERE team_id IS NOT NULL AND (backlog = 1 OR last_sync < ?) ORDER BY last_sync LIMIT 50').bind(cutoff).all()
  ).results;
  // Alternate between the two so neither starves the other.
  const queue = [];
  for (let i = 0; i < Math.max(notion.length, linear.length); i++) {
    if (linear[i]) queue.push(['linear', linear[i]]);
    if (notion[i]) queue.push(['notion', notion[i]]);
  }
  for (const [kind, inst] of queue) {
    if (budget < 6) break;
    const slice = Math.min(budget, 25);
    budget -= kind === 'notion' ? await syncNotion(env, inst, slice) : await syncLinear(env, inst, slice);
  }
}

// ---------- router ----------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+$/, '') || '/';
    const m = request.method;
    try {
      if (m === 'GET' && p === '/') return homePage();
      if (m === 'GET' && p === '/privacy') return privacyPage();
      if (m === 'GET' && p === '/health') return new Response('ok');
      if (m === 'GET' && p === '/notion') return notionPage();
      if (m === 'POST' && p === '/notion/connect') return startConnect(request, env, 'notion');
      if (m === 'GET' && p === '/notion/callback') return notionCallback(request, env);
      if (m === 'GET' && p === '/notion/setup') return notionSetupGet(request, env);
      if (m === 'POST' && p === '/notion/setup') return notionSetupPost(request, env, ctx);
      if (m === 'POST' && p === '/notion/sync') return notionSyncPost(request, env);
      if (m === 'GET' && p === '/linear') return linearPage();
      if (m === 'POST' && p === '/linear/connect') return startConnect(request, env, 'linear');
      if (m === 'GET' && p === '/linear/callback') return linearCallback(request, env);
      if (m === 'GET' && p === '/linear/setup') return linearSetupGet(request, env);
      if (m === 'POST' && p === '/linear/setup') return linearSetupPost(request, env);
      if (m === 'POST' && p === '/linear/disconnect') return linearDisconnect(request, env);
      return page('Not found', '<h1>Not found</h1><p><a href="/">Home</a></p>', 404);
    } catch (e) {
      console.error(e);
      return errorPage('Unexpected error. Please try again or email contactmuhtadin@gmail.com.');
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduled(env));
  },
};
