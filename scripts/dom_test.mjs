/**
 * DOM smoke test for the dashboard client (app.js).
 *
 * Renders dashboard.html inside jsdom with a stubbed API, then asserts the
 * UI actually populates and that the main interactions fire the right calls.
 *
 *     node scripts/dom_test.mjs
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM, VirtualConsole } from 'jsdom';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TPL = join(ROOT, 'app', 'templates', 'dashboard.html');
const JS = join(ROOT, 'app', 'static', 'js', 'app.js');

/* ---------------------------------------------------------------- fixture */
const NOW = Math.floor(Date.now() / 1000);

const OVERVIEW = {
  devices: [
    {
      mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.1.10', hostname: 'tablet',
      custom_name: "Sam's Tablet", name: "Sam's Tablet",
      group_id: 1, group_name: 'Kids', group_color: '#f87171',
      blocked: false, group_blocked: false, approved: true,
      effective_blocked: true, reason: 'Schedule “Bedtime” (21:00–07:00)',
      online: true, first_seen: NOW - 500, last_seen: NOW - 20,
    },
    {
      mac: 'AA:BB:CC:DD:EE:02', ip: '192.168.1.11', hostname: 'living-room-tv',
      custom_name: null, name: 'living-room-tv',
      group_id: 2, group_name: 'Smart TVs', group_color: '#22d3ee',
      blocked: false, group_blocked: false, approved: true,
      effective_blocked: false, reason: null,
      online: false, first_seen: NOW - 900, last_seen: NOW - 800,
    },
    {
      mac: 'AA:BB:CC:DD:EE:03', ip: '192.168.1.12', hostname: null,
      custom_name: null, name: 'AA:BB:CC:DD:EE:03',
      group_id: null, group_name: null, group_color: null,
      blocked: true, group_blocked: false, approved: false,
      effective_blocked: true, reason: 'New device - waiting for approval',
      online: true, first_seen: NOW - 100, last_seen: NOW - 5,
    },
  ],
  groups: [
    { id: 1, name: 'Kids', color: '#f87171', blocked: false, device_count: 1 },
    { id: 2, name: 'Smart TVs', color: '#22d3ee', blocked: true, device_count: 1 },
  ],
  schedules: [
    {
      id: 7, group_id: 1, group_name: 'Kids', group_color: '#f87171',
      name: 'Bedtime', days: [0, 1, 2, 3, 4], start_time: '21:00',
      end_time: '07:00', enabled: true,
    },
  ],
  pauses: [
    {
      id: 3, target_type: 'device', target_id: 'AA:BB:CC:DD:EE:02',
      kind: 'block', label: 'Paused', created_at: NOW - 60,
      expires_at: NOW + 1500, remaining_seconds: 1500, remaining_human: '25m',
    },
  ],
  events: [
    { id: 1, created_at: NOW - 90, level: 'info', source: 'firewall', message: 'Blocked 1 device(s): AA:BB:CC:DD:EE:03' },
    { id: 2, created_at: NOW - 400, level: 'warn', source: 'auth', message: "Failed login for 'root'" },
  ],
  status: {
    gateway: {
      gateway_mode: true, ip_forward: true, subnet: '192.168.1.0/24', nat_configured: true,
      lan_iface: { name: 'eth1', address: '192.168.1.1/24', state: 'UP' },
      wan_iface: { name: 'eth0', address: '10.0.0.2/24', state: 'UP' },
    },
    firewall: {
      binary: 'iptables', chain: 'PCTRL', available: true, dry_run: false,
      mode: 'auto', blocked_count: 2, last_ok: true, last_error: null,
      last_applied: ['AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:03'],
    },
    policy: { blocked_count: 2, applied_at: NOW - 12, error: null, changed: true },
    server_time: NOW,
  },
  settings: {
    lan_iface: 'eth1', wan_iface: 'eth0', gateway_mode: true,
    firewall_mode: 'auto', online_window_minutes: 5, scan_interval_minutes: 10,
    day_names: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
  },
};

const RULES = {
  filter: '-N PCTRL\n-A FORWARD -j PCTRL\n-A PCTRL -m mac --mac-source AA:BB:CC:DD:EE:01 -j DROP\n-A PCTRL -j RETURN',
  nat: '-A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE',
  status: OVERVIEW.status.firewall,
};

/* ------------------------------------------------------------ fetch stub */
const calls = [];

function jsonResponse(data, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    json: async () => structuredClone(data),
  };
}

function router(url, init = {}) {
  const method = (init.method || 'GET').toUpperCase();
  // record decoded URLs: `encodeURIComponent` escapes the colons in MACs
  const path = decodeURIComponent(String(url));
  calls.push({ method, url: path, body: init.body ? JSON.parse(init.body) : null, headers: init.headers || {} });

  if (path === '/api/session') {
    return jsonResponse({ authenticated: true, user: { id: 1, username: 'admin' }, csrf: 'test-csrf', expires_at: NOW + 3600 });
  }
  if (path === '/api/overview') {
    const overview = structuredClone(OVERVIEW);
    if (state.masterPaused) {
      overview.pauses = overview.pauses.concat([{
        id: 99, target_type: 'all', target_id: '*', kind: 'block',
        label: 'Paused (all devices)', created_at: NOW, expires_at: NOW + 3600,
        remaining_seconds: 3600, remaining_human: '1h', indefinite: false,
      }]);
    }
    return jsonResponse(overview);
  }
  if (path === '/api/rules') return jsonResponse(RULES);
  if (path === '/api/logout') return jsonResponse({ ok: true });

  if (path === '/api/pause-all') { state.masterPaused = true; return jsonResponse({ ok: true, paused: true }); }
  if (path === '/api/resume-all') { state.masterPaused = false; return jsonResponse({ ok: true, paused: false }); }

  if (path === '/api/web-rules') {
    return jsonResponse({ rules: state.rules });
  }
  if (path === '/api/dns/status') {
    return jsonResponse({
      running: state.dnsRunning, port: 53, listen_port: 53, interceptable: true,
      bound_to: ['0.0.0.0', 53],
      upstreams: ['1.1.1.1', '8.8.8.8'],
      stats: { queries: 412, blocked: 37, allowed: 375, errors: 0, started_at: NOW - 3600 },
      interception: state.dnsRunning, lan_iface: 'eth1',
      rule_count: state.rules.length, block_rules: 2, allow_rules: 1, dry_run: false,
    });
  }
  if (path.startsWith('/api/dns/queries')) {
    return jsonResponse({
      queries: [
        { ts: NOW - 30, mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.1.10', domain: 'doubleclick.net', action: 'blocked', reason: 'blocked by doubleclick.net', device_name: "Sam's Tablet" },
        { ts: NOW - 90, mac: 'AA:BB:CC:DD:EE:02', ip: '192.168.1.11', domain: 'bbc.co.uk', action: 'allowed', reason: 'no matching rule', device_name: 'living-room-tv' },
      ],
      stats: { total: 412, blocked: 37, allowed: 375, top_blocked: [{ domain: 'doubleclick.net', n: 21 }] },
    });
  }
  if (path === '/api/settings') {
    return jsonResponse({ auto_block_unknown: state.autoBlock, dns_filtering: state.dnsRunning, min_password_length: 8, usage_enabled: true });
  }
  if (path.startsWith('/api/usage')) {
    return jsonResponse({
      range: '24h', label: 'Last 24 hours', granularity: 'raw', since: NOW - 86400, now: NOW,
      timeline: [{ ts: NOW - 3600, up: 1200, down: 8400, total: 9600 }, { ts: NOW - 1800, up: 400, down: 2100, total: 2500 }],
      devices: [
        { mac: 'AA:BB:CC:DD:EE:01', name: "Sam's Tablet", up: 800, down: 6400, total: 7200, percent: 60, group_color: '#f87171' },
        { mac: 'AA:BB:CC:DD:EE:02', name: 'living-room-tv', up: 600, down: 4100, total: 4700, percent: 40, group_color: '#22d3ee' },
      ],
      groups: [
        { group_id: 1, name: 'Kids', color: '#f87171', up: 800, down: 6400, total: 7200, percent: 60, device_count: 1 },
        { group_id: 2, name: 'Smart TVs', color: '#22d3ee', up: 600, down: 4100, total: 4700, percent: 40, device_count: 1 },
      ],
      totals: { up: 1400, down: 10500, total: 11900 },
      row_count: 2, sampling_interval: 60, retention_hours: 48,
    });
  }

  return jsonResponse({ ok: true, device: OVERVIEW.devices[0], pauses: OVERVIEW.pauses });
}

const state = {
  rules: [
    { id: 11, group_id: 0, group_name: null, pattern: 'doubleclick.net', action: 'block', enabled: true, source: 'custom' },
    { id: 12, group_id: 1, group_name: 'Kids', pattern: 'youtube.com', action: 'block', enabled: true, source: 'custom' },
    { id: 13, group_id: 0, group_name: null, pattern: 'school.example.org', action: 'allow', enabled: false, source: 'custom' },
  ],
  dnsRunning: true,
  autoBlock: false,
  masterPaused: false,
};

/* ------------------------------------------------------------------ test */
let PASS = 0;
let FAIL = 0;
const problems = [];

function check(label, cond, detail = '') {
  if (cond) { PASS += 1; console.log(`  ok   ${label}`); }
  else { FAIL += 1; console.log(`  FAIL ${label} ${detail}`); }
}

const html = readFileSync(TPL, 'utf8')
  // templates use `{{ asset('…') }}`; fall back to plain url_for for safety
  .replace(/\{\{\s*(?:url_for\('static',\s*filename='([^']+)'\)|asset\('([^']+)'\))\s*\}\}/g,
    (_m, byUrlFor, byAsset) => '/static/' + (byUrlFor || byAsset))
  // NOTE: use a replacer *function* - a string replacement would interpret
  // `$$`, `$&` etc. inside the JavaScript source as substitution patterns.
  .replace('<script src="/static/js/chart.js"></script>',
    () => `<script>\n${readFileSync(join(ROOT, 'app', 'static', 'js', 'chart.js'), 'utf8')}\n</script>`)
  .replace('<script src="/static/js/app.js"></script>', () => `<script>\n${readFileSync(JS, 'utf8')}\n</script>`);

const virtualConsole = new VirtualConsole();
virtualConsole.on('jsdomError', (e) => problems.push('jsdomError: ' + e.message));
virtualConsole.on('error', (...a) => problems.push('console.error: ' + a.join(' ')));

const dom = new JSDOM(html, {
  runScripts: 'dangerously',
  pretendToBeVisual: true,
  url: 'http://127.0.0.1:8765/',
  virtualConsole,
  beforeParse(window) {
    window.fetch = (url, init) => Promise.resolve(router(String(url), init));
    window.structuredClone = window.structuredClone || ((v) => JSON.parse(JSON.stringify(v)));
  },
});

const { window } = dom;
const { document } = window;

// let the async init() settle
await new Promise((r) => setTimeout(r, 300));
if (problems.length) console.log('DIAGNOSTICS:\n  ' + problems.join('\n  '));

console.log('\n-- initial render --');
check('device rows rendered', document.querySelectorAll('#device-body tr').length === 3,
  String(document.querySelectorAll('#device-body tr').length));
check('group cards rendered', document.querySelectorAll('.group-card').length === 2);
check('schedule rows rendered', document.querySelectorAll('#schedule-body tr').length === 1);
check('timer chip rendered', document.querySelectorAll('.timer-chip').length === 1);
check('stat: devices = 3', document.getElementById('stat-devices').textContent === '3',
  document.getElementById('stat-devices').textContent);
check('stat: blocked = 2', document.getElementById('stat-blocked').textContent === '2',
  document.getElementById('stat-blocked').textContent);
check('stat: timers = 1', document.getElementById('stat-timers').textContent === '1');
check('stat: online = 2', document.getElementById('stat-online').textContent === '2');
check('blocked device flagged', document.querySelectorAll('#device-body tr.is-blocked').length === 2);
check('reason chip shows schedule', /Bedtime/.test(document.querySelector('#device-body').textContent));
check('group card shows block state', /Allow all/.test(document.getElementById('group-grid').textContent));
check('activity log rendered', document.querySelectorAll('#activity-list li').length === 2);
check('system panel populated', document.querySelectorAll('#system-kv .kv').length >= 10,
  String(document.querySelectorAll('#system-kv .kv').length));
check('user chip filled', document.getElementById('user-name').textContent === 'admin');
check('custom name displayed', /Sam's Tablet/.test(document.getElementById('device-body').innerHTML));
check('access switch present', document.querySelectorAll('[data-access-for]').length === 3);
check('docs link in topbar', document.querySelector('.topbar-actions a[href="/docs"]') !== null);

console.log('\n-- filtering --');
const search = document.getElementById('device-search');
search.value = 'tablet';
search.dispatchEvent(new window.Event('input', { bubbles: true }));
check('search filters rows', document.querySelectorAll('#device-body tr').length === 1,
  String(document.querySelectorAll('#device-body tr').length));
search.value = '';
search.dispatchEvent(new window.Event('input', { bubbles: true }));

const filter = document.getElementById('device-filter');
filter.value = 'ungrouped';
filter.dispatchEvent(new window.Event('change', { bubbles: true }));
check('group filter works', document.querySelectorAll('#device-body tr').length === 1,
  String(document.querySelectorAll('#device-body tr').length));
filter.value = 'all';
filter.dispatchEvent(new window.Event('change', { bubbles: true }));

console.log('\n-- rules tab --');
document.getElementById('btn-rules').click();
await new Promise((r) => setTimeout(r, 60));
check('filter ruleset loaded', /PCTRL/.test(document.getElementById('rules-pre').textContent));
document.querySelector('[data-rules-tab="nat"]').click();
check('nat tab switches', /MASQUERADE/.test(document.getElementById('rules-pre').textContent));

console.log('\n-- interactions --');
document.querySelector('[data-group-toggle]').click();
await new Promise((r) => setTimeout(r, 60));
check('group toggle posts to API',
  calls.some((c) => c.method === 'POST' && c.url === '/api/groups/1/access' && c.body.blocked === true),
  JSON.stringify(calls.filter((c) => c.url.includes('/access'))));

const switchEl = document.querySelector('[data-access-for="AA:BB:CC:DD:EE:02"]');
switchEl.checked = true;
switchEl.dispatchEvent(new window.Event('change', { bubbles: true }));
await new Promise((r) => setTimeout(r, 60));
check('device switch posts to API',
  calls.some((c) => c.method === 'POST' && c.url === '/api/devices/AA:BB:CC:DD:EE:02/access' && c.body.blocked === false));

document.querySelector('[data-device-timer]').click();
check('timer modal opens', document.getElementById('modal').hidden === false);
check('timer modal has choices', document.querySelectorAll('#modal-body [data-timer-kind]').length === 10);
document.querySelector('[data-timer-kind="block"][data-minutes="30"]').click();
await new Promise((r) => setTimeout(r, 60));
check('pause timer posted',
  calls.some((c) => c.url === '/api/devices/AA:BB:CC:DD:EE:01/timer' && c.body.minutes === 30 && c.body.kind === 'block'));
check('modal closed after action', document.getElementById('modal').hidden === true);

document.querySelector('[data-rename-device]').click();
check('rename modal opens', document.getElementById('modal').hidden === false);
check('rename input prefilled', document.getElementById('rename-input').value === "Sam's Tablet");
document.getElementById('rename-input').value = 'Kitchen iPad';
document.getElementById('rename-save').click();
await new Promise((r) => setTimeout(r, 60));
check('rename patch posted',
  calls.some((c) => c.method === 'PATCH' && c.url === '/api/devices/AA:BB:CC:DD:EE:01' && c.body.name === 'Kitchen iPad'));

document.getElementById('btn-new-group').click();
check('group modal opens', document.getElementById('modal').hidden === false);
check('colour swatches offered', document.querySelectorAll('#color-picker .color-dot').length === 8);
document.getElementById('group-name').value = 'Guests';
document.querySelector('[data-color="#34d399"]').click();
document.getElementById('group-save').click();
await new Promise((r) => setTimeout(r, 60));
check('group create posted',
  calls.some((c) => c.url === '/api/groups' && c.method === 'POST' && c.body.name === 'Guests' && c.body.color === '#34d399'));

document.getElementById('btn-new-schedule').click();
check('schedule modal opens', document.getElementById('modal').hidden === false);
check('day chips offered', document.querySelectorAll('#day-picker .day-chip').length === 7);
check('5 weekdays preselected', document.querySelectorAll('#day-picker .day-chip.on').length === 5);
document.getElementById('sched-save').click();
await new Promise((r) => setTimeout(r, 60));
check('schedule create posted',
  calls.some((c) => c.url === '/api/schedules' && c.method === 'POST' && Array.isArray(c.body.days) && c.body.days.length === 5));

console.log('\n-- csrf --');
const mutating = calls.filter((c) => c.method !== 'GET');
check('every mutation carries X-CSRF-Token',
  mutating.length > 0 && mutating.every((c) => c.headers['X-CSRF-Token'] === 'test-csrf'),
  JSON.stringify(mutating.map((c) => [c.method, c.url, c.headers['X-CSRF-Token']])));

/* ============================================================ setup wizard */
/* ============================================== web filtering + controls */
console.log('\n-- web filtering & controls --');
await new Promise((r) => setTimeout(r, 250));

check('filter panel present', document.getElementById('filter-panel') !== null);
check('dns pill shows running', /DNS filtering on/.test(document.getElementById('dns-pill').textContent));
check('rule rows rendered', document.querySelectorAll('#rule-body tr').length === 3,
  String(document.querySelectorAll('#rule-body tr').length));
check('query log rendered', document.querySelectorAll('#dns-query-log .query-row').length === 2);
check('blocked query styled', document.querySelectorAll('#dns-query-log .query-row.blocked').length === 1);
check('filter stats rendered', document.querySelectorAll('#filter-stats .usage-stat').length === 5);
check('rule group options populated', document.querySelectorAll('#rule-group option').length === 3,
  String(document.querySelectorAll('#rule-group option').length));

document.getElementById('rule-pattern').value = 'tiktok.com';
document.getElementById('rule-action').value = 'block';
document.getElementById('rule-form').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
await new Promise((r) => setTimeout(r, 100));
check('rule POSTed',
  calls.some((c) => c.url === '/api/web-rules' && c.method === 'POST' &&
    c.body.pattern === 'tiktok.com' && c.body.action === 'block'),
  JSON.stringify(calls.filter((c) => c.url === '/api/web-rules')));

document.querySelector('[data-rule-toggle]').click();
await new Promise((r) => setTimeout(r, 80));
check('rule PATCHed', calls.some((c) => c.url === '/api/web-rules/11' && c.method === 'PATCH' && c.body.enabled === false));

document.querySelector('[data-rule-delete]').click();
check('delete asks for confirmation', document.getElementById('modal').hidden === false);
document.getElementById('confirm-yes').click();
await new Promise((r) => setTimeout(r, 80));
check('rule DELETEd', calls.some((c) => c.url === '/api/web-rules/11' && c.method === 'DELETE'));

console.log('\n-- master pause --');
document.getElementById('btn-pause-all').click();
check('pause modal opens', document.getElementById('modal').hidden === false);
check('pause modal offers choices', document.querySelectorAll('#modal-body [data-master-minutes]').length === 5,
  String(document.querySelectorAll('#modal-body [data-master-minutes]').length));
check('indefinite option offered', document.querySelector('[data-master-minutes="indefinite"]') !== null);
document.querySelector('[data-master-minutes="30"]').click();
await new Promise((r) => setTimeout(r, 150));
check('pause-all POSTed', calls.some((c) => c.url === '/api/pause-all' && c.body && c.body.minutes === 30),
  JSON.stringify(calls.filter((c) => c.url === '/api/pause-all')));
check('button flips to Resume', /Resume all/.test(document.getElementById('btn-pause-all').textContent),
  document.getElementById('btn-pause-all').textContent);

document.getElementById('btn-pause-all').click();
await new Promise((r) => setTimeout(r, 150));
check('resume-all POSTed', calls.some((c) => c.url === '/api/resume-all'));
check('button flips back', /Pause all/.test(document.getElementById('btn-pause-all').textContent));

console.log('\n-- settings --');
const autoblock = document.getElementById('set-autoblock');
check('autoblock switch starts off', autoblock.checked === false);
autoblock.checked = true;
autoblock.dispatchEvent(new window.Event('change', { bubbles: true }));
await new Promise((r) => setTimeout(r, 100));
check('autoblock PATCHed',
  calls.some((c) => c.url === '/api/settings' && c.body && c.body.auto_block_unknown === true));

const dnsSwitch = document.getElementById('set-dns');
check('dns switch reflects status', dnsSwitch.checked === true, String(dnsSwitch.checked));
dnsSwitch.checked = false;
dnsSwitch.dispatchEvent(new window.Event('change', { bubbles: true }));
await new Promise((r) => setTimeout(r, 100));
check('dns toggle PATCHed',
  calls.some((c) => c.url === '/api/settings' && c.body && c.body.dns_filtering === false));

console.log('\n-- device approval --');
check('approve button for unapproved device',
  document.querySelector('[data-approve-device="AA:BB:CC:DD:EE:03"]') !== null);
check('no approve button once approved',
  document.querySelector('[data-approve-device="AA:BB:CC:DD:EE:01"]') === null);
document.querySelector('[data-approve-device="AA:BB:CC:DD:EE:03"]').click();
await new Promise((r) => setTimeout(r, 100));
check('approve POSTed',
  calls.some((c) => c.url === '/api/devices/AA:BB:CC:DD:EE:03/approve' && c.body.approved === true));

console.log('\n-- usage charts --');
check('usage panel present', document.getElementById('usage-panel') !== null);
check('usage summary rendered', document.querySelectorAll('#usage-summary .usage-stat').length === 5,
  String(document.querySelectorAll('#usage-summary .usage-stat').length));
check('usage device bars rendered', document.querySelectorAll('#usage-devices .usage-row').length === 2);
check('usage group bars rendered', document.querySelectorAll('#usage-groups .usage-row').length === 2);
check('svg chart rendered', document.querySelector('#usage-chart .pg-svg') !== null);
check('chart legend rendered', document.querySelectorAll('#usage-chart .pg-key').length === 2);
check('totals shown', /Total traffic/.test(document.getElementById('usage-summary').textContent) &&
  /Download/.test(document.getElementById('usage-summary').textContent) &&
  /11\.6 KB/.test(document.getElementById('usage-summary').textContent),
  document.getElementById('usage-summary').textContent.slice(0, 120));

console.log('\n-- setup wizard --');
{
  const setupCalls = [];
  const setupProblems = [];
  const setupConsole = new VirtualConsole();
  setupConsole.on('jsdomError', (e) => {
    // jsdom cannot navigate; the wizard redirects on success, which is fine.
    if (/Not implemented: navigation/.test(e.message)) return;
    setupProblems.push('jsdomError: ' + e.message);
  });
  setupConsole.on('error', (...a) => setupProblems.push('console.error: ' + a.join(' ')));

  const setupHtml = readFileSync(join(ROOT, 'app', 'templates', 'setup.html'), 'utf8')
    .replace(/\{\{\s*(?:url_for\('static',\s*filename='([^']+)'\)|asset\('([^']+)'\))\s*\}\}/g,
      (_m, a, b) => '/static/' + (a || b));

  const SETUP_STATUS = {
    required: true,
    min_password_length: 8,
    gateway_mode: true,
    detected_subnet: '192.168.1.0/24',
    default_route_iface: 'eth0',
    recommended: { lan: 'eth1', wan: 'eth0' },
    network: { lan_iface: 'eth1', wan_iface: 'eth0', lan_subnet: '192.168.1.0/24' },
    interfaces: [
      { name: 'eth1', address: '192.168.1.1/24', state: 'UP' },
      { name: 'eth0', address: '10.0.0.2/24', state: 'UP' },
    ],
    firewall: { dry_run: false, chain: 'PCTRL' },
  };

  const setupDom = new JSDOM(setupHtml, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'http://127.0.0.1:8765/setup',
    virtualConsole: setupConsole,
    beforeParse(window) {
      window.fetch = (url, init = {}) => {
        const path = decodeURIComponent(String(url));
        setupCalls.push({
          method: (init.method || 'GET').toUpperCase(),
          url: path,
          body: init.body ? JSON.parse(init.body) : null,
        });
        if (path === '/api/setup/status') return Promise.resolve(jsonResponse(SETUP_STATUS));
        return Promise.resolve(jsonResponse({ ok: true, authenticated: true, csrf: 'setup-csrf', user: { id: 1, username: 'admin' } }));
      };
      window.structuredClone = window.structuredClone || ((v) => JSON.parse(JSON.stringify(v)));
    },
  });

  const sd = setupDom.window.document;
  const sw = setupDom.window;
  await new Promise((r) => setTimeout(r, 250));

  const currentStep = () => Number(sd.querySelector('.wizard-step.active').getAttribute('data-step'));

  check('4 wizard steps present', sd.querySelectorAll('.wizard-step').length === 4);
  check('starts on step 1', currentStep() === 1, String(currentStep()));
  check('preflight rows rendered', sd.querySelectorAll('#preflight .check-row').length === 4,
    String(sd.querySelectorAll('#preflight .check-row').length));
  check('firewall reported as enforcing', /iptables ready/.test(sd.getElementById('preflight').textContent));
  check('LAN interface pre-filled', sd.getElementById('su-lan').value === 'eth1', sd.getElementById('su-lan').value);
  check('WAN interface pre-filled', sd.getElementById('su-wan').value === 'eth0', sd.getElementById('su-wan').value);
  check('subnet pre-filled', sd.getElementById('su-subnet').value === '192.168.1.0/24');
  check('interface dropdown populated', sd.querySelectorAll('#su-lan option').length === 2,
    String(sd.querySelectorAll('#su-lan option').length));
  check('recommended interface flagged', /recommended/.test(sd.getElementById('su-lan').innerHTML));
  check('detected subnet shown', /192\.168\.1\.0\/24/.test(sd.getElementById('detected-subnet').textContent));

  // navigation
  check('back button hidden on first step', sd.getElementById('btn-back').hidden === true);
  sd.getElementById('btn-next').click();
  check('next advances to step 2', currentStep() === 2, String(currentStep()));
  check('back button appears', sd.getElementById('btn-back').hidden === false);
  sd.getElementById('btn-back').click();
  check('back returns to step 1', currentStep() === 1, String(currentStep()));
  sd.getElementById('btn-next').click();

  // validation blocks the way through
  sd.getElementById('btn-next').click();
  check('empty username blocked', currentStep() === 2, String(currentStep()));
  check('validation message shown', /valid username/.test(sd.getElementById('setup-error').textContent));

  sd.getElementById('su-username').value = 'admin';
  sd.getElementById('su-password').value = 'short';
  sd.getElementById('btn-next').click();
  check('short password blocked', currentStep() === 2, String(currentStep()));
  check('password error shown', /at least 8/.test(sd.getElementById('setup-error').textContent));

  sd.getElementById('su-password').value = 'a-good-password-1';
  sd.getElementById('su-confirm').value = 'different-value-here';
  sd.getElementById('btn-next').click();
  check('mismatched password blocked', currentStep() === 2, String(currentStep()));

  sd.getElementById('su-confirm').value = 'a-good-password-1';
  sd.getElementById('su-confirm').dispatchEvent(new sw.Event('input', { bubbles: true }));
  check('match hint shown', /Passwords match/.test(sd.getElementById('confirm-hint').textContent));

  sd.getElementById('btn-next').click();
  check('step 3 reachable with valid account', currentStep() === 3, String(currentStep()));

  sd.getElementById('su-subnet').value = 'garbage';
  sd.getElementById('btn-next').click();
  check('bad subnet blocked', currentStep() === 3, String(currentStep()));
  sd.getElementById('su-subnet').value = '192.168.50.0/24';
  sd.getElementById('btn-next').click();
  check('step 4 reachable with valid network', currentStep() === 4, String(currentStep()));

  // summary + submit
  check('summary lists administrator', /admin/.test(sd.getElementById('summary-list').textContent));
  check('summary lists subnet', /192\.168\.50\.0\/24/.test(sd.getElementById('summary-list').textContent));
  check('button relabelled for finish', /Open dashboard/.test(sd.getElementById('btn-next').textContent));

  sd.getElementById('btn-next').click();
  await new Promise((r) => setTimeout(r, 120));

  const submitted = setupCalls.find((c) => c.url === '/api/setup');
  check('setup POSTed', Boolean(submitted), JSON.stringify(setupCalls.map((c) => c.url)));
  check('setup payload complete',
    submitted && submitted.body.username === 'admin' &&
    submitted.body.password === 'a-good-password-1' &&
    submitted.body.confirm === 'a-good-password-1' &&
    submitted.body.lan_iface === 'eth1' &&
    submitted.body.wan_iface === 'eth0' &&
    submitted.body.lan_subnet === '192.168.50.0/24',
    JSON.stringify(submitted && submitted.body));
  check('status polled first', setupCalls.some((c) => c.url === '/api/setup/status' && c.method === 'GET'));
  check('no setup wizard errors', setupProblems.length === 0, setupProblems.join(' | '));

  setupDom.window.close();
}

console.log('\n-- runtime errors --');
check('no jsdom errors', problems.length === 0, problems.join(' | '));

console.log('\n-- css guards --');
{
  // jsdom does no CSS layout, so assert the guard that keeps `hidden` working:
  // author rules setting `display` (e.g. .modal-backdrop, .btn) otherwise
  // out-rank the UA `[hidden] { display: none }` and the element stays visible.
  const css = readFileSync(join(ROOT, 'app', 'static', 'css', 'app.css'), 'utf8');
  check('[hidden] display override present',
    /\[hidden\]\s*\{\s*display:\s*none\s*!important\s*;?\s*\}/.test(css));

  const hiddenUsed = [];
  for (const file of ['dashboard.html', 'setup.html', 'login.html']) {
    const html = readFileSync(join(ROOT, 'app', 'templates', file), 'utf8');
    for (const m of html.matchAll(/class="([^"]+)"[^>]*\shidden|\shidden[^>]*class="([^"]+)"/g)) {
      for (const cls of (m[1] || m[2] || '').split(/\s+/)) if (cls) hiddenUsed.push(cls);
    }
  }
  const needsGuard = [...new Set(hiddenUsed)].filter((cls) =>
    new RegExp(`\\.${cls}\\s*\\{[^}]*\\bdisplay\\s*:`).test(css));
  check('every hidden element is guarded', needsGuard.length === 0 || /\[hidden\]/.test(css),
    needsGuard.join(', '));
  check('modal starts hidden', document.getElementById('modal').hidden === true);

  // Static assets are cacheable, so every reference must be content-versioned
  // (`asset()`), otherwise a fixed stylesheet never reaches a warm browser.
  const unversioned = [];
  for (const file of ['dashboard.html', 'setup.html', 'login.html']) {
    const tpl = readFileSync(join(ROOT, 'app', 'templates', file), 'utf8');
    for (const m of tpl.matchAll(/url_for\('static'/g)) unversioned.push(file);
  }
  check('all asset refs use versioned asset()', unversioned.length === 0, unversioned.join(', '));
}

console.log(`\n== ${PASS} passed, ${FAIL} failed ==`);
window.close();
process.exit(FAIL ? 1 : 0);
