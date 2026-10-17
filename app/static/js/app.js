/* ==========================================================================
   Parental Gateway - dashboard client
   ========================================================================== */
'use strict';

/* ------------------------------------------------------------------ state */
const state = {
  csrf: null,
  user: null,
  devices: [],
  groups: [],
  schedules: [],
  pauses: [],
  events: [],
  status: null,
  settings: {},
  rules: { filter: '', nat: '' },
  rulesTab: 'filter',
  search: '',
  filter: 'all',
  refreshTimer: null,
  tickTimer: null,
};

const DAY_NAMES = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const GROUP_COLORS = ['#6366f1', '#22d3ee', '#34d399', '#fbbf24', '#f87171', '#a78bfa', '#f472b6', '#94a3b8'];

/* ---------------------------------------------------------------- helpers */
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.prototype.slice.call((root || document).querySelectorAll(sel));

function esc(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function fmtDateTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
         d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function countdown(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return h + 'h ' + String(m).padStart(2, '0') + 'm';
  if (m > 0) return m + 'm ' + String(sec).padStart(2, '0') + 's';
  return sec + 's';
}

function groupById(id) {
  return state.groups.find(function (g) { return String(g.id) === String(id); }) || null;
}

function deviceByMac(mac) {
  return state.devices.find(function (d) { return d.mac === mac; }) || null;
}

/* ------------------------------------------------------------------ toasts */
function toast(title, body, kind) {
  const stack = $('#toast-stack');
  const el = document.createElement('div');
  el.className = 'toast ' + (kind || 'ok');
  el.innerHTML =
    '<div>' +
      '<div class="t-title">' + esc(title) + '</div>' +
      (body ? '<div class="t-body">' + esc(body) + '</div>' : '') +
    '</div>';
  stack.appendChild(el);
  setTimeout(function () {
    el.style.transition = 'opacity .25s ease, transform .25s ease';
    el.style.opacity = '0';
    el.style.transform = 'translateX(14px)';
    setTimeout(function () { el.remove(); }, 260);
  }, 4200);
}

/* --------------------------------------------------------------- api call */
async function api(path, options) {
  const opts = options || {};
  const init = {
    method: opts.method || 'GET',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
  };
  if (state.csrf) init.headers['X-CSRF-Token'] = state.csrf;
  if (opts.headers) Object.assign(init.headers, opts.headers);
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);

  let response;
  try {
    response = await fetch(path, init);
  } catch (err) {
    throw new Error('gateway unreachable');
  }

  if (response.status === 401) {
    window.location.href = '/login';
    throw new Error('signed out');
  }

  const data = await response.json().catch(function () { return {}; });
  if (!response.ok) {
    const error = new Error(data.error || response.statusText || 'request failed');
    error.status = response.status;
    throw error;
  }
  return data;
}

/* ------------------------------------------------------------------ modal */
function openModal(title, bodyHtml, footHtml) {
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = bodyHtml;
  $('#modal-foot').innerHTML = footHtml || '';
  $('#modal').hidden = false;
}

function closeModal() {
  $('#modal').hidden = true;
  $('#modal-body').onclick = null;
  $('#modal-body').innerHTML = '';
  $('#modal-foot').innerHTML = '';
}

/* ================================================================== render */
function renderAll(data) {
  if (data.devices) state.devices = data.devices;
  if (data.groups) state.groups = data.groups;
  if (data.schedules) state.schedules = data.schedules;
  if (data.pauses) state.pauses = data.pauses;
  if (data.events) state.events = data.events;
  if (data.status) state.status = data.status;
  if (data.settings) state.settings = data.settings;

  renderTopbar();
  renderStats();
  renderTimers();
  renderGroups();
  renderDevices();
  renderSchedules();
  renderSystem();
  renderActivity();
}

function renderTopbar() {
  const st = state.status || {};
  const gw = st.gateway || {};
  const fw = st.firewall || {};

  const gwPill = $('#pill-gateway');
  const gwOk = gw.ip_forward === true || gw.gateway_mode;
  gwPill.innerHTML = '<span class="dot ' + (gwOk ? 'dot-ok' : 'dot-warn') + '"></span>Gateway' +
    (gw.subnet ? ' <span class="muted">' + esc(gw.subnet) + '</span>' : '');
  gwPill.title = 'LAN ' + ((gw.lan_iface && gw.lan_iface.name) || '?') +
    ' · WAN ' + ((gw.wan_iface && gw.wan_iface.name) || '?');

  const fwPill = $('#pill-firewall');
  if (fw.dry_run) {
    fwPill.innerHTML = '<span class="dot dot-warn"></span>Firewall · dry-run';
    fwPill.title = 'iptables unavailable - rules are computed but not enforced';
  } else {
    fwPill.innerHTML = '<span class="dot ' + (fw.last_ok === false ? 'dot-bad' : 'dot-ok') + '"></span>Firewall · ' + esc(fw.chain || 'PCTRL');
    fwPill.title = fw.last_error ? String(fw.last_error) : 'Rules applied at ' + fmtTime((st.policy || {}).applied_at);
  }

  const policy = st.policy || {};
  $('#pill-blocked').innerHTML = '<span class="dot dot-bad"></span>Blocked ' + (policy.blocked_count || 0);
}

function renderStats() {
  const online = state.devices.filter(function (d) { return d.online; }).length;
  const blocked = state.devices.filter(function (d) { return d.effective_blocked; }).length;
  $('#stat-devices').textContent = state.devices.length;
  $('#stat-online').textContent = online;
  $('#stat-groups').textContent = state.groups.length;
  $('#stat-blocked').textContent = blocked;
  $('#stat-timers').textContent = state.pauses.length;
}

function renderTimers() {
  const panel = $('#timers-panel');
  const strip = $('#timer-strip');
  if (!state.pauses.length) {
    panel.hidden = true;
    strip.innerHTML = '';
    return;
  }
  panel.hidden = false;
  strip.innerHTML = state.pauses.map(function (p) {
    const label = p.label || (p.kind === 'block' ? 'Paused' : 'Allowed');
    const target = describeTarget(p);
    return '<div class="timer-chip ' + esc(p.kind) + '">' +
      '<span class="dot ' + (p.kind === 'block' ? 'dot-bad' : 'dot-ok') + '"></span>' +
      '<strong>' + esc(label) + '</strong>' +
      '<span class="muted">' + esc(target) + '</span>' +
      '<span class="countdown" data-countdown="' + esc(p.expires_at) + '">' + countdown(p.remaining_seconds) + '</span>' +
      '<button class="icon-btn" data-clear-timer="' + esc(p.id) + '" title="Cancel timer">' +
        '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m6 6 12 12M18 6 6 18"/></svg>' +
      '</button>' +
    '</div>';
  }).join('');
}

function describeTarget(pause) {
  if (pause.target_type === 'device') {
    const device = deviceByMac(pause.target_id);
    return device ? device.name : pause.target_id;
  }
  const group = groupById(pause.target_id);
  return group ? group.name : ('group #' + pause.target_id);
}

function renderGroups() {
  const grid = $('#group-grid');
  $('#groups-empty').hidden = state.groups.length > 0;
  grid.innerHTML = state.groups.map(function (g) {
    return '<div class="group-card ' + (g.blocked ? 'blocked' : '') + '">' +
      '<div class="group-top">' +
        '<div>' +
          '<div class="group-name">' +
            '<span class="group-swatch" style="background:' + esc(g.color || '#6366f1') + '"></span>' +
            esc(g.name) +
          '</div>' +
          '<div class="group-count">' + esc(g.device_count) + ' device' + (g.device_count === 1 ? '' : 's') +
            (g.blocked ? ' · all blocked' : '') + '</div>' +
        '</div>' +
        '<div class="group-menu">' +
          '<button class="icon-btn" data-edit-group="' + esc(g.id) + '" title="Edit group">' +
            '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>' +
          '</button>' +
          '<button class="icon-btn" data-delete-group="' + esc(g.id) + '" title="Delete group">' +
            '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/></svg>' +
          '</button>' +
        '</div>' +
      '</div>' +
      '<div class="group-actions">' +
        '<button class="btn btn-sm ' + (g.blocked ? 'btn-primary' : 'btn-danger') + '" data-group-toggle="' + esc(g.id) + '">' +
          (g.blocked ? 'Allow all' : 'Block all') +
        '</button>' +
        '<button class="btn btn-sm btn-ghost" data-group-timer="' + esc(g.id) + '">Pause…</button>' +
      '</div>' +
    '</div>';
  }).join('');
}

function visibleDevices() {
  const term = state.search.trim().toLowerCase();
  return state.devices.filter(function (d) {
    if (state.filter === 'online' && !d.online) return false;
    if (state.filter === 'blocked' && !d.effective_blocked) return false;
    if (state.filter === 'ungrouped' && d.group_id) return false;
    if (!term) return true;
    return [d.name, d.ip, d.mac, d.hostname, d.custom_name, d.group_name]
      .filter(Boolean)
      .some(function (v) { return String(v).toLowerCase().indexOf(term) !== -1; });
  });
}

function renderDevices() {
  const body = $('#device-body');
  const list = visibleDevices();
  $('#devices-empty').hidden = list.length > 0;

  const groupOptions = function (selected) {
    return '<option value="">— ungrouped —</option>' + state.groups.map(function (g) {
      return '<option value="' + esc(g.id) + '"' + (String(g.id) === String(selected) ? ' selected' : '') + '>' + esc(g.name) + '</option>';
    }).join('');
  };

  body.innerHTML = list.map(function (d) {
    const allowed = !d.effective_blocked;
    return '<tr class="' + (d.effective_blocked ? 'is-blocked' : '') + '">' +
      '<td class="col-status"><span class="dot ' + (d.online ? 'dot-ok' : 'dot-idle') + '" title="' + (d.online ? 'online' : 'last seen ' + fmtDateTime(d.last_seen)) + '"></span></td>' +
      '<td><div class="cell-name"><strong>' + esc(d.name) + '</strong>' +
        '<span class="muted">' + esc(d.hostname || d.ip || 'unidentified') + '</span></div></td>' +
      '<td class="mono">' + esc(d.ip || '—') + '</td>' +
      '<td class="mono">' + esc(d.mac) + '</td>' +
      '<td><select class="input input-select" data-group-for="' + esc(d.mac) + '" style="width:132px;padding:5px 8px;font-size:12px">' + groupOptions(d.group_id) + '</select></td>' +
      '<td class="col-reason">' + (d.reason
          ? '<span class="reason-chip" title="' + esc(d.reason) + '">' + esc(d.reason) + '</span>'
          : '<span class="reason-chip none">—</span>') + '</td>' +
      '<td class="col-actions">' +
        '<label class="switch ' + (allowed ? '' : 'blocked') + '" title="' + (allowed ? 'Internet allowed' : 'Internet blocked') + '">' +
          '<input type="checkbox" data-access-for="' + esc(d.mac) + '" ' + (allowed ? 'checked' : '') + ' aria-label="Internet access for ' + esc(d.name) + '">' +
          '<span class="track"></span><span class="thumb"></span>' +
        '</label>' +
      '</td>' +
      '<td class="col-actions"><div class="row-actions">' +
        '<button class="btn btn-xs btn-ghost" data-device-timer="' + esc(d.mac) + '" title="Pause / allow timer">⏱</button>' +
        '<button class="btn btn-xs btn-ghost" data-rename-device="' + esc(d.mac) + '" title="Rename">Rename</button>' +
        '<button class="btn btn-xs btn-danger" data-remove-device="' + esc(d.mac) + '" title="Forget device">✕</button>' +
      '</div></td>' +
    '</tr>';
  }).join('');
}

function renderSchedules() {
  const body = $('#schedule-body');
  $('#schedules-empty').hidden = state.schedules.length > 0;
  body.innerHTML = state.schedules.map(function (s) {
    const days = (s.days || []).map(function (d) { return DAY_NAMES[d]; }).join(' ');
    return '<tr>' +
      '<td><strong>' + esc(s.name || 'Bedtime') + '</strong></td>' +
      '<td><span class="reason-chip" style="background:' + esc(s.group_color || '#6366f1') + '22;border-color:' + esc(s.group_color || '#6366f1') + '55;color:#dbe3ff">' + esc(s.group_name || 'unknown') + '</span></td>' +
      '<td class="mono">' + esc(days || '—') + '</td>' +
      '<td class="mono">' + esc(s.start_time) + ' → ' + esc(s.end_time) + '</td>' +
      '<td>' + (s.enabled
          ? '<span class="dot dot-ok"></span> enabled'
          : '<span class="dot dot-idle"></span> disabled') + '</td>' +
      '<td class="col-actions"><div class="row-actions">' +
        '<button class="btn btn-xs btn-ghost" data-toggle-schedule="' + esc(s.id) + '">' + (s.enabled ? 'Disable' : 'Enable') + '</button>' +
        '<button class="btn btn-xs btn-ghost" data-edit-schedule="' + esc(s.id) + '">Edit</button>' +
        '<button class="btn btn-xs btn-danger" data-delete-schedule="' + esc(s.id) + '">✕</button>' +
      '</div></td>' +
    '</tr>';
  }).join('');
}

function renderSystem() {
  const st = state.status || {};
  const gw = st.gateway || {};
  const fw = st.firewall || {};
  const policy = st.policy || {};

  const rows = [
    ['Gateway mode', (state.settings.gateway_mode ? 'enabled' : 'disabled')],
    ['LAN interface', ((gw.lan_iface && gw.lan_iface.name) || '—') + ((gw.lan_iface && gw.lan_iface.address) ? '  ' + gw.lan_iface.address : '')],
    ['WAN interface', ((gw.wan_iface && gw.wan_iface.name) || '—')],
    ['Detected subnet', gw.subnet || 'unknown'],
    ['IP forwarding', gw.ip_forward === true ? 'on' : (gw.ip_forward === false ? 'off' : 'unknown')],
    ['NAT / masquerade', gw.nat_configured ? 'configured' : 'not configured'],
    ['Firewall chain', (fw.chain || 'PCTRL') + (fw.dry_run ? ' (dry-run)' : '')],
    ['Firewall mode', fw.mode || 'auto'],
    ['Enforced blocks', String(policy.blocked_count || 0)],
    ['Last applied', fmtDateTime(policy.applied_at)],
    ['Scan interval', (state.settings.scan_interval_minutes || 0) + ' min'],
  ];

  $('#system-kv').innerHTML = rows.map(function (row) {
    return '<div class="kv"><span class="k">' + esc(row[0]) + '</span><span class="v">' + esc(row[1]) + '</span></div>';
  }).join('');

  $('#rules-pre').textContent = state.rules[state.rulesTab] ||
    ('Press “Refresh rules” to inspect the live ' + state.rulesTab + ' ruleset.');
}

function renderActivity() {
  const list = $('#activity-list');
  if (!state.events.length) {
    list.innerHTML = '<li class="muted">No activity recorded yet.</li>';
    return;
  }
  list.innerHTML = state.events.slice(0, 25).map(function (e) {
    return '<li class="lvl-' + esc(e.level || 'info') + '">' +
      '<span class="when">' + esc(fmtDateTime(e.created_at)) + '</span>' +
      '<span>' + esc(e.message) + '</span>' +
    '</li>';
  }).join('');
}

/* ================================================================ actions */
async function refresh(silent) {
  try {
    const data = await api('/api/overview');
    renderAll(data);
    if (!silent) toast('Refreshed', 'Dashboard data updated', 'ok');
  } catch (err) {
    if (!silent) toast('Refresh failed', err.message, 'error');
  }
}

async function doScan() {
  const btn = $('#btn-scan');
  btn.disabled = true;
  btn.querySelector('span').textContent = 'Scanning…';
  try {
    const result = await api('/api/scan', { method: 'POST', body: {} });
    const found = (result.scan && result.scan.found) || 0;
    toast('Scan complete', found + ' device(s) found on ' + (result.scan.subnet || 'the LAN'), 'ok');
    await refresh(true);
  } catch (err) {
    toast('Scan failed', err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.querySelector('span').textContent = 'Scan';
  }
}

async function doReconcile() {
  try {
    await api('/api/system/reconcile', { method: 'POST', body: {} });
    toast('Rules applied', 'Firewall ruleset re-applied', 'ok');
    await refresh(true);
  } catch (err) {
    toast('Apply failed', err.message, 'error');
  }
}

async function setDeviceAccess(mac, allowed, source) {
  try {
    await api('/api/devices/' + encodeURIComponent(mac) + '/access', {
      method: 'POST',
      body: { blocked: !allowed },
    });
    await refresh(true);
    const device = deviceByMac(mac);
    if (allowed && device && device.effective_blocked) {
      toast('Still blocked', '“' + device.name + '” is blocked by: ' + (device.reason || 'a schedule or group'), 'warn');
    } else {
      toast(allowed ? 'Internet allowed' : 'Internet blocked',
            device ? device.name : mac, allowed ? 'ok' : 'warn');
    }
  } catch (err) {
    toast('Could not change access', err.message, 'error');
    if (source) source.checked = !allowed;
    else await refresh(true);
  }
}

async function setGroupAccess(groupId, blocked) {
  const group = groupById(groupId);
  try {
    await api('/api/groups/' + groupId + '/access', { method: 'POST', body: { blocked: blocked } });
    toast(blocked ? 'Group blocked' : 'Group allowed', group ? group.name : '', blocked ? 'warn' : 'ok');
    await refresh(true);
  } catch (err) {
    toast('Could not change group', err.message, 'error');
  }
}

function openTimerDialog(targetType, targetId, label) {
  const body =
    '<p class="muted" style="margin-top:0">Apply a temporary override to <strong>' + esc(label) + '</strong>.</p>' +
    '<div class="modal-section-title">Pause internet (block)</div>' +
    '<div class="choice-grid">' +
      '<button class="choice danger" data-timer-kind="block" data-minutes="15">15 min</button>' +
      '<button class="choice danger" data-timer-kind="block" data-minutes="30">30 min</button>' +
      '<button class="choice danger" data-timer-kind="block" data-minutes="60">1 hour</button>' +
      '<button class="choice danger" data-timer-kind="block" data-minutes="120">2 hours</button>' +
      '<button class="choice danger" data-timer-kind="block" data-minutes="240">4 hours</button>' +
      '<button class="choice danger" data-timer-kind="block" data-minutes="480">Until morning</button>' +
    '</div>' +
    '<div class="modal-section-title">Allow internet (override schedules)</div>' +
    '<div class="choice-grid">' +
      '<button class="choice ok" data-timer-kind="allow" data-minutes="15">15 min</button>' +
      '<button class="choice ok" data-timer-kind="allow" data-minutes="30">30 min</button>' +
      '<button class="choice ok" data-timer-kind="allow" data-minutes="60">1 hour</button>' +
      '<button class="choice ok" data-timer-kind="allow" data-minutes="120">2 hours</button>' +
    '</div>';

  openModal('Timers · ' + label, body, '<button class="btn btn-ghost" data-close-modal>Cancel</button>');

  $('#modal-body').onclick = async function (event) {
    const btn = event.target.closest('[data-timer-kind]');
    if (!btn) return;
    const minutes = parseInt(btn.getAttribute('data-minutes'), 10);
    const kind = btn.getAttribute('data-timer-kind');
    const url = targetType === 'device'
      ? '/api/devices/' + encodeURIComponent(targetId) + '/timer'
      : '/api/groups/' + encodeURIComponent(targetId) + '/timer';
    try {
      await api(url, {
        method: 'POST',
        body: { minutes: minutes, kind: kind, label: (kind === 'block' ? 'Paused' : 'Allowed') },
      });
      closeModal();
      toast(kind === 'block' ? 'Internet paused' : 'Internet allowed',
            label + ' · ' + minutes + ' minutes', kind === 'block' ? 'warn' : 'ok');
      await refresh(true);
    } catch (err) {
      toast('Timer failed', err.message, 'error');
    }
  };
}

function openRenameDialog(mac) {
  const device = deviceByMac(mac);
  if (!device) return;
  const body =
    '<div class="field">' +
      '<label for="rename-input">Friendly name</label>' +
      '<input id="rename-input" type="text" value="' + esc(device.custom_name || device.name) + '" placeholder="e.g. Sam’s Tablet" maxlength="48">' +
    '</div>' +
    '<p class="muted" style="margin:0;font-size:12px">MAC <span class="mono">' + esc(mac) + '</span> · leave blank to use the discovered hostname.</p>';
  openModal('Rename device', body,
    '<button class="btn btn-ghost" data-close-modal>Cancel</button>' +
    '<button class="btn btn-primary" id="rename-save">Save</button>');

  const input = $('#rename-input');
  input.focus();
  input.select();

  $('#rename-save').addEventListener('click', async function () {
    try {
      await api('/api/devices/' + encodeURIComponent(mac), { method: 'PATCH', body: { name: input.value } });
      closeModal();
      toast('Device renamed', input.value || 'Name cleared', 'ok');
      await refresh(true);
    } catch (err) {
      toast('Rename failed', err.message, 'error');
    }
  });
}

function openGroupDialog(groupId) {
  const editing = groupId ? groupById(groupId) : null;
  const selected = (editing && editing.color) || GROUP_COLORS[0];
  const body =
    '<div class="field">' +
      '<label for="group-name">Group name</label>' +
      '<input id="group-name" type="text" maxlength="40" placeholder="e.g. Kids" value="' + esc(editing ? editing.name : '') + '">' +
    '</div>' +
    '<div class="field">' +
      '<label>Colour</label>' +
      '<div class="color-picker" id="color-picker">' +
        GROUP_COLORS.map(function (c) {
          return '<span class="color-dot ' + (c === selected ? 'on' : '') + '" data-color="' + c + '" style="background:' + c + '"></span>';
        }).join('') +
      '</div>' +
    '</div>';

  openModal(editing ? 'Edit group' : 'New group', body,
    '<button class="btn btn-ghost" data-close-modal>Cancel</button>' +
    '<button class="btn btn-primary" id="group-save">' + (editing ? 'Save' : 'Create') + '</button>');

  let colour = selected;
  $('#color-picker').addEventListener('click', function (event) {
    const dot = event.target.closest('[data-color]');
    if (!dot) return;
    colour = dot.getAttribute('data-color');
    $$('#color-picker .color-dot').forEach(function (el) { el.classList.remove('on'); });
    dot.classList.add('on');
  });

  $('#group-save').addEventListener('click', async function () {
    const name = $('#group-name').value.trim();
    if (!name) { toast('Name required', 'Please enter a group name', 'error'); return; }
    try {
      if (editing) {
        await api('/api/groups/' + editing.id, { method: 'PATCH', body: { name: name, color: colour } });
        toast('Group updated', name, 'ok');
      } else {
        await api('/api/groups', { method: 'POST', body: { name: name, color: colour } });
        toast('Group created', name, 'ok');
      }
      closeModal();
      await refresh(true);
    } catch (err) {
      toast('Could not save group', err.message, 'error');
    }
  });
}

function openScheduleDialog(scheduleId) {
  const editing = scheduleId ? state.schedules.find(function (s) { return String(s.id) === String(scheduleId); }) : null;
  const days = editing ? (editing.days || []) : [0, 1, 2, 3, 4];
  const groupOptions = state.groups.map(function (g) {
    return '<option value="' + esc(g.id) + '"' + (editing && String(editing.group_id) === String(g.id) ? ' selected' : '') + '>' + esc(g.name) + '</option>';
  }).join('');

  const body =
    '<div class="field">' +
      '<label for="sched-name">Label</label>' +
      '<input id="sched-name" type="text" maxlength="40" placeholder="e.g. School nights" value="' + esc(editing ? editing.name : '') + '">' +
    '</div>' +
    '<div class="field">' +
      '<label for="sched-group">Group</label>' +
      '<select id="sched-group">' + groupOptions + '</select>' +
    '</div>' +
    '<div class="field">' +
      '<label>Days</label>' +
      '<div class="day-picker" id="day-picker">' +
        DAY_NAMES.map(function (label, index) {
          return '<span class="day-chip ' + (days.indexOf(index) !== -1 ? 'on' : '') + '" data-day="' + index + '">' + label + '</span>';
        }).join('') +
      '</div>' +
    '</div>' +
    '<div class="time-row">' +
      '<div class="field"><label for="sched-start">Block from</label><input id="sched-start" type="time" value="' + esc(editing ? editing.start_time : '21:00') + '"></div>' +
      '<div class="field"><label for="sched-end">Until</label><input id="sched-end" type="time" value="' + esc(editing ? editing.end_time : '07:00') + '"></div>' +
    '</div>' +
    '<p class="muted" style="font-size:12px;margin:0">Windows that cross midnight (21:00 → 07:00) block the selected nights and the following morning.</p>';

  openModal(editing ? 'Edit schedule' : 'New schedule', body,
    '<button class="btn btn-ghost" data-close-modal>Cancel</button>' +
    '<button class="btn btn-primary" id="sched-save">' + (editing ? 'Save' : 'Create') + '</button>');

  $('#day-picker').addEventListener('click', function (event) {
    const chip = event.target.closest('[data-day]');
    if (chip) chip.classList.toggle('on');
  });

  $('#sched-save').addEventListener('click', async function () {
    const selectedDays = $$('#day-picker .day-chip.on').map(function (el) {
      return parseInt(el.getAttribute('data-day'), 10);
    });
    const payload = {
      name: $('#sched-name').value.trim(),
      group_id: $('#sched-group').value,
      days: selectedDays,
      start_time: $('#sched-start').value,
      end_time: $('#sched-end').value,
    };
    if (!selectedDays.length) { toast('Select a day', 'Pick at least one weekday', 'error'); return; }
    if (!payload.group_id) { toast('Select a group', 'A schedule must target a group', 'error'); return; }
    try {
      if (editing) {
        await api('/api/schedules/' + editing.id, { method: 'PATCH', body: payload });
        toast('Schedule updated', payload.name || 'Bedtime', 'ok');
      } else {
        await api('/api/schedules', { method: 'POST', body: payload });
        toast('Schedule created', payload.name || 'Bedtime', 'ok');
      }
      closeModal();
      await refresh(true);
    } catch (err) {
      toast('Could not save schedule', err.message, 'error');
    }
  });
}

function confirmDialog(title, message, confirmLabel, onConfirm) {
  openModal(title,
    '<p style="margin:0">' + esc(message) + '</p>',
    '<button class="btn btn-ghost" data-close-modal>Cancel</button>' +
    '<button class="btn btn-danger" id="confirm-yes">' + esc(confirmLabel) + '</button>');
  $('#confirm-yes').addEventListener('click', async function () {
    closeModal();
    await onConfirm();
  });
}

async function loadRules() {
  try {
    const data = await api('/api/rules');
    state.rules.filter = data.filter || '';
    state.rules.nat = data.nat || '';
    renderSystem();
    toast('Rules loaded', 'iptables ruleset refreshed', 'ok');
  } catch (err) {
    toast('Could not load rules', err.message, 'error');
  }
}

/* ================================================================ wiring */
function bindEvents() {
  $('#btn-scan').addEventListener('click', doScan);
  $('#btn-reconcile').addEventListener('click', doReconcile);
  $('#btn-rules').addEventListener('click', loadRules);
  $('#btn-new-group').addEventListener('click', function () { openGroupDialog(null); });
  $('#btn-new-schedule').addEventListener('click', function () {
    if (!state.groups.length) {
      toast('No groups yet', 'Create a group before adding a schedule', 'warn');
      return;
    }
    openScheduleDialog(null);
  });

  $('#btn-logout').addEventListener('click', async function () {
    try { await api('/api/logout', { method: 'POST', body: {} }); } catch (err) { /* ignore */ }
    window.location.href = '/login';
  });

  $('#device-search').addEventListener('input', function (event) {
    state.search = event.target.value;
    renderDevices();
  });
  $('#device-filter').addEventListener('change', function (event) {
    state.filter = event.target.value;
    renderDevices();
  });

  $('#modal-close').addEventListener('click', closeModal);
  $('#modal').addEventListener('click', function (event) {
    if (event.target.id === 'modal' || event.target.closest('[data-close-modal]')) closeModal();
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && !$('#modal').hidden) closeModal();
  });

  $$('.tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      $$('.tab').forEach(function (t) { t.classList.remove('active'); });
      tab.classList.add('active');
      state.rulesTab = tab.getAttribute('data-rules-tab');
      renderSystem();
    });
  });

  /* delegated actions */
  document.addEventListener('change', async function (event) {
    const access = event.target.closest('[data-access-for]');
    if (access) {
      await setDeviceAccess(access.getAttribute('data-access-for'), access.checked, access);
      return;
    }
    const groupSelect = event.target.closest('[data-group-for]');
    if (groupSelect) {
      const mac = groupSelect.getAttribute('data-group-for');
      try {
        await api('/api/devices/' + encodeURIComponent(mac), {
          method: 'PATCH',
          body: { group_id: groupSelect.value || null },
        });
        toast('Device grouped', groupSelect.value ? 'Moved to ' + (groupById(groupSelect.value) || {}).name : 'Removed from group', 'ok');
        await refresh(true);
      } catch (err) {
        toast('Could not move device', err.message, 'error');
      }
    }
  });

  document.addEventListener('click', async function (event) {
    const target = event.target;
    let attr;

    if ((attr = target.closest('[data-group-toggle]'))) {
      const group = groupById(attr.getAttribute('data-group-toggle'));
      if (group) await setGroupAccess(group.id, !group.blocked);
      return;
    }
    if ((attr = target.closest('[data-group-timer]'))) {
      const group = groupById(attr.getAttribute('data-group-timer'));
      if (group) openTimerDialog('group', group.id, group.name);
      return;
    }
    if ((attr = target.closest('[data-edit-group]'))) {
      openGroupDialog(parseInt(attr.getAttribute('data-edit-group'), 10));
      return;
    }
    if ((attr = target.closest('[data-delete-group]'))) {
      const group = groupById(attr.getAttribute('data-delete-group'));
      if (!group) return;
      confirmDialog('Delete group',
        'Delete “' + group.name + '”? Devices stay on the network but lose their grouping and schedules.',
        'Delete',
        async function () {
          try {
            await api('/api/groups/' + group.id, { method: 'DELETE' });
            toast('Group deleted', group.name, 'ok');
            await refresh(true);
          } catch (err) {
            toast('Could not delete group', err.message, 'error');
          }
        });
      return;
    }

    if ((attr = target.closest('[data-device-timer]'))) {
      const device = deviceByMac(attr.getAttribute('data-device-timer'));
      if (device) openTimerDialog('device', device.mac, device.name);
      return;
    }
    if ((attr = target.closest('[data-rename-device]'))) {
      openRenameDialog(attr.getAttribute('data-rename-device'));
      return;
    }
    if ((attr = target.closest('[data-remove-device]'))) {
      const mac = attr.getAttribute('data-remove-device');
      const device = deviceByMac(mac);
      confirmDialog('Forget device',
        'Remove “' + (device ? device.name : mac) + '” from the database? Its firewall rules and group membership are deleted.',
        'Forget',
        async function () {
          try {
            await api('/api/devices/' + encodeURIComponent(mac), { method: 'DELETE' });
            toast('Device removed', device ? device.name : mac, 'ok');
            await refresh(true);
          } catch (err) {
            toast('Could not remove device', err.message, 'error');
          }
        });
      return;
    }

    if ((attr = target.closest('[data-clear-timer]'))) {
      const id = attr.getAttribute('data-clear-timer');
      try {
        await api('/api/pauses/' + id, { method: 'DELETE' });
        toast('Timer cancelled', '', 'ok');
        await refresh(true);
      } catch (err) {
        toast('Could not cancel timer', err.message, 'error');
      }
      return;
    }

    if ((attr = target.closest('[data-toggle-schedule]'))) {
      const id = attr.getAttribute('data-toggle-schedule');
      const schedule = state.schedules.find(function (s) { return String(s.id) === String(id); });
      if (!schedule) return;
      try {
        await api('/api/schedules/' + id, { method: 'PATCH', body: { enabled: !schedule.enabled } });
        toast(schedule.enabled ? 'Schedule disabled' : 'Schedule enabled', schedule.name || 'Bedtime', 'ok');
        await refresh(true);
      } catch (err) {
        toast('Could not update schedule', err.message, 'error');
      }
      return;
    }
    if ((attr = target.closest('[data-edit-schedule]'))) {
      openScheduleDialog(parseInt(attr.getAttribute('data-edit-schedule'), 10));
      return;
    }
    if ((attr = target.closest('[data-delete-schedule]'))) {
      const id = attr.getAttribute('data-delete-schedule');
      confirmDialog('Delete schedule', 'Remove this weekly rule?', 'Delete', async function () {
        try {
          await api('/api/schedules/' + id, { method: 'DELETE' });
          toast('Schedule deleted', '', 'ok');
          await refresh(true);
        } catch (err) {
          toast('Could not delete schedule', err.message, 'error');
        }
      });
      return;
    }
  });
}

function startTimers() {
  state.refreshTimer = setInterval(function () { refresh(true); }, 30000);
  state.tickTimer = setInterval(function () {
    const now = Date.now() / 1000;
    $$('[data-countdown]').forEach(function (el) {
      const expires = parseInt(el.getAttribute('data-countdown'), 10);
      el.textContent = countdown(expires - now);
    });
    const clock = $('#clock');
    if (clock) clock.textContent = new Date().toLocaleString([], {
      weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  }, 1000);
}

/* =================================================================== init */
async function init() {
  try {
    const session = await api('/api/session');
    if (!session.authenticated) {
      window.location.href = '/login';
      return;
    }
    state.csrf = session.csrf;
    state.user = session.user;
    $('#user-name').textContent = session.user.username;
    $('#user-avatar').textContent = session.user.username.slice(0, 1).toUpperCase();
  } catch (err) {
    window.location.href = '/login';
    return;
  }

  bindEvents();
  startTimers();

  try {
    const data = await api('/api/overview');
    renderAll(data);
    if (!state.status.firewall.dry_run && state.status.policy.error) {
      toast('Firewall error', state.status.policy.error, 'error');
    }
  } catch (err) {
    toast('Could not load dashboard', err.message, 'error');
  }
}

document.addEventListener('DOMContentLoaded', init);
