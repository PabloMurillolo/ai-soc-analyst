'use strict';
const $ = s => document.querySelector(s);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const time = s => new Date(s).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
const date = s => new Date(s).toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
const attackUrl = id => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
let state, selected, provider = 'offline', activeView = 'overview';
async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {headers:{'Content-Type':'application/json'}, ...options});
  if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${response.status}).`); }
  return response.json();
}
function notice(message, error=false) { $('#notice').textContent = `${error ? 'Error: ' : ''}${message}`; $('#notice').hidden = false; }
async function refresh() {
  state = await api('/overview');
  const active = (state.counts.open || 0) + (state.counts.investigating || 0);
  $('#stat-active').textContent = active; $('#queue-count').textContent = active;
  $('#stat-critical').textContent = state.critical; $('#stat-events').textContent = state.events.toLocaleString();
  $('#pipe-events').textContent = state.events; $('#pipe-incidents').textContent = state.total_incidents;
  $('#incident-total').textContent = state.total_incidents;
  $('#coverage-list').innerHTML = state.rules.map(r => `<a class="coverage-row" href="${attackUrl(r.technique)}" target="_blank" rel="noreferrer"><code>${esc(r.technique)}</code><span>${esc(r.tactic)}</span><small>1 rule ↗</small></a>`).join('');
  renderQueue();
  $('#rule-cards').innerHTML = state.rules.map(r => `<article class="card"><code>${esc(r.id)}</code> <span class="severity ${r.severity}">${esc(r.severity)}</span><h2>${esc(r.name)}</h2><p>${esc(r.description)}</p><p><strong>Threshold</strong><br>${esc(r.threshold)}</p><p><strong>Potential false positive</strong><br>${esc(r.false_positive)}</p><a href="${attackUrl(r.technique)}" target="_blank" rel="noreferrer">${esc(r.technique)} · ${esc(r.tactic)} ↗</a></article>`).join('');
  $('#scenario-cards').innerHTML = Object.entries(state.scenarios).map(([id,s]) => `<article class="card"><span class="pill cyan">SYNTHETIC</span><h2>${esc(s.name)}</h2><p>${esc(s.description)}</p><code>${esc(s.technique || 'Negative control')}</code><br><button class="primary simulate" data-scenario="${id}">▷ Run scenario</button></article>`).join('');
  $('#simulation-choices').innerHTML = Object.entries(state.scenarios).map(([id,s]) => `<button class="scenario-choice simulate" data-scenario="${id}">${esc(s.name)} <small>${esc(s.description)}</small></button>`).join('');
  document.querySelectorAll('.simulate').forEach(b => b.addEventListener('click', () => simulate(b.dataset.scenario)));
  $('#run-history').innerHTML = state.runs.map(r => `<div class="run-row"><span>${esc(state.scenarios[r.scenario]?.name || r.scenario)} <span class="muted">· ${esc(r.id.slice(0,8))}</span></span><time>${date(r.created_at)}</time></div>`).join('') || '<div class="empty">No simulations yet.</div>';
}
function renderQueue() {
  const query = $('#search').value.toLowerCase();
  const rows = state.incidents.filter(i => (!$('#severity-filter').value || i.severity === $('#severity-filter').value) && (!$('#status-filter').value || i.status === $('#status-filter').value) && `${i.title} ${i.host} ${i.user} ${i.id} ${i.rule_id}`.toLowerCase().includes(query));
  $('#incident-rows').innerHTML = rows.map(i => `<tr><td><button class="incident-link" data-id="${i.id}"><strong>${esc(i.title)}</strong><small>INC-${esc(i.id.slice(0,8).toUpperCase())} <span> · ${esc(i.rule_id)}</span></small></button></td><td><span class="severity ${i.severity}">${esc(i.severity[0].toUpperCase()+i.severity.slice(1))}</span></td><td>${esc(i.host)}<small>${esc(i.user)}</small></td><td><span class="status ${i.status}">${esc(i.status[0].toUpperCase()+i.status.slice(1))}</span></td><td>${time(i.created_at)}<small>${new Date(i.created_at).toLocaleDateString([], {month:'short',day:'numeric'})}</small></td><td><button class="text-button incident-link" data-id="${i.id}" aria-label="Investigate ${esc(i.title)}">↗</button></td></tr>`).join('') || '<tr><td colspan="6" class="empty">No incidents match these filters. Try another search or run a simulation.</td></tr>';
  $('#results-count').textContent = `Showing ${rows.length} of ${state.total_incidents} incidents${state.total_incidents > 500 ? ' (latest 500 loaded)' : ''}`;
  document.querySelectorAll('.incident-link').forEach(b => b.addEventListener('click', () => openIncident(b.dataset.id)));
}
function navigate(view) {
  activeView = view;
  document.querySelectorAll('.nav').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  const titles = {overview:['Operations overview','From signal to investigation. Every finding backed by evidence.'],incidents:['Incident queue','Review the evidence. Record the decision. Move the investigation forward.'],detections:['Detection library','Transparent logic, practical thresholds, and ATT&CK context.'],simulations:['Simulation lab','Create safe, repeatable scenarios and watch your detections respond.']};
  $('#page-title').textContent = titles[view][0]; $('#page-description').textContent = titles[view][1];
  $('#breadcrumb').textContent = view === 'overview' ? 'Overview' : titles[view][0];
  document.querySelectorAll('.view').forEach(el => el.hidden = el.id !== `view-${view === 'incidents' ? 'overview' : view}`);
  document.querySelectorAll('.stats,.overview-grid,.bottom-note').forEach(el => el.hidden = view === 'incidents');
}
async function simulate(scenario) {
  document.querySelectorAll('.simulate').forEach(b => b.disabled = true);
  try {
    const result = await api('/simulations', {method:'POST', body:JSON.stringify({scenario})});
    $('#simulation-dialog').close(); await refresh();
    notice(`${state.scenarios[scenario].name}: ${result.events_created} events analyzed, ${result.incidents_created} incident(s) created.`);
  } catch (e) { $('#simulation-dialog').close(); notice(e.message,true); }
  finally { document.querySelectorAll('.simulate').forEach(b => b.disabled = false); }
}
async function openIncident(id) {
  try {
    selected = await api(`/incidents/${id}`); renderDetail();
    if (!$('#incident-dialog').open) $('#incident-dialog').showModal();
  } catch (e) { notice(e.message,true); }
}
function renderDetail() {
  const i = selected, r = i.rule;
  $('#detail-content').innerHTML = `<h2 class="detail-title">${esc(i.title)}</h2><div class="detail-meta"><span class="severity ${i.severity}">${esc(i.severity.toUpperCase())}</span><span class="muted">INC-${esc(i.id.slice(0,8).toUpperCase())}</span><a href="${attackUrl(r.technique)}" target="_blank" rel="noreferrer">${esc(r.technique)} ↗</a><span class="pill cyan">SYNTHETIC</span></div><div class="detail-grid"><div><section class="detail-section"><h3>Detection rationale</h3><p>${esc(r.description)}</p><p><br><strong>Asset:</strong> ${esc(i.host)}<br><strong>User:</strong> ${esc(i.user)}<br><strong>Detected:</strong> ${date(i.created_at)}</p><p><br><strong>Alternative explanation:</strong> ${esc(r.false_positive)}</p></section><section class="detail-section"><h3>Event evidence · ${i.evidence.length} records</h3><pre class="evidence">${esc(JSON.stringify(i.evidence,null,2))}</pre></section><section class="detail-section"><h3>Suggested response</h3><ol>${r.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol></section></div><div><section class="detail-section"><h3>✧ Investigation assistant</h3><div class="assistant-intro">${provider === 'ollama' ? 'Local Ollama model · AI output requires analyst verification.' : 'Offline guide · deterministic, rule-based responses. Enable Ollama for local generative AI.'}</div><div class="suggestions"><button data-question="Summarize the evidence">Summarize evidence</button><button data-question="Could this be a false positive?">False positives</button><button data-question="What should I do next?">Next steps</button></div><div id="chat-output" class="chat-output" role="status">Ask about the evidence, alternative explanations, or next steps.</div><form id="question-form"><label for="question">Ask about this incident</label><textarea id="question" maxlength="2000" required placeholder="What should I investigate next?"></textarea><button class="primary" id="ask-button" type="submit">Investigate ↗</button></form></section><section class="detail-section"><h3>Analyst decision</h3><form id="decision-form"><label for="decision-status">Status</label><select id="decision-status">${['open','investigating','resolved'].map(s => `<option ${s===i.status?'selected':''} value="${s}">${s[0].toUpperCase()+s.slice(1)}</option>`).join('')}</select><label for="decision-note">Investigation note</label><textarea id="decision-note" maxlength="2000" placeholder="Record your findings and rationale…"></textarea><button class="primary" type="submit">Save decision</button><p id="decision-feedback" role="status"></p></form></section><section class="detail-section"><h3>Audit trail</h3>${i.audit.map(a => `<div class="audit-row">${esc(a.action)}<small>${date(a.created_at)}</small><p>${esc(a.note)}</p></div>`).join('')}</section></div></div>`;
  $('#question-form').addEventListener('submit', e => { e.preventDefault(); ask($('#question').value); });
  document.querySelectorAll('[data-question]').forEach(b => b.addEventListener('click', () => { $('#question').value = b.dataset.question; ask(b.dataset.question); }));
  $('#decision-form').addEventListener('submit', async e => {
    e.preventDefault(); const button = e.submitter; button.disabled = true;
    try { selected = await api(`/incidents/${i.id}`, {method:'PATCH', body:JSON.stringify({status:$('#decision-status').value,note:$('#decision-note').value})}); await refresh(); renderDetail(); $('#decision-feedback').textContent = 'Decision saved to the audit trail.'; }
    catch (error) { $('#decision-feedback').textContent = error.message; button.disabled = false; }
  });
}
async function ask(question) {
  if (!question.trim()) return;
  const id = selected.id, output = $('#chat-output');
  const controls = [...document.querySelectorAll('#ask-button,[data-question]')]; controls.forEach(b => b.disabled = true);
  output.textContent = 'Reviewing incident evidence…';
  try { const result = await api(`/incidents/${id}/investigate`, {method:'POST',body:JSON.stringify({question})}); if (selected.id === id) output.textContent = result.answer; }
  catch(e) { output.textContent = e.message; }
  finally { controls.forEach(b => b.disabled = false); }
}
document.querySelectorAll('.nav').forEach(b => b.addEventListener('click', () => navigate(b.dataset.view)));
$('#view-all').addEventListener('click', () => navigate('incidents'));
$('#run-demo').addEventListener('click', () => $('#simulation-dialog').showModal());
$('#close-simulation').addEventListener('click', () => $('#simulation-dialog').close());
$('#close-detail').addEventListener('click', () => $('#incident-dialog').close());
['search','severity-filter','status-filter'].forEach(id => $(`#${id}`).addEventListener('input', () => state && renderQueue()));
$('#clock').textContent = new Date().toLocaleDateString([], {month:'short',day:'numeric',year:'numeric'});
(async () => { try { const health = await api('/health'); provider = health.ai_provider; await refresh(); } catch(e) { notice(`Unable to load the workspace. ${e.message} Refresh to retry.`,true); } })();
