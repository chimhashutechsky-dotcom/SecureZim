const $ = (selector) => document.querySelector(selector);
const api = async (url, options = {}) => {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || 'Something went wrong');
  return body;
};

const toast = (message, error = false) => {
  const el = $('#toast'); el.textContent = message; el.className = `toast visible ${error ? 'error' : ''}`;
  setTimeout(() => el.classList.remove('visible'), 3500);
};
const openModal = (id) => { const el = $(`#${id}`); el.hidden = false; document.body.classList.add('modal-open'); loadCompanies(); };
const closeModals = () => { document.querySelectorAll('.modal-backdrop').forEach((el) => { el.hidden = true; }); document.body.classList.remove('modal-open'); };
document.querySelectorAll('[data-open-modal]').forEach((button) => button.addEventListener('click', () => openModal(button.dataset.openModal)));
document.querySelectorAll('[data-close-modal]').forEach((button) => button.addEventListener('click', closeModals));
document.querySelectorAll('.modal-backdrop').forEach((el) => el.addEventListener('click', (event) => { if (event.target === el) closeModals(); }));

async function loadCompanies() {
  const companies = await api('/api/companies');
  const select = $('#company-select');
  if (!companies.length) { select.innerHTML = '<option value="">Create a company first</option>'; return; }
  select.innerHTML = companies.map((company) => `<option value="${company.id}">${escapeHtml(company.name)}</option>`).join('');
}
async function loadDashboard() {
  try {
    const [summary, assets, scans] = await Promise.all([api('/api/summary'), api('/api/assets'), api('/api/scans')]);
    Object.entries(summary).forEach(([key, value]) => { const el = $(`#${key}-count`); if (el) el.textContent = value; });
    $('#assets-list').innerHTML = assets.length ? assets.map(assetCard).join('') : '<div class="empty">No assets yet. Add your first authorized asset above.</div>';
    $('#scans-list').innerHTML = scans.length ? scans.map(scanRow).join('') : '<div class="empty">No scans yet. Add an asset to begin monitoring.</div>';
    document.querySelectorAll('[data-scan]').forEach((button) => button.addEventListener('click', () => startScan(button.dataset.scan, button)));
  } catch (error) { toast(error.message, true); }
}
const assetCard = (asset) => `<div class="asset-row"><span class="asset-icon">◈</span><div class="asset-main"><strong>${escapeHtml(asset.target)}</strong><small>Asset #${asset.id} · Authorized</small></div><span class="pill"><span class="status-dot"></span> Ready</span><button class="scan-button" data-scan="${asset.id}">Scan now</button></div>`;
const scanRow = (scan) => `<div class="scan-row"><strong>${escapeHtml(scan.target)}</strong><span class="status ${scan.status}">${scan.status}</span><strong>${scan.security_score ?? '—'}${scan.security_score != null ? '<small>/100</small>' : ''}</strong><span>${scan.finished_at ? new Date(scan.finished_at).toLocaleDateString() : 'In progress'}</span></div>`;
async function startScan(id, button) { button.disabled = true; button.textContent = 'Scanning…'; try { await api(`/api/scans/${id}`, { method: 'POST' }); toast('Scan completed successfully'); await loadDashboard(); } catch (error) { toast(error.message, true); button.disabled = false; button.textContent = 'Scan now'; } }
$('#asset-form').addEventListener('submit', async (event) => { event.preventDefault(); const form = new FormData(event.target); const message = $('#form-message'); try { await api('/api/assets', { method: 'POST', body: JSON.stringify({ company_id: Number(form.get('company_id')), target: form.get('target'), authorized: form.get('authorized') === 'on' }) }); closeModals(); event.target.reset(); toast('Asset added to your protected inventory'); await loadDashboard(); } catch (error) { message.textContent = error.message; message.className = 'form-message error-text'; } });
$('#refresh-button').addEventListener('click', loadDashboard);
function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char])); }
loadDashboard();
