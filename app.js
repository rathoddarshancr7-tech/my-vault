'use strict';

// ── State ──────────────────────────────────────────────────────────
let transactions  = [];
let chartInstance = null;
let currentPassword = '';
let currentSection  = 'dashboard';
let currentBill     = null; // { name, type, data }

// ── DOM ────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// Vault
const vaultScreen   = $('vault-screen');
const appShell      = $('app-shell');
const passwordInput = $('vault-password');
const unlockBtn     = $('unlock-btn');
const unlockText    = $('unlock-text');
const unlockSpinner = $('unlock-spinner');
const vaultError    = $('vault-error');
const togglePwBtn   = $('toggle-password');
const pwEyeIcon     = $('pw-eye-icon');

// Nav
const sidebar          = $('sidebar');
const sidebarOverlay   = $('sidebar-overlay');
const sidebarCloseBtn  = $('sidebar-close-btn');
const menuBtn          = $('menu-btn');
const topbarAddBtn     = $('topbar-add-btn');
const topbarTitle      = $('topbar-title');
const lockBtn          = $('lock-btn');
const exportBtn        = $('export-btn');
const bnavMenu         = $('bnav-menu');

// Dashboard
const totalExpenseEl = $('total-expense');
const totalMonthEl   = $('total-month');
const totalCountEl   = $('total-count');
const recentList     = $('recent-list');
const topCategories  = $('top-categories');
const weeklyReminder = $('weekly-reminder');
const dismissBtn     = $('dismiss-reminder-btn');

// Form
const transactionForm = $('transaction-form');
const categoryGroup   = $('category-group');
const categorySelect  = $('category');
const payeeGroup      = $('payee-group');
const payeeInput      = $('payee');
const paymentModes    = $('payment-modes');
const paymentModeHidden = $('payment-mode');
const uploadZone      = $('upload-zone');
const billFileInput   = $('bill-file');
const billPreview     = $('bill-preview');
const billThumb       = $('bill-thumb');
const billNameEl      = $('bill-name');
const removeBillBtn   = $('remove-bill-btn');

// History
const historyList  = $('history-list');
const historyCount = $('history-count');
const searchInput  = $('search-input');
const filterType   = $('filter-type');
const filterCategory = $('filter-category');
const filterMode   = $('filter-mode');

// Bills
const billsGrid  = $('bills-grid');
const billsEmpty = $('bills-empty');

// Modal
const billModal       = $('bill-modal');
const closeModalBtn   = $('close-modal-btn');
const modalTitle      = $('modal-title');
const modalSubtitle   = $('modal-subtitle');
const modalBillImg    = $('modal-bill-img');
const modalPdfBox     = $('modal-pdf-box');
const modalDetails    = $('modal-details');
const modalDownload   = $('modal-download');

// Toast
const toastEl  = $('toast');
const toastMsg = $('toast-message');

// ── Constants ──────────────────────────────────────────────────────
const CATEGORY_COLORS = {
  'Food':          '#f59e0b',
  'Travel':        '#3b82f6',
  'Rent':          '#8b5cf6',
  'Electricity':   '#f97316',
  'Grocery':       '#10b981',
  'Shopping':      '#ec4899',
  'Miscellaneous': '#6b7280',
  'Lending Money': '#ef4444',
};
const CATEGORY_EMOJI = {
  'Food':'🍔','Travel':'✈️','Rent':'🏠','Electricity':'⚡',
  'Grocery':'🛒','Shopping':'🛍️','Miscellaneous':'📦','Lending Money':'💸',
};
const PAYMENT_MODES = {
  cash:        { label: 'Cash',          color: '#059669', bg: '#ecfdf5' },
  paytm:       { label: 'Paytm',         color: '#1a56db', bg: '#ebf5ff' },
  phonepe:     { label: 'PhonePe',       color: '#6d28d9', bg: '#f5f3ff' },
  credit_card: { label: 'Credit Card',   color: '#d97706', bg: '#fffbeb' },
  debit_card:  { label: 'Debit Card',    color: '#2563eb', bg: '#eff6ff' },
  upi:         { label: 'UPI',           color: '#dc2626', bg: '#fef2f2' },
  bank:        { label: 'Bank',          color: '#475569', bg: '#f1f5f9' },
};
const SECTION_TITLES = {
  dashboard: 'Dashboard',
  add:       'Add Transaction',
  history:   'History',
  bills:     'Bills & Receipts',
};

// ── Encryption ─────────────────────────────────────────────────────
function uint8ToBase64(arr) {
  let s = '';
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s);
}
function base64ToUint8(b64) {
  const s = atob(b64);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
}
async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function encryptData(data, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const enc  = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(data))
  );
  const out = new Uint8Array(28 + enc.byteLength);
  out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(enc), 28);
  return uint8ToBase64(out);
}
async function decryptData(b64, password) {
  try {
    const b = base64ToUint8(b64);
    const key = await deriveKey(password, b.slice(0,16));
    const dec = await crypto.subtle.decrypt({ name:'AES-GCM', iv: b.slice(16,28) }, key, b.slice(28));
    return JSON.parse(new TextDecoder().decode(dec));
  } catch { return null; }
}
async function decryptLegacy(b64, password) {
  try {
    const enc = new TextEncoder();
    const b   = base64ToUint8(b64);
    const km  = await crypto.subtle.importKey('raw', enc.encode(password), { name:'PBKDF2' }, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name:'PBKDF2', salt: enc.encode('vault-salt'), iterations: 100000, hash: 'SHA-256' },
      km, { name:'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const dec = await crypto.subtle.decrypt({ name:'AES-GCM', iv: b.slice(0,12) }, key, b.slice(12));
    return JSON.parse(new TextDecoder().decode(dec));
  } catch { return null; }
}

// ── Vault ──────────────────────────────────────────────────────────
async function unlockVault() {
  const pwd = passwordInput.value;
  if (!pwd) { passwordInput.focus(); return; }
  unlockText.textContent = 'Unlocking…';
  unlockSpinner.classList.remove('hidden');
  unlockBtn.disabled = true;
  vaultError.classList.add('hidden');

  const stored = localStorage.getItem('vault_data');
  if (stored) {
    let dec = await decryptData(stored, pwd);
    if (!dec) { dec = await decryptLegacy(stored, pwd); if (dec) { currentPassword = pwd; transactions = dec; await saveData(); } }
    if (dec) { transactions = dec; currentPassword = pwd; showApp(); }
    else vaultError.classList.remove('hidden');
  } else {
    transactions = []; currentPassword = pwd; await saveData(); showApp();
  }
  unlockText.textContent = 'Unlock Vault';
  unlockSpinner.classList.add('hidden');
  unlockBtn.disabled = false;
}
async function saveData() {
  if (!currentPassword) return;
  localStorage.setItem('vault_data', await encryptData(transactions, currentPassword));
}
function lockVault() {
  transactions = []; currentPassword = ''; passwordInput.value = '';
  vaultError.classList.add('hidden');
  appShell.classList.remove('visible'); appShell.classList.add('hidden');
  vaultScreen.classList.remove('screen'); vaultScreen.classList.add('screen','active');
  lucide.createIcons();
}

function showApp() {
  vaultScreen.classList.remove('active');
  appShell.classList.remove('hidden'); appShell.classList.add('visible');
  $('date').valueAsDate = new Date();
  showSection('dashboard');
  lucide.createIcons();
}

// ── Navigation ─────────────────────────────────────────────────────
function showSection(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  const sec = $(`section-${name}`);
  if (sec) sec.classList.add('active');

  document.querySelectorAll('.nav-item[data-section], .bnav-item[data-section]').forEach(el => {
    el.classList.toggle('active', el.dataset.section === name);
  });

  topbarTitle.textContent = SECTION_TITLES[name] || name;
  currentSection = name;

  if (name === 'history') renderHistory();
  if (name === 'bills')   renderBills();
  if (name === 'dashboard') updateDashboard();

  // Close sidebar on mobile
  closeSidebar();
  // Scroll top
  const ca = document.querySelector('.content-area');
  if (ca) ca.scrollTo(0, 0);
}

function openSidebar() {
  sidebar.classList.add('open');
  sidebarOverlay.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}
function closeSidebar() {
  sidebar.classList.remove('open');
  sidebarOverlay.classList.add('hidden');
  document.body.style.overflow = '';
}

// ── Dashboard ──────────────────────────────────────────────────────
function formatDate(str) {
  const [y, m, d] = str.split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString('en-IN', { month: 'short', day: 'numeric', year: 'numeric' });
}
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])
  );
}

function updateDashboard() {
  let expense = 0, monthExpense = 0;
  const catTotals = {};
  const now = new Date();
  const curMonth = now.getMonth(), curYear = now.getFullYear();

  for (const tx of transactions) {
    if (tx.type === 'expense') {
      expense += tx.amount;
      catTotals[tx.category] = (catTotals[tx.category] || 0) + tx.amount;
      const [y,m] = tx.date.split('-').map(Number);
      if (m - 1 === curMonth && y === curYear) monthExpense += tx.amount;
    }
  }
  const count = transactions.filter(t => t.type === 'expense').length;
  totalExpenseEl.textContent = `₹${expense.toFixed(2)}`;
  totalMonthEl.textContent   = `₹${monthExpense.toFixed(2)}`;
  totalCountEl.textContent   = count;

  // ── Today's spend gadget ──────────────────────────────────────────
  const todayStr  = now.toISOString().slice(0, 10);
  let todaySpend = 0, todayCount = 0;
  const todayCats = new Set();
  for (const tx of transactions) {
    if (tx.type === 'expense' && tx.date === todayStr) {
      todaySpend += tx.amount;
      todayCount++;
      todayCats.add(tx.category);
    }
  }
  $('today-amount').textContent = `₹${todaySpend.toFixed(2)}`;
  $('today-meta').textContent   = todayCount === 0
    ? 'No transactions today'
    : `${todayCount} transaction${todayCount !== 1 ? 's' : ''} · ${todayCats.size} categor${todayCats.size !== 1 ? 'ies' : 'y'}`;
  const dayName  = now.toLocaleDateString('en-IN', { weekday: 'short' });
  const monthStr = now.toLocaleDateString('en-IN', { month: 'short' });
  $('today-date').textContent = `${dayName}, ${now.getDate()} ${monthStr}`;

  // Recent 5
  const recent = [...transactions].sort((a,b) => new Date(b.date)-new Date(a.date)).slice(0,5);
  renderTxList(recentList, recent, false);

  // Top categories
  renderTopCategories(catTotals);

  // Chart
  updateChart(catTotals);

  // Reminder
  checkWeeklyReminder();

  lucide.createIcons();
}

function renderTopCategories(catTotals) {
  const sorted = Object.entries(catTotals).sort((a,b) => b[1]-a[1]).slice(0,5);
  if (!sorted.length) { topCategories.innerHTML = '<p class="empty-small">No expense data yet.</p>'; return; }
  const max = sorted[0][1];
  topCategories.innerHTML = sorted.map(([cat, amt]) => `
    <div class="top-cat-item">
      <div class="top-cat-row">
        <span class="top-cat-name">${CATEGORY_EMOJI[cat]||'📦'} ${escapeHtml(cat)}</span>
        <span class="top-cat-amt">₹${amt.toFixed(0)}</span>
      </div>
      <div class="top-cat-bar">
        <div class="top-cat-fill" style="width:${(amt/max*100).toFixed(1)}%;background:${CATEGORY_COLORS[cat]||'#6b7280'}"></div>
      </div>
    </div>`).join('');
}

function updateChart(catTotals) {
  const ctx = $('expenseChart').getContext('2d');
  const chartEmpty = $('chart-empty');
  const labels = Object.keys(catTotals);
  const data   = Object.values(catTotals);
  if (chartInstance) { chartInstance.destroy(); chartInstance = null; }
  if (!data.length) { chartEmpty.classList.remove('hidden'); return; }
  chartEmpty.classList.add('hidden');
  const isMobile = window.innerWidth <= 768;
  chartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: labels.map(l => CATEGORY_COLORS[l]||'#6b7280'), borderWidth: 2, borderColor: '#fff', hoverOffset: 6 }] },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: isMobile ? '65%' : '70%',
      plugins: {
        legend: {
          position: isMobile ? 'bottom' : 'right',
          labels: { color: '#4c4780', font: { family: 'Outfit', size: isMobile ? 10 : 11 }, usePointStyle: true, pointStyleWidth: 7, padding: isMobile ? 10 : 12 }
        },
        tooltip: { callbacks: { label: ctx => ` ₹${ctx.parsed.toFixed(2)}` } }
      }
    }
  });
}

function checkWeeklyReminder() {
  const exp = transactions.filter(t => t.type === 'expense');
  if (!exp.length) return;
  const last = exp.reduce((a,b) => new Date(a.date) > new Date(b.date) ? a : b);
  if ((Date.now() - new Date(last.date)) / 86400000 > 7) weeklyReminder.classList.remove('hidden');
}

// ── Transaction rendering ──────────────────────────────────────────
function modeBadgeHtml(mode) {
  if (!mode) return '';
  const m = PAYMENT_MODES[mode] || { label: mode, color: '#6b7280', bg: '#f1f5f9' };
  return `<span class="mode-badge" style="color:${m.color};background:${m.bg}">${m.label}</span>`;
}

function createTxItem(tx, showDelete = true) {
  const color = CATEGORY_COLORS[tx.category] || '#6b7280';
  const emoji = tx.type === 'income' ? '💰' : (CATEGORY_EMOJI[tx.category] || '📦');
  const label = tx.type === 'income' ? 'Income' : tx.category;
  const sign  = tx.type === 'income' ? '+' : '-';

  const div = document.createElement('div');
  div.className = 'transaction-item';
  div.dataset.id = tx.id;
  div.innerHTML = `
    <div class="tx-left">
      <div class="tx-emoji" style="background:${color}18;color:${color}">${emoji}</div>
      <div class="tx-info">
        <span class="tx-cat">${escapeHtml(label)}</span>
        <div class="tx-meta">
          ${tx.payee  ? `<span class="tx-payee">→ ${escapeHtml(tx.payee)}</span>` : ''}
          ${tx.note   ? `<span class="tx-note">${escapeHtml(tx.note)}</span>` : ''}
          ${modeBadgeHtml(tx.paymentMode)}
        </div>
        <span class="tx-date">${formatDate(tx.date)}</span>
      </div>
    </div>
    <div class="tx-right">
      <span class="tx-amount ${tx.type}">${sign}₹${tx.amount.toFixed(2)}</span>
      ${tx.bill ? `<span class="bill-clip" data-id="${tx.id}" title="View receipt"><i data-lucide="paperclip"></i></span>` : ''}
      ${showDelete ? `<button class="tx-delete-btn" data-id="${tx.id}" title="Delete"><i data-lucide="trash-2"></i></button>` : ''}
    </div>`;
  return div;
}

function renderTxList(container, list, isRecent = false) {
  container.querySelectorAll('.transaction-item').forEach(el => el.remove());
  const empty = container.querySelector('.empty-state');
  if (!list.length) { if (empty) empty.classList.remove('hidden'); return; }
  if (empty) empty.classList.add('hidden');
  for (const tx of list) container.appendChild(createTxItem(tx, !isRecent));
  lucide.createIcons();
}

// ── History ────────────────────────────────────────────────────────
function getFiltered() {
  const q    = searchInput.value.toLowerCase();
  const type = filterType.value;
  const cat  = filterCategory.value;
  const mode = filterMode.value;
  return [...transactions]
    .filter(tx => {
      if (type !== 'all' && tx.type !== type) return false;
      if (cat  !== 'all' && tx.category !== cat) return false;
      if (mode !== 'all' && tx.paymentMode !== mode) return false;
      if (q) {
        const hay = [tx.category, tx.note, tx.payee, String(tx.amount), tx.date].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    })
    .sort((a,b) => new Date(b.date) - new Date(a.date))
    .slice(0, 20);
}

function renderHistory() {
  const filtered = getFiltered();
  historyCount.textContent = filtered.length
    ? `Showing ${filtered.length} of ${transactions.length} transaction${transactions.length!==1?'s':''}`
    : '';
  renderTxList(historyList, filtered);
}

// ── Bills ──────────────────────────────────────────────────────────
function renderBills() {
  const withBills = [...transactions]
    .filter(tx => tx.bill)
    .sort((a,b) => new Date(b.date) - new Date(a.date))
    .slice(0, 20);

  billsGrid.innerHTML = '';
  if (!withBills.length) {
    billsEmpty.classList.remove('hidden');
    billsGrid.classList.add('hidden');
    return;
  }
  billsEmpty.classList.add('hidden');
  billsGrid.classList.remove('hidden');

  for (const tx of withBills) {
    const isImg = tx.bill.type.startsWith('image/');
    const card  = document.createElement('div');
    card.className = 'bill-card'; card.dataset.id = tx.id;
    card.innerHTML = `
      ${isImg
        ? `<img class="bill-card-thumb" src="${tx.bill.data}" alt="Receipt" loading="lazy">`
        : `<div class="bill-card-pdf-thumb"><i data-lucide="file-text"></i><span>PDF</span></div>`}
      <div class="bill-card-info">
        <div class="bill-card-cat">${CATEGORY_EMOJI[tx.category]||'💰'} ${escapeHtml(tx.category || 'Income')}</div>
        ${tx.payee ? `<div class="bill-card-date" style="font-size:.75rem;color:#4b5563;font-weight:600;margin-bottom:2px">→ ${escapeHtml(tx.payee)}</div>` : ''}
        <div class="bill-card-amount">${tx.type==='expense'?'-':'+'  }₹${tx.amount.toFixed(2)}</div>
        <div class="bill-card-date">${formatDate(tx.date)}</div>
      </div>`;
    billsGrid.appendChild(card);
  }
  lucide.createIcons();
}

// ── Bill Preview Modal ─────────────────────────────────────────────
function openBillModal(txId) {
  const tx = transactions.find(t => t.id === txId);
  if (!tx || !tx.bill) return;

  const isImg = tx.bill.type.startsWith('image/');
  modalTitle.textContent    = tx.bill.name || 'Receipt';
  modalSubtitle.textContent = `${tx.category || 'Income'} · ${formatDate(tx.date)}`;

  modalBillImg.classList.add('hidden');
  modalPdfBox.classList.add('hidden');

  if (isImg) {
    modalBillImg.src = tx.bill.data;
    modalBillImg.classList.remove('hidden');
  } else {
    modalPdfBox.classList.remove('hidden');
  }

  const pm = PAYMENT_MODES[tx.paymentMode];
  modalDetails.innerHTML = `
    <div class="modal-detail-row"><span class="label">Amount</span><span class="value ${tx.type}" style="color:${tx.type==='income'?'#059669':'#dc2626'}">${tx.type==='income'?'+':'-'}₹${tx.amount.toFixed(2)}</span></div>
    ${tx.payee ? `<div class="modal-detail-row"><span class="label">Paid to</span><span class="value">${escapeHtml(tx.payee)}</span></div>` : ''}
    ${tx.paymentMode ? `<div class="modal-detail-row"><span class="label">Payment Mode</span><span class="value">${pm ? pm.label : tx.paymentMode}</span></div>` : ''}
    ${tx.note ? `<div class="modal-detail-row"><span class="label">Note</span><span class="value">${escapeHtml(tx.note)}</span></div>` : ''}
    <div class="modal-detail-row"><span class="label">Date</span><span class="value">${formatDate(tx.date)}</span></div>
  `;

  modalDownload.href     = tx.bill.data;
  modalDownload.download = tx.bill.name || 'receipt';
  billModal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  lucide.createIcons();
}
function closeBillModal() {
  billModal.classList.add('hidden');
  document.body.style.overflow = '';
  modalBillImg.src = '';
}

// ── Bill Upload ────────────────────────────────────────────────────
async function compressBill(file) {
  return new Promise(resolve => {
    if (!file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = e => resolve({ name: file.name, type: file.type, data: e.target.result });
      reader.readAsDataURL(file);
      return;
    }
    const reader = new FileReader();
    reader.onload = e => {
      const img = new Image();
      img.onload = () => {
        const MAX = 900;
        let w = img.width, h = img.height;
        if (w > MAX) { h = Math.round(h * MAX / w); w = MAX; }
        if (h > MAX) { w = Math.round(w * MAX / h); h = MAX; }
        const canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        canvas.getContext('2d').drawImage(img, 0, 0, w, h);
        resolve({ name: file.name.replace(/\.[^.]+$/, '.jpg'), type: 'image/jpeg', data: canvas.toDataURL('image/jpeg', 0.75) });
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  });
}

async function handleBillFile(file) {
  if (file.size > 5 * 1024 * 1024) { showToast('File too large. Max 5 MB.', 'warning'); return; }
  currentBill = await compressBill(file);
  billThumb.src       = currentBill.data;
  billNameEl.textContent = currentBill.name;
  billThumb.style.display = currentBill.type.startsWith('image/') ? 'block' : 'none';
  uploadZone.classList.add('hidden');
  billPreview.classList.remove('hidden');
}

// ── PDF Export ─────────────────────────────────────────────────────
function exportPDF() {
  if (!transactions.length) { showToast('No transactions to export.', 'warning'); return; }
  const { jsPDF } = window.jspdf;
  const doc  = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pw   = doc.internal.pageSize.getWidth();

  let income = 0, expense = 0;
  for (const tx of transactions) { if (tx.type==='income') income+=tx.amount; else expense+=tx.amount; }
  const savings = income - expense;

  // Header
  doc.setFillColor(17,24,39); doc.rect(0,0,pw,38,'F');
  doc.setTextColor(255,255,255); doc.setFontSize(20); doc.setFont('helvetica','bold');
  doc.text('My Vault',14,16);
  doc.setFontSize(9); doc.setFont('helvetica','normal');
  doc.text('Personal Finance Report',14,24);
  doc.text(`Generated: ${new Date().toLocaleDateString('en-IN',{day:'numeric',month:'long',year:'numeric'})}`,14,31);

  // Summary
  let y = 48;
  doc.setTextColor(17,24,39); doc.setFontSize(11); doc.setFont('helvetica','bold');
  doc.text('Summary',14,y); y += 7;
  const cw = (pw-28-8)/3;
  [
    { label:'Total Income',   value:`+₹${income.toFixed(2)}`,  rgb:[5,150,105],   bg:[236,253,245] },
    { label:'Total Expenses', value:`-₹${expense.toFixed(2)}`, rgb:[220,38,38],   bg:[254,242,242] },
    { label:'Net Savings',    value:`₹${savings.toFixed(2)}`,  rgb: savings>=0?[37,99,235]:[220,38,38], bg: savings>=0?[239,246,255]:[254,242,242] },
  ].forEach((s,i) => {
    const x = 14 + i*(cw+4);
    doc.setFillColor(...s.bg); doc.setDrawColor(229,231,235);
    doc.roundedRect(x,y,cw,24,2,2,'FD');
    doc.setFontSize(8); doc.setFont('helvetica','normal'); doc.setTextColor(107,114,128);
    doc.text(s.label,x+5,y+8);
    doc.setFontSize(11); doc.setFont('helvetica','bold'); doc.setTextColor(...s.rgb);
    doc.text(s.value,x+5,y+18);
  });
  y += 32;

  doc.setTextColor(17,24,39); doc.setFontSize(11); doc.setFont('helvetica','bold');
  doc.text('Transactions',14,y); y += 4;

  const sorted = [...transactions].sort((a,b)=>new Date(b.date)-new Date(a.date));
  doc.autoTable({
    startY: y,
    head: [['Date','Type','Category','Payee','Mode','Amount']],
    body: sorted.map(tx => [
      formatDate(tx.date), tx.type.charAt(0).toUpperCase()+tx.type.slice(1),
      tx.category||'—', tx.payee||'—',
      PAYMENT_MODES[tx.paymentMode]?.label || tx.paymentMode || '—',
      `${tx.type==='income'?'+':'-'}₹${tx.amount.toFixed(2)}`
    ]),
    theme: 'grid',
    headStyles: { fillColor:[17,24,39], textColor:[255,255,255], fontStyle:'bold', fontSize:8, cellPadding:3.5 },
    bodyStyles: { fontSize:8, textColor:[31,41,55], cellPadding:3 },
    alternateRowStyles: { fillColor:[249,250,251] },
    columnStyles: { 0:{cellWidth:28}, 1:{cellWidth:18}, 2:{cellWidth:26}, 3:{cellWidth:'auto'}, 4:{cellWidth:22}, 5:{cellWidth:28,halign:'right',fontStyle:'bold'} },
    didParseCell: d => {
      if (d.section==='body' && d.column.index===5) d.cell.styles.textColor = d.cell.raw.startsWith('+') ? [5,150,105] : [220,38,38];
    },
    margin: { left:14, right:14 },
  });

  const pc = doc.internal.getNumberOfPages(), ph = doc.internal.pageSize.getHeight();
  for (let i=1;i<=pc;i++) {
    doc.setPage(i); doc.setFontSize(7); doc.setTextColor(156,163,175);
    doc.text(`Page ${i} of ${pc}`,pw-14,ph-8,{align:'right'});
    doc.text('My Vault',14,ph-8);
  }
  doc.save('expense-vault-report.pdf');
  showToast('PDF downloaded!');
}

// ── Form Events ────────────────────────────────────────────────────

// Payee: required when amount > 5000
function checkPayeeRequired() {
  const amt = parseFloat($('amount').value) || 0;
  const show = amt > 5000;
  payeeGroup.classList.toggle('hidden', !show);
  payeeInput.required = show;
}
$('amount').addEventListener('input', checkPayeeRequired);

// Payment mode chips
paymentModes.addEventListener('click', e => {
  const chip = e.target.closest('.mode-chip');
  if (!chip) return;
  paymentModes.querySelectorAll('.mode-chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  paymentModeHidden.value = chip.dataset.mode;
});

// Upload zone
uploadZone.addEventListener('click', () => billFileInput.click());
uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop', e => {
  e.preventDefault(); uploadZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0]; if (f) handleBillFile(f);
});
billFileInput.addEventListener('change', e => { const f = e.target.files[0]; if (f) handleBillFile(f); });
removeBillBtn.addEventListener('click', () => {
  currentBill = null; billFileInput.value = '';
  billPreview.classList.add('hidden'); uploadZone.classList.remove('hidden');
});

// Submit
transactionForm.addEventListener('submit', async e => {
  e.preventDefault();
  const type     = 'expense';
  const amount   = parseFloat($('amount').value);
  const date     = $('date').value;
  const category = type === 'expense' ? categorySelect.value : null;
  const note     = $('note').value.trim();
  const payee    = payeeInput.value.trim();
  const mode     = paymentModeHidden.value;

  if (!amount || amount <= 0 || !date) return;
  if (amount > 5000 && !payee) { payeeInput.focus(); showToast('Please enter who you are paying.', 'warning'); return; }

  const tx = { id: crypto.randomUUID(), type, amount, date, category, paymentMode: mode };
  if (note)  tx.note  = note;
  if (payee) tx.payee = payee;
  if (currentBill) tx.bill = currentBill;

  transactions.push(tx);
  await saveData();

  // Reset form
  transactionForm.reset();
  $('date').valueAsDate = new Date();
  payeeGroup.classList.add('hidden');
  payeeInput.required = false;
  paymentModes.querySelectorAll('.mode-chip').forEach(c => c.classList.remove('active'));
  paymentModes.querySelector('[data-mode="cash"]').classList.add('active');
  paymentModeHidden.value = 'cash';
  currentBill = null; billFileInput.value = '';
  billPreview.classList.add('hidden'); uploadZone.classList.remove('hidden');

  updateDashboard();
  weeklyReminder.classList.add('hidden');
  showToast('Transaction added!');
  showSection('dashboard');
  lucide.createIcons();
});

// Delete (event delegation on both lists)
function handleDeleteClick(e) {
  const btn = e.target.closest('.tx-delete-btn');
  if (!btn) return;
  (async () => {
    transactions = transactions.filter(t => t.id !== btn.dataset.id);
    await saveData();
    updateDashboard();
    if (currentSection === 'history') renderHistory();
    if (currentSection === 'bills')   renderBills();
    showToast('Transaction deleted.');
  })();
}
historyList.addEventListener('click', handleDeleteClick);
recentList.addEventListener('click', handleDeleteClick);

// Bill clip click
document.querySelector('.content-area').addEventListener('click', e => {
  const clip = e.target.closest('.bill-clip');
  if (clip) openBillModal(clip.dataset.id);
  const billCard = e.target.closest('.bill-card');
  if (billCard) openBillModal(billCard.dataset.id);
  const navLink = e.target.closest('[data-section]');
  if (navLink && !navLink.classList.contains('nav-item') && !navLink.classList.contains('bnav-item') && !navLink.classList.contains('bnav-fab')) {
    showSection(navLink.dataset.section);
  }
});

// ── Global Events ──────────────────────────────────────────────────
unlockBtn.addEventListener('click', unlockVault);
passwordInput.addEventListener('keydown', e => e.key === 'Enter' && unlockVault());
togglePwBtn.addEventListener('click', () => {
  const show = passwordInput.type === 'password';
  passwordInput.type = show ? 'text' : 'password';
  pwEyeIcon.setAttribute('data-lucide', show ? 'eye-off' : 'eye');
  lucide.createIcons();
});

lockBtn.addEventListener('click', lockVault);
exportBtn.addEventListener('click', exportPDF);
menuBtn.addEventListener('click', openSidebar);
sidebarOverlay.addEventListener('click', closeSidebar);
sidebarCloseBtn.addEventListener('click', closeSidebar);
bnavMenu.addEventListener('click', openSidebar);

topbarAddBtn.addEventListener('click', () => showSection('add'));
dismissBtn.addEventListener('click', () => weeklyReminder.classList.add('hidden'));

// Nav items (sidebar + bottom nav)
document.addEventListener('click', e => {
  const item = e.target.closest('.nav-item[data-section], .bnav-item[data-section], .bnav-fab[data-section]');
  if (item) showSection(item.dataset.section);
});

// Filters
[searchInput, filterType, filterCategory, filterMode].forEach(el =>
  el?.addEventListener('input', () => { if (currentSection==='history') renderHistory(); })
);

// Modal close
closeModalBtn.addEventListener('click', closeBillModal);
billModal.addEventListener('click', e => { if (e.target === billModal) closeBillModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeBillModal(); });

// ── Toast ──────────────────────────────────────────────────────────
let toastTimer;
function showToast(msg, type = 'success') {
  clearTimeout(toastTimer);
  toastMsg.textContent = msg;
  toastEl.className = `toast ${type} show`;
  toastTimer = setTimeout(() => toastEl.classList.remove('show'), 3000);
}

// ── Init ───────────────────────────────────────────────────────────
lucide.createIcons();
