'use strict';

// ── State ──────────────────────────────────────────────────────────
let transactions  = [];
let budgets       = {};   // { category: monthlyLimit }
let chartInstance = null;
let weeklyChartInst  = null;
let monthlyChartInst = null;
let calYear  = new Date().getFullYear();
let calMonth = new Date().getMonth();
let currentPassword = '';
let currentSection  = 'dashboard';
let currentBill     = null; // { name, type, data }
let editingId       = null; // id of tx being edited, or null
let splitTxId       = null; // id of tx being split, or null
let undoBuffer      = null; // { tx, timer } — pending delete
let savingsGoal     = 0;    // monthly savings target (₹)
let bulkMode        = false;
let bulkSelected    = new Set();
let voiceRecognition = null;
let reminderTimerId  = null;
let tesseractLoaded  = false;
let tesseractLoading = false;
let bowlPeriod       = 'month'; // 'month' | 'all'

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
  dashboard:  'Dashboard',
  add:        'Add Transaction',
  analytics:  'Analytics',
  history:    'History',
  calendar:   'Calendar',
  budget:     'Budget Planner',
  bills:      'Bills & Receipts',
  moneybowl:  'Money Bowl',
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

// ── Biometric (Face ID / Touch ID) ────────────────────────────────
async function isBiometricAvailable() {
  try {
    if (!window.PublicKeyCredential) return false;
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch { return false; }
}
function getBiometricData() {
  try { return JSON.parse(localStorage.getItem('vault_biometric') || 'null'); }
  catch { return null; }
}
async function registerBiometric(password) {
  try {
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge, rp: { name: 'My Vault' },
        user: { id: userId, name: 'vault', displayName: 'My Vault' },
        pubKeyCredParams: [{ type:'public-key', alg:-7 }, { type:'public-key', alg:-257 }],
        authenticatorSelection: { authenticatorAttachment:'platform', userVerification:'required' },
        extensions: { prf: { eval: { first: new TextEncoder().encode('my-vault-v1') } } },
        timeout: 60000
      }
    });
    const prfOut = cred.getClientExtensionResults()?.prf?.results?.first;
    let stored;
    if (prfOut) {
      const iv  = crypto.getRandomValues(new Uint8Array(12));
      const km  = await crypto.subtle.importKey('raw', prfOut, 'HKDF', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey(
        { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('my-vault-bio') },
        km, { name:'AES-GCM', length:256 }, false, ['encrypt']
      );
      const enc = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(password));
      const combined = new Uint8Array(12 + enc.byteLength);
      combined.set(iv); combined.set(new Uint8Array(enc), 12);
      stored = { credId: uint8ToBase64(new Uint8Array(cred.rawId)), enc: uint8ToBase64(combined), prf: true };
    } else {
      stored = { credId: uint8ToBase64(new Uint8Array(cred.rawId)), enc: btoa(encodeURIComponent(password)), prf: false };
    }
    localStorage.setItem('vault_biometric', JSON.stringify(stored));
    return true;
  } catch (err) { console.warn('Biometric register failed:', err.message); return false; }
}
async function authenticateWithBiometric() {
  const data = getBiometricData();
  if (!data) return null;
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge, rpId: location.hostname,
        allowCredentials: [{ type:'public-key', id: base64ToUint8(data.credId) }],
        userVerification: 'required',
        extensions: data.prf ? { prf: { eval: { first: new TextEncoder().encode('my-vault-v1') } } } : {},
        timeout: 60000
      }
    });
    if (data.prf) {
      const prfOut = assertion.getClientExtensionResults()?.prf?.results?.first;
      if (!prfOut) throw new Error('PRF unavailable');
      const km  = await crypto.subtle.importKey('raw', prfOut, 'HKDF', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey(
        { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('my-vault-bio') },
        km, { name:'AES-GCM', length:256 }, false, ['decrypt']
      );
      const enc = base64ToUint8(data.enc);
      const dec = await crypto.subtle.decrypt({ name:'AES-GCM', iv: enc.slice(0,12) }, key, enc.slice(12));
      return new TextDecoder().decode(dec);
    } else {
      return decodeURIComponent(atob(data.enc));
    }
  } catch (err) { console.warn('Biometric auth failed:', err.message); return null; }
}
async function initBiometricUI() {
  const hasData   = !!getBiometricData();
  const available = await isBiometricAvailable();
  // Vault screen unlock button — only shown when registered
  $('biometric-btn').classList.toggle('hidden', !(hasData && available));
  // Sidebar: Enable button — shown when available but NOT yet registered
  $('enable-faceid-sidebar-btn')?.classList.toggle('hidden', hasData || !available);
  // Sidebar: Disable button — shown when registered
  $('disable-faceid-btn')?.classList.toggle('hidden', !hasData);
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
    if (!dec) { dec = await decryptLegacy(stored, pwd); }
    if (dec) {
      let migrated = false;
      if (Array.isArray(dec)) {
        // Old format — plain array. Migrate to new object format.
        transactions = dec; budgets = {}; migrated = true;
      } else if (dec && typeof dec === 'object') {
        // New format — { transactions, budgets, savingsGoal }
        transactions = Array.isArray(dec.transactions) ? dec.transactions : [];
        budgets      = (dec.budgets && typeof dec.budgets === 'object') ? dec.budgets : {};
        savingsGoal  = typeof dec.savingsGoal === 'number' ? dec.savingsGoal : 0;
      }
      currentPassword = pwd;
      // Only write back if we migrated format — never overwrite with empty
      if (migrated && transactions.length > 0) await saveData();
      showApp(false);
    } else vaultError.classList.remove('hidden');
  } else {
    // Brand new vault — nothing stored yet
    transactions = []; budgets = {}; currentPassword = pwd; await saveData(); showApp(false);
  }
  unlockText.textContent = 'Unlock Vault';
  unlockSpinner.classList.add('hidden');
  unlockBtn.disabled = false;
}
async function saveData() {
  if (!currentPassword) return;
  localStorage.setItem('vault_data', await encryptData({ transactions, budgets, savingsGoal }, currentPassword));
}
function lockVault() {
  transactions = []; budgets = {}; savingsGoal = 0;
  if (undoBuffer) { clearTimeout(undoBuffer.timer); undoBuffer = null; }
  bulkMode = false; bulkSelected.clear();
  currentPassword = ''; passwordInput.value = '';
  vaultError.classList.add('hidden');
  appShell.classList.remove('visible'); appShell.classList.add('hidden');
  vaultScreen.classList.remove('screen'); vaultScreen.classList.add('screen','active');
  lucide.createIcons();
}

async function showApp(fromBiometric = false) {
  vaultScreen.classList.remove('active');
  appShell.classList.remove('hidden'); appShell.classList.add('visible');
  $('date').valueAsDate = new Date();
  showSection('dashboard');
  lucide.createIcons();
  // Offer Face ID setup after first password unlock (not after biometric unlock)
  if (!fromBiometric && !getBiometricData() && await isBiometricAvailable()) {
    $('faceid-banner').classList.remove('hidden');
  }
  initBiometricUI();
}

// ── Navigation ─────────────────────────────────────────────────────
function showSection(name) {
  // If navigating away from add while editing, reset form
  if (currentSection === 'add' && name !== 'add' && editingId) resetFormToAdd();

  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  const sec = $(`section-${name}`);
  if (sec) sec.classList.add('active');

  document.querySelectorAll('.nav-item[data-section], .bnav-item[data-section]').forEach(el => {
    el.classList.toggle('active', el.dataset.section === name);
  });

  topbarTitle.textContent = SECTION_TITLES[name] || name;
  currentSection = name;

  if (name === 'history')    renderHistory();
  if (name === 'bills')      renderBills();
  if (name === 'dashboard')  updateDashboard();
  if (name === 'analytics')  renderAnalytics();
  if (name === 'calendar')   renderCalendar();
  if (name === 'budget')     renderBudget();
  if (name === 'moneybowl')  renderMoneyBowl();

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
  let expense = 0, monthExpense = 0, totalIncome = 0;
  const catTotals = {};
  const now = new Date();
  const curMonth = now.getMonth(), curYear = now.getFullYear();

  for (const tx of transactions) {
    const [y,m] = tx.date.split('-').map(Number);
    if (tx.type === 'expense') {
      expense += tx.amount;
      catTotals[tx.category] = (catTotals[tx.category] || 0) + tx.amount;
      if (m - 1 === curMonth && y === curYear) monthExpense += tx.amount;
    } else if (tx.type === 'income') {
      totalIncome += tx.amount;
    }
  }
  const count = transactions.length;
  totalExpenseEl.textContent = `₹${expense.toFixed(2)}`;
  totalMonthEl.textContent   = `₹${monthExpense.toFixed(2)}`;
  totalCountEl.textContent   = count;

  // ── Income + Net Savings ──────────────────────────────────────────
  const net = totalIncome - expense;
  $('total-income').textContent = `₹${totalIncome.toFixed(2)}`;
  const netEl = $('net-savings');
  netEl.textContent = `${net >= 0 ? '' : '-'}₹${Math.abs(net).toFixed(2)}`;
  netEl.style.color = net >= 0 ? '#059669' : '#ef4444';

  // ── Month forecast ────────────────────────────────────────────────
  const daysInMonth = new Date(curYear, curMonth + 1, 0).getDate();
  const dayOfMonth  = now.getDate();
  const dailyAvg    = dayOfMonth > 0 ? monthExpense / dayOfMonth : 0;
  $('forecast-amount').textContent = `₹${(dailyAvg * daysInMonth).toFixed(2)}`;

  // ── Today's spend ─────────────────────────────────────────────────
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
  const dayName  = now.toLocaleDateString('en-IN', { weekday: 'short' });
  const monthStr = now.toLocaleDateString('en-IN', { month: 'short' });
  $('today-date').textContent = `${dayName}, ${now.getDate()} ${monthStr}`;

  // ── Hero card ─────────────────────────────────────────────────────
  const heroBalance  = totalIncome - expense;
  const moneyLeft    = totalIncome - monthExpense;
  const savingsRate  = totalIncome > 0 ? Math.round(((totalIncome - expense) / totalIncome) * 100) : 0;
  const forecastAmt  = dailyAvg * daysInMonth;

  const heroBalEl = $('hero-balance');
  if (heroBalEl) {
    heroBalEl.textContent = `${heroBalance >= 0 ? '' : '-'}₹${Math.abs(heroBalance).toFixed(2)}`;
  }
  if ($('hero-monthly-income'))  $('hero-monthly-income').textContent  = `₹${totalIncome.toFixed(0)}`;
  if ($('hero-monthly-expense')) $('hero-monthly-expense').textContent = `₹${monthExpense.toFixed(0)}`;
  const mlEl = $('hero-money-left');
  if (mlEl) {
    mlEl.textContent = `${moneyLeft >= 0 ? '' : '-'}₹${Math.abs(moneyLeft).toFixed(0)}`;
    mlEl.style.color = moneyLeft >= 0 ? 'rgba(255,255,255,.9)' : '#fca5a5';
  }
  if ($('hero-savings-rate')) $('hero-savings-rate').textContent = `${savingsRate}%`;

  // Hero insight text
  const insightEl = $('hero-insight-text');
  if (insightEl) {
    if (transactions.length === 0) {
      insightEl.textContent = 'Add your first transaction to see insights here.';
    } else if (savingsRate >= 30) {
      insightEl.textContent = `🟢 Great job! You're saving ${savingsRate}% of your income this month.`;
    } else if (savingsRate >= 10) {
      insightEl.textContent = `🟡 You're saving ${savingsRate}% — try to push past 20% this month.`;
    } else if (totalIncome === 0) {
      insightEl.textContent = `💡 Add income entries to see your savings rate.`;
    } else {
      insightEl.textContent = `🔴 Savings rate is ${savingsRate}%. Review your top spending categories.`;
    }
  }

  // ── Marquee values ────────────────────────────────────────────────
  const mqPairs = [
    ['mq-today',    `₹${todaySpend.toFixed(2)}`],
    ['mq-month',    `₹${monthExpense.toFixed(2)}`],
    ['mq-income',   `₹${totalIncome.toFixed(2)}`],
    ['mq-savings',  `${heroBalance >= 0 ? '' : '-'}₹${Math.abs(heroBalance).toFixed(2)}`],
    ['mq-forecast', `₹${forecastAmt.toFixed(2)}`],
    ['mq-count',    String(transactions.length)],
    ['mq-today2',    `₹${todaySpend.toFixed(2)}`],
    ['mq-month2',    `₹${monthExpense.toFixed(2)}`],
    ['mq-income2',   `₹${totalIncome.toFixed(2)}`],
    ['mq-savings2',  `${heroBalance >= 0 ? '' : '-'}₹${Math.abs(heroBalance).toFixed(2)}`],
    ['mq-forecast2', `₹${forecastAmt.toFixed(2)}`],
    ['mq-count2',    String(transactions.length)],
  ];
  for (const [id, val] of mqPairs) { const el = $(id); if (el) el.textContent = val; }
  // Color net savings marquee
  ['mq-savings','mq-savings2'].forEach(id => {
    const el = $(id); if (el) el.className = `m-val ${heroBalance >= 0 ? 'up' : 'down'}`;
  });

  // Recent 5
  const recent = [...transactions].sort((a,b) => new Date(b.date)-new Date(a.date)).slice(0,5);
  renderTxList(recentList, recent, false);

  // Top categories
  renderTopCategories(catTotals);

  // Chart
  updateChart(catTotals);

  // Reminder
  checkWeeklyReminder();
  renderInsights();
  renderSavingsGoal();
  renderRecurringReminder();

  // Refresh money bowl if visible
  if (currentSection === 'moneybowl') renderMoneyBowl();

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
  const checked = bulkSelected.has(tx.id);
  div.innerHTML = `
    <div class="tx-left">
      ${bulkMode && showDelete ? `<input type="checkbox" class="bulk-checkbox" data-id="${tx.id}" ${checked?'checked':''}
         style="margin-right:8px;width:18px;height:18px;accent-color:var(--accent);flex-shrink:0">` : ''}
      <div class="tx-emoji" style="background:${color}18;color:${color}">${emoji}</div>
      <div class="tx-info">
        <span class="tx-cat">${escapeHtml(label)}</span>
        <div class="tx-meta">
          ${tx.payee  ? `<span class="tx-payee">→ ${escapeHtml(tx.payee)}</span>` : ''}
          ${tx.note   ? `<span class="tx-note">${escapeHtml(tx.note)}</span>` : ''}
          ${modeBadgeHtml(tx.paymentMode)}
          ${tx.recurring ? `<span class="mode-badge" style="color:#8b5cf6;background:#f5f3ff">🔁</span>` : ''}
        </div>
        <span class="tx-date">${formatDate(tx.date)}</span>
      </div>
    </div>
    <div class="tx-right">
      <span class="tx-amount ${tx.type}">${sign}₹${tx.amount.toFixed(2)}</span>
      ${tx.bill ? `<span class="bill-clip" data-id="${tx.id}" title="View receipt"><i data-lucide="paperclip"></i></span>` : ''}
      ${showDelete && !bulkMode ? `
        <button class="tx-edit-btn" data-id="${tx.id}" title="Edit"><i data-lucide="pencil"></i></button>
        <button class="tx-split-btn" data-id="${tx.id}" title="Split"><i data-lucide="scissors"></i></button>
        <button class="tx-delete-btn" data-id="${tx.id}" title="Delete"><i data-lucide="trash-2"></i></button>
      ` : ''}
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
  const from = $('filter-date-from')?.value || '';
  const to   = $('filter-date-to')?.value   || '';
  return [...transactions]
    .filter(tx => {
      if (type !== 'all' && tx.type !== type) return false;
      if (cat  !== 'all' && tx.category !== cat) return false;
      if (mode !== 'all' && tx.paymentMode !== mode) return false;
      if (from && tx.date < from) return false;
      if (to   && tx.date > to)   return false;
      if (q) {
        const hay = [tx.category, tx.note, tx.payee, String(tx.amount), tx.date].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    })
    .sort((a,b) => new Date(b.date) - new Date(a.date));
}

function renderHistory() {
  const filtered = getFiltered();
  const total = transactions.length;
  historyCount.textContent = filtered.length
    ? `Showing ${filtered.length} of ${total} transaction${total !== 1 ? 's' : ''}`
    : (total ? 'No transactions match your filters.' : '');
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
  // Show scan button only for images (not PDFs)
  const scanBtn = $('scan-receipt-btn');
  if (scanBtn) scanBtn.classList.toggle('hidden', !currentBill.type.startsWith('image/'));
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

// ── CSV Export ─────────────────────────────────────────────────────
function exportCSV() {
  if (!transactions.length) { showToast('No transactions to export.', 'warning'); return; }
  const sorted = [...transactions].sort((a,b) => new Date(b.date) - new Date(a.date));
  const header = ['Date','Type','Category','Payee','Payment Mode','Amount (₹)','Note'];
  const rows = sorted.map(tx => [
    tx.date,
    tx.type,
    tx.category || '',
    tx.payee || '',
    PAYMENT_MODES[tx.paymentMode]?.label || tx.paymentMode || '',
    (tx.type === 'income' ? '' : '-') + tx.amount.toFixed(2),
    tx.note || ''
  ]);
  const csv = [header, ...rows]
    .map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))
    .join('\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'expense-vault-export.csv'; a.click();
  URL.revokeObjectURL(url);
  showToast('CSV downloaded!');
}

// ── Edit Transaction ───────────────────────────────────────────────
function resetFormToAdd() {
  editingId = null;
  $('form-title-text').textContent  = 'New Transaction';
  $('form-submit-label').textContent = 'Add Transaction';
  $('form-submit-icon').setAttribute('data-lucide', 'plus');
  $('cancel-edit-btn').classList.add('hidden');
  lucide.createIcons();
}

function startEditTx(id) {
  const tx = transactions.find(t => t.id === id);
  if (!tx) return;
  editingId = id;

  $('form-title-text').textContent  = 'Edit Transaction';
  $('form-submit-label').textContent = 'Update Transaction';
  $('form-submit-icon').setAttribute('data-lucide', 'check');
  $('cancel-edit-btn').classList.remove('hidden');

  // type toggle
  const txType = tx.type || 'expense';
  $('tx-type').value = txType;
  $('type-toggle').querySelectorAll('.type-btn').forEach(b => b.classList.remove('active'));
  $('type-toggle').querySelector(`[data-type="${txType}"]`)?.classList.add('active');
  if (txType === 'income') {
    categoryGroup.classList.add('hidden'); categorySelect.required = false;
    payeeGroup.classList.remove('hidden'); payeeInput.required = false;
    $('payee-label').childNodes[0].textContent = 'Income Source ';
    $('payee-req-badge').classList.add('hidden');
    payeeInput.placeholder = 'e.g. Salary, Freelance...';
  } else {
    categoryGroup.classList.remove('hidden'); categorySelect.required = true;
  }

  $('amount').value      = tx.amount;
  $('date').value        = tx.date;
  categorySelect.value   = tx.category || 'Food';
  $('note').value        = tx.note  || '';
  payeeInput.value       = tx.payee || '';
  $('tx-recurring').checked = !!tx.recurring;

  // payment mode chip
  const mode = tx.paymentMode || 'cash';
  paymentModes.querySelectorAll('.mode-chip').forEach(c => c.classList.remove('active'));
  const chip = paymentModes.querySelector(`[data-mode="${mode}"]`);
  if (chip) chip.classList.add('active');
  paymentModeHidden.value = mode;

  // payee visibility
  checkPayeeRequired();
  if (tx.payee) payeeGroup.classList.remove('hidden');

  // bill
  if (tx.bill) {
    currentBill = tx.bill;
    billThumb.src = tx.bill.data;
    billNameEl.textContent = tx.bill.name;
    billThumb.style.display = tx.bill.type.startsWith('image/') ? 'block' : 'none';
    uploadZone.classList.add('hidden');
    billPreview.classList.remove('hidden');
  } else {
    currentBill = null;
    billPreview.classList.add('hidden');
    uploadZone.classList.remove('hidden');
  }

  showSection('add');
  lucide.createIcons();
}

// ── Split Modal ────────────────────────────────────────────────────
function openSplitModal(txId) {
  const tx = transactions.find(t => t.id === txId);
  if (!tx) return;
  splitTxId = txId;
  $('split-original-info').textContent =
    `${tx.category || 'Income'} · ₹${tx.amount.toFixed(2)} · ${formatDate(tx.date)}`;
  $('split-rows').innerHTML = '';
  const half = parseFloat((tx.amount / 2).toFixed(2));
  addSplitRow(half, tx.category || 'Food', tx.date);
  addSplitRow(parseFloat((tx.amount - half).toFixed(2)), tx.category || 'Food', tx.date);
  updateSplitRemaining();
  $('split-modal').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  lucide.createIcons();
}

function addSplitRow(amount = 0, cat = 'Food', date = '') {
  const rowId = crypto.randomUUID();
  const div   = document.createElement('div');
  div.className = 'split-row';
  div.dataset.splitRowId = rowId;
  const catOptions = Object.keys(CATEGORY_COLORS)
    .map(c => `<option value="${c}" ${c === cat ? 'selected' : ''}>${CATEGORY_EMOJI[c]||'📦'} ${c}</option>`)
    .join('');
  div.innerHTML = `
    <div class="split-row-fields">
      <div class="input-with-icon split-amount-wrap">
        <span class="input-prefix">₹</span>
        <input type="number" class="split-amount-input" placeholder="Amount"
               value="${amount > 0 ? amount.toFixed(2) : ''}" min="0.01" step="0.01">
      </div>
      <div class="select-wrapper split-cat-wrap">
        <select class="split-cat-select">${catOptions}</select>
      </div>
      <input type="date" class="split-date-input filter-select" value="${date}">
      <button type="button" class="btn ghost icon-btn split-remove-btn">
        <i data-lucide="trash-2"></i>
      </button>
    </div>`;
  div.querySelector('.split-amount-input').addEventListener('input', updateSplitRemaining);
  div.querySelector('.split-remove-btn').addEventListener('click', () => {
    div.remove(); updateSplitRemaining();
  });
  $('split-rows').appendChild(div);
  lucide.createIcons();
}

function updateSplitRemaining() {
  if (!splitTxId) return;
  const tx = transactions.find(t => t.id === splitTxId);
  if (!tx) return;
  const total = [...$('split-rows').querySelectorAll('.split-amount-input')]
    .reduce((s, inp) => s + (parseFloat(inp.value) || 0), 0);
  const rem = tx.amount - total;
  const el  = $('split-remaining');
  el.textContent = rem < 0
    ? `-₹${Math.abs(rem).toFixed(2)} over`
    : `₹${rem.toFixed(2)} left`;
  el.style.color = rem < 0 ? '#ef4444' : Math.abs(rem) < 0.01 ? '#10b981' : '#f59e0b';
}

async function confirmSplit() {
  if (!splitTxId) return;
  const tx = transactions.find(t => t.id === splitTxId);
  if (!tx) return;
  const rows = [...$('split-rows').querySelectorAll('.split-row')];
  if (rows.length < 2) { showToast('Need at least 2 splits.', 'warning'); return; }
  const splits = rows.map(row => ({
    amount:   parseFloat(row.querySelector('.split-amount-input').value) || 0,
    category: row.querySelector('.split-cat-select').value,
    date:     row.querySelector('.split-date-input').value || tx.date,
  }));
  if (splits.some(s => s.amount <= 0)) {
    showToast('All split amounts must be > 0.', 'warning'); return;
  }
  const total = splits.reduce((s, r) => s + r.amount, 0);
  if (Math.abs(total - tx.amount) > 0.01) {
    showToast(`Splits total ₹${total.toFixed(2)} — must equal ₹${tx.amount.toFixed(2)}.`, 'warning');
    return;
  }
  transactions = transactions.filter(t => t.id !== splitTxId);
  for (const s of splits) {
    const newTx = {
      id: crypto.randomUUID(), type: tx.type,
      amount: s.amount, date: s.date, category: s.category,
      paymentMode: tx.paymentMode
    };
    if (tx.note)  newTx.note  = `Split: ${tx.note}`;
    if (tx.payee) newTx.payee = tx.payee;
    transactions.push(newTx);
  }
  await saveData();
  closeSplitModal();
  updateDashboard();
  if (currentSection === 'history') renderHistory();
  showToast(`Split into ${splits.length} transactions! ✂️`);
}

function closeSplitModal() {
  $('split-modal').classList.add('hidden');
  document.body.style.overflow = '';
  splitTxId = null;
}

// ── Dark Mode ──────────────────────────────────────────────────────
function initDarkMode() {
  const saved = localStorage.getItem('vault_theme') || 'light';
  applyTheme(saved, false);
}
function applyTheme(theme, save = true) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = $('dark-mode-btn');
  if (btn) {
    btn.querySelector('i').setAttribute('data-lucide', theme === 'dark' ? 'sun' : 'moon');
    btn.querySelector('span').textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
  }
  if (save) localStorage.setItem('vault_theme', theme);
  lucide.createIcons();
}
function toggleDarkMode() {
  const cur = document.documentElement.getAttribute('data-theme') || 'light';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
  closeSidebar();
}

// ── Backup / Restore ───────────────────────────────────────────────
async function exportBackup() {
  if (!currentPassword) return;
  const enc  = await encryptData({ transactions, budgets, savingsGoal }, currentPassword);
  const blob = new Blob([JSON.stringify({ v: 1, enc })], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = `my-vault-backup-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Backup downloaded!');
  closeSidebar();
}
async function importBackup(file) {
  try {
    const text = await file.text();
    const obj  = JSON.parse(text);
    const dec  = await decryptData(obj.enc, currentPassword);
    if (!dec) { showToast('Wrong password or corrupt backup.', 'warning'); return; }
    if (Array.isArray(dec)) {
      transactions = dec; budgets = {}; savingsGoal = 0;
    } else if (typeof dec === 'object') {
      transactions = Array.isArray(dec.transactions) ? dec.transactions : [];
      budgets      = (dec.budgets && typeof dec.budgets === 'object') ? dec.budgets : {};
      savingsGoal  = typeof dec.savingsGoal === 'number' ? dec.savingsGoal : 0;
    }
    await saveData();
    updateDashboard();
    showToast(`✅ Restored ${transactions.length} transactions!`);
  } catch { showToast('Failed to import backup.', 'warning'); }
}

// ── Undo Delete ────────────────────────────────────────────────────
function showUndoToast(msg = 'Deleted') {
  clearTimeout(toastTimer);
  toastMsg.textContent = msg;
  $('toast-undo-btn').classList.remove('hidden');
  toastEl.className = 'toast show';
  toastTimer = setTimeout(() => {
    toastEl.classList.remove('show');
    $('toast-undo-btn').classList.add('hidden');
    if (undoBuffer) { undoBuffer = null; saveData(); }
  }, 5000);
}
function handleDeleteWithUndo(id) {
  const tx = transactions.find(t => t.id === id);
  if (!tx) return;
  // Finalize any pending undo
  if (undoBuffer) { clearTimeout(undoBuffer.timer); saveData(); undoBuffer = null; }
  transactions = transactions.filter(t => t.id !== id);
  updateDashboard();
  if (currentSection === 'history') renderHistory();
  if (currentSection === 'bills')   renderBills();
  const timer = setTimeout(() => { undoBuffer = null; saveData(); }, 5000);
  undoBuffer = { tx, timer };
  showUndoToast('Deleted');
}
function undoDelete() {
  if (!undoBuffer) return;
  clearTimeout(undoBuffer.timer);
  transactions.push(undoBuffer.tx);
  transactions.sort((a, b) => new Date(b.date) - new Date(a.date));
  undoBuffer = null;
  updateDashboard();
  if (currentSection === 'history') renderHistory();
  if (currentSection === 'bills')   renderBills();
  clearTimeout(toastTimer);
  toastEl.classList.remove('show');
  $('toast-undo-btn').classList.add('hidden');
  showToast('↩️ Undo! Transaction restored.');
}

// ── Smart Insights ─────────────────────────────────────────────────
function computeInsights() {
  const now = new Date();
  const curM = now.getMonth(), curY = now.getFullYear();
  const prevM = curM === 0 ? 11 : curM - 1;
  const prevY = curM === 0 ? curY - 1 : curY;
  const inMonth = (t, y, m) => { const [ty,tm] = t.date.split('-').map(Number); return ty===y && tm-1===m; };
  const curExp  = transactions.filter(t => t.type==='expense' && inMonth(t, curY, curM));
  const prevExp = transactions.filter(t => t.type==='expense' && inMonth(t, prevY, prevM));
  const insights = [];

  // Category trend
  const curCats={}, prevCats={};
  for (const t of curExp)  curCats[t.category]  = (curCats[t.category]||0)  + t.amount;
  for (const t of prevExp) prevCats[t.category] = (prevCats[t.category]||0) + t.amount;
  let bigCat=null, bigPct=0;
  for (const [cat, amt] of Object.entries(curCats)) {
    const prev = prevCats[cat] || 0;
    if (prev > 0) { const pct=((amt-prev)/prev*100); if (Math.abs(pct)>Math.abs(bigPct)){bigPct=pct;bigCat={cat,amt,pct};} }
  }
  if (bigCat) {
    const dir = bigCat.pct>0?'up':'down'; const icon=bigCat.pct>0?'📈':'📉';
    insights.push(`${icon} ${bigCat.cat} spend ${dir} ${Math.abs(bigCat.pct).toFixed(0)}% vs last month.`);
  }

  // Day of week with most spending
  const dayTotals = Array(7).fill(0);
  for (const t of transactions.filter(x=>x.type==='expense')) {
    dayTotals[new Date(t.date+'T00:00:00').getDay()] += t.amount;
  }
  const maxDay = dayTotals.indexOf(Math.max(...dayTotals));
  if (Math.max(...dayTotals)>0) {
    insights.push(`📅 You spend most on ${['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][maxDay]}s.`);
  }

  // Biggest expense this month
  const bigTx = curExp.reduce((a,b)=>b.amount>(a?.amount||0)?b:a, null);
  if (bigTx) insights.push(`💸 Biggest this month: ₹${bigTx.amount.toFixed(0)} on ${bigTx.category}.`);

  // Savings rate if income tracked
  const curInc = transactions.filter(t=>t.type==='income'&&inMonth(t,curY,curM)).reduce((s,t)=>s+t.amount,0);
  const curSpend = curExp.reduce((s,t)=>s+t.amount,0);
  if (curInc>0) {
    const rate=((curInc-curSpend)/curInc*100);
    insights.push(`${rate>=20?'🎉':rate>=0?'👍':'⚠️'} Savings rate this month: ${rate.toFixed(0)}%.`);
  }
  return insights.slice(0,3);
}
function renderInsights() {
  const card=$('insights-card'), list=$('insights-list');
  if (!card||!list) return;
  const ins=computeInsights();
  if (!ins.length) { card.classList.add('hidden'); return; }
  card.classList.remove('hidden');
  list.innerHTML = ins.map(i=>`<div class="insight-item">${escapeHtml(i)}</div>`).join('');
}

// ── Savings Goal ───────────────────────────────────────────────────
function renderSavingsGoal() {
  const card=$('savings-goal-card'), body=$('savings-goal-body');
  if (!card||!body) return;
  const now=new Date(); const curM=now.getMonth(), curY=now.getFullYear();
  const inMonth=(t,y,m)=>{const[ty,tm]=t.date.split('-').map(Number);return ty===y&&tm-1===m;};
  const curInc = transactions.filter(t=>t.type==='income'&&inMonth(t,curY,curM)).reduce((s,t)=>s+t.amount,0);
  const curSpend = transactions.filter(t=>t.type==='expense'&&inMonth(t,curY,curM)).reduce((s,t)=>s+t.amount,0);
  const net = curInc - curSpend;
  if (curInc===0 && savingsGoal===0) { card.classList.add('hidden'); return; }
  card.classList.remove('hidden');
  if (savingsGoal<=0) {
    body.innerHTML=`<div class="savings-no-goal"><span>Net this month:</span><strong style="color:${net>=0?'#10b981':'#ef4444'}">₹${net.toFixed(0)}</strong></div>`;
    return;
  }
  const pct=Math.min((net/savingsGoal)*100,100);
  const color=pct>=100?'#10b981':pct>=50?'#f59e0b':'#ef4444';
  body.innerHTML=`
    <div class="savings-goal-nums">
      <span>Saved: <strong>₹${Math.max(net,0).toFixed(0)}</strong></span>
      <span>Goal: <strong>₹${savingsGoal.toFixed(0)}</strong></span>
    </div>
    <div class="budget-bar-track" style="margin:8px 0">
      <div class="budget-bar-fill" style="width:${Math.max(0,pct).toFixed(1)}%;background:${color}"></div>
    </div>
    <div class="savings-goal-status">${pct>=100?'🎉 Goal reached!':net<0?'⚠️ Spending > income':pct.toFixed(0)+'% of goal'}</div>`;
}
async function setSavingsGoal() {
  const val = prompt('Monthly savings goal (₹):', savingsGoal || '');
  if (val === null) return;
  savingsGoal = parseFloat(val) || 0;
  await saveData();
  renderSavingsGoal();
  showToast('Savings goal saved!');
}

// ── Recurring Reminders ────────────────────────────────────────────
function renderRecurringReminder() {
  const banner=$('recurring-reminder'), list=$('recurring-list');
  if (!banner||!list) return;
  const now=new Date(); const curM=now.getMonth(), curY=now.getFullYear();
  const prevM=curM===0?11:curM-1; const prevY=curM===0?curY-1:curY;
  const inMonth=(t,y,m)=>{const[ty,tm]=t.date.split('-').map(Number);return ty===y&&tm-1===m;};
  const lastMonRec = transactions.filter(t=>t.recurring&&inMonth(t,prevY,prevM));
  const thisMonCats = new Set(transactions.filter(t=>inMonth(t,curY,curM)).map(t=>t.category+'|'+t.type));
  const due = lastMonRec.filter(t=>!thisMonCats.has(t.category+'|'+t.type));
  if (!due.length) { banner.classList.add('hidden'); return; }
  banner.classList.remove('hidden');
  list.innerHTML = `<strong>${due.length} recurring due:</strong> ${due.map(t=>`${CATEGORY_EMOJI[t.category]||'📦'} ${t.category} (₹${t.amount.toFixed(0)})`).join(', ')}`;
}

// ── Payee Analytics ────────────────────────────────────────────────
function renderPayeeChart() {
  const el=$('payee-stats');
  if (!el) return;
  const map={};
  for (const tx of transactions) {
    if (tx.type==='expense'&&tx.payee) map[tx.payee]=(map[tx.payee]||0)+tx.amount;
  }
  const sorted=Object.entries(map).sort((a,b)=>b[1]-a[1]).slice(0,12);
  if (!sorted.length) {
    el.innerHTML='<p class="empty-small">No payee data yet.<br>Add transactions with payee/merchant names.</p>'; return;
  }
  const max=sorted[0][1];
  el.innerHTML=sorted.map(([payee,amt])=>`
    <div class="top-cat-item">
      <div class="top-cat-row">
        <span class="top-cat-name">👤 ${escapeHtml(payee)}</span>
        <span class="top-cat-amt">₹${amt.toFixed(0)}</span>
      </div>
      <div class="top-cat-bar">
        <div class="top-cat-fill" style="width:${(amt/max*100).toFixed(1)}%;background:var(--accent)"></div>
      </div>
    </div>`).join('');
}

// ── Bulk Delete ────────────────────────────────────────────────────
function toggleBulkMode() {
  bulkMode = !bulkMode;
  bulkSelected.clear();
  const btn=$('bulk-select-btn'), delBtn=$('bulk-delete-btn');
  if (bulkMode) {
    btn.innerHTML='<i data-lucide="x"></i> Cancel';
    delBtn.classList.remove('hidden');
  } else {
    btn.innerHTML='<i data-lucide="check-square"></i> Select';
    delBtn.classList.add('hidden');
  }
  renderHistory();
  lucide.createIcons();
}
async function bulkDeleteSelected() {
  const count=bulkSelected.size;
  if (!count) { showToast('Nothing selected.', 'warning'); return; }
  transactions=transactions.filter(t=>!bulkSelected.has(t.id));
  await saveData();
  bulkSelected.clear();
  bulkMode=false;
  $('bulk-delete-btn').classList.add('hidden');
  $('bulk-select-btn').innerHTML='<i data-lucide="check-square"></i> Select';
  updateDashboard();
  renderHistory();
  showToast(`🗑️ ${count} transaction${count>1?'s':''} deleted.`);
  lucide.createIcons();
}

// ── Analytics ──────────────────────────────────────────────────────
const BUDGET_CATEGORIES = [
  { key:'Food',          emoji:'🍔', color:'#f59e0b' },
  { key:'Travel',        emoji:'✈️', color:'#3b82f6' },
  { key:'Rent',          emoji:'🏠', color:'#8b5cf6' },
  { key:'Electricity',   emoji:'⚡', color:'#f97316' },
  { key:'Grocery',       emoji:'🛒', color:'#10b981' },
  { key:'Shopping',      emoji:'🛍️', color:'#ec4899' },
  { key:'Online Orders', emoji:'📦', color:'#06b6d4' },
  { key:'Miscellaneous', emoji:'📋', color:'#6b7280' },
  { key:'Lending Money', emoji:'💸', color:'#ef4444' },
];

function lineChartOptions(color) {
  return {
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { label: c => ` ₹${c.parsed.y.toFixed(2)}` } }
    },
    scales: {
      x: { grid: { display: false }, ticks: { font: { family:'Outfit', size:11 }, color:'#4c4780' } },
      y: { beginAtZero: true, grid: { color:'rgba(99,102,241,.08)' },
           ticks: { font:{ family:'Outfit', size:11 }, color:'#4c4780',
                    callback: v => v >= 1000 ? `₹${(v/1000).toFixed(0)}k` : `₹${v}` } }
    }
  };
}

function renderAnalytics() {
  renderWeeklyChart();
  // tab listeners wired once via event delegation below
}

function renderWeeklyChart() {
  const days = [], amounts = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    const ds = d.toISOString().slice(0,10);
    const spend = transactions.filter(t => t.type==='expense' && t.date===ds)
                              .reduce((s,t) => s+t.amount, 0);
    days.push(d.toLocaleDateString('en-IN',{weekday:'short',day:'numeric'}));
    amounts.push(parseFloat(spend.toFixed(2)));
  }
  const ctx = $('weeklyChart').getContext('2d');
  if (weeklyChartInst) { weeklyChartInst.destroy(); weeklyChartInst = null; }
  weeklyChartInst = new Chart(ctx, {
    type:'line',
    data:{ labels:days, datasets:[{
      label:'Spend', data:amounts,
      borderColor:'#6366f1', backgroundColor:'rgba(99,102,241,.1)',
      fill:true, tension:0.4,
      pointBackgroundColor:'#6366f1', pointRadius:5, pointHoverRadius:7
    }]},
    options: lineChartOptions('#6366f1')
  });
  const total = amounts.reduce((s,a)=>s+a,0);
  const maxAmt = amounts.length ? Math.max(...amounts) : 0;
  const maxDay = maxAmt > 0 ? days[amounts.indexOf(maxAmt)] : '—';
  $('weekly-stats').innerHTML = `
    <div class="astat"><span class="astat-label">Week Total</span><span class="astat-value">₹${total.toFixed(2)}</span></div>
    <div class="astat"><span class="astat-label">Daily Avg</span><span class="astat-value">₹${(total/7).toFixed(2)}</span></div>
    <div class="astat"><span class="astat-label">Highest Day</span><span class="astat-value">${maxDay}</span></div>`;
}

function renderMonthlyChart() {
  const labels = [], amounts = [];
  const now = new Date();
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const y = d.getFullYear(), m = d.getMonth();
    const spend = transactions
      .filter(t => { if (t.type!=='expense') return false; const [ty,tm]=t.date.split('-').map(Number); return ty===y && tm-1===m; })
      .reduce((s,t)=>s+t.amount, 0);
    labels.push(d.toLocaleDateString('en-IN',{month:'short',year:'2-digit'}));
    amounts.push(parseFloat(spend.toFixed(2)));
  }
  const ctx = $('monthlyChart').getContext('2d');
  if (monthlyChartInst) { monthlyChartInst.destroy(); monthlyChartInst = null; }
  monthlyChartInst = new Chart(ctx, {
    type:'line',
    data:{ labels, datasets:[{
      label:'Spend', data:amounts,
      borderColor:'#8b5cf6', backgroundColor:'rgba(139,92,246,.1)',
      fill:true, tension:0.4,
      pointBackgroundColor:'#8b5cf6', pointRadius:5, pointHoverRadius:7
    }]},
    options: lineChartOptions('#8b5cf6')
  });
  const total = amounts.reduce((s,a)=>s+a,0);
  const maxAmt = amounts.length ? Math.max(...amounts) : 0;
  const maxMon = maxAmt > 0 ? labels[amounts.indexOf(maxAmt)] : '—';
  $('monthly-stats').innerHTML = `
    <div class="astat"><span class="astat-label">Year Total</span><span class="astat-value">₹${total.toFixed(2)}</span></div>
    <div class="astat"><span class="astat-label">Monthly Avg</span><span class="astat-value">₹${(total/12).toFixed(2)}</span></div>
    <div class="astat"><span class="astat-label">Highest Month</span><span class="astat-value">${maxMon}</span></div>`;
}

// Analytics tab switching
document.addEventListener('click', e => {
  const tab = e.target.closest('.atab');
  if (!tab) return;
  const tabGroup = tab.closest('.atab-group');
  if (!tabGroup) return;
  tabGroup.querySelectorAll('.atab').forEach(t => t.classList.remove('active'));
  tab.classList.add('active');
  const which = tab.dataset.tab;
  $('analytics-weekly').classList.toggle('hidden', which !== 'weekly');
  $('analytics-monthly').classList.toggle('hidden', which !== 'monthly');
  $('analytics-payees').classList.toggle('hidden', which !== 'payees');
  if (which === 'weekly') renderWeeklyChart();
  else if (which === 'monthly') renderMonthlyChart();
  else if (which === 'payees') renderPayeeChart();
});

// ── Calendar ───────────────────────────────────────────────────────
function renderCalendar() {
  $('cal-month-label').textContent =
    new Date(calYear, calMonth, 1).toLocaleDateString('en-IN',{month:'long',year:'numeric'});

  const firstDay   = new Date(calYear, calMonth, 1).getDay();
  const daysInMonth = new Date(calYear, calMonth+1, 0).getDate();
  const todayStr   = new Date().toISOString().slice(0,10);

  // Daily totals
  const dailyTotals = {};
  for (const tx of transactions) {
    if (tx.type !== 'expense') continue;
    const [y,m,d] = tx.date.split('-').map(Number);
    if (y === calYear && m-1 === calMonth)
      dailyTotals[d] = (dailyTotals[d]||0) + tx.amount;
  }
  const maxDaily = Math.max(0, ...Object.values(dailyTotals));

  let html = '';
  for (let i = 0; i < firstDay; i++) html += '<div class="cal-cell empty"></div>';
  for (let d = 1; d <= daysInMonth; d++) {
    const ds = `${calYear}-${String(calMonth+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    const spend = dailyTotals[d] || 0;
    const isToday = ds === todayStr;
    let tier = '';
    if (spend > 0) {
      const pct = maxDaily > 0 ? spend/maxDaily*100 : 0;
      tier = pct >= 70 ? 'cal-high' : pct >= 35 ? 'cal-mid' : 'cal-low';
    }
    const amt = spend > 0
      ? `<span class="cal-day-spend">${spend>=1000 ? (spend/1000).toFixed(1)+'k' : spend.toFixed(0)}</span>`
      : '';
    html += `<div class="cal-cell ${tier}${isToday?' cal-today':''}" data-date="${ds}">
      <span class="cal-day-num">${d}</span>${amt}</div>`;
  }
  $('calendar-grid').innerHTML = html;
  $('cal-day-detail').classList.add('hidden');
  lucide.createIcons();
}

$('calendar-grid') && document.addEventListener('click', e => {
  const cell = e.target.closest('.cal-cell:not(.empty)');
  if (!cell || !cell.dataset.date) return;
  if (!cell.closest('#calendar-grid')) return;
  const txs = transactions.filter(t => t.type==='expense' && t.date===cell.dataset.date);
  const detail = $('cal-day-detail');
  const d = new Date(cell.dataset.date+'T00:00:00');
  $('cal-detail-title').textContent =
    d.toLocaleDateString('en-IN',{weekday:'long',day:'numeric',month:'long'});
  const list = $('cal-detail-list');
  if (!txs.length) {
    list.innerHTML = '<div class="empty-state"><p style="padding:20px">No expenses this day.</p></div>';
  } else {
    renderTxList(list, txs, false);
    lucide.createIcons();
  }
  detail.classList.remove('hidden');
  detail.scrollIntoView({behavior:'smooth', block:'nearest'});
});

// ── Budget Planner ─────────────────────────────────────────────────
function budgetColorClass(pct) {
  if (pct > 100) return 'b-over';
  if (pct >= 86)  return 'b-red';
  if (pct >= 61)  return 'b-warn';
  return 'b-ok';
}
function budgetBarColor(pct) {
  if (pct > 100) return '#991b1b';
  if (pct >= 86)  return '#ef4444';
  if (pct >= 61)  return '#f59e0b';
  return '#10b981';
}
function budgetStatusLabel(pct) {
  if (pct > 100) return '🔴 Over Budget!';
  if (pct >= 86)  return '🚨 Critical';
  if (pct >= 61)  return '⚠️ Warning';
  return '✅ On Track';
}

function renderBudget() {
  const now = new Date();
  $('budget-month-label').textContent =
    now.toLocaleDateString('en-IN',{month:'long',year:'numeric'});

  const curMonth = now.getMonth(), curYear = now.getFullYear();
  const catSpend = {};
  for (const tx of transactions) {
    if (tx.type !== 'expense') continue;
    const [y,m] = tx.date.split('-').map(Number);
    if (y===curYear && m-1===curMonth)
      catSpend[tx.category] = (catSpend[tx.category]||0) + tx.amount;
  }

  const activeBudgets = BUDGET_CATEGORIES.filter(c => budgets[c.key] > 0);
  const wrap = $('budget-cards-wrap');
  const empty = $('budget-empty');

  if (!activeBudgets.length) {
    wrap.innerHTML = ''; empty.classList.remove('hidden'); return;
  }
  empty.classList.add('hidden');

  wrap.innerHTML = activeBudgets.map(cat => {
    const limit  = budgets[cat.key];
    const spent  = catSpend[cat.key] || 0;
    const pct    = (spent/limit)*100;
    const cls    = budgetColorClass(pct);
    const barClr = budgetBarColor(pct);
    const remaining = limit - spent;
    const remStr = remaining >= 0
      ? `₹${remaining.toFixed(0)} left`
      : `₹${Math.abs(remaining).toFixed(0)} over`;
    return `
      <div class="budget-card">
        <div class="budget-card-header">
          <div class="budget-cat-info">
            <span class="budget-cat-emoji">${cat.emoji}</span>
            <div>
              <div class="budget-cat-name">${cat.key}</div>
              <div class="budget-cat-sub">₹${spent.toFixed(0)} of ₹${limit.toFixed(0)}</div>
            </div>
          </div>
          <span class="budget-pct-badge ${cls}">${pct.toFixed(0)}%</span>
        </div>
        <div class="budget-bar-track">
          <div class="budget-bar-fill" style="width:${Math.min(pct,100).toFixed(1)}%;background:${barClr}"></div>
        </div>
        <div class="budget-card-footer">
          <span class="budget-status ${cls}">${budgetStatusLabel(pct)}</span>
          <span class="budget-remaining">${remStr}</span>
        </div>
      </div>`;
  }).join('');
}

function openBudgetEdit() {
  const panel = $('budget-edit-panel');
  panel.classList.remove('hidden');
  $('budget-edit-grid').innerHTML = BUDGET_CATEGORIES.map(cat => `
    <div class="budget-edit-row">
      <label class="budget-edit-label"><span>${cat.emoji}</span>${cat.key}</label>
      <div class="input-with-icon">
        <span class="input-prefix">₹</span>
        <input type="number" class="budget-input" data-cat="${cat.key}"
               value="${budgets[cat.key]||''}" placeholder="0" min="0" step="100">
      </div>
    </div>`).join('');
}

async function saveBudgets() {
  document.querySelectorAll('.budget-input').forEach(inp => {
    budgets[inp.dataset.cat] = parseFloat(inp.value) || 0;
  });
  await saveData();
  $('budget-edit-panel').classList.add('hidden');
  renderBudget();
  showToast('Budgets saved!');
}

// ── Form Events ────────────────────────────────────────────────────

// Type toggle
$('type-toggle').addEventListener('click', e => {
  const btn = e.target.closest('.type-btn');
  if (!btn) return;
  const type = btn.dataset.type;
  $('type-toggle').querySelectorAll('.type-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  $('tx-type').value = type;
  if (type === 'income') {
    categoryGroup.classList.add('hidden');
    categorySelect.required = false;
    // Always show source field for income
    payeeGroup.classList.remove('hidden');
    payeeInput.required = false;
    $('payee-label').childNodes[0].textContent = 'Income Source ';
    $('payee-req-badge').classList.add('hidden');
    payeeInput.placeholder = 'e.g. Salary, Freelance, Rent received...';
  } else {
    categoryGroup.classList.remove('hidden');
    categorySelect.required = true;
    payeeGroup.classList.add('hidden');
    payeeInput.required = false;
    $('payee-label').childNodes[0].textContent = 'Paying to ';
    $('payee-req-badge').classList.remove('hidden');
    payeeInput.placeholder = 'e.g. Amazon, Landlord, Swiggy...';
    checkPayeeRequired();
  }
});

// Payee: required when amount > 5000
function checkPayeeRequired() {
  if ($('tx-type').value === 'income') return;
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
  $('scan-receipt-btn')?.classList.add('hidden');
});

// Submit
transactionForm.addEventListener('submit', async e => {
  e.preventDefault();
  const type      = $('tx-type').value;
  const amount    = parseFloat($('amount').value);
  const date      = $('date').value;
  const category  = type === 'expense' ? categorySelect.value : null;
  const note      = $('note').value.trim();
  const payee     = payeeInput.value.trim();
  const mode      = paymentModeHidden.value;
  const recurring = $('tx-recurring').checked;

  if (!amount || amount <= 0 || !date) return;
  if (amount > 5000 && !payee) { payeeInput.focus(); showToast('Please enter who you are paying.', 'warning'); return; }

  if (editingId) {
    // ── Update existing transaction ──────────────────────────────
    const idx = transactions.findIndex(t => t.id === editingId);
    if (idx !== -1) {
      transactions[idx] = { ...transactions[idx], amount, date, category, paymentMode: mode };
      if (note)        transactions[idx].note  = note;  else delete transactions[idx].note;
      if (payee)       transactions[idx].payee = payee; else delete transactions[idx].payee;
      if (currentBill) transactions[idx].bill  = currentBill; else delete transactions[idx].bill;
      if (recurring)   transactions[idx].recurring = true; else delete transactions[idx].recurring;
    }
    editingId = null;
    resetFormToAdd();
    await saveData();
    updateDashboard();
    weeklyReminder.classList.add('hidden');
    showToast('Transaction updated! ✏️');
    showSection('history');
  } else {
    // ── Add new transaction ──────────────────────────────────────
    const tx = { id: crypto.randomUUID(), type, amount, date, category, paymentMode: mode };
    if (note)      tx.note      = note;
    if (payee)     tx.payee     = payee;
    if (currentBill) tx.bill    = currentBill;
    if (recurring) tx.recurring = true;
    transactions.push(tx);
    await saveData();
    updateDashboard();
    weeklyReminder.classList.add('hidden');
    showToast('Transaction added!');
    showSection('dashboard');
  }

  // Reset form
  transactionForm.reset();
  $('date').valueAsDate = new Date();
  // Reset type toggle to expense
  $('tx-type').value = 'expense';
  $('type-toggle').querySelectorAll('.type-btn').forEach(b=>b.classList.remove('active'));
  $('type-toggle').querySelector('[data-type="expense"]').classList.add('active');
  categoryGroup.classList.remove('hidden');
  categorySelect.required = true;
  // Reset payee
  payeeGroup.classList.add('hidden');
  payeeInput.required = false;
  $('payee-label').childNodes[0].textContent = 'Paying to ';
  $('payee-req-badge').classList.remove('hidden');
  payeeInput.placeholder = 'e.g. Amazon, Landlord, Swiggy...';
  // Reset payment mode
  paymentModes.querySelectorAll('.mode-chip').forEach(c => c.classList.remove('active'));
  paymentModes.querySelector('[data-mode="cash"]').classList.add('active');
  paymentModeHidden.value = 'cash';
  // Reset bill + recurring
  currentBill = null; billFileInput.value = '';
  billPreview.classList.add('hidden'); uploadZone.classList.remove('hidden');
  $('tx-recurring').checked = false;
  lucide.createIcons();
});

// Delete / bulk-checkbox delegation
function handleListClick(e) {
  const delBtn = e.target.closest('.tx-delete-btn');
  if (delBtn) { handleDeleteWithUndo(delBtn.dataset.id); return; }
  const cb = e.target.closest('.bulk-checkbox');
  if (cb) {
    const id = cb.dataset.id;
    if (cb.checked) bulkSelected.add(id); else bulkSelected.delete(id);
    // Update delete button label
    const delBtnBulk = $('bulk-delete-btn');
    if (delBtnBulk) delBtnBulk.innerHTML = `<i data-lucide="trash-2"></i> Delete (${bulkSelected.size})`;
    lucide.createIcons();
  }
}
historyList.addEventListener('click', handleListClick);
recentList.addEventListener('click', e => {
  const delBtn = e.target.closest('.tx-delete-btn');
  if (delBtn) handleDeleteWithUndo(delBtn.dataset.id);
});

// Bill clip click + edit + split (delegation on content area)
document.querySelector('.content-area').addEventListener('click', e => {
  const clip = e.target.closest('.bill-clip');
  if (clip) { openBillModal(clip.dataset.id); return; }
  const billCard = e.target.closest('.bill-card');
  if (billCard) { openBillModal(billCard.dataset.id); return; }
  const editBtn = e.target.closest('.tx-edit-btn');
  if (editBtn) { startEditTx(editBtn.dataset.id); return; }
  const splitBtn = e.target.closest('.tx-split-btn');
  if (splitBtn) { openSplitModal(splitBtn.dataset.id); return; }
  const navLink = e.target.closest('[data-section]');
  if (navLink && !navLink.classList.contains('nav-item') && !navLink.classList.contains('bnav-item') && !navLink.classList.contains('bnav-fab')) {
    showSection(navLink.dataset.section);
  }
});

// ── Global Events ──────────────────────────────────────────────────
unlockBtn.addEventListener('click', unlockVault);
passwordInput.addEventListener('keydown', e => e.key === 'Enter' && unlockVault());

// Face ID unlock button
$('biometric-btn').addEventListener('click', async () => {
  $('biometric-btn').textContent = 'Scanning…';
  const pwd = await authenticateWithBiometric();
  if (!pwd) {
    $('biometric-btn').innerHTML = `<svg class="faceid-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 8V6a2 2 0 0 1 2-2h2M3 16v2a2 2 0 0 0 2 2h2M21 8V6a2 2 0 0 0-2-2h-2M21 16v2a2 2 0 0 1-2 2h-2"/><path d="M9 12a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM15 12a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"/><path d="M9.5 16a4.5 4.5 0 0 0 5 0"/><line x1="12" y1="8" x2="12" y2="9"/></svg> Unlock with Face ID`;
    showToast('Face ID failed. Use password.', 'warning'); return;
  }
  // Unlock with retrieved password
  unlockText.textContent = 'Unlocking…'; unlockSpinner.classList.remove('hidden'); unlockBtn.disabled = true;
  const stored = localStorage.getItem('vault_data');
  if (stored) {
    let dec = await decryptData(stored, pwd);
    if (dec) {
      if (Array.isArray(dec)) { transactions = dec; budgets = {}; }
      else { transactions = dec.transactions || []; budgets = dec.budgets || {}; }
      currentPassword = pwd; showApp(true);
    } else { showToast('Face ID data mismatch. Use password.', 'warning'); }
  }
  unlockText.textContent = 'Unlock Vault'; unlockSpinner.classList.add('hidden'); unlockBtn.disabled = false;
  $('biometric-btn').innerHTML = `<svg class="faceid-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 8V6a2 2 0 0 1 2-2h2M3 16v2a2 2 0 0 0 2 2h2M21 8V6a2 2 0 0 0-2-2h-2M21 16v2a2 2 0 0 1-2 2h-2"/><path d="M9 12a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM15 12a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"/><path d="M9.5 16a4.5 4.5 0 0 0 5 0"/><line x1="12" y1="8" x2="12" y2="9"/></svg> Unlock with Face ID`;
});

// Enable Face ID banner
$('faceid-enable-btn').addEventListener('click', async () => {
  $('faceid-banner').classList.add('hidden');
  const ok = await registerBiometric(currentPassword);
  if (ok) { showToast('Face ID enabled! 🔐'); initBiometricUI(); }
  else showToast('Could not enable Face ID.', 'warning');
});
$('faceid-dismiss-btn').addEventListener('click', () => $('faceid-banner').classList.add('hidden'));

// Enable Face ID (sidebar button)
$('enable-faceid-sidebar-btn')?.addEventListener('click', async () => {
  closeSidebar();
  showToast('Follow the Face ID prompt…');
  const ok = await registerBiometric(currentPassword);
  if (ok) {
    showToast('Face ID enabled! 🔐');
    initBiometricUI();
  } else {
    showToast('Face ID setup failed. Make sure Face ID is set up in iPhone Settings → Face ID & Passcode.', 'warning');
  }
});

// Disable Face ID
$('disable-faceid-btn')?.addEventListener('click', () => {
  localStorage.removeItem('vault_biometric');
  initBiometricUI();
  showToast('Face ID disabled.');
  closeSidebar();
});
togglePwBtn.addEventListener('click', () => {
  const show = passwordInput.type === 'password';
  passwordInput.type = show ? 'text' : 'password';
  pwEyeIcon.setAttribute('data-lucide', show ? 'eye-off' : 'eye');
  lucide.createIcons();
});

lockBtn.addEventListener('click', lockVault);
exportBtn.addEventListener('click', exportPDF);
$('export-csv-btn')?.addEventListener('click', () => { closeSidebar(); exportCSV(); });
$('dark-mode-btn')?.addEventListener('click', toggleDarkMode);
$('backup-btn')?.addEventListener('click', exportBackup);
$('restore-btn')?.addEventListener('click', () => { closeSidebar(); $('restore-file-input').click(); });
$('restore-file-input')?.addEventListener('change', e => { const f=e.target.files[0]; if(f) importBackup(f); e.target.value=''; });
$('toast-undo-btn')?.addEventListener('click', undoDelete);
$('set-goal-btn')?.addEventListener('click', setSavingsGoal);
$('bulk-select-btn')?.addEventListener('click', toggleBulkMode);
$('bulk-delete-btn')?.addEventListener('click', bulkDeleteSelected);
$('dismiss-recurring-btn')?.addEventListener('click', () => $('recurring-reminder').classList.add('hidden'));

// Voice input
$('voice-input-btn')?.addEventListener('click', openVoiceOverlay);
$('voice-close-btn')?.addEventListener('click', closeVoiceOverlay);
$('voice-mic-btn')?.addEventListener('click', startVoiceListening);
$('voice-overlay')?.addEventListener('click', e => {
  if (e.target === $('voice-overlay')) closeVoiceOverlay();
});

// Scan receipt (OCR)
$('scan-receipt-btn')?.addEventListener('click', scanReceiptImage);

// Daily reminder
$('reminder-btn')?.addEventListener('click', () => { closeSidebar(); openReminderModal(); });
$('reminder-close-btn')?.addEventListener('click', closeReminderModal);
$('reminder-modal')?.addEventListener('click', e => {
  if (e.target === $('reminder-modal')) closeReminderModal();
});
$('reminder-enable-btn')?.addEventListener('click', async () => {
  const t = $('reminder-time-input').value || '20:00';
  const ok = await enableReminder(t);
  if (ok) {
    showToast(`🔔 Reminder set for ${t} daily!`);
    const [h,m] = t.split(':');
    const d = new Date(); d.setHours(+h,+m,0,0);
    if (d <= new Date()) d.setDate(d.getDate()+1);
    const label = d.toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit'});
    $('reminder-status-text').textContent = `🔔 Next reminder: ${label}`;
    $('reminder-enable-btn').textContent = 'Update Time';
    $('reminder-disable-btn').classList.remove('hidden');
  }
});
$('reminder-disable-btn')?.addEventListener('click', async () => {
  await disableReminder();
  $('reminder-status-text').textContent = '🔕 Reminder is off';
  $('reminder-enable-btn').textContent = 'Enable';
  $('reminder-disable-btn').classList.add('hidden');
  showToast('Reminder disabled.');
});

menuBtn.addEventListener('click', openSidebar);
sidebarOverlay.addEventListener('click', closeSidebar);
sidebarCloseBtn.addEventListener('click', closeSidebar);
bnavMenu.addEventListener('click', openSidebar);

topbarAddBtn.addEventListener('click', () => showSection('add'));
dismissBtn.addEventListener('click', () => weeklyReminder.classList.add('hidden'));

// Calendar nav
$('cal-prev').addEventListener('click', () => {
  calMonth--; if (calMonth<0){calMonth=11;calYear--;} renderCalendar();
});
$('cal-next').addEventListener('click', () => {
  calMonth++; if (calMonth>11){calMonth=0;calYear++;} renderCalendar();
});
$('cal-detail-close').addEventListener('click', () => $('cal-day-detail').classList.add('hidden'));

// Budget edit / save
$('budget-edit-btn').addEventListener('click', openBudgetEdit);
$('budget-save-btn').addEventListener('click', saveBudgets);

// Nav items (sidebar + bottom nav + dock)
document.addEventListener('click', e => {
  const item = e.target.closest('.nav-item[data-section], .bnav-item[data-section], .bnav-fab[data-section], .dock-btn[data-section], .hero-action-btn[data-section]');
  if (item) showSection(item.dataset.section);
});

// Hero "Add Income" + dock "Add Income" — navigate to add form pre-set to income
function goAddIncome() {
  showSection('add');
  $('tx-type').value = 'income';
  $('type-toggle').querySelectorAll('.type-btn').forEach(b => b.classList.remove('active'));
  $('type-toggle').querySelector('[data-type="income"]')?.classList.add('active');
  categoryGroup.classList.add('hidden'); categorySelect.required = false;
  payeeGroup.classList.remove('hidden');
}
const heroIncomeBtn = $('hero-add-income-btn');
if (heroIncomeBtn) heroIncomeBtn.addEventListener('click', goAddIncome);
const dockIncomeBtn = $('dock-add-income-btn');
if (dockIncomeBtn) dockIncomeBtn.addEventListener('click', goAddIncome);

// Cancel edit
$('cancel-edit-btn').addEventListener('click', () => {
  resetFormToAdd();
  transactionForm.reset();
  $('date').valueAsDate = new Date();
  paymentModes.querySelectorAll('.mode-chip').forEach(c => c.classList.remove('active'));
  paymentModes.querySelector('[data-mode="cash"]').classList.add('active');
  paymentModeHidden.value = 'cash';
  payeeGroup.classList.add('hidden');
  payeeInput.required = false;
  currentBill = null; billFileInput.value = '';
  billPreview.classList.add('hidden'); uploadZone.classList.remove('hidden');
  showSection('history');
});

// Split modal controls
$('add-split-row-btn').addEventListener('click', () => {
  const tx = splitTxId ? transactions.find(t => t.id === splitTxId) : null;
  addSplitRow(0, tx?.category || 'Food', tx?.date || new Date().toISOString().slice(0,10));
});
$('confirm-split-btn').addEventListener('click', confirmSplit);
$('close-split-modal-btn').addEventListener('click', closeSplitModal);
$('split-modal').addEventListener('click', e => { if (e.target === $('split-modal')) closeSplitModal(); });

// Filters
[searchInput, filterType, filterCategory, filterMode,
 $('filter-date-from'), $('filter-date-to')].forEach(el =>
  el?.addEventListener('input', () => { if (currentSection==='history') renderHistory(); })
);

// Modal close
closeModalBtn.addEventListener('click', closeBillModal);
billModal.addEventListener('click', e => { if (e.target === billModal) closeBillModal(); });
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closeBillModal(); closeSplitModal();
    closeVoiceOverlay(); closeReminderModal();
  }
});

// ── Money Bowl (Luxury Vault Jar) ──────────────────────────────────
function renderMoneyBowl() {
  const now = new Date();
  const curM = now.getMonth(), curY = now.getFullYear();

  let income = 0, expense = 0;
  for (const tx of transactions) {
    const [y, m] = tx.date.split('-').map(Number);
    const inPeriod = bowlPeriod === 'all' || (y === curY && m - 1 === curM);
    if (!inPeriod) continue;
    if (tx.type === 'income')  income  += tx.amount;
    if (tx.type === 'expense') expense += tx.amount;
  }

  const remaining = income - expense;
  const pct       = income > 0 ? Math.max(0, Math.min(100, (remaining / income) * 100)) : 0;
  const overflow   = expense > income && income > 0;

  // ── Liquid level (SVG translateY — vase interior height 440 px) ──
  const liquid = $('bowl-liquid');
  if (liquid) liquid.style.transform = `translateY(${Math.round((100 - pct) / 100 * 440)}px)`;

  // ── Centre: show balance ₹ amount (large) + % text (small) ───────
  const valEl = $('bowl-pct-val');
  const subEl = $('bowl-pct-sub');
  const fmtBig = v => {
    if (v >= 10000000) return `₹${(v/10000000).toFixed(2)}Cr`;
    if (v >= 100000)   return `₹${(v/100000).toFixed(1)}L`;
    if (v >= 1000)     return `₹${(v/1000).toFixed(1)}k`;
    return `₹${v.toFixed(0)}`;
  };
  if (valEl) {
    valEl.textContent = income === 0 ? '—' : fmtBig(Math.max(0, remaining));
    valEl.style.color = overflow ? '#f87171' : '#fff';
  }
  if (subEl) {
    if (income === 0)   subEl.textContent = 'add income to fill';
    else if (overflow)  subEl.textContent = 'overspent!';
    else                subEl.textContent = `${Math.round(pct)}%  remaining`;
    subEl.style.color = overflow ? 'rgba(248,113,113,.7)' : 'rgba(147,197,253,.75)';
  }

  // ── Stats panel ───────────────────────────────────────────────────
  const fmt2 = v => `₹${v.toFixed(2)}`;
  const si = $('bowl-stat-income');
  if (si) si.textContent = fmt2(income);
  const ss = $('bowl-stat-spent');
  if (ss) ss.textContent = fmt2(expense);
  const sr = $('bowl-stat-remaining');
  if (sr) {
    sr.textContent = `${remaining < 0 ? '-' : ''}${fmt2(Math.abs(remaining))}`;
    sr.style.color = remaining >= 0 ? '#60a5fa' : '#f87171';
  }

  // ── Alerts ───────────────────────────────────────────────────────
  const ow = $('bowl-overflow-warn');
  if (ow) ow.classList.toggle('hidden', !overflow);
  const ni = $('bowl-no-income');
  if (ni) ni.classList.toggle('hidden', income > 0);

  // ── Filter buttons ────────────────────────────────────────────────
  document.querySelectorAll('.bowl-filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.period === bowlPeriod));

  // ── Drip on level drop ───────────────────────────────────────────
  spawnBowlDrip();
}

// Brief drip splash animation when liquid level drops (SVG vase version)
let lastBowlPct = null;
function spawnBowlDrip() {
  const liquid = $('bowl-liquid');
  if (!liquid) return;
  const tfm = liquid.style.transform || '';
  const match = tfm.match(/translateY\(([\d.]+)px\)/);
  const translatePx = match ? parseFloat(match[1]) : 440;
  const curPct = Math.round((1 - translatePx / 440) * 100);
  if (lastBowlPct !== null && curPct < lastBowlPct) {
    const zone = $('vase-drip-zone');
    if (zone) {
      const drip = document.createElement('div');
      drip.className = 'vase-drip-particle';
      zone.appendChild(drip);
      setTimeout(() => drip.remove(), 900);
    }
  }
  lastBowlPct = curPct;
}

// Bowl filter click
document.addEventListener('click', e => {
  const btn = e.target.closest('.bowl-filter-btn');
  if (!btn) return;
  bowlPeriod = btn.dataset.period;
  lastBowlPct = null; // reset drip tracker so we don't falsely trigger
  renderMoneyBowl();
});

// ── Voice Input ────────────────────────────────────────────────────
function initVoiceInput() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) return;
  voiceRecognition = new SpeechRec();
  voiceRecognition.lang = 'en-IN';
  voiceRecognition.continuous = false;
  voiceRecognition.interimResults = true;
  voiceRecognition.maxAlternatives = 3;

  voiceRecognition.onresult = e => {
    // Always build from all results (not from resultIndex) to avoid accumulation glitches
    let transcript = Array.from(e.results).map(r => r[0].transcript).join(' ').trim();
    const el = $('voice-transcript');
    if (el) el.textContent = transcript;
    // Only process on final result
    if (e.results[e.results.length - 1].isFinal) {
      processVoiceTranscript(transcript);
    }
  };
  voiceRecognition.onerror = e => {
    const st = $('voice-status');
    if (st) st.textContent = `Couldn't hear. Tap mic and try again.`;
    $('voice-mic-btn')?.classList.remove('listening');
  };
  voiceRecognition.onend = () => {
    $('voice-mic-btn')?.classList.remove('listening');
    // Only fall back if onresult never fired (e.g. no speech detected)
    const t = $('voice-transcript')?.textContent?.trim();
    const alreadyParsed = ($('voice-parsed-wrap')?.children.length || 0) > 0;
    if (t && !alreadyParsed) {
      processVoiceTranscript(t);
    }
  };
}

function parseVoiceTransaction(rawText) {
  // ── Pre-process STT output ──────────────────────────────────────
  // Fix common STT glitch: digits glued to prepositions, e.g. "500for" → "500 for"
  //                         "5004 food" when user said "500 for food" (STT heard "four")
  let text = rawText
    .replace(/(\d+)(for|from|at|on|into|in|and)\b/gi, '$1 $2') // "500for" → "500 for"
    .replace(/\b(\d{3,})4\b(?=\s+\w)/g, (_, n) => n)           // "5004 food" → "500 food" (trailing "4" before a word = "for")
    .trim();

  const lower = text.toLowerCase();
  const result = { amount: null, category: null, payee: null, mode: null };

  // Amount detection — priority order:
  // 1. ₹-prefixed (most explicit)
  let amtMatch = text.match(/₹\s*([\d,]+(?:\.\d{1,2})?)/);
  // 2. rs/rupees suffixed
  if (!amtMatch) amtMatch = text.match(/\b([\d,]+(?:\.\d{1,2})?)\s*(?:rs\.?|rupees?)\b/i);
  // 3. Standalone number with word boundaries (no adjacent digits)
  if (!amtMatch) amtMatch = text.match(/(?<![.\d])\b(\d{1,6}(?:,\d{3})*(?:\.\d{1,2})?)\b(?![.\d])/);
  if (amtMatch) result.amount = parseFloat((amtMatch[1] || amtMatch[0]).replace(/,/g, ''));

  // Word numbers fallback (if no digit found)
  if (!result.amount) {
    const wordNums = {
      'ten thousand':10000,'five thousand':5000,'three thousand':3000,
      'two thousand':2000,'one thousand':1000,'thousand':1000,
      'nine hundred':900,'eight hundred':800,'seven hundred':700,
      'six hundred':600,'five hundred':500,'four hundred':400,
      'three hundred':300,'two hundred':200,'one hundred':100,'hundred':100,
    };
    for (const [w, v] of Object.entries(wordNums)) {
      if (lower.includes(w)) { result.amount = v; break; }
    }
  }

  // Category keyword map
  const catMap = [
    [['food','eat','restaurant','lunch','dinner','breakfast','zomato','swiggy','dominos','pizza','biryani'],'Food'],
    [['travel','cab','uber','ola','flight','train','bus','auto','metro','ticket','rickshaw','petrol','fuel'],'Travel'],
    [['rent','house','flat','apartment','pg','hostel'],'Rent'],
    [['electricity','electric','light bill','power bill','current bill','gas bill','water bill'],'Electricity'],
    [['grocery','grocer','vegetable','fruit','kirana','bigbasket','blinkit','zepto'],'Grocery'],
    [['shopping','amazon','flipkart','meesho','cloth','dress','shirt','shoes','myntra'],'Shopping'],
    [['lending','lend','loan','borrow','credit','advance'],'Lending Money'],
  ];
  for (const [kws, cat] of catMap) {
    if (kws.some(k => lower.includes(k))) { result.category = cat; break; }
  }
  // Default to Miscellaneous if nothing found
  if (!result.category) result.category = 'Miscellaneous';

  // Payment mode
  const modeKws = [
    [['cash'],'cash'],[['paytm'],'paytm'],[['phonepe','phone pe'],'phonepe'],
    [['credit card','credit'],'credit_card'],[['debit card','debit'],'debit_card'],
    [['upi','gpay','google pay'],'upi'],[['bank','neft','imps','rtgs'],'bank'],
  ];
  for (const [kws, mode] of modeKws) {
    if (kws.some(k => lower.includes(k))) { result.mode = mode; break; }
  }

  // Payee: after "to", "at", "from", "paid to"
  const payeeMatch = text.match(/(?:paid?\s+to|to|at|from)\s+([A-Za-z][A-Za-z\s]{1,25}?)(?:\s+(?:for|using|via|by|with|on)|[,.]|$)/i);
  if (payeeMatch) result.payee = payeeMatch[1].trim();

  return result;
}

function processVoiceTranscript(text) {
  if (!text) return;
  const parsed = parseVoiceTransaction(text);
  const st = $('voice-status');
  if (st) st.textContent = 'Got it! Confirm below:';

  const wrap = $('voice-parsed-wrap');
  if (!wrap) return;
  wrap.innerHTML = '';
  const tags = [];
  if (parsed.amount !== null)  tags.push(['Amount', `₹${parsed.amount}`]);
  if (parsed.category)         tags.push(['Category', parsed.category]);
  if (parsed.payee)            tags.push(['Payee', parsed.payee]);
  if (parsed.mode)             tags.push(['Mode', parsed.mode.replace('_',' ')]);

  wrap.innerHTML = tags.map(([l,v]) => `
    <div class="voice-tag">
      <span class="vtag-label">${l}</span>
      <span class="vtag-val">${v}</span>
    </div>`).join('');

  const applyBtn = $('voice-apply-btn');
  if (applyBtn) {
    applyBtn.classList.remove('hidden');
    applyBtn.onclick = () => applyVoiceToForm(parsed);
  }
}

function applyVoiceToForm(parsed) {
  closeVoiceOverlay();
  showSection('add');
  if (parsed.amount !== null) $('amount').value = parsed.amount;
  if (parsed.category) categorySelect.value = parsed.category;
  if (parsed.payee) {
    payeeGroup.classList.remove('hidden');
    payeeInput.value = parsed.payee;
  }
  if (parsed.mode) {
    paymentModes.querySelectorAll('.mode-chip').forEach(c => c.classList.remove('active'));
    const chip = paymentModes.querySelector(`[data-mode="${parsed.mode}"]`);
    if (chip) { chip.classList.add('active'); paymentModeHidden.value = parsed.mode; }
  }
  checkPayeeRequired();
  showToast('🎙️ Voice filled! Review & submit.');
}

function openVoiceOverlay() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    showToast('Voice input not supported on this browser. Try Chrome.', 'warning');
    return;
  }
  $('voice-overlay').classList.remove('hidden');
  $('voice-transcript').textContent = '';
  $('voice-status').textContent = 'Tap mic to start';
  $('voice-parsed-wrap').innerHTML = '';
  $('voice-apply-btn').classList.add('hidden');
  lucide.createIcons();
}

function closeVoiceOverlay() {
  $('voice-overlay').classList.add('hidden');
  if (voiceRecognition) { try { voiceRecognition.stop(); } catch(e) {} }
  $('voice-mic-btn')?.classList.remove('listening');
}

function startVoiceListening() {
  if (!voiceRecognition) initVoiceInput();
  if (!voiceRecognition) return;
  $('voice-transcript').textContent = '';
  $('voice-status').textContent = 'Listening…';
  $('voice-parsed-wrap').innerHTML = '';
  $('voice-apply-btn').classList.add('hidden');
  $('voice-mic-btn').classList.add('listening');
  try {
    voiceRecognition.start();
  } catch(e) {
    // already running — recreate
    initVoiceInput();
    setTimeout(() => {
      $('voice-mic-btn').classList.add('listening');
      try { voiceRecognition.start(); } catch(e2) {}
    }, 150);
  }
}

// ── Daily Reminder ──────────────────────────────────────────────────
function getReminderSettings() {
  try { return JSON.parse(localStorage.getItem('vault_reminder') || 'null'); }
  catch { return null; }
}
function saveReminderSettings(s) {
  localStorage.setItem('vault_reminder', JSON.stringify(s));
}

async function requestNotificationPermission() {
  if (!('Notification' in window)) return false;
  if (Notification.permission === 'granted') return true;
  const p = await Notification.requestPermission();
  return p === 'granted';
}

function scheduleNextReminder(timeStr) {
  if (reminderTimerId) clearTimeout(reminderTimerId);
  const [h, m] = timeStr.split(':').map(Number);
  const now = new Date();
  const target = new Date();
  target.setHours(h, m, 0, 0);
  if (target <= now) target.setDate(target.getDate() + 1);
  const delay = target - now;
  reminderTimerId = setTimeout(() => {
    fireReminder();
    scheduleNextReminder(timeStr);
  }, delay);
}

async function fireReminder() {
  if (Notification.permission !== 'granted') return;
  const opts = {
    body: "Don't forget to log today's expenses! 💸",
    icon: './icon.svg',
    badge: './icon.svg',
    tag: 'daily-reminder',
    renotify: true,
    requireInteraction: false,
  };
  // Prefer Service Worker notification (required on mobile/PWA)
  if ('serviceWorker' in navigator) {
    try {
      const reg = await navigator.serviceWorker.ready;
      await reg.showNotification('My Vault', opts);
      return;
    } catch(e) { /* fall through */ }
  }
  // Desktop fallback
  try { new Notification('My Vault', opts); } catch(e) {}
}

async function enableReminder(timeStr) {
  const granted = await requestNotificationPermission();
  if (!granted) {
    showToast('Allow notifications in browser settings first.', 'warning');
    return false;
  }
  saveReminderSettings({ enabled: true, time: timeStr });
  scheduleNextReminder(timeStr);
  // Immediate test notification so user confirms it works
  setTimeout(() => fireReminder(), 500);
  // Register Periodic Background Sync for installed PWA on Android
  if ('serviceWorker' in navigator) {
    try {
      const reg = await navigator.serviceWorker.ready;
      if ('periodicSync' in reg) {
        await reg.periodicSync.register('expense-reminder', {
          minInterval: 24 * 60 * 60 * 1000
        });
      }
    } catch(e) { /* not supported or not installed as PWA */ }
  }
  return true;
}

async function disableReminder() {
  if (reminderTimerId) clearTimeout(reminderTimerId);
  reminderTimerId = null;
  saveReminderSettings({ enabled: false, time: $('reminder-time-input')?.value || '20:00' });
  if ('serviceWorker' in navigator) {
    try {
      const reg = await navigator.serviceWorker.ready;
      if ('periodicSync' in reg) await reg.periodicSync.unregister('expense-reminder');
    } catch(e) {}
  }
}

function initReminder() {
  const s = getReminderSettings();
  if (s?.enabled && s.time) scheduleNextReminder(s.time);
}

function openReminderModal() {
  const s = getReminderSettings();
  $('reminder-time-input').value = s?.time || '20:00';
  const isOn = s?.enabled || false;
  const permStr = !('Notification' in window) ? ' (not supported)' :
                  Notification.permission === 'granted' ? '' :
                  Notification.permission === 'denied'  ? ' — notifications BLOCKED in browser' :
                  ' — permission not yet granted';
  if (isOn) {
    const [h,m] = (s.time||'20:00').split(':');
    const d = new Date(); d.setHours(+h,+m,0,0);
    if (d <= new Date()) d.setDate(d.getDate()+1);
    const label = d.toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit'});
    $('reminder-status-text').textContent = `🔔 Next: ${label}${permStr}`;
  } else {
    $('reminder-status-text').textContent = `🔕 Reminder is off${permStr}`;
  }
  $('reminder-enable-btn').textContent = isOn ? 'Update Time' : 'Enable';
  $('reminder-disable-btn').classList.toggle('hidden', !isOn);
  $('reminder-modal').classList.remove('hidden');
  lucide.createIcons();
}
function closeReminderModal() { $('reminder-modal').classList.add('hidden'); }

// ── Receipt OCR ─────────────────────────────────────────────────────
async function loadTesseract() {
  if (tesseractLoaded) return true;
  if (tesseractLoading) {
    return new Promise(resolve => {
      const id = setInterval(() => {
        if (tesseractLoaded) { clearInterval(id); resolve(true); }
      }, 250);
    });
  }
  tesseractLoading = true;
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js';
    s.onload  = () => { tesseractLoaded = true; tesseractLoading = false; resolve(true); };
    s.onerror = () => { tesseractLoading = false; reject(false); };
    document.head.appendChild(s);
  });
}

function extractAmountFromText(text) {
  const patterns = [
    /(?:grand\s+)?total\s*[:\-]?\s*₹?\s*(\d[\d,]*(?:\.\d{1,2})?)/i,
    /amount\s+(?:due|paid|payable|charged)\s*[:\-]?\s*₹?\s*(\d[\d,]*(?:\.\d{1,2})?)/i,
    /net\s+(?:amount|total|payable)\s*[:\-]?\s*₹?\s*(\d[\d,]*(?:\.\d{1,2})?)/i,
    /(?:bill|invoice|order)\s+(?:amount|total)\s*[:\-]?\s*₹?\s*(\d[\d,]*(?:\.\d{1,2})?)/i,
    /₹\s*(\d[\d,]*(?:\.\d{1,2})?)/,
    /(\d[\d,]*\.\d{2})\s*(?:rs|inr|rupees?)?/i,
  ];
  for (const p of patterns) {
    const m = text.match(p);
    if (m) {
      const v = parseFloat(m[1].replace(/,/g,''));
      if (v > 0) return v;
    }
  }
  return null;
}

function extractMerchantFromText(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  for (const line of lines.slice(0, 5)) {
    if (line.length >= 3 && line.length <= 50
      && !/^\d/.test(line)
      && !/^(receipt|invoice|tax|vat|gst|date|time|order|bill|ref|transaction)/i.test(line)) {
      return line;
    }
  }
  return null;
}

async function scanReceiptImage() {
  if (!currentBill || !currentBill.type.startsWith('image/')) {
    showToast('Attach an image receipt first.', 'warning');
    return;
  }
  $('ocr-overlay').classList.remove('hidden');
  $('ocr-status').textContent = 'Loading OCR engine…';
  try {
    await loadTesseract();
    $('ocr-status').textContent = 'Scanning receipt…';
    const { data: { text } } = await Tesseract.recognize(currentBill.data, 'eng', {
      logger: m => {
        if (m.status === 'recognizing text') {
          const pct = Math.round(m.progress * 100);
          const el = $('ocr-status');
          if (el) el.textContent = `Scanning… ${pct}%`;
        }
      }
    });
    const amount   = extractAmountFromText(text);
    const merchant = extractMerchantFromText(text);
    $('ocr-overlay').classList.add('hidden');
    if (amount) {
      $('amount').value = amount;
      if (merchant) $('note').value = merchant;
      checkPayeeRequired();
      showToast(`📄 Found ₹${amount}${merchant ? ' · ' + merchant : ''}`);
    } else {
      showToast('No amount found. Try a clearer photo.', 'warning');
    }
  } catch(e) {
    $('ocr-overlay').classList.add('hidden');
    showToast('OCR failed. Try a clearer image.', 'warning');
  }
}

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
initBiometricUI();
initDarkMode();
initVoiceInput();
initReminder();
