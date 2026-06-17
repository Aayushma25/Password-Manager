/* =========================================================
   VaultGen — Frontend Logic
   ========================================================= */

"use strict";

// ---- Utilities ----

function showToast(msg, type = "success") {
  const el = document.getElementById("vgToast");
  const msgEl = document.getElementById("toastMsg");
  msgEl.innerHTML = `<i class="bi bi-${type === "success" ? "check-circle" : "exclamation-triangle"} me-2"></i>${msg}`;
  el.className = `toast vg-toast align-items-center border-${type === "success" ? "success" : "danger"}`;
  bootstrap.Toast.getOrCreateInstance(el, { delay: 2500 }).show();
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast("Copied to clipboard");
  } catch {
    // Fallback for non-HTTPS localhost
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    showToast("Copied to clipboard");
  }
}

async function apiFetch(url, options = {}) {
  const resp = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || "Request failed");
  }
  return resp.json();
}

// ---- Toggle password visibility ----
function wireToggle(btnId, inputId) {
  const btn = document.getElementById(btnId);
  const inp = document.getElementById(inputId);
  if (!btn || !inp) return;
  btn.addEventListener("click", () => {
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    btn.innerHTML = show ? '<i class="bi bi-eye-slash"></i>' : '<i class="bi bi-eye"></i>';
  });
}

// ===========================================================================
// TAB 1 — GENERATOR
// ===========================================================================

let currentPassword = "";
let currentStrengthScore = null;
let currentBreachCount = null;

const genDisplay    = document.getElementById("generatedDisplay");
const entropyBadge  = document.getElementById("entropyBadge");
const entropyVal    = document.getElementById("entropyVal");
const btnCopyGen    = document.getElementById("btnCopyGen");
const saveForm      = document.getElementById("saveForm");

// Length slider
const pwLength  = document.getElementById("pwLength");
const lenLabel  = document.getElementById("lenLabel");
pwLength.addEventListener("input", () => { lenLabel.textContent = pwLength.value; });

// Word count slider
const wordCount      = document.getElementById("wordCount");
const wordCountLabel = document.getElementById("wordCountLabel");
wordCount.addEventListener("input", () => { wordCountLabel.textContent = wordCount.value; });

// Mode toggle
document.querySelectorAll('input[name="genMode"]').forEach(radio => {
  radio.addEventListener("change", () => {
    const isPass = radio.value === "password";
    document.getElementById("passwordOptions").style.display   = isPass ? "" : "none";
    document.getElementById("passphraseOptions").style.display = isPass ? "none" : "";
  });
});

// Generate button
document.getElementById("btnGenerate").addEventListener("click", async () => {
  const mode = document.querySelector('input[name="genMode"]:checked').value;
  const payload = mode === "passphrase"
    ? { mode: "passphrase", word_count: parseInt(wordCount.value) }
    : {
        mode: "password",
        length: parseInt(pwLength.value),
        use_upper:  document.getElementById("useUpper").checked,
        use_lower:  document.getElementById("useLower").checked,
        use_digits: document.getElementById("useDigits").checked,
        use_symbols: document.getElementById("useSymbols").checked,
        exclude_ambiguous: document.getElementById("excludeAmbiguous").checked,
      };

  try {
    const data = await apiFetch("/api/generate", { method: "POST", body: JSON.stringify(payload) });
    currentPassword = data.password;

    genDisplay.textContent = data.password;
    genDisplay.style.color = "";

    entropyVal.textContent = data.entropy;
    entropyBadge.style.display = "";
    btnCopyGen.style.display = "";
    saveForm.style.display = "";

    // Auto-run strength check for feedback
    runStrengthOnGenerated(data.password);
  } catch (e) {
    showToast(e.message, "danger");
  }
});

async function runStrengthOnGenerated(pw) {
  try {
    const data = await apiFetch("/api/strength", { method: "POST", body: JSON.stringify({ password: pw }) });
    currentStrengthScore = data.score;
  } catch { /* non-critical */ }
}

btnCopyGen.addEventListener("click", () => {
  if (currentPassword) copyToClipboard(currentPassword);
});

// Save to vault
document.getElementById("btnSaveToVault").addEventListener("click", async () => {
  const appName = document.getElementById("saveAppName").value.trim();
  if (!appName) {
    showToast("Application name is required", "danger");
    return;
  }
  try {
    await apiFetch("/api/vault/save", {
      method: "POST",
      body: JSON.stringify({
        app_name:    appName,
        username:    document.getElementById("saveUsername").value.trim(),
        password:    currentPassword,
        notes:       document.getElementById("saveNotes").value.trim(),
        strength:    currentStrengthScore,
        breach_count: currentBreachCount,
      }),
    });
    showToast("Saved to vault");
    document.getElementById("saveAppName").value = "";
    document.getElementById("saveUsername").value = "";
    document.getElementById("saveNotes").value = "";
    loadVault();
  } catch (e) {
    showToast(e.message, "danger");
  }
});

// ===========================================================================
// TAB 2 — STRENGTH CHECKER
// ===========================================================================

const strengthInput  = document.getElementById("strengthInput");
const strengthBar    = document.getElementById("strengthBarFill");
const strengthLabel  = document.getElementById("strengthLabel");
const strengthResults = document.getElementById("strengthResults");

wireToggle("btnToggleStrengthVis", "strengthInput");

let strengthTimer = null;
strengthInput.addEventListener("input", () => {
  clearTimeout(strengthTimer);
  const val = strengthInput.value;
  if (!val) {
    strengthBar.style.width = "0%";
    strengthBar.className = "vg-strength-bar-fill";
    strengthLabel.textContent = "—";
    strengthResults.style.display = "none";
    return;
  }
  strengthTimer = setTimeout(() => checkStrength(val), 250);
});

const scoreColors = ["strength-0","strength-1","strength-2","strength-3","strength-4"];
const scoreWidths = ["15%","30%","55%","80%","100%"];

async function checkStrength(pw) {
  try {
    const data = await apiFetch("/api/strength", { method: "POST", body: JSON.stringify({ password: pw }) });
    const s = data.score;

    strengthBar.className = `vg-strength-bar-fill ${scoreColors[s]}`;
    strengthBar.style.width = scoreWidths[s];
    strengthLabel.textContent = data.label;
    strengthLabel.style.color = "";

    document.getElementById("scoreVal").textContent      = s;
    document.getElementById("entropyStrength").textContent = data.entropy;
    document.getElementById("guessesVal").textContent    = data.guesses_log10;
    document.getElementById("crackOffline").textContent  = data.crack_time_offline;
    document.getElementById("crackOnline").textContent   = data.crack_time_online;

    const warnBlock = document.getElementById("warningsBlock");
    const warnList  = document.getElementById("warningsList");
    warnList.innerHTML = "";
    if (data.warnings && data.warnings.length) {
      data.warnings.forEach(w => {
        const li = document.createElement("li");
        li.className = "vg-warning-item";
        li.innerHTML = `<i class="bi bi-exclamation-circle text-warning flex-shrink-0 mt-1"></i>${w}`;
        warnList.appendChild(li);
      });
      warnBlock.style.display = "";
    } else {
      warnBlock.style.display = "none";
    }

    strengthResults.style.display = "";
  } catch (e) {
    console.error(e);
  }
}

// ===========================================================================
// TAB 3 — BREACH CHECKER
// ===========================================================================

wireToggle("btnToggleBreachVis", "breachInput");

document.getElementById("btnCheckBreach").addEventListener("click", async () => {
  const pw = document.getElementById("breachInput").value;
  if (!pw) { showToast("Enter a password first", "danger"); return; }

  const resultDiv = document.getElementById("breachResult");
  resultDiv.style.display = "";
  resultDiv.innerHTML = `<div class="text-muted small"><span class="spinner-border spinner-border-sm me-2"></span>Checking via k-anonymity API…</div>`;

  try {
    const data = await apiFetch("/api/breach", { method: "POST", body: JSON.stringify({ password: pw }) });

    if (data.error) {
      resultDiv.innerHTML = `<div class="alert alert-warning small"><i class="bi bi-wifi-off me-2"></i>Could not reach HIBP API: ${data.error}</div>`;
    } else if (data.pwned) {
      resultDiv.innerHTML = `
        <div class="vg-breach-danger">
          <div class="d-flex align-items-start gap-3">
            <i class="bi bi-exclamation-octagon-fill text-danger fs-3 flex-shrink-0"></i>
            <div>
              <div class="fw-semibold mb-1">Password found in data breaches</div>
              <div class="small text-muted">
                This password appeared <strong class="text-danger">${data.count.toLocaleString()} times</strong>
                in known breach databases. You should never use it.
              </div>
            </div>
          </div>
        </div>`;
      currentBreachCount = data.count;
    } else {
      resultDiv.innerHTML = `
        <div class="vg-breach-safe">
          <div class="d-flex align-items-start gap-3">
            <i class="bi bi-shield-check-fill text-success fs-3 flex-shrink-0"></i>
            <div>
              <div class="fw-semibold mb-1">No breaches found</div>
              <div class="small text-muted">
                This password does not appear in any known breach database.
                That said, always combine a strong password with a unique one per service.
              </div>
            </div>
          </div>
        </div>`;
      currentBreachCount = 0;
    }
  } catch (e) {
    resultDiv.innerHTML = `<div class="alert alert-danger small">${e.message}</div>`;
  }
});

// ===========================================================================
// TAB 4 — VAULT
// ===========================================================================

let vaultData = [];
let deleteTargetId = null;
let editTargetId   = null;

const entryModal  = new bootstrap.Modal(document.getElementById("entryModal"));
const deleteModal = new bootstrap.Modal(document.getElementById("deleteModal"));

wireToggle("btnToggleEditPw", "editPassword");

async function loadVault() {
  try {
    vaultData = await apiFetch("/api/vault/list");
    renderVault(vaultData);
    updateVaultBadge(vaultData.length);
  } catch (e) {
    console.error(e);
  }
}

function updateVaultBadge(count) {
  const badge = document.getElementById("vault-count-badge");
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = "";
  } else {
    badge.style.display = "none";
  }
}

function strengthBadge(score) {
  if (score === null || score === undefined) return '<span class="text-muted small">—</span>';
  const labels = ["Very Weak","Weak","Fair","Strong","Very Strong"];
  const classes = ["danger","warning","warning","success","success"];
  return `<span class="badge bg-${classes[score]}-subtle text-${classes[score]} border border-${classes[score]}-subtle">${labels[score]}</span>`;
}

function breachBadge(count) {
  if (count === null || count === undefined) return '<span class="text-muted small">—</span>';
  if (count === 0) return '<span class="badge bg-success-subtle text-success border border-success-subtle">Clean</span>';
  return `<span class="badge bg-danger-subtle text-danger border border-danger-subtle">${count.toLocaleString()} breaches</span>`;
}

function formatDate(iso) {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

function renderVault(entries) {
  const empty = document.getElementById("vaultEmpty");
  const wrap  = document.getElementById("vaultTableContainer");
  const tbody = document.getElementById("vaultTableBody");

  if (!entries.length) {
    empty.style.display = "";
    wrap.style.display  = "none";
    return;
  }
  empty.style.display = "none";
  wrap.style.display  = "";

  tbody.innerHTML = entries.map(e => `
    <tr data-id="${e.id}">
      <td>
        <div class="fw-medium">${escHtml(e.app_name)}</div>
      </td>
      <td class="text-muted">${escHtml(e.username || "—")}</td>
      <td>${strengthBadge(e.strength)}</td>
      <td>${breachBadge(e.breach_count)}</td>
      <td class="text-muted small">${formatDate(e.date_saved)}</td>
      <td class="text-end">
        <div class="d-flex gap-1 justify-content-end">
          <button class="btn btn-sm btn-outline-secondary btn-copy-pw" data-id="${e.id}" title="Copy password">
            <i class="bi bi-clipboard"></i>
          </button>
          <button class="btn btn-sm btn-outline-secondary btn-edit" data-id="${e.id}" title="Edit">
            <i class="bi bi-pencil"></i>
          </button>
          <button class="btn btn-sm btn-outline-danger btn-delete" data-id="${e.id}" title="Delete">
            <i class="bi bi-trash"></i>
          </button>
        </div>
      </td>
    </tr>
  `).join("");
}

function escHtml(str) {
  return (str || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// Vault search
document.getElementById("vaultSearch").addEventListener("input", function() {
  const q = this.value.toLowerCase();
  const filtered = vaultData.filter(e =>
    (e.app_name  || "").toLowerCase().includes(q) ||
    (e.username  || "").toLowerCase().includes(q) ||
    (e.notes     || "").toLowerCase().includes(q)
  );
  renderVault(filtered);
});

// Vault table event delegation
document.getElementById("vaultTableBody").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  const id = parseInt(btn.dataset.id);

  if (btn.classList.contains("btn-copy-pw")) {
    try {
      const data = await apiFetch(`/api/vault/get/${id}`);
      await copyToClipboard(data.password);
    } catch (err) { showToast(err.message, "danger"); }
  }

  if (btn.classList.contains("btn-edit")) {
    try {
      const data = await apiFetch(`/api/vault/get/${id}`);
      editTargetId = id;
      document.getElementById("entryModalTitle").textContent = `Edit — ${data.app_name}`;
      document.getElementById("editAppName").value  = data.app_name  || "";
      document.getElementById("editUsername").value = data.username  || "";
      document.getElementById("editPassword").value = data.password  || "";
      document.getElementById("editNotes").value    = data.notes     || "";
      entryModal.show();
    } catch (err) { showToast(err.message, "danger"); }
  }

  if (btn.classList.contains("btn-delete")) {
    deleteTargetId = id;
    deleteModal.show();
  }
});

// Copy from edit modal
document.getElementById("btnCopyEditPw").addEventListener("click", async () => {
  const pw = document.getElementById("editPassword").value;
  if (pw) await copyToClipboard(pw);
});

// Save edit
document.getElementById("btnSaveEdit").addEventListener("click", async () => {
  if (!editTargetId) return;
  try {
    await apiFetch(`/api/vault/update/${editTargetId}`, {
      method: "PUT",
      body: JSON.stringify({
        app_name: document.getElementById("editAppName").value.trim(),
        username: document.getElementById("editUsername").value.trim(),
        password: document.getElementById("editPassword").value,
        notes:    document.getElementById("editNotes").value.trim(),
      }),
    });
    entryModal.hide();
    showToast("Entry updated");
    loadVault();
  } catch (err) { showToast(err.message, "danger"); }
});

// Confirm delete
document.getElementById("btnConfirmDelete").addEventListener("click", async () => {
  if (!deleteTargetId) return;
  try {
    await apiFetch(`/api/vault/delete/${deleteTargetId}`, { method: "DELETE" });
    deleteModal.hide();
    showToast("Entry deleted");
    loadVault();
  } catch (err) { showToast(err.message, "danger"); }
});

// Export vault
document.getElementById("btnExportVault").addEventListener("click", async () => {
  try {
    const data = await apiFetch("/api/vault/export");
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `vaultgen-backup-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Vault exported — passwords remain encrypted");
  } catch (err) { showToast(err.message, "danger"); }
});

// Load vault on tab switch
document.querySelector('[data-bs-target="#tab-vault"]').addEventListener("shown.bs.tab", loadVault);

// Initial load
loadVault();
