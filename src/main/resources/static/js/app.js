const API = 'http://localhost:8080/api';

function showTab(name) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}

function onFileSelect(input, labelId) {
  const label = document.getElementById(labelId);
  label.textContent = input.files[0] ? '📎 ' + input.files[0].name : '';
}

function onEncAlgoChange() {
  const enc = document.getElementById('sign-enc-algo').value;
  const hashSel = document.getElementById('sign-hash-algo');
  const md5 = hashSel.querySelector('option[value="MD5"]');
  if (enc === 'ECDSA') {
    if (hashSel.value === 'MD5') hashSel.value = 'SHA-256';
    md5.disabled = true;
    md5.textContent = 'MD5 (not supported with ECDSA)';
  } else {
    md5.disabled = false;
    md5.textContent = 'MD5 (weak, RSA only)';
  }
}

function copyText(id, btn) {
  const el = document.getElementById(id);
  navigator.clipboard.writeText(el.value).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (loading) {
    btn._orig = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Processing...';
    btn.disabled = true;
  } else {
    btn.innerHTML = btn._orig;
    btn.disabled = false;
  }
}

async function generateKeys() {
  const algo = document.getElementById('keys-algo').value;
  setLoading('keys-gen-btn', true);
  try {
    const res = await fetch(API + '/generate-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ algorithm: algo })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    document.getElementById('private-key-out').value = data.privateKey;
    document.getElementById('public-key-out').value = data.publicKey;
    document.getElementById('keys-result').style.display = 'block';
  } catch (e) {
    alert('Error: ' + e.message);
  } finally {
    setLoading('keys-gen-btn', false);
  }
}

async function signDocument() {
  const file = document.getElementById('sign-file').files[0];
  const privateKey = document.getElementById('sign-private-key').value.trim();
  const publicKey = document.getElementById('sign-public-key').value.trim();
  const encAlgo = document.getElementById('sign-enc-algo').value;
  const hashAlgo = document.getElementById('sign-hash-algo').value;
  const resultDiv = document.getElementById('sign-result');

  if (!file) return showResult(resultDiv, 'error', '❌', 'No file selected', 'Please choose a file to sign.');
  if (!privateKey) return showResult(resultDiv, 'error', '❌', 'Missing private key', 'Please paste your private key.');
  if (!publicKey) return showResult(resultDiv, 'error', '❌', 'Missing public key', 'Please paste your public key.');

  setLoading('sign-btn', true);

  const formData = new FormData();
  formData.append('file', file);
  formData.append('privateKey', privateKey);
  formData.append('publicKey', publicKey);
  formData.append('encryptionAlgorithm', encAlgo);
  formData.append('hashAlgorithm', hashAlgo);

  try {
    const res = await fetch(API + '/sign', { method: 'POST', body: formData });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const signedName = file.name + '.signed.zip';
    resultDiv.innerHTML = `
      <div class="download-zone">
        <div class="icon">📦</div>
        <div>
          <div class="name">✅ Document signed successfully!</div>
          <div class="desc">${signedName} — original file + metadata.json (signature)</div>
        </div>
        <a href="${url}" download="${signedName}" class="btn success-btn" style="margin-left:auto; text-decoration:none">⬇️ Download</a>
      </div>
      <div class="result-box info" style="margin-top:12px">
        <strong>What's inside the ZIP:</strong><br>
        📄 <code>original/${file.name}</code> — your file, completely unchanged<br>
        📋 <code>metadata.json</code> — signature, algorithm, timestamp, public key
      </div>`;
  } catch (e) {
    showResult(resultDiv, 'error', '❌', 'Signing failed', e.message);
  } finally {
    setLoading('sign-btn', false);
  }
}

async function verifyDocument() {
  const file = document.getElementById('verify-file').files[0];
  const publicKey = document.getElementById('verify-public-key').value.trim();
  const resultDiv = document.getElementById('verify-result');

  if (!file) return showResult(resultDiv, 'error', '❌', 'No file selected', 'Please choose a .signed.zip file.');

  setLoading('verify-btn', true);

  const formData = new FormData();
  formData.append('file', file);
  if (publicKey) formData.append('publicKey', publicKey);

  try {
    const res = await fetch(API + '/verify', { method: 'POST', body: formData });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    const isValid = data.valid;
    resultDiv.innerHTML = `
      <div class="result-box ${isValid ? 'success' : 'error'}">
        <div class="result-icon">${isValid ? '✅' : '❌'}</div>
        <div class="result-title">${isValid ? 'Signature Valid' : 'Signature INVALID'}</div>
        <div>${data.details}</div>
      </div>
      <div class="card" style="margin-top:16px">
        <h2>Signature Details</h2>
        <table class="meta-table">
          <tr><td>File</td><td>${data.fileName || '—'}</td></tr>
          <tr><td>Algorithm</td><td>${data.algorithm || '—'}</td></tr>
          <tr><td>Hash</td><td>${data.hashAlgorithm || '—'}</td></tr>
          <tr><td>Signed at</td><td>${data.timestamp ? new Date(data.timestamp).toLocaleString() : '—'}</td></tr>
          <tr><td>Status</td><td><span class="algo-badge ${isValid ? 'badge-safe' : 'badge-weak'}">${isValid ? '✓ VALID' : '✗ INVALID'}</span></td></tr>
        </table>
      </div>`;
  } catch (e) {
    showResult(resultDiv, 'error', '❌', 'Verification error', e.message);
  } finally {
    setLoading('verify-btn', false);
  }
}

async function runWeakAttack() {
  const input = document.getElementById('weak-input').value.trim();
  const resultDiv = document.getElementById('weak-result');
  if (!input) return;

  setLoading('weak-btn', true);

  try {
    const res = await fetch(API + '/weak/attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    resultDiv.innerHTML = `
      <div class="card">
        <h2>⚡ Attack Result: ${data.attackType}</h2>
        <p class="subtitle">${data.success ? 'Collision found instantly!' : 'Attack failed'}</p>
        <div class="collision-grid">
          <div class="collision-item original">
            <h4>Original Document</h4>
            <div class="value">"${escHtml(data.originalInput)}"</div>
            <div class="hash">${data.originalHash}</div>
            <div style="font-size:11px;color:var(--text2);margin-top:4px">Weak Hash value</div>
          </div>
          <div class="collision-item tampered">
            <h4>🔴 Tampered Document (crafted by attacker)</h4>
            <div class="value">"${escHtml(data.collidingInput)}"</div>
            <div class="hash">${data.collidingHash}</div>
            <div style="font-size:11px;color:var(--text2);margin-top:4px">Weak Hash value</div>
          </div>
        </div>
        <div class="hash-match">⚠️ SAME HASH → Signature would be VALID for BOTH documents!</div>
        <div class="divider"></div>
        <h2 style="margin-bottom:12px">Explanation</h2>
        <div class="explanation-box">${escHtml(data.explanation)}</div>
      </div>`;
  } catch (e) {
    showResult(resultDiv, 'error', '❌', 'Error', e.message);
  } finally {
    setLoading('weak-btn', false);
  }
}

async function loadWeakInfo() {
  const div = document.getElementById('weak-info');
  const res = await fetch(API + '/weak/info');
  const data = await res.json();
  const comp = data.comparison;
  const cards = Object.entries(comp).map(([name, info]) => `
    <div class="algo-card">
      <div class="name">${name}</div>
      <div class="bits">${info.bits} bits output</div>
      <span class="algo-badge ${info.safe ? 'badge-safe' : 'badge-weak'}">${info.safe ? '✓ Safe' : '✗ Broken'}</span>
      ${info.reason ? `<div style="font-size:11px;color:var(--text2);margin-top:6px">${info.reason}</div>` : ''}
    </div>`).join('');
  div.innerHTML = `
    <div class="card">
      <h2>Hash Algorithm Comparison</h2>
      <p class="subtitle">More output bits = harder to find collisions</p>
      <div class="algo-comparison">${cards}</div>
    </div>`;
}

function showResult(div, type, icon, title, message) {
  div.innerHTML = `<div class="result-box ${type}"><div class="result-icon">${icon}</div><div class="result-title">${title}</div><div>${escHtml(message)}</div></div>`;
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
