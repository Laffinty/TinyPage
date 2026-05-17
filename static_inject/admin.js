/* TinyPage Admin — Trae-Inspired Dashboard JS */

// ===== Theme =====
function toggleTheme() {
  var d = document.documentElement;
  d.classList.toggle('light');
  try {
    localStorage.setItem('theme', d.classList.contains('light') ? 'light' : 'dark');
  } catch(e) {}
}

// ===== Toast =====
function showToast(message, type) {
  type = type || 'info';
  var container = document.getElementById('toast-container');
  if (!container) return;
  var toast = document.createElement('div');
  toast.className = 'toast ' + type;
  var icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
  toast.innerHTML = '<span style="font-weight:800;font-size:1.1rem;">' + icon + '</span><span>' + escapeHtml(message) + '</span>' +
    '<button class="toast-close" onclick="this.parentElement.remove()">×</button>';
  container.appendChild(toast);
  setTimeout(function() {
    if (toast.parentElement) toast.remove();
  }, 4000);
}

function escapeHtml(text) {
  var div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ===== Article Filter =====
function filterArticles(q) {
  var rows = document.querySelectorAll('table.admin-table tbody tr');
  q = q.toLowerCase();
  rows.forEach(function(row) {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// ===== Drag & Drop Upload =====
function handleDrop(e) {
  e.preventDefault();
  var zone = document.getElementById('drop-zone');
  if (zone) zone.classList.remove('dragover');
  var file = e.dataTransfer.files[0];
  if (file && file.type.startsWith('image/')) uploadFile(file);
}

function handleFileSelect(e) {
  var file = e.target.files[0];
  if (file) uploadFile(file);
}

function uploadFile(file) {
  var csrfInput = document.querySelector('input[name=csrf_token]');
  if (!csrfInput || !csrfInput.value) { showToast('CSRF token missing', 'error'); return; }
  var reader = new FileReader();
  reader.onload = function(ev) {
    var b64 = ev.target.result;
    var b64Data = b64.split(',')[1];
    var body = 'csrf_token=' + encodeURIComponent(csrfInput.value) +
               '&filename=' + encodeURIComponent(file.name) + '&data=' + encodeURIComponent(b64Data);
    showToast('上传中...', 'info');
    fetch('/upload', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.success) {
          var ta = document.querySelector('textarea[name=content]');
          ta.value += '\n![](' + data.url + ')\n';
          ta.dispatchEvent(new Event('input', { bubbles: true }));
          showToast('上传成功', 'success');
        } else {
          showToast('上传失败: ' + (data.error || '未知错误'), 'error');
        }
      })
      .catch(function(err) { showToast('上传失败: 网络错误', 'error'); });
  };
  reader.onerror = function() { showToast('文件读取失败', 'error'); };
  reader.readAsDataURL(file);
}

// ===== AI Assistant =====
function showAIPanel() {
  var panel = document.getElementById('ai-panel');
  if (panel) panel.style.display = 'block';
}

function setAIStatus(msg, isError) {
  var el = document.getElementById('ai-status');
  if (el) { el.textContent = msg; el.style.color = isError ? 'var(--a-danger)' : 'var(--a-primary)'; }
}

function setAIBusy(busy) {
  document.querySelectorAll('.ai-btn').forEach(function(b) { b.disabled = busy; });
}

function aiCall(action, data, callback) {
  setAIBusy(true);
  setAIStatus('AI 处理中...', false);
  var csrf = document.querySelector('[name=csrf_token]');
  if (!csrf) { setAIBusy(false); setAIStatus('CSRF错误', true); return; }
  var body = 'csrf_token=' + encodeURIComponent(csrf.value) + '&action=' + action;
  for (var k in data) { body += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(data[k]); }
  fetch('/ai-assist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body
  }).then(function(r) { return r.json(); }).then(function(result) {
    setAIBusy(false);
    if (result.error) { setAIStatus('错误: ' + result.error, true); }
    else { setAIStatus('✓', false); callback(result); }
  }).catch(function(e) { setAIBusy(false); setAIStatus('网络错误', true); });
}

function aiComplete() {
  var ta = document.querySelector('textarea[name=content]');
  if (!ta.value) { setAIStatus('请先输入内容', true); return; }
  aiCall('complete', { text: ta.value }, function(r) { ta.value += '\n\n' + r.result; ta.dispatchEvent(new Event('input', { bubbles: true })); });
}

function aiPolish() {
  var ta = document.querySelector('textarea[name=content]');
  if (!ta.value) { setAIStatus('请先输入内容', true); return; }
  aiCall('polish', { text: ta.value }, function(r) { ta.value = r.result; ta.dispatchEvent(new Event('input', { bubbles: true })); });
}

function aiTranslate(lang) {
  var ta = document.querySelector('textarea[name=content]');
  if (!ta.value) { setAIStatus('请先输入内容', true); return; }
  aiCall('translate', { text: ta.value, lang: lang }, function(r) { ta.value = r.result; ta.dispatchEvent(new Event('input', { bubbles: true })); });
}

function aiSuggestTags() {
  var ta = document.querySelector('textarea[name=content]');
  var tagsInput = document.querySelector('input[name=tags]');
  if (!ta.value) { setAIStatus('请先输入内容', true); return; }
  aiCall('suggest_tags', { text: ta.value }, function(r) {
    if (r.result && r.result.length > 0) {
      var current = tagsInput.value || '';
      var newTags = current ? current.split(',').map(function(t) { return t.trim(); }) : [];
      r.result.forEach(function(t) { if (newTags.indexOf(t) < 0) newTags.push(t); });
      tagsInput.value = newTags.join(', ');
      setAIStatus('已推荐 ' + r.result.length + ' 个标签', false);
    } else { setAIStatus('未找到标签', true); }
  });
}

// Show AI panel immediately
document.addEventListener('DOMContentLoaded', function() {
  showAIPanel();
});

// ===== Regen button spinner =====
document.addEventListener('htmx:beforeRequest', function(evt) {
  var btn = evt.detail.elt.closest('#regen-btn');
  if (btn) {
    btn.innerHTML = '<span class="spinner"></span> 生成中...';
    btn.disabled = true;
  }
});

document.addEventListener('htmx:afterRequest', function(evt) {
  var btn = document.getElementById('regen-btn');
  if (btn) {
    btn.innerHTML = '<span class="btn-icon">↻</span> 重新生成静态页';
    btn.disabled = false;
  }
});

// ===== Close mobile menu on outside click =====
document.addEventListener('click', function(e) {
  if (document.body.classList.contains('menu-open')) {
    var sidebar = document.querySelector('.admin-sidebar');
    var toggle = document.querySelector('.mobile-menu-toggle');
    if (sidebar && !sidebar.contains(e.target) && !toggle.contains(e.target)) {
      document.body.classList.remove('menu-open');
    }
  }
});
