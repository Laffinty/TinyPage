/**
 * TinyPage Client-Side Search
 * Uses a pre-generated JSON index for instant full-text search.
 */
(function () {
  const input = document.getElementById('search-input');
  const results = document.getElementById('search-results');
  if (!input || !results) return;

  let index = [];
  let debounceTimer;

  fetch('/search-index.json')
    .then((r) => r.json())
    .then((data) => {
      index = data;
    })
    .catch(() => {
      results.innerHTML = '<p class="no-results">搜索索引加载失败</p>';
    });

  function render(items) {
    if (!items.length) {
      results.innerHTML = '<p class="no-results">未找到匹配文章</p>';
      return;
    }
    results.innerHTML = items
      .map(
        (item) =>
          `<article class="result-item">` +
          `<a href="${item.url}">${escapeHtml(item.title)}</a>` +
          `<p>${escapeHtml(truncate(item.summary, 120))}</p>` +
          `<div class="result-meta">${escapeHtml(item.date)}${item.tags.length ? ' · ' + item.tags.map(escapeHtml).join(', ') : ''}</div>` +
          `</article>`
      )
      .join('');
  }

  function search(query) {
    const q = query.trim().toLowerCase();
    if (!q) {
      results.innerHTML = '';
      return;
    }
    const scored = index
      .map((item) => {
        const hay = (item.title + ' ' + item.summary + ' ' + item.tags.join(' ')).toLowerCase();
        let score = 0;
        if (item.title.toLowerCase().includes(q)) score += 10;
        if (item.tags.some((t) => t.toLowerCase().includes(q))) score += 5;
        if (hay.includes(q)) score += 1;
        return { item, score };
      })
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 20)
      .map((x) => x.item);
    render(scored);
  }

  input.addEventListener('input', (e) => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => search(e.target.value), 150);
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      input.value = '';
      results.innerHTML = '';
    }
  });

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function truncate(str, len) {
    return str.length > len ? str.slice(0, len) + '…' : str;
  }
})();
