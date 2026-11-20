import { TOOLS } from '../data/tools.js';
import { escapeHtml } from '../utils/dom.js';

/**
 * 10-Tool MCP Contract Explorer Controller
 */
export function createToolExplorer({ getLang }) {
  let currentFilter = 'all';

  const filterBar = document.getElementById('tools-filter-bar');
  const grid = document.getElementById('tools-grid');

  function render() {
    if (!grid) return;
    const lang = getLang();
    const filtered = TOOLS.filter(
      (t) => currentFilter === 'all' || t.tier === currentFilter,
    );

    grid.innerHTML = filtered
      .map((t) => {
        const badgeClass =
          t.tier === 'tier-1' ? 't1' : t.tier === 'tier-2' ? 't2' : 't3';
        const tierLabel = lang === 'zh' ? t.tierLabelZh : t.tierLabelEn;
        const desc = lang === 'zh' ? t.descZh : t.descEn;
        const roClass = t.readOnlyHint ? 'annot-chip true-green' : 'annot-chip';
        const destClass = t.destructiveHint ? 'annot-chip true-red' : 'annot-chip';

        return `<article class="tool-card ${escapeHtml(t.tier)}">
          <div>
            <div class="tool-head">
              <div>
                <div class="tool-num">TOOL #${escapeHtml(t.num)} &middot; ${escapeHtml(t.sourceFile.split('/').pop())}</div>
                <div class="tool-name">${escapeHtml(t.name)}</div>
              </div>
              <span class="tier-badge ${badgeClass}">${escapeHtml(tierLabel)}</span>
            </div>
            <p class="tool-desc">${escapeHtml(desc)}</p>
          </div>
          <div>
            <div class="tool-actions-list">${escapeHtml(t.actions)}</div>
            <div class="annot-row">
              <span class="annot-chip scope-chip">${escapeHtml(t.scope)}</span>
              <span class="${roClass}">readOnlyHint: ${escapeHtml(t.readOnlyHint)}</span>
              <span class="${destClass}">destructiveHint: ${escapeHtml(t.destructiveHint)}</span>
              <span class="annot-chip">openWorldHint: ${escapeHtml(t.openWorldHint)}</span>
            </div>
          </div>
        </article>`;
      })
      .join('');
  }

  if (filterBar) {
    filterBar.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-filter]');
      if (!btn) return;
      currentFilter = btn.getAttribute('data-filter') || 'all';
      const pills = filterBar.querySelectorAll('.filter-pill');
      pills.forEach((pill) => {
        const active = pill === btn;
        pill.classList.toggle('active', active);
        pill.setAttribute('aria-selected', String(active));
      });
      render();
    });
  }

  render();
  return { render };
}
