import { I18N } from '../catalog/i18n.js';
import { OAUTH_SEQUENCE, SETUP_MODES } from '../catalog/walkthrough.js';
import { escapeHtml, normalizeDomainInput } from '../utils/dom.js';

/**
 * Interactive OAuth 2.1 + Cloudflare Tunnel Setup & Handshake Walkthrough Controller
 */
export function createSetupWalkthrough({ getLang, onDomainChange }) {
  let currentModeId = 'cloudflare';
  let domainState = normalizeDomainInput('https://mcp.yourdomain.com');

  const domainInput = document.getElementById('setup-domain-input');
  const resetBtn = document.getElementById('setup-domain-reset');
  const modeTabsEl = document.getElementById('setup-mode-tabs');
  const stepsContainerEl = document.getElementById('setup-steps-list');
  const oauthSeqGridEl = document.getElementById('oauth-seq-grid');

  function applyPlaceholders(text) {
    return String(text)
      .replace(/\{\{DOMAIN\}\}/g, domainState.origin)
      .replace(/\{\{HOST\}\}/g, domainState.host);
  }

  function render() {
    const lang = getLang();
    const dict = I18N[lang];
    const mode = SETUP_MODES.find((m) => m.id === currentModeId) || SETUP_MODES[0];

    if (modeTabsEl) {
      modeTabsEl.innerHTML = SETUP_MODES.map((m) => {
        const active = m.id === mode.id ? ' active' : '';
        const label = lang === 'zh' ? m.tabZh : m.tabEn;
        return `<button class="filter-pill${active}" type="button" role="tab" aria-selected="${m.id === mode.id}" data-setup-mode="${escapeHtml(m.id)}">${escapeHtml(label)}</button>`;
      }).join('');
    }

    if (stepsContainerEl) {
      stepsContainerEl.innerHTML = mode.steps
        .map((st, idx) => {
          const codeId = `setup-cmd-${mode.id}-${idx}`;
          const title = lang === 'zh' ? st.titleZh : st.titleEn;
          const note = lang === 'zh' ? st.noteZh : st.noteEn;
          const resolvedCode = applyPlaceholders(st.code);
          return `<article class="setup-step-card">
            <div class="setup-step-head">
              <div class="setup-step-title-wrap">
                <span class="setup-step-num">${escapeHtml(st.num)}</span>
                <h3>${escapeHtml(title)}</h3>
              </div>
              <button class="btn btn-sm" type="button" data-copy-target="${escapeHtml(codeId)}">${escapeHtml(dict.btn_copy)}</button>
            </div>
            <p class="setup-step-note">${escapeHtml(note)}</p>
            <pre id="${escapeHtml(codeId)}" class="code-block">${escapeHtml(resolvedCode)}</pre>
          </article>`;
        })
        .join('');
    }

    if (oauthSeqGridEl) {
      oauthSeqGridEl.innerHTML = OAUTH_SEQUENCE.map((item) => {
        const desc = applyPlaceholders(lang === 'zh' ? item.descZh : item.descEn);
        return `<div class="oauth-seq-step">
          <div class="oauth-seq-rfc">${escapeHtml(item.rfc)}</div>
          <div class="oauth-seq-route">${escapeHtml(item.route)}</div>
          <p class="oauth-seq-desc">${escapeHtml(desc)}</p>
        </div>`;
      }).join('');
    }

    if (onDomainChange) {
      onDomainChange(domainState);
    }
  }

  if (domainInput) {
    domainInput.addEventListener('input', () => {
      domainState = normalizeDomainInput(domainInput.value);
      render();
    });
  }

  if (resetBtn && domainInput) {
    resetBtn.addEventListener('click', () => {
      domainInput.value = 'https://mcp.yourdomain.com';
      domainState = normalizeDomainInput(domainInput.value);
      render();
    });
  }

  if (modeTabsEl) {
    modeTabsEl.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-setup-mode]');
      if (!btn) return;
      currentModeId = btn.getAttribute('data-setup-mode') || 'cloudflare';
      render();
    });
  }

  render();
  return {
    render,
    getDomainState: () => domainState,
  };
}
