import { createGateSimulator } from './components/gateSimulator.js';
import { createSetupWalkthrough } from './components/setupWalkthrough.js';
import { createToolExplorer } from './components/toolExplorer.js';
import { createUiPreview } from './components/uiPreview.js';
import { I18N } from './catalog/i18n.js';

/**
 * GeminiBastionMCP Showcase Entrypoint
 */
(function initShowcase() {
  const LANG_STORAGE_KEY = 'bastion_showcase_lang';

  function detectInitialLang() {
    try {
      const saved = window.localStorage.getItem(LANG_STORAGE_KEY);
      if (saved === 'en' || saved === 'zh') return saved;
    } catch {
      // Ignore storage access errors in restricted browsers
    }
    const nav = (navigator.language || '').toLowerCase();
    return nav.startsWith('zh') ? 'zh' : 'en';
  }

  let currentLang = detectInitialLang();
  const getLang = () => currentLang;

  const uiPreview = createUiPreview();
  const toolExplorer = createToolExplorer({ getLang });
  const gateSimulator = createGateSimulator({ getLang });
  const setupWalkthrough = createSetupWalkthrough({
    getLang,
    onDomainChange: (domainState) => {
      uiPreview.updateDomain(domainState);
    },
  });

  function applyLanguage(lang) {
    currentLang = lang === 'zh' ? 'zh' : 'en';
    document.documentElement.lang = currentLang === 'zh' ? 'zh-CN' : 'en';
    try {
      window.localStorage.setItem(LANG_STORAGE_KEY, currentLang);
    } catch {
      // Ignore storage errors
    }

    const dict = I18N[currentLang];
    document.querySelectorAll('[data-i18n]').forEach((node) => {
      const key = node.getAttribute('data-i18n');
      if (key && dict[key]) {
        node.textContent = dict[key];
      }
    });

    const langBtn = document.getElementById('lang-toggle-btn');
    if (langBtn) {
      langBtn.textContent = currentLang === 'zh' ? 'English / 中文' : 'EN / 简体中文';
    }

    toolExplorer.render();
    gateSimulator.render();
    setupWalkthrough.render();
  }

  // Language switcher
  const langToggleBtn = document.getElementById('lang-toggle-btn');
  if (langToggleBtn) {
    langToggleBtn.addEventListener('click', () => {
      applyLanguage(currentLang === 'en' ? 'zh' : 'en');
    });
  }

  // Responsive mobile navigation drawer
  const mobileMenuBtn = document.getElementById('mobile-menu-btn');
  const mobileDrawer = document.getElementById('mobile-drawer');
  if (mobileMenuBtn && mobileDrawer) {
    mobileMenuBtn.addEventListener('click', () => {
      const isOpen = mobileDrawer.classList.toggle('open');
      mobileMenuBtn.setAttribute('aria-expanded', String(isOpen));
    });
    mobileDrawer.addEventListener('click', (e) => {
      if (e.target.closest('a')) {
        mobileDrawer.classList.remove('open');
        mobileMenuBtn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // Copy-to-clipboard button delegation
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-copy-target]');
    if (!btn) return;
    const targetId = btn.getAttribute('data-copy-target');
    const el = targetId ? document.getElementById(targetId) : null;
    if (!el) return;

    const text =
      el.tagName === 'INPUT' && el.value !== undefined
        ? el.value
        : el.textContent || '';

    const dict = I18N[currentLang];
    const showCopied = () => {
      btn.textContent = dict.copied_label;
      setTimeout(() => {
        btn.textContent = dict.btn_copy;
      }, 1600);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(showCopied).catch(showCopied);
    } else {
      showCopied();
    }
  });

  applyLanguage(currentLang);
})();
