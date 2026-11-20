/**
 * Built-In Web UI Previews Controller (GET /, /oauth/authorize, /admin PWA)
 */
export function createUiPreview() {
  const tabGroup = document.getElementById('preview-tab-group');
  const toggleLogBtn = document.getElementById('mock-toggle-log-btn');
  const mockJobLog = document.getElementById('mock-job-log');
  const mockMcpInput = document.getElementById('mock-mcp-url');
  const mockPortalBarUrl = document.getElementById('mock-portal-bar-url');
  const mockConsentBarUrl = document.getElementById('mock-consent-bar-url');
  const mockConsentResource = document.getElementById('mock-consent-resource');
  const mockAdminBarUrl = document.getElementById('mock-admin-bar-url');

  const TAB_IDS = ['portal', 'consent', 'admin'];

  function activateTab(targetId) {
    TAB_IDS.forEach((id) => {
      const btn = document.getElementById(`tab-btn-${id}`);
      const pane = document.getElementById(`preview-pane-${id}`);
      const isActive = id === targetId;
      if (btn) {
        btn.classList.toggle('btn-primary', isActive);
        btn.setAttribute('aria-selected', String(isActive));
      }
      if (pane) {
        pane.classList.toggle('active', isActive);
      }
    });
  }

  function updateDomain(domainState) {
    const origin = domainState.origin;
    if (mockMcpInput) mockMcpInput.value = `${origin}/mcp`;
    if (mockPortalBarUrl) {
      mockPortalBarUrl.textContent = `GET ${origin}/ (Zero Private Data Leakage)`;
    }
    if (mockConsentBarUrl) {
      mockConsentBarUrl.textContent = `GET ${origin}/oauth/authorize?code_challenge_method=S256`;
    }
    if (mockConsentResource) {
      mockConsentResource.textContent = `${origin}/mcp`;
    }
    if (mockAdminBarUrl) {
      mockAdminBarUrl.textContent = `GET ${origin}/admin (Operator Cockpit PWA)`;
    }
  }

  if (tabGroup) {
    tabGroup.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-preview-tab]');
      if (!btn) return;
      const target = btn.getAttribute('data-preview-tab');
      if (target) activateTab(target);
    });
  }

  if (toggleLogBtn && mockJobLog) {
    toggleLogBtn.addEventListener('click', () => {
      const isHidden = mockJobLog.style.display === 'none';
      mockJobLog.style.display = isHidden ? 'block' : 'none';
    });
  }

  return { updateDomain };
}
