import { GATE_SCENARIOS, PIPELINE_NODES } from '../data/gateScenarios.js';
import { I18N } from '../data/i18n.js';
import { escapeHtml } from '../utils/dom.js';

/**
 * Interactive 1-Gate Blast-Radius Flow Simulator Controller
 */
export function createGateSimulator({ getLang }) {
  let scenarioIdx = 0;
  let stepIdx = 0;
  let autoTimer = null;

  const tabsEl = document.getElementById('sim-scenario-tabs');
  const popupBadgeEl = document.getElementById('sim-popup-badge');
  const stepCounterEl = document.getElementById('sim-step-counter');
  const pipelineEl = document.getElementById('sim-pipeline');
  const stepsListEl = document.getElementById('sim-steps-list');
  const inspectorTitleEl = document.getElementById('sim-inspector-title');
  const inspectorBadgeEl = document.getElementById('sim-inspector-badge');
  const inspectorExplainEl = document.getElementById('sim-inspector-explain');
  const reqPreEl = document.getElementById('sim-req-pre');
  const statePreEl = document.getElementById('sim-state-pre');
  const prevBtn = document.getElementById('sim-prev-btn');
  const nextBtn = document.getElementById('sim-next-btn');
  const autoBtn = document.getElementById('sim-auto-btn');

  function stopAuto() {
    if (autoTimer !== null) {
      clearInterval(autoTimer);
      autoTimer = null;
    }
    syncAutoBtnLabel();
  }

  function syncAutoBtnLabel() {
    if (!autoBtn) return;
    const dict = I18N[getLang()];
    autoBtn.textContent = autoTimer !== null ? dict.sim_stop : dict.sim_auto;
  }

  function render() {
    const lang = getLang();
    const scenario = GATE_SCENARIOS[scenarioIdx] || GATE_SCENARIOS[0];
    const step = scenario.steps[stepIdx] || scenario.steps[0];

    if (tabsEl) {
      tabsEl.innerHTML = GATE_SCENARIOS.map((sc, idx) => {
        const label = lang === 'zh' ? sc.tabZh : sc.tabEn;
        const active = idx === scenarioIdx ? ' active' : '';
        return `<button class="sim-tab${active}" type="button" role="tab" aria-selected="${idx === scenarioIdx}" data-scenario-idx="${idx}">${escapeHtml(label)}</button>`;
      }).join('');
    }

    if (popupBadgeEl) {
      let cls = 'sim-metric-pill popups-zero';
      let text =
        lang === 'zh'
          ? '弹窗计数：0 次（自治放行）'
          : 'Client Popups So Far: 0 (Always Allow)';
      if (step.kind === 'gate') {
        cls = 'sim-metric-pill popups-one';
        text =
          lang === 'zh'
            ? '弹窗计数：1 次（唯一写闸门确认）'
            : 'Client Popups: 1 (Single Write Gate)';
      } else if (step.kind === 'blocked') {
        cls = 'sim-metric-pill popups-blocked';
        text =
          lang === 'zh'
            ? '安全护栏：已物理拒绝 (Fail-Closed)'
            : 'Guardrail: Physically Rejected';
      }
      popupBadgeEl.className = cls;
      popupBadgeEl.textContent = text;
    }

    if (stepCounterEl) {
      stepCounterEl.textContent =
        lang === 'zh'
          ? `步骤 ${stepIdx + 1} / ${scenario.steps.length}`
          : `Step ${stepIdx + 1} of ${scenario.steps.length}`;
    }

    if (pipelineEl) {
      pipelineEl.innerHTML = PIPELINE_NODES.map((node) => {
        let stateCls = '';
        if (node.id === step.activeNode) {
          if (step.kind === 'gate') stateCls = ' is-gate';
          else if (step.kind === 'blocked') stateCls = ' is-blocked';
          else stateCls = ' is-active';
        } else if (step.passedNodes.includes(node.id)) {
          stateCls = ' is-passed';
        }
        const title = lang === 'zh' ? node.labelZh : node.labelEn;
        const sub = lang === 'zh' ? node.subZh : node.subEn;
        return `<div class="sim-pipe-node${stateCls}">
          <div class="sim-pipe-idx">${escapeHtml(node.id.toUpperCase())}</div>
          <div class="sim-pipe-title">${escapeHtml(title)}</div>
          <div class="sim-pipe-sub">${escapeHtml(sub)}</div>
        </div>`;
      }).join('');
    }

    if (stepsListEl) {
      stepsListEl.innerHTML = scenario.steps
        .map((st, idx) => {
          const isCurrent = idx === stepIdx;
          const kindCls =
            st.kind === 'gate' ? ' gate-step' : st.kind === 'blocked' ? ' blocked-step' : '';
          const summary = lang === 'zh' ? st.summaryZh : st.summaryEn;
          const badgeVariant =
            st.kind === 'gate' ? 'amber' : st.kind === 'blocked' ? 'red' : 'green';
          return `<button class="sim-step-btn${isCurrent ? ' active' : ''}${kindCls}" type="button" data-step-idx="${idx}">
            <div class="sim-step-top">
              <span class="sim-step-tool">${idx + 1}. ${escapeHtml(st.tool)}()</span>
              <span class="badge ${badgeVariant}">${escapeHtml(st.tierBadge)}</span>
            </div>
            <div class="sim-step-summary">${escapeHtml(summary)}</div>
          </button>`;
        })
        .join('');
    }

    if (inspectorTitleEl) {
      inspectorTitleEl.textContent = `Step ${stepIdx + 1} · ${step.tool}()`;
    }
    if (inspectorBadgeEl) {
      inspectorBadgeEl.className =
        step.kind === 'gate'
          ? 'badge amber'
          : step.kind === 'blocked'
            ? 'badge red'
            : 'badge green';
      inspectorBadgeEl.textContent = step.tierBadge;
    }
    if (inspectorExplainEl) {
      inspectorExplainEl.textContent = lang === 'zh' ? step.explainZh : step.explainEn;
    }
    if (reqPreEl) {
      reqPreEl.textContent = step.requestJson;
    }
    if (statePreEl) {
      statePreEl.textContent = step.stateJson;
    }

    syncAutoBtnLabel();
  }

  if (tabsEl) {
    tabsEl.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-scenario-idx]');
      if (!btn) return;
      stopAuto();
      scenarioIdx = Number(btn.getAttribute('data-scenario-idx')) || 0;
      stepIdx = 0;
      render();
    });
  }

  if (stepsListEl) {
    stepsListEl.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-step-idx]');
      if (!btn) return;
      stopAuto();
      stepIdx = Number(btn.getAttribute('data-step-idx')) || 0;
      render();
    });
  }

  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      stopAuto();
      const scenario = GATE_SCENARIOS[scenarioIdx] || GATE_SCENARIOS[0];
      stepIdx = (stepIdx - 1 + scenario.steps.length) % scenario.steps.length;
      render();
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      stopAuto();
      const scenario = GATE_SCENARIOS[scenarioIdx] || GATE_SCENARIOS[0];
      stepIdx = (stepIdx + 1) % scenario.steps.length;
      render();
    });
  }

  if (autoBtn) {
    autoBtn.addEventListener('click', () => {
      if (autoTimer !== null) {
        stopAuto();
        return;
      }
      autoTimer = setInterval(() => {
        const scenario = GATE_SCENARIOS[scenarioIdx] || GATE_SCENARIOS[0];
        if (stepIdx + 1 < scenario.steps.length) {
          stepIdx += 1;
        } else {
          scenarioIdx = (scenarioIdx + 1) % GATE_SCENARIOS.length;
          stepIdx = 0;
        }
        render();
      }, 2800);
      syncAutoBtnLabel();
    });
  }

  render();
  return { render };
}
