// Oxidra Showcase - Main Application Entrypoint
import { PROJECT_INFO, BUILTIN_TOOLS, ARCHITECTURE_PILLARS, HISTORY_TOOLS } from './data.js';
import { initRoadmap } from './roadmap.js';
import { initTerminalSimulator } from './terminal.js';

document.addEventListener('DOMContentLoaded', () => {
  renderHeroStats();
  renderArchitecturePillars();
  renderToolsTabs();
  renderHistoryTools();
  initRoadmap();
  initTerminalSimulator();
  initCopyButtons();
  initMobileMenu();
});

// Render Hero Stats
function renderHeroStats() {
  const container = document.getElementById('hero-stats-container');
  if (!container) return;

  container.innerHTML = PROJECT_INFO.stats.map(stat => `
    <div class="stat-card">
      <div class="stat-value">${escapeHtml(stat.value)}</div>
      <div class="stat-label">${escapeHtml(stat.label)}</div>
      <div class="stat-desc">${escapeHtml(stat.desc)}</div>
    </div>
  `).join('');
}

// Render Architecture Pillars
function renderArchitecturePillars() {
  const container = document.getElementById('pillars-container');
  if (!container) return;

  const icons = {
    journal: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>`,
    shield: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
    cpu: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>`,
    lock: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`
  };

  container.innerHTML = ARCHITECTURE_PILLARS.map(p => `
    <div class="pillar-card">
      <div class="pillar-icon">${icons[p.icon] || icons.journal}</div>
      <h4 class="pillar-title">${escapeHtml(p.title)}</h4>
      <div class="pillar-sub">${escapeHtml(p.subtitle)}</div>
      <p class="pillar-desc">${escapeHtml(p.desc)}</p>
    </div>
  `).join('');
}

// Render 5 Built-in Tools Tabs and Card Details
function renderToolsTabs() {
  const tabsContainer = document.getElementById('tools-tabs');
  const detailsContainer = document.getElementById('tool-details-container');
  if (!tabsContainer || !detailsContainer) return;

  tabsContainer.innerHTML = BUILTIN_TOOLS.map((tool, idx) => `
    <button class="tool-tab ${idx === 0 ? 'active' : ''}" data-tool="${tool.name}">
      <span>⚡</span> ${tool.name}
    </button>
  `).join('');

  function showTool(name) {
    const tool = BUILTIN_TOOLS.find(t => t.name === name) || BUILTIN_TOOLS[0];

    detailsContainer.innerHTML = `
      <div class="tool-info">
        <h3>
          ${escapeHtml(tool.name)}
          <span class="tool-badge status-badge ${tool.badgeColor}">${escapeHtml(tool.badge)}</span>
        </h3>
        <p class="tool-summary">${escapeHtml(tool.summary)}</p>

        <div class="tool-prop-group">
          <div class="tool-prop-label">边界限制与配额 (Limits)</div>
          <div class="tool-prop-val">${escapeHtml(tool.limits)}</div>
        </div>

        <div class="tool-prop-group">
          <div class="tool-prop-label">安全守卫与原子校验 (Security Guard)</div>
          <div class="tool-prop-val">${escapeHtml(tool.securityGuard)}</div>
        </div>

        <div class="tool-prop-group" style="margin-top: 24px;">
          <div class="tool-prop-label">输入 JSON Schema</div>
          <pre class="code-preview-body" style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: var(--radius-sm); font-size: 0.76rem;"><code>${escapeHtml(JSON.stringify(tool.schema, null, 2))}</code></pre>
        </div>
      </div>

      <div class="tool-preview-column">
        <div class="code-preview-box" style="margin-bottom: 20px;">
          <div class="code-preview-header">
            <span>MODEL REQUEST PAYLOAD</span>
            <span style="color: var(--accent-cyan);">JSON</span>
          </div>
          <pre class="code-preview-body"><code>${escapeHtml(tool.exampleCall)}</code></pre>
        </div>

        <div class="code-preview-box">
          <div class="code-preview-header">
            <span>DURABLE TOOL RESULT</span>
            <span style="color: var(--accent-emerald);">VERIFIED</span>
          </div>
          <pre class="code-preview-body"><code>${escapeHtml(tool.exampleOutput)}</code></pre>
        </div>
      </div>
    `;
  }

  // Initial show first tool
  showTool(BUILTIN_TOOLS[0].name);

  // Tab click events
  const tabButtons = tabsContainer.querySelectorAll('.tool-tab');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      showTool(btn.getAttribute('data-tool'));
    });
  });
}

// Render History Tools in M5 section
function renderHistoryTools() {
  const container = document.getElementById('history-tools-container');
  if (!container) return;

  container.innerHTML = HISTORY_TOOLS.map(h => `
    <div class="history-tool-item">
      <h4>⚡ ${escapeHtml(h.name)}</h4>
      <p><strong>${escapeHtml(h.title)}</strong></p>
      <p style="margin-top: 6px;">${escapeHtml(h.desc)}</p>
    </div>
  `).join('');
}

// Clipboard Copy Buttons
function initCopyButtons() {
  document.querySelectorAll('[data-copy-target]').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-copy-target');
      const targetEl = document.getElementById(targetId);
      const textToCopy = targetEl ? targetEl.textContent.trim() : btn.getAttribute('data-copy-text');

      if (textToCopy) {
        navigator.clipboard.writeText(textToCopy).then(() => {
          const origHtml = btn.innerHTML;
          btn.innerHTML = `✔ 已复制`;
          btn.style.color = 'var(--accent-emerald)';
          setTimeout(() => {
            btn.innerHTML = origHtml;
            btn.style.color = '';
          }, 2000);
        }).catch(() => {
          alert('请手动复制命令：' + textToCopy);
        });
      }
    });
  });
}

// Mobile Menu Toggle
function initMobileMenu() {
  const menuBtn = document.getElementById('mobile-menu-btn');
  const navLinks = document.querySelector('.nav-links');

  if (menuBtn && navLinks) {
    menuBtn.addEventListener('click', () => {
      const isVisible = navLinks.style.display === 'flex';
      navLinks.style.display = isVisible ? 'none' : 'flex';
      if (!isVisible) {
        navLinks.style.position = 'absolute';
        navLinks.style.top = '68px';
        navLinks.style.left = '0';
        navLinks.style.right = '0';
        navLinks.style.background = 'var(--bg-secondary)';
        navLinks.style.flexDirection = 'column';
        navLinks.style.padding = '24px';
        navLinks.style.borderBottom = '1px solid var(--border-subtle)';
        navLinks.style.gap = '16px';
      }
    });
  }
}

function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
