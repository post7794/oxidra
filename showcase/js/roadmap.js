// Oxidra Showcase - Roadmap & Milestone Matrix Controller
import { MILESTONES } from './data.js';

export function initRoadmap() {
  const container = document.getElementById('milestones-grid');
  const filterButtons = document.querySelectorAll('.filter-btn');

  if (!container) return;

  function renderMilestones(filter = 'all') {
    container.innerHTML = '';

    const filtered = filter === 'all'
      ? MILESTONES
      : MILESTONES.filter(m => m.status === filter);

    filtered.forEach((m, idx) => {
      const card = document.createElement('div');
      card.className = 'milestone-card animate-fade-in';
      card.style.animationDelay = `${idx * 0.06}s`;

      const deliverablesHtml = m.deliverables
        .map(item => `<li>${escapeHtml(item)}</li>`)
        .join('');

      card.innerHTML = `
        <div class="milestone-header">
          <span class="milestone-code">
            <span class="brand-badge">${m.code}</span>
          </span>
          <span class="status-badge ${m.status}">${m.statusLabel}</span>
        </div>
        <h3 class="milestone-title">${escapeHtml(m.title)}</h3>
        <p class="milestone-summary">${escapeHtml(m.summary)}</p>
        <ul class="deliverables-list">
          ${deliverablesHtml}
        </ul>
        <div class="milestone-footer">
          <span class="tech-anchor">⚓ ${escapeHtml(m.techAnchor)}</span>
        </div>
      `;

      container.appendChild(card);
    });
  }

  filterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      filterButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.getAttribute('data-filter') || 'all';
      renderMilestones(filter);
    });
  });

  // Initial render with all milestones
  renderMilestones('all');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
