// Oxidra Showcase - Interactive Terminal Simulation
import { TERMINAL_SCENARIOS } from './data.js';

export function initTerminalSimulator() {
  const terminalBody = document.getElementById('sandbox-term-body');
  const scenarioBtns = document.querySelectorAll('.scenario-btn');
  const rerunBtn = document.getElementById('sandbox-rerun-btn');
  const termTitle = document.getElementById('sandbox-term-title');

  if (!terminalBody) return;

  let currentScenarioKey = 'test-fix';
  let activeTimer = null;
  let isRunning = false;

  function runScenario(key) {
    if (activeTimer) {
      clearTimeout(activeTimer);
      activeTimer = null;
    }

    const scenario = TERMINAL_SCENARIOS[key];
    if (!scenario) return;

    currentScenarioKey = key;
    terminalBody.innerHTML = '';
    isRunning = true;

    if (termTitle) {
      termTitle.textContent = `oxidra-session — ${scenario.name}`;
    }

    // Print command line
    const cmdLine = document.createElement('div');
    cmdLine.className = 'term-line user';
    cmdLine.innerHTML = `<span style="color: var(--accent-cyan);">$</span> ${escapeHtml(scenario.command)}<span class="term-cursor"></span>`;
    terminalBody.appendChild(cmdLine);

    let stepIndex = 0;

    function nextStep() {
      if (!isRunning) return;

      if (stepIndex >= scenario.steps.length) {
        // Finished: add trailing prompt with cursor
        const endPrompt = document.createElement('div');
        endPrompt.className = 'term-line output';
        endPrompt.style.marginTop = '12px';
        endPrompt.innerHTML = `<span style="color: var(--accent-cyan);">$</span> <span class="term-cursor"></span>`;
        terminalBody.appendChild(endPrompt);
        terminalBody.scrollTop = terminalBody.scrollHeight;
        isRunning = false;

        // Remove previous cursor
        const oldCursor = cmdLine.querySelector('.term-cursor');
        if (oldCursor) oldCursor.remove();
        return;
      }

      // Remove initial cursor if we are running steps
      const oldCursor = cmdLine.querySelector('.term-cursor');
      if (oldCursor) oldCursor.remove();

      const step = scenario.steps[stepIndex];
      stepIndex++;

      const lineEl = document.createElement('div');
      lineEl.className = `term-line ${step.type}`;
      lineEl.textContent = step.text;
      terminalBody.appendChild(lineEl);
      terminalBody.scrollTop = terminalBody.scrollHeight;

      // Realistic timing based on operation type
      let delay = 350;
      if (step.type === 'action') delay = 500;
      else if (step.type === 'diff') delay = 400;
      else if (step.type === 'telemetry') delay = 300;
      else if (step.type === 'success') delay = 450;

      activeTimer = setTimeout(nextStep, delay);
    }

    activeTimer = setTimeout(nextStep, 600);
  }

  // Bind scenario buttons
  scenarioBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      scenarioBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const key = btn.getAttribute('data-scenario') || 'test-fix';
      runScenario(key);
    });
  });

  if (rerunBtn) {
    rerunBtn.addEventListener('click', () => {
      runScenario(currentScenarioKey);
    });
  }

  // Initial Run
  runScenario('test-fix');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
