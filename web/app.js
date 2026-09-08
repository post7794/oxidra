import { tools, installs, documents, renderCodeLines, renderCommand } from './content.js';

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
let toastTimer;
const copyFeedback = new WeakMap();

function notify(message) {
  const toast = $('#toast');
  clearTimeout(toastTimer);
  toast.querySelector('span').textContent = message;
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, 2800);
}

async function copyText(text, button) {
  const previousFocus = document.activeElement;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      // Clipboard fallback for non-secure static hosting, never execute a command.
      const input = document.createElement('textarea');
      input.value = text;
      input.setAttribute('aria-label', '待复制的命令');
      input.className = 'sr-only';
      document.body.append(input);
      input.select();
      let copied;
      try { copied = document.execCommand('copy'); } finally { input.remove(); }
      previousFocus?.focus({ preventScroll: true });
      if (!copied) throw new Error('Clipboard unavailable');
    }
    const icon = button?.querySelector('use');
    if (icon) {
      const feedback = copyFeedback.get(icon) || { href: icon.getAttribute('href') };
      clearTimeout(feedback.timer);
      icon.setAttribute('href', '#i-check');
      feedback.timer = setTimeout(() => icon.setAttribute('href', feedback.href), 1800);
      copyFeedback.set(icon, feedback);
    }
    notify('命令已复制。去终端开始吧。');
  } catch {
    notify('浏览器未允许复制，请手动选中并复制命令。');
  }
}

$$('[data-copy]').forEach(button => button.addEventListener('click', () => {
  void copyText(button.dataset.copy, button);
}));

// Shared roving-tabindex pattern: arrows, Home and End select and focus a tab.
function bindTabs(selector, select) {
  const buttons = $$(selector);
  for (const [index, button] of buttons.entries()) {
    button.addEventListener('click', () => select(button));
    button.addEventListener('keydown', event => {
      const positions = {
        ArrowRight: (index + 1) % buttons.length,
        ArrowLeft: (index + buttons.length - 1) % buttons.length,
        Home: 0,
        End: buttons.length - 1,
      };
      if (!(event.key in positions)) return;
      event.preventDefault();
      const next = buttons[positions[event.key]];
      select(next);
      next.focus({ preventScroll: true });
    });
  }
  return buttons;
}

function markSelected(selector, active) {
  $$(selector).forEach(button => {
    const selected = button === active;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
}

bindTabs('[data-tool]', button => {
  const tool = tools[button.dataset.tool];
  if (!tool) return;
  markSelected('[data-tool]', button);
  $('#tool-panel').setAttribute('aria-labelledby', button.id);
  $('#tool-index').textContent = tool.index;
  $('#tool-title').textContent = tool.title;
  $('#tool-description').textContent = tool.description;
  $('#tool-filename').textContent = tool.filename;
  $('#tool-footnote').textContent = tool.footnote;
  $('#tool-code').innerHTML = renderCodeLines(tool.lines);
  $('#tool-code').scrollTop = 0;
  $('#tool-code').scrollLeft = 0;
  $('#tool-tags').replaceChildren(...tool.tags.map(tag => {
    const span = document.createElement('span');
    span.textContent = tag;
    return span;
  }));
});

let selectedInstall = 'source';
bindTabs('[data-install]', button => {
  const install = installs[button.dataset.install];
  if (!install) return;
  selectedInstall = button.dataset.install;
  markSelected('[data-install]', button);
  $('#install-panel-content').setAttribute('aria-labelledby', button.id);
  $('#install-language').textContent = install.language;
  $('#install-code').innerHTML = renderCommand(install.command);
  $('#install-requirements').textContent = install.requirements;
});
$('#copy-install').addEventListener('click', event => {
  void copyText(installs[selectedInstall].command, event.currentTarget);
});

function selectDemo(button) {
  markSelected('[data-demo-tab]', button);
  for (const panel of ['agent', 'journal']) {
    $(`#demo-panel-${panel}`).hidden = panel !== button.dataset.demoTab;
  }
}
bindTabs('[data-demo-tab]', selectDemo);

// A deterministic, local-only illustration. No fetch, shell, API key or model call.
const demoSteps = $$('[data-step]');
let demoTimers = [];
function finishDemo() {
  demoTimers.forEach(clearTimeout);
  demoTimers = [];
  demoSteps.forEach(step => step.classList.remove('demo-pending'));
  $('#demo-state').textContent = '演示完成 · 3 次工具调用';
  $('#replay-demo').disabled = false;
  $('#play-demo').disabled = false;
  $('#demo-panel-agent').removeAttribute('aria-busy');
}
function playDemo(scroll = false) {
  finishDemo();
  selectDemo($('#demo-tab-agent'));
  if (scroll && window.innerWidth <= 760) {
    $('#demo').scrollIntoView({ behavior: reducedMotion.matches ? 'instant' : 'smooth', block: 'center' });
  }
  if (reducedMotion.matches) {
    $('#demo-state').textContent = '演示完成 · 已按减少动态效果设置直接展示';
    return;
  }
  demoSteps.forEach(step => step.classList.add('demo-pending'));
  $('#replay-demo').disabled = true;
  $('#play-demo').disabled = true;
  $('#demo-panel-agent').setAttribute('aria-busy', 'true');
  const labels = ['演示中 · 读取项目文件', '演示中 · 精确修改代码', '演示中 · 确认并运行测试', '演示完成 · 3 次工具调用'];
  $('#demo-state').textContent = '演示开始 · read → edit → shell';
  demoSteps.forEach((step, index) => {
    demoTimers.push(setTimeout(() => {
      step.classList.remove('demo-pending');
      $('#demo-state').textContent = labels[index];
      if (index === demoSteps.length - 1) finishDemo();
    }, 500 + index * 850));
  });
}
$('#play-demo').addEventListener('click', () => playDemo(true));
$('#replay-demo').addEventListener('click', () => playDemo());
reducedMotion.addEventListener('change', () => { if (reducedMotion.matches) finishDemo(); });
window.addEventListener('pagehide', finishDemo);

$$('[data-filter]').forEach(button => button.addEventListener('click', () => {
  const filter = button.dataset.filter;
  $$('[data-filter]').forEach(other => other.setAttribute('aria-pressed', String(other === button)));
  let count = 0;
  $$('.milestone').forEach(milestone => {
    milestone.hidden = filter !== 'all' && milestone.dataset.status !== filter;
    if (!milestone.hidden) count += 1;
  });
  $('#roadmap-grid').classList.toggle('is-filtered', filter !== 'all');
  $('#filter-result').textContent = `显示 ${count} 项${filter === 'all' ? '全部' : button.textContent.trim()}进展`;
}));

const mobileNav = $('#mobile-nav');
const menuToggle = $('#menu-toggle');
function closeMenu(restoreFocus = false) {
  mobileNav.hidden = true;
  menuToggle.setAttribute('aria-expanded', 'false');
  menuToggle.setAttribute('aria-label', '打开导航');
  menuToggle.querySelector('use').setAttribute('href', '#i-menu');
  if (restoreFocus) menuToggle.focus();
}
menuToggle.addEventListener('click', () => {
  if (!mobileNav.hidden) { closeMenu(); return; }
  mobileNav.hidden = false;
  menuToggle.setAttribute('aria-expanded', 'true');
  menuToggle.setAttribute('aria-label', '关闭导航');
  menuToggle.querySelector('use').setAttribute('href', '#i-close');
});
mobileNav.querySelectorAll('a').forEach(link => link.addEventListener('click', () => closeMenu()));
document.addEventListener('click', event => {
  if (!mobileNav.hidden && !event.target.closest('.site-header')) closeMenu();
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && !mobileNav.hidden) closeMenu(true);
});
window.matchMedia('(min-width: 761px)').addEventListener('change', event => {
  if (event.matches) closeMenu();
});

const dialog = $('#docs-dialog');
let documentTrigger;
function displayDocument(key) {
  const page = documents[key];
  if (!page) return;
  $('#docs-title').textContent = page.title;
  $('#docs-body').innerHTML = page.body;
  $('#docs-source').setAttribute('href', `./reference/${page.source}`);
  $$('[data-doc-page]').forEach(button => {
    if (button.dataset.docPage === key) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  $('#docs-article').scrollTop = 0;
  requestAnimationFrame(() => {
    if (dialog.open) {
      $('.docs-nav [aria-current="page"]')?.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'instant' });
    }
  });
}
function openDocument(key, trigger) {
  if (!documents[key]) return;
  documentTrigger = trigger.closest('#mobile-nav') ? menuToggle : trigger;
  closeMenu();
  displayDocument(key);
  if (!dialog.open) dialog.showModal();
  $('#close-docs').focus({ preventScroll: true });
}
$$('[data-doc]').forEach(button => button.addEventListener('click', () => openDocument(button.dataset.doc, button)));
$$('[data-doc-page]').forEach(button => button.addEventListener('click', () => {
  displayDocument(button.dataset.docPage);
}));
$('#close-docs').addEventListener('click', () => dialog.close());
dialog.addEventListener('click', event => {
  const rect = dialog.getBoundingClientRect();
  if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom)) dialog.close();
});
dialog.addEventListener('close', () => documentTrigger?.focus({ preventScroll: true }));
