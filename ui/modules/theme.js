// theme.js - dark / light / system theme cycle persisted in localStorage
import { t } from "./i18n.js";
import { $ } from "./dom.js";

const _themes = ["dark", "light", "system"];
let _themeIndex = 0;

const _sunIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
const _moonIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
const _systemIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`;

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "system") {
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = prefersDark ? "dark" : "light";
  } else {
    root.dataset.theme = theme;
  }
  // Update icon
  const btn = $("themeToggleBtn");
  if (btn) {
    if (theme === "light") btn.innerHTML = _moonIcon;
    else if (theme === "system") btn.innerHTML = _systemIcon;
    else btn.innerHTML = _sunIcon;
    btn.title = t(`theme_${theme}`);
  }
}

function cycleTheme() {
  _themeIndex = (_themeIndex + 1) % _themes.length;
  const theme = _themes[_themeIndex];
  applyTheme(theme);
  try { localStorage.setItem("cryptera_theme", theme); } catch (_) { /* ignore */ }
}

export function initTheme() {
  let saved = "dark";
  try { saved = localStorage.getItem("cryptera_theme") || "dark"; } catch (_) { /* ignore */ }
  _themeIndex = _themes.indexOf(saved);
  if (_themeIndex < 0) _themeIndex = 0;
  applyTheme(_themes[_themeIndex]);
  const btn = $("themeToggleBtn");
  if (btn) btn.addEventListener("click", cycleTheme);
  // React to system changes when theme is "system"
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (_themes[_themeIndex] === "system") applyTheme("system");
  });
}
