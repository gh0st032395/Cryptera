// tooltip.js - shared cursor-following tooltip for [data-tooltip] elements
let _tooltip = null;
let _timer = null;
let _setup = false;

function ensureTooltip() {
  if (_tooltip) return _tooltip;
  _tooltip = document.createElement("div");
  _tooltip.className = "custom-tooltip";
  _tooltip.style.display = "none";
  document.body.appendChild(_tooltip);
  return _tooltip;
}

function moveTooltip(e) {
  const tooltip = ensureTooltip();
  const x = e.clientX + 15;
  const y = e.clientY + 15;
  let finalX = x, finalY = y;
  if (x + tooltip.offsetWidth > window.innerWidth) finalX = e.clientX - tooltip.offsetWidth - 10;
  if (y + tooltip.offsetHeight > window.innerHeight) finalY = e.clientY - tooltip.offsetHeight - 10;
  tooltip.style.left = `${finalX}px`;
  tooltip.style.top = `${finalY}px`;
}

function showTooltip(e, text) {
  const tooltip = ensureTooltip();
  tooltip.textContent = text;
  tooltip.style.display = "block";
  moveTooltip(e);
}

function hideTooltip() {
  const tooltip = ensureTooltip();
  tooltip.style.display = "none";
  if (_timer) { clearTimeout(_timer); _timer = null; }
}

export function attachTooltip(el) {
  el.addEventListener("mouseenter", (e) => {
    const text = el.getAttribute("data-tooltip");
    if (!text) return;
    _timer = setTimeout(() => showTooltip(e, text), 600);
  });
  el.addEventListener("mousemove", (e) => {
    if (ensureTooltip().style.display === "block") moveTooltip(e);
  });
  el.addEventListener("mouseleave", hideTooltip);
  el.addEventListener("mousedown", hideTooltip);
}

export function setupTooltips() {
  if (_setup) return;
  _setup = true;
  document.querySelectorAll("[data-tooltip]").forEach(attachTooltip);
}
