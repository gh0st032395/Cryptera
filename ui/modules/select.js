// select.js - accessible custom select component (ARIA + keyboard support)
import { updateLanguage } from "./i18n.js";
import { attachTooltip } from "./tooltip.js";

function closeSelectWrapper(wrapper) {
  wrapper.classList.remove("open");
  const trigger = wrapper.querySelector(".select-trigger");
  if (trigger) trigger.setAttribute("aria-expanded", "false");
}

let _setup = false;

export function setupCustomSelects() {
  if (_setup) return;
  _setup = true;
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".custom-select")) {
      document.querySelectorAll(".custom-select.open").forEach(closeSelectWrapper);
    }
  });

  document.querySelectorAll(".custom-select").forEach(wrapper => {
    const trigger = wrapper.querySelector(".select-trigger");
    const input = wrapper.querySelector("input[type='hidden']");
    const optionsBox = wrapper.querySelector(".select-options");
    const options = Array.from(wrapper.querySelectorAll(".option"));

    if (!trigger) return;
    trigger.setAttribute("role", "button");
    trigger.setAttribute("tabindex", "0");
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");
    if (optionsBox) optionsBox.setAttribute("role", "listbox");
    options.forEach(o => {
      o.setAttribute("role", "option");
      o.setAttribute("tabindex", "-1");
    });

    const setOpen = (open) => {
      wrapper.classList.toggle("open", open);
      trigger.setAttribute("aria-expanded", String(open));
    };
    const toggleOpen = () => {
      document.querySelectorAll(".custom-select.open").forEach(el => {
        if (el !== wrapper) closeSelectWrapper(el);
      });
      setOpen(!wrapper.classList.contains("open"));
    };
    const selectOption = (opt) => {
      const val = opt.dataset.value;
      const text = opt.textContent;
      if (input) {
        input.value = val;
        if (input.id === "languageSelect") updateLanguage(val);
        // Let listeners react to programmatic value changes (hidden inputs
        // do not fire change events on their own).
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
      trigger.textContent = text;
      options.forEach(o => o.classList.remove("selected"));
      opt.classList.add("selected");
      setOpen(false);
    };

    trigger.addEventListener("click", toggleOpen);
    trigger.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleOpen();
      } else if (e.key === "Escape") {
        setOpen(false);
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        if (!wrapper.classList.contains("open")) toggleOpen();
        if (options[0]) options[0].focus();
      }
    });

    options.forEach((opt, idx) => {
      opt.addEventListener("click", (e) => {
        e.stopPropagation();
        selectOption(opt);
      });
      opt.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          selectOption(opt);
          trigger.focus();
        } else if (e.key === "Escape") {
          setOpen(false);
          trigger.focus();
        } else if (e.key === "ArrowDown") {
          e.preventDefault();
          const next = options[Math.min(idx + 1, options.length - 1)];
          if (next) next.focus();
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          if (idx === 0) trigger.focus();
          else options[idx - 1].focus();
        }
      });
      attachTooltip(opt);
    });
  });
}
