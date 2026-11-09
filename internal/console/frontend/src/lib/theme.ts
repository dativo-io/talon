// Theme preference is a per-viewer convenience kept in localStorage; it is
// the only thing the console stores in the browser. Storage can be blocked,
// so every access is guarded and the system preference is the fallback.
export type Theme = "system" | "light" | "dark";
const KEY = "talon-console-theme";

export function loadTheme(): Theme {
  try {
    const v = window.localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

export function applyTheme(t: Theme): void {
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  try {
    if (t === "system") window.localStorage.removeItem(KEY);
    else window.localStorage.setItem(KEY, t);
  } catch {
    // storage blocked: the choice lasts for this page only
  }
}
