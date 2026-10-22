// Applies the saved color mode before first paint to avoid a flash (CSP-safe external script).
(function () {
  try {
    var pref = localStorage.getItem("flare-theme") || "system";
    var dark = pref === "dark" || (pref === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.setAttribute("data-mode", dark ? "dark" : "light");
  } catch (e) {}
})();
