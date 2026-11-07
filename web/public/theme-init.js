/* Runs before the first paint (a blocking script in <head>, after the stylesheet) so the page never flashes the
   wrong theme or density. It must stay in step with resolveTheme() in src/design/themes.ts; theme-init.test.ts
   checks that. Plain ES5 on purpose: it is not bundled. */
(function () {
  var root = document.documentElement;
  try {
    var ls = null;
    try { ls = window.localStorage; } catch (e) { ls = null; }
    var org = {};
    var el = document.getElementById("branding-data");
    if (el) { try { org = JSON.parse(el.textContent || "{}") || {}; } catch (e) { org = {}; } }
    var allowed = org.allowed_themes || [];
    var dark = !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
    var choice = (ls && ls.getItem("lp-theme")) || "";
    var exists = function (id) {
      root.setAttribute("data-theme", id);
      return getComputedStyle(root).getPropertyValue("--lp-scheme").replace(/\s/g, "") !== "";
    };
    var offered = function (id) { return allowed.length === 0 || allowed.indexOf(id) >= 0; };
    var concrete = function (id) {
      if (id === "system") {
        if (!offered("system")) return null;
        var order = dark ? ["dark", "light"] : ["light", "dark"];
        for (var k = 0; k < order.length; k++) if (exists(order[k])) return order[k];
        return null;
      }
      return offered(id) && exists(id) ? id : null;
    };
    var candidates = [choice, org.default_theme || "system"].concat(allowed, [dark ? "dark" : "light"]);
    var picked = null;
    for (var i = 0; i < candidates.length && !picked; i++) if (candidates[i]) picked = concrete(candidates[i]);
    root.setAttribute("data-theme", picked || "light");
    var density = ls && ls.getItem("lp-density");
    if (density === "compact" || density === "comfortable") root.setAttribute("data-density", density);
  } catch (e) {
    root.setAttribute("data-theme", "light");
  }
})();
