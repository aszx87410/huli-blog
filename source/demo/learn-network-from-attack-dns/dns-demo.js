(function () {
  function normalizeLang(value) {
    return /^en\b/i.test(value || "") ? "en" : "zh";
  }

  function readTheme(params) {
    var explicit = params.get("theme") || params.get("mode") || params.get("dark");
    if (explicit) {
      return /^(1|true|yes|dark)$/i.test(explicit) ? "dark" : "light";
    }

    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function includesStep(value, index) {
    return value.split(",").some(function (part) {
      var trimmed = part.trim();
      if (trimmed === "*") return true;
      if (trimmed.indexOf("-") > -1) {
        var range = trimmed.split("-").map(Number);
        return index >= range[0] && index <= range[1];
      }
      return Number(trimmed) === index;
    });
  }

  function applyStepVisibility(index) {
    document.querySelectorAll("[data-step-show]").forEach(function (node) {
      node.hidden = !includesStep(node.getAttribute("data-step-show"), index);
    });

    document.querySelectorAll("[data-active-steps]").forEach(function (node) {
      node.classList.toggle("is-active", includesStep(node.getAttribute("data-active-steps"), index));
    });
  }

  function start(options) {
    var params = new URLSearchParams(window.location.search);
    var lang = normalizeLang(params.get("lang") || params.get("language") || "");
    var theme = readTheme(params);
    var copy = options.copy[lang] || options.copy.zh;
    var stepCount = options.steps;
    var state = { index: 0 };
    var timer = 0;
    var autoplayParam = params.get("autoplay");
    var autoplay = options.autoplay !== false && !/^(0|false|no|off)$/i.test(autoplayParam || "");
    var autoplayDelay = Number(params.get("delay")) || options.autoplayDelay || 1800;

    document.documentElement.lang = lang === "en" ? "en" : "zh-TW";
    document.documentElement.dataset.theme = theme;

    document.querySelectorAll("[data-i18n]").forEach(function (node) {
      var key = node.getAttribute("data-i18n");
      if (copy[key] !== undefined) {
        node.textContent = copy[key];
      }
    });

    document.querySelectorAll("[data-short-i18n]").forEach(function (node) {
      var key = node.getAttribute("data-short-i18n");
      if (copy[key] !== undefined) {
        node.setAttribute("data-short", copy[key]);
      }
    });

    var prev = document.querySelector("[data-prev]");
    var next = document.querySelector("[data-next]");
    var dots = document.querySelector("[data-dots]");
    var live = document.querySelector("[data-step-live]");

    if (dots) {
      for (var index = 0; index < stepCount; index += 1) {
        var dot = document.createElement("button");
        dot.className = "dns-dot";
        dot.type = "button";
        dot.setAttribute("aria-label", (copy.step || "Step") + " " + (index + 1));
        dot.addEventListener("click", (function (nextIndex) {
          return function () {
            goTo(nextIndex);
          };
        }(index)));
        dots.appendChild(dot);
      }
    }

    function scheduleAutoplay() {
      window.clearTimeout(timer);
      if (!autoplay || stepCount < 2 || document.hidden) return;

      timer = window.setTimeout(function () {
        state.index = (state.index + 1) % stepCount;
        render();
        scheduleAutoplay();
      }, autoplayDelay);
    }

    function goTo(index) {
      state.index = (index + stepCount) % stepCount;
      render();
      scheduleAutoplay();
    }

    function render() {
      applyStepVisibility(state.index);

      if (live && copy.stepText) {
        live.textContent = copy.stepText[state.index] || "";
      }

      if (prev) {
        prev.disabled = state.index === 0;
      }

      if (dots) {
        Array.prototype.forEach.call(dots.children, function (dot, index) {
          dot.classList.toggle("is-active", index === state.index);
        });
      }

      if (options.render) {
        options.render(state.index, copy);
      }
    }

    if (prev) {
      prev.addEventListener("click", function () {
        goTo(Math.max(0, state.index - 1));
      });
    }

    if (next) {
      next.addEventListener("click", function () {
        goTo(state.index + 1);
      });
    }

    document.addEventListener("visibilitychange", scheduleAutoplay);

    render();
    scheduleAutoplay();
  }

  window.DnsDemo = { start: start };
}());
