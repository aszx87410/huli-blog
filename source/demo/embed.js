(function () {
  function getLang() {
    var lang = document.documentElement.getAttribute("lang") || "zh-tw";
    return /^en\b/i.test(lang) ? "en" : "zh-tw";
  }

  function getTheme() {
    return document.body.classList.contains("dark-mode") ? "dark" : "light";
  }

  function numberFromAttribute(element, name, fallback) {
    var value = Number(element.getAttribute(name));
    return Number.isFinite(value) && value > 0 ? value : fallback;
  }

  function getFrameHeight(iframe) {
    var rect = iframe.getBoundingClientRect();
    var width = rect.width || (iframe.parentElement && iframe.parentElement.clientWidth) || window.innerWidth;

    if (width <= 620) {
      return numberFromAttribute(iframe, "data-height-mobile", 620);
    }

    if (width <= 860) {
      return numberFromAttribute(iframe, "data-height-tablet", 560);
    }

    return numberFromAttribute(iframe, "data-height-desktop", 520);
  }

  function updateFrame(iframe) {
    var base = iframe.getAttribute("data-src");
    if (!base) return;

    iframe.style.height = getFrameHeight(iframe) + "px";

    var params = new URLSearchParams({
      lang: getLang(),
      theme: getTheme()
    });
    var nextSrc = base + "?" + params.toString();
    if (iframe.getAttribute("src") !== nextSrc) {
      iframe.setAttribute("src", nextSrc);
    }
  }

  function updateAllFrames() {
    document.querySelectorAll("iframe[data-demo-frame][data-src]").forEach(updateFrame);
  }

  updateAllFrames();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", updateAllFrames);
  }

  if (!window.__demoFrameObserver && window.MutationObserver) {
    window.__demoFrameObserver = new MutationObserver(updateAllFrames);
    window.__demoFrameObserver.observe(document.body, {
      attributes: true,
      attributeFilter: ["class"]
    });
  }

  if (!window.__demoFrameResizeListener) {
    window.__demoFrameResizeListener = true;
    window.addEventListener("resize", updateAllFrames);
  }
}());
