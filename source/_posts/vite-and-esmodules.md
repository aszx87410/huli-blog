---
title: Vite 怎麼能那麼快？從 ES modules 開始談起
catalog: true
date: 2020-08-07 23:21:12
tags: [JavaScript,Front-end]
categories:
  - Front-end
---

## 前言

不知道大家有沒有聽過 [vite](https://github.com/vitejs/vite) 這個工具，看它名字有個 v，大概就可以猜到可能跟 Vue 有關。沒錯，這是 Vue 的作者尤雨溪開發出來的另外一套工具，原本是想要給 [VuePress](https://vuepress.vuejs.org/) 用的，但是強大之處就在於它不僅限於此。

Vite 在 GitHub 上的 About 只寫了兩個句子：

> Native-ESM powered web dev build tool. It's fast.

如果你有體驗過，就會發現真的很快。Vite 是 build tool 跟 dev server 的綜合體，這篇會簡單教大家使用一下 vite，然後來談 ES modules，再來看看 vite 神奇的地方。

<!-- more -->

## 初探 Vite

先來大致講一下 vite 這個工具到底是在做什麼。我們可以從它的定位來看：build tool + dev server，我們先著重於後面那一塊。Dev server 就是像我們用 webpack 時會用的 webpack dev server + hot module reload，提供給我們 local 開發的環境，讓我們只要存檔以後就會自動更新整個 app，已經是現在寫前端不可或缺的工具了。

而 vite 的概念也是如此，就是提供一個「更快速的 dev server」，讓我們在開發時能夠使用。

接著直接帶大家跑一次流程。

雖然說 vite 跟 Vue 的整合度最好，但 vite 並不是 Vue 專屬的工具。事實上，不管是什麼都可以用 vite 來開發，而 vite 也提供了 React 的 template。

我們直接拿 React 來做示範：

``` js
npm init vite-app react-demo --template react
cd react-demo
npm install
npm run dev
```

就這短短四行指令，立刻讓你體驗 vite 的威力。第一行就是用 vite 提供的工具幫你產生一個 boilerplate 出來，之後切進去資料夾裡面進行開發。

成功以後 terminal 會跟你說 dev server 跑起來了，接著打開：[http://localhost:3000](http://localhost:3000) ，就會看到熟悉的一直轉圈圈的 React

![](/img/vite/vite01.png)

接著我們試著打開 `src/App.jsx`，隨意更改一些東西存檔，就會看到 React app 非常快速地更新了。Vite 無論是啟動的速度還是更新的速度，都比 create-react-app 或者是 webpack dev server 快上不少。在[推特](https://twitter.com/swyx/status/1290410811802804226)上也有一些人針對這兩者做了一些比較，vite 顯然是樂勝的。

Vite 這麼快的原因到底是什麼？我就直說了，就是 Native ES Modules。所以接下來，就讓我們看看什麼是 Native ES Modules。

## Native ES Modules

在繼續往下讀之前，建議大家要先知道在 JavaScript 裡面 module 發展的一些歷史，可以先參考我之前寫過的這篇文章：[webpack 新手教學之淺談模組化與 snowpack](https://blog.huli.tw/2020/01/21/webpack-newbie-tutorial/)。

在文章中我有提到，早期在瀏覽器並沒有原生的 module 機制，所以才會產生出各個標準，像是大家可能都有聽過的 CommonJS、AMD 或是 UMD。但是這點在 ES6 的時候有了改變，因為 ES6 的規範裡終於有 module 了！我們就稱這個做 ES Modules，簡稱 ESM。

ESM 的規範其實大家應該都用過，就是：

```
// a.js
export const PI = 3.14

// b.js
import { PI } from './a'
```

只要你看到 `export` 跟 `import`，那八成就是 ESM 的語法。除了有了規範以外，更令人興奮的是現在所有的主流瀏覽器都已經原生支援 ESM 了！

我這邊做了一個簡單的 demo 網站：https://aszx87410.github.io/esm-demo/vanilla/index.html

打開以後可以開啟 devtool 並切到 network tab 去，點開 index.js 跟 utils.js，發現兩個檔案都是使用 ESM 的語法：

![](/img/vite/vite02.png)

採用原生的 ESM 載入機制，就是 Native ESM，讓瀏覽器來幫你處理這些 import 跟 export 的東西。

等等，我剛特地強調原生這兩個字，難道說還有其他東西不是原生的嗎？是的，沒錯喔。你平常在用的 webpack 或者是類似的工具，別忘了它的名稱叫做「bundler」，就是要把你的 JS 檔案跟 dependencies 打包在一起。儘管你在寫程式的時候是用 import 跟 export 沒錯，但是在輸出時很有可能已經被 babel 或者是 webpack 轉成 CommonJS 或是其他形式了，而且外面還有再包一層來負責解析 `require` 這一些語法。

而這也是 webpack 這些打包工具之所以慢的原因，那就是他們需要靜態分析過 app 的所有檔案以及套件的相依性，然後根據這些資訊把東西包在一起，當你的檔案愈來愈大的時候，花的時間也就自然愈來愈多，因為 webpack 要搞清楚到底要怎麼打包。

如果我們能避開 bundling，不要把所有東西都包在一起的話，是不是就會快很多了？

是，這就是為什麼 vite 這麼快。

## 再探 vite

在稍早附的文章裡面我有提到了 snowpack，其實 snowpack 的概念與 vite 相當類似，都是採用了 Native ESM 的解法。與其把東西全部打包在一起，不如好好利用瀏覽器，讓瀏覽器幫你處理那些複雜的相依性。

像是 snowpack 就會把你用到的 node_modules 放到一個特定的地方讓你可以引入。

接著我們可以回來看 vite 了，打開我們剛開始裝的那個 demo 專案並且開啟 devtool 然後切到 network，一目瞭然：

![](/img/vite/vite03.png)

原理就跟 snowpack 滿像的，都是使用 ESM 去載入不同的 package，才會看到瀏覽器有這麼多的 request。

點開 `main.jsx`，就可以看到裡面的程式碼：

``` js
import React from "/@modules/@pika/react/source.development.js";
import ReactDOM from "/@modules/@pika/react-dom/source.development.js";
import "/src/index.css?import";
import App2 from "/src/App.jsx";
ReactDOM.render(/* @__PURE__ */ React.createElement(React.StrictMode, null, /* @__PURE__ */ React.createElement(App2, null)), document.getElementById("root"));
```

Vite 在 server side 會幫我們把程式做一點轉換，這邊它會把程式裡的 `import React from 'react'` 換掉，把路徑改成自己準備好的 React build。這是因為 React 官方其實目前還沒有 ESM 的 build！現在大家在用的好像是種 UMD 與 CommonJS 的混合體。未來有計畫要做，但可能需要一段時間，詳情可參考：[#11503 Formalize top-level ES exports](https://github.com/facebook/react/issues/11503)。

雖然說官方沒有，但社群中已經有人自己先做出來了，所以這邊用的是社群版的。這邊順便補充一個東西，原本的 `import React from 'react'` 被稱為「bare module imports」，bare 指的是後面的 `react`，它並不是一個檔案路徑。根據 Evan You 的說法，ESM 的標準裡面這是未定義行為，所以要特別處理。

如果我們把前面自己試的 ESM 小範例，`import { add } from './utils.js'` 換成 `import { add } from 'utils.js'`，就會出現這個錯誤：

> Uncaught TypeError: Failed to resolve module specifier "utils.js". Relative references must start with either "/", "./", or "../".

所以一定要是 `/`、`./` 或是 `../` 開頭才行。

接著我們來看 `App.jsx`：

``` jsx
import { createHotContext } from "/vite/client"; import.meta.hot = createHotContext("/src/App.jsx");   import RefreshRuntime from "/@react-refresh";  let prevRefreshReg;  let prevRefreshSig;  if (!window.__vite_plugin_react_preamble_installed__) {    throw new Error(      "vite-plugin-react can't detect preamble. Something is wrong. See https://github.com/vitejs/vite-plugin-react/pull/11#discussion_r430879201"    );  }  if (import.meta.hot) {    prevRefreshReg = window.$RefreshReg$;    prevRefreshSig = window.$RefreshSig$;    window.$RefreshReg$ = (type, id) => {      RefreshRuntime.register(type, "/Users/huli/Documents/lidemy/test/react-demo/src/App.jsx" + " " + id)    };    window.$RefreshSig$ = RefreshRuntime.createSignatureFunctionForTransform;  }var _s = $RefreshSig$();

import React, { useState } from "/@modules/@pika/react/source.development.js";
import logo2 from "/src/logo.svg?import";
import "/src/App.css?import";

function App2() {
  _s();

  const [count, setCount] = useState(0);
  return /* @__PURE__ */React.createElement("div", {
    className: "App"
  }, /* @__PURE__ */React.createElement("header", {
    className: "App-header"
  }, /* @__PURE__ */React.createElement("img", {
    src: logo2,
    className: "App-logo",
    alt: "logo"
  }), /* @__PURE__ */React.createElement("p", null, "Hello Vite + React!wwaaaa"), /* @__PURE__ */React.createElement("p", null, /* @__PURE__ */React.createElement("button", {
    onClick: () => setCount(count2 => count2 + 1)
  }, "count is: ", count)), /* @__PURE__ */React.createElement("p", null, "Edit ", /* @__PURE__ */React.createElement("code", null, "App.jsx"), " and save to test HMR updates."), /* @__PURE__ */React.createElement("a", {
    className: "App-link",
    href: "https://reactjs.org",
    target: "_blank",
    rel: "noopener noreferrer"
  }, "Learn React")));
}

_s(App2, "oDgYfYHkD9Wkv4hrAPCkI/ev3YU=");

_c = App2;
export default App2;

var _c;

$RefreshReg$(_c, "App2");
  if (import.meta.hot) {
    window.$RefreshReg$ = prevRefreshReg;
    window.$RefreshSig$ = prevRefreshSig;

    import.meta.hot.accept();
    RefreshRuntime.performReactRefresh();
  }
```

可以看到原本的 jsx 已經在 server 被轉成了 JS，然後有些與 HMR（Hot Module Reload）有關的程式碼。如果你試著修改 source code 然後存檔，會發現 network request 的網址上多了一個 timestamp：

![](/img/vite/vite04.png)

可以猜出這應該跟 cache invalidation 有關，在 reload module 的時候避免載入到舊的，所以加上一個 timestamp 強制重新抓取。

最後我們來看一下 CSS 的部分是怎麼處理的：

``` js
import { updateStyle } from "/vite/client"
const css = ".App {\n  text-align: center;\n}\n\n.App-logo {\n  height: 40vmin;\n  pointer-events: none;\n}\n\n@media (prefers-reduced-motion: no-preference) {\n  .App-logo {\n    animation: App-logo-spin infinite 20s linear;\n  }\n}\n\n.App-header {\n  background-color: #282c34;\n  min-height: 100vh;\n  display: flex;\n  flex-direction: column;\n  align-items: center;\n  justify-content: center;\n  font-size: calc(10px + 2vmin);\n  color: white;\n}\n\n.App-link {\n  color: #61dafb;\n}\n\n@keyframes App-logo-spin {\n  from {\n    transform: rotate(0deg);\n  }\n  to {\n    transform: rotate(360deg);\n  }\n}\n\nbutton {\n  font-size: calc(10px + 2vmin);\n}\n"
updateStyle("\"7ac702d2\"", css)
export default css
```

把 CSS 變成一個字串，然後呼叫 `updateStyle` 這個 function。只要是在 client 載入 vite，就會自動一起載入 `/vite/client` 這個 utils，裡面會處理像是 HMR 或者是載入 CSS，例如說上面的 `updateStyle` 就在這個檔案裡面。

好，寫到這邊其實我們大致上了解 vite 的面貌了。為什麼它比較快？因為 webpack 需要 bundle，可是 vite 不需要，所以它不需要把你的 source code 全都包在一起，它只需要起一個 local server，讓你的 `import` 可以抓到正確的檔案就好了。少了打包，速度自然快很多，這就是 Natvie ESM 的威力。

## How about production?

只要下 `npx vite build` 就可以產生 production build，但產出的檔案或許會讓你小失望，因為就跟 webpack 一樣，是個很大包的 `index.js`，所有程式碼都在裡面。

這是因為 production 目前就是用 rollup 幫你去 build，就是走傳統的打包策略了，就跟 webpack 沒兩樣。原因 [vite 的 docs](https://github.com/vitejs/vite#production-build) 也已經跟你說了：

> Vite does utilize bundling for production builds, because native ES module imports result in waterfall network requests that are simply too punishing for page load time in production.

跟大家解釋一下這個問題是什麼，問題就來自於套件之間的 dependecy。

假設你用了一個套件 A，它需要去載入套件 B，然後套件 B 依賴於套件 C，就這樣一直互相依賴，然後相連到天邊，就產生了很長一大串的依賴鍊。那瀏覽器就要等到這些套件全部都下載完成以後才能開始執行 JavaScript，這就是原文說的「waterfall network requests」，所以在 production 上這樣用的話是有問題的。

尤其是 HTTP/1.1，瀏覽器都會有 parallel 的上限，大部分是 5 個上下，所以如果你有 60 個 dependencies 要下載，就需要等好長一段時間。雖然說 HTTP/2 多少可以改善這問題，但若是東西太多，依然沒辦法。

那為什麼在 local 不會有問題呢？因為 local server 的下載時間幾乎是 0 啊！所以這是在 production 上面才會有的 issue。而這個問題已經有人在試著解決，例如說 [pika](https://www.pika.dev/about)：

> Pika is building a world where third-party libraries can be loaded, cached, and shared across sites

依照我的理解，就有點像是如果所有人的 ESM 都從 pika 下載，那瀏覽器就可以 cache 住這些套件，下載過的就不需要再下載一次，速度就會快上許多。不過當然還有其他問題有待解決，例如說瀏覽器會提供這麼多空間給你放嗎？等等之類的。

## 結語

Vite 最近好像掀起了一股小小的炫風，在一些開源專案中都會看到有人問說是不是有機會改用 vite 作為 dev server。雖然說 snowpack 已經出來一陣子了，但是 Native ESM 的這個用法，應該是到 vite 紅起來才比較廣為人知。

我自己是覺得在 local 開發的時候，ESM 的確是能讓速度快上許多，是個很值得嘗試的方向，我甚至認為未來可能這會是標準的開發方式，取代原本的 bundler。而在 production 上面如果能解決剛剛說的 waterfall 問題，或許就能產生兩種 target，一種是 target modern browser，直接用 ESM + ES6 輸出，少了許多 build 的時間；另一種是針對比較舊的瀏覽器，就走老路用 webpack 或是 rollup 等等。

Evan You 之前有跟 Adam Wathan（Tailwind CSS 的作者）錄了一集 podcast，有講到為什麼會想做 vite，以及 vite 在未來發展方向或者是 production build 會碰到的問題等等，很推薦大家去聽聽看：[140: Evan You - Reimagining the Modern Dev Server with Vite](https://player.fm/series/series-1401837/ep-140-evan-you-reimagining-the-modern-dev-server-with-vite)。