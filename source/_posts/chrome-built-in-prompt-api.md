---
title: Chrome 內建的翻譯與 Prompt API
date: 2025-09-27 06:50:00
catalog: true
tags: [Web]
categories: [Web]
photos: /img/chrome-built-in-prompt-api/cover.png
---

前陣子有個讀者分享給我他自己做的 Chrome extension：[JP NEWS Helper](https://github.com/Stevetanus/JPNEWS-helper/tree/main)，能夠摘要、翻譯 NHK News Easy 上面的文章，幫助學日文。

由於這個擴充套件是開源的，因此我第一件好奇的事就是：「它是用哪一間 AI 的服務，key 怎麼處理？」，結果看了 source code 才發現居然是 Chrome 內建的 Web API，不是我以為的 HTTP API。

算是有點後知後覺，現在才發現原來有內建的 Web API 可以用，因此寫篇文章簡單記錄一下。

<!-- more -->

## Chrome 的內建 AI 相關 API

如果想直接看 Google 的官方影片，可以參考這個：[The future of Chrome Extensions with Gemini in your browser](https://www.youtube.com/watch?v=8iIvAMZ-XYU)，文字版的話則是這篇：[內建 AI API](https://developer.chrome.com/docs/ai/built-in-apis)。

Chrome 從 138 版本開始（寫這篇文章當下，最新穩定版是 140），提供了三個內建的 Web API：

1. Translator API，翻譯
2. Language Detector API，偵測語言
3. Summarizer API，摘要文章

這三個 API 在使用前會需要下載一些小模型，而整體的使用方式超級簡單，底下以翻譯的功能為例。

首先，會需要檢查是否可用以及是否需要下載：

``` js
const translator = await Translator.create({
  sourceLanguage: 'en',
  targetLanguage: 'zh-TW',
  monitor(m) {
    m.addEventListener('downloadprogress', (e) => {
      console.log(`Downloaded ${e.loaded * 100}%`);
    });
  },
});
```

那個 monitor 就是監控下載進度用的，以翻譯來說滿快就可以下載完。

下載完之後，只要一行程式碼就可以翻譯：

``` js
await translator.translate('How are you?');
// 你好嗎?
```

就這樣，沒了，超級簡單。

不過我試了一下，翻譯的品質沒有到很好，還是比不上直接去用真的大型 LLM 模型。但這功能可以直接內建在 Web API 裡，已經是一大進步了。

## Prompt API

除了開頭提的那三種，也有幾個還在測試中的 API，如 prompt API，就是可以直接下 prompt，跟平常使用 ChatGPT 等等的 API 差不多。目前要用的話需要去申請個 origin trial 拿 key，我之前有寫過怎麼申請：[透過 Chrome Origin Trials 搶先試用新功能](https://blog.huli.tw/2022/02/02/origin-trials-try-new-feature/)。

我做了一個 demo 網站，有興趣可以玩玩看。因為 prompt API 的模型滿大的，建議在非手機網路環境下載，否則網路流量可能會爆掉。

另外，由於這個 API 還在測試階段，所以可能會有些問題。我一開始自己玩幾次都沒問題，但後來好像踩到了什麼 bug，每次問 AI 後都會直接系統級 panic，整個 Mac 當掉自動重開。

https://aszx87410.github.io/demo/ai/prompt-api.html

![Prompt API 示範網站截圖](/img/chrome-built-in-prompt-api/p1.png)

而這個 API 的使用方法也超簡單，第一步同樣是確認可用性以及下載：

``` js
await LanguageModel.create({
  monitor(m) {
    // 監控下載進度
    m.addEventListener('downloadprogress', (e) => {
      updateProgress(e.loaded);
      if (e.loaded >= 1) {
        updateStatus('✅ AI 下載完成並已就緒！', 'available');
      }
    });
  }
});
```

下載完之後就可以用了：

``` js
const session = await LanguageModel.create();
const response = await session.prompt('你可以做什麼？');
console.log(response)
```

有更多參數可以調整啦，而且可以支援更複雜的對話，上面只是一個很基礎的範例而已。

儘管模型不大，可以做的事情也沒有其他大模型多，但是在瀏覽器上面放一個可以在本地跑的小模型，已經能分擔掉一部分需要 API key 才能做的事了。

現在 Chrome 也越來越積極把小模型直接包在裡面，提供更多原生的 AI 功能，而未來開發者也可以運用這些 Web API 直接開發產品，不需要自己準備後端。

## 其他瀏覽器呢？

Translation API 已經隨著 Chrome 138 一起正式發佈，Google 也訂出了相關標準，不過目前 Firefox 跟 Safari 則是還在很早期的階段。

Firefox 對目前的 API design [不太滿意](https://github.com/mozilla/standards-positions/issues/1015)，有提了另一個[版本](https://github.com/mozilla/explainers/blob/main/translation.md)。而 Safari 對目前的做法也有一些隱私與資安上的[考量](https://github.com/WebKit/standards-positions/issues/339)，看起來還沒什麼進展。

至於其他更強大的 API 如 Prompt API，Firefox 直接對目前的提案給了個 [negative](https://github.com/mozilla/standards-positions/issues/1213#issuecomment-2950074313)，而 Safari [那邊](https://github.com/WebKit/standards-positions/issues/495)看起來似乎沒什麼消息。

因此，這篇所提到的東西目前都只有 Chromium-based 的瀏覽器可以用，如 Chrome 與 Edge。未來其他瀏覽器會不會跟上，還是個未知數。

## 結語

各種 AI 與現有產品的整合勢在必行，瀏覽器身為使用者會重度使用的應用程式，更是兵家必爭之地。

例如說 Perplexity 自己推了個 [Comet Browser](https://www.perplexity.ai/comet)，而 Chrome 也有越來越多內建的 AI 功能。

如果 AI 沒騙我的話，目前 Chrome 的 Prompt API 用的是 [Gemma](https://ai.google.dev/gemma/docs)，Edge 上的是 [Phi](https://azure.microsoft.com/en-us/products/phi)。

當瀏覽器內建的 AI 模型越來越進化，能做的事情就更多了。不過以目前的狀況來看，在本地能跑的模型絕對是很有限的，畢竟能用的資源就那些，效果還是沒有那些大模型來得好，但未來可以持續關注，應該會一直不斷進化。



