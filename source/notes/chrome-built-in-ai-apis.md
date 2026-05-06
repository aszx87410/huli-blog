---
layout: note
title: "Chrome內建AI初探"
date: 2025-09-28 09:26:15
---
前幾天有讀者私訊我，分享一個他自己做的 Chrome 擴充套件，可以幫忙翻譯、摘要日本的新聞，幫助學習日語。由於這個套件是開源的，因此我好奇這些功能是怎麼做到的，接的是哪個 LLM API，看了一下才發現居然全部都是 Chrome 內建的 Web API！

換句話說，現在已經可以透過 JavaScript 直接翻譯跟摘要了，不需要準備任何後端，用到的是瀏覽器的 Translate API 跟 Summarizer API。

因此我花了點時間去研究，發現除了這些以外，還有一個更強大的 [Prompt](https://aszx87410.github.io/demo/ai/prompt-api.html) API，可以在瀏覽器上跑一個小模型，就可以不需要接任何付費服務，免費跑一些簡單的 prompt。

雖然性能跟沒有你去接 ChatGPT 或別的 API 來得好，能做的事也沒有比較多，但一些很基本的事情應該是夠用了。另外，AI 跟各種產品的整合原本就是勢在必行，當瀏覽器直接有 API 讓開發者使用的時候，開發者也不需要準備自己的後端，就可以用到 LLM 的各種功能。

不過目前這些 API 只有 Chromium-based 的瀏覽器如 Chrome 跟 Edge 可以用，其他瀏覽器還在觀望狀態，看起來沒有這麼快。

我有寫了一篇介紹文與一個簡單的 Prompt API demo，有興趣的讀者可以試試看在自己的電腦上跑（先提醒一下這些 API 還在測試階段，可能會有問題。例如說我剛開始跑幾次都沒問題，昨天每次跑都直接當機重開）

總之呢，感覺這些 API 是值得持續關注的。

介紹文： https://blog.huli.tw/2025/09/27/chrome-built-in-prompt-api/
