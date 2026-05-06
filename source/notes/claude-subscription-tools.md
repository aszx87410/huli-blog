---
layout: note
title: "Claude 訂閱與工具限制"
date: 2026-04-04 20:02:03
---
4/6 07:00 更新：

一早起來看到 Peter Steinberger 的[推文](https://x.com/EricBuess/status/2040207443636973927)，就算用 claude -p 只要你帶上 OpenClaw 的 system prompt 還是會被 ban，所以之前我的理解可能有些偏差，就算你自己 claude -p 給龍蝦用也還是不行（Peter Steinberger 原本也以為可以  😂）

雖然說只要把那段字串稍微改一下就會過，但官方的態度就擺在那裡。之後等等看有沒有個官方聲明好了，再繼續更新這篇貼文。

===

小聊一下 Claude 訂閱制把第三方工具 ban 掉這件事

如果我的理解沒錯，無論是 Claude 的訂閱方案也好，還是 Google Antigravity 的訂閱方案，使用規則都是一樣的，那就是禁止你把訂閱方案的 token 拿去其他非官方工具用。

其實最大的那幾間，所謂固定費用的「訂閱制」，本來就不是針對模型本身，而是針對產品，是讓你使用他們產品的時候可以用得更多，卻只需要付出固定費用。若是你有其他客製化需求，就是去接 API，一律使用 API key 的方案按量收費，否則就是違反使用條款。

Claude 的立場從以前就這樣了，上次對 OpenCode 也是一樣，不是不能用 Claude 模型，而是你不能用訂閱制拿到的 token 去使用，要用的話就要用 API key。

有用過的都知道，認真在用的話訂閱制一定是比 API key 便宜的，一些 AI 中轉站的原理就是這樣，背後有一堆訂閱制的帳號，然後把 auth token 拿出來轉成呼叫 API 的形式，用這些固定費用的帳號創造出更大的利益來賺價差（顯然不符合官方使用條款）。

雖然可以理解訂閱制與 API 的差異以及官方的考量，但身為使用者的我們當然還是想省錢，除了換個模型以外還有其他做法嗎？

有的，第一個是用 OpenAI 的 codex 訂閱方案，OpenAI 目前並沒有禁止把訂閱方案用在 OpenClaw 上面，所以我之前架小龍蝦來玩，第一件事情就是訂閱 codex 方案。

如果你是開發者想要寫一點自己的服務，那正解就是參考 Paperclip 的做法，與其接入 AI 模型，不如接入 AI agent。在 Paperclip 的模式中，他直接接入 codex 或是 Claude Code 等工具，幫每一種工具做一個 adapter，然後用 headless mode 跑起來。

換句話說，當你建立一個任務時，背後是直接去跑 claude -p "analyze this repo for security issues" 並把結果回傳。因此最後跟 Claude 模型的互動還是透過 Claude Code，這是完全符合規則的。

面一些論述的出處做為佐證。

參考資料：<https://x.com/steipete/status/2024182608746217953>
