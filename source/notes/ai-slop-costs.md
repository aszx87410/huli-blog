---
layout: note
title: "AI 熱潮背後的代價"
date: 2026-01-19 21:31:53
---
我不會否認 AI 很厲害，但我也不會一直無腦吹 AI，彷彿每一次的更新都會改變世界，每個新功能都重塑了整個產業。

比起分享 AI 的新功能又可以做哪些事情，我更喜歡分享那些只會一味吹捧的人沒去關心的後續，或是 AI 在增加生產力的同時，是如何同時造成另外一群人的負擔。

## 其一
Cursor 前幾天說他們在測試一堆 AI agent 全自動化能做到什麼地步，最後弄出了個瀏覽器，程式碼足足有 300 萬行以上，而且最重要的 rendering 引擎是從零開始的，原話是：

> The rendering engine is from-scratch in Rust with HTML parsing, CSS cascade, layout, text shaping, paint, and a custom JS VM.

聽起來就超級猛，居然可以直接從零弄一套瀏覽器出來。

但沒多久就有人質疑這些所謂的「從零開始」其實依賴了很多現成套件，HTML parser、CSS parser 以及 JavaScript 引擎等等，都只是現有套件再往上包一層。

而 Cursor 的人也有出來回應，說確實有些地方用了套件，但他們覺得 agent 自己其實也做得出來，這個實驗性質的專案之後會慢慢遷移這些。

但總之，看來 Cursor 的「from-scratch」定義似乎跟想像中不一樣。我認知的 「from-scratch」也是從頭自己刻，就算依賴套件也不會到這種程度。

同我開頭所述，我很喜歡 Cursor 這些實驗性的專案，讓人可以窺探目前 AI coding 的上限大概到哪裡，成果很厲害沒錯，但稍嫌誇大了。就算沒這麼誇大，只說是把現有套件整合弄出個瀏覽器，我也會覺得很厲害的。

## 其二
拿來畫圖很好用的開源套件 [tldraw](https://tldraw.dev/blog/stay-away-from-my-trash) 日前宣佈不再接受來自外部的 Pull Requets 了，理由是太多 AI 垃圾（AI slop），發了 PR 就跑，也不討論不改東西，原本提的東西可能也沒測過，就這樣發上來了。

這種 AI 垃圾一多讓維護者身心俱疲，畢竟每個垃圾都是一種雜訊，光是要篩選出哪些是真的可以用的，本身就是一個成本。

但作者有強調這是暫時的，之後 [GitHub](https://github.com/curl/curl/pull/20312) 似乎會上新功能來解決這問題，我猜可能是用魔法對付魔法，先弄個自動 AI 分類？或可能有辦法識別出這種 AI 帳號，或是某個帳號提出的 PR 品質之類的。

總之，到時候推出了再來寫一篇吧。

## 其三
同上，一直被 AI 垃圾深深困擾的 cURL 正式停止了 bug bounty program，理由是：

> We have concluded the hard way that a bug bounty gives people too strong incentives to find and make up "problems" in bad faith that cause overload and
abuse.
> 漏洞懸賞計畫給了人們過於強烈的誘因，導致有人出於惡意，去尋找，甚至捏造所謂的「問題」，從而造成負擔過重與濫用。

簡單來講就是一堆 AI 仔隨便讓 AI 找些問題，自動寫報告交出去，自己也沒驗過（搞不好也不知道怎麼驗），讓維護者們收到一堆垃圾，心力交瘁。之前 cURL 就寫過這問題了，現在正式靠著把賞金拿掉，希望減少一點誘因。

AI 時代很多東西的成本變低，濫用也變得更加嚴重，我可以想像得到有些人寫個 AI agent 自動掃描所有 bug bounty target，自動找一些簡單的洞，自動寫報告然後送出。

是不是 false positive 不重要，反正有人會幫我驗，100 個裡面成功 1 個我就有錢拿，驗證的成本轉嫁到別人身上，錢是我在賺，好爽。

以上是三個，最近看到的與 AI 相關的新聞。AI 很厲害，很好用，我自己也很常用，但它絕對不是百利而無一害，這樣的方便性也造成另外一群人的困擾。

有許多人都還在找尋與 AI 共存的方式，我也還在找。看到臉書一堆 AI 垃圾也增加了我篩選的負擔，我通常看一個封鎖一個，還想過要不要自己寫一個貼文收集工具，AI 先幫我過濾一輪（但我懶，只是想想而已，我知道有類似工具，但我也懶得去用，結論是我就懶）。

，有興趣的可以看一下。

參考資料：<https://x.com/wilsonzlin/status/2012404100298871048>
