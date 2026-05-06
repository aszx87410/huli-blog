---
layout: note
title: "AI假漏洞報告氾濫"
date: 2025-05-08 21:33:15
---
今天看到一篇文章《AI Slop Is [Polluting](https://socket.dev/blog/ai-slop-polluting-bug-bounty-platforms) Bug Bounty Platforms with Fake Vulnerability Reports》在描述 AI 產的假報告如何污染 bug bounty。

故事要從 curl 公開的一份 bug bounty report 說起，這份報告看似有道理，還附上程式碼來讓你 reproduce，但細看之後會發現整份報告都不合理，強烈懷疑是用 AI 產生的假報告。

而且還真的有些公司會因為人力不足，直接花錢應付了事，為一個根本就不存在的漏洞付錢 😅

這種現象一直出現的話就是劣幣驅逐良幣，你用 AI 隨便產個假的東西就可以拿到錢，結果我認真找了兩天的漏洞你說我 Duplicate/Not Applicable

上面是文章中的說法，不過我去看了一下原始資料，curl 的那個 report 看起來確實是亂掰的沒錯，報告中提的 commit 不存在。但是「有其他公司會付錢」這件事就不一定了。

文章的依據應該是同一個 bug hunter 在一個月前有其他 valid report 的紀錄，不過因為都是非公開的，無法得知報告內容，說不定以前人家也是乖乖找漏洞，最近才開始用 AI 寫報告（？）
