---
layout: note
title: "React RSC 嚴重漏洞"
date: 2025-12-04 07:17:05
---
一早醒來就看到 React server components 爆了個嚴重漏洞 CVE-2025-55182，給了滿分 10 分，官方描述是：There is an unauthenticated remote code execution vulnerability in React Server Components.

說是 RSC 的實作上有個 unauth 的 RCE，只要發個請求到 server 就能打下來，是最嚴重的那種。

而有用到 RSC 的下游都連帶受到影響，例如說 [Next.js](https://nextjs.org/blog/CVE-2025-66478) 也迅速標了個 CVE-2025-66478 然後出了 patch，目前在描述中也沒有給太多資訊。

現在駭客們正在想辦法從 patch 反推回 PoC，應該很快就會出來了（原始 RSC 的已經有部分了，但是 Next.js 的還沒看到），雖然看起來攻擊有些前提，但目前是謠傳你用預設設定也會出事，有不少資安公司也都發了初步公告了。

總之呢，有用到 Next.js 的都建議盡快升級修掉。等有人分享出完整 PoC 跟技術分析之後，再來寫一篇談談吧。
