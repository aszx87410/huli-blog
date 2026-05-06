---
layout: note
title: "Next.js中介層繞過"
date: 2025-03-23 08:33:32
---
[Next.js](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware) 昨天剛爆出一個嚴重漏洞 CVE-2025-29927，可以繞過 middleware。雖然說 CVSS 給的是 9.1 分所以是 critical，但其實我覺得沒這麼嚴重，且聽我娓娓道來。

一言以蔽之呢，這個漏洞可以不讓 middleware 執行，因此如果你有在 middleware 做一些權限檢查，就可以繞過這部分。舉例來說，用 middleware 保護 /admin 頁面，當 token 驗證失敗時跳轉到 /，此時就可以用這漏洞繞過 middleware，直接訪問 /admin 頁面。

但我覺得之所以沒這麼嚴重，是因為通常就算 middleware 這關過了，後端 API 還是需要一個合法的 token 才能取得資料，在這狀況下會是空的，所以理論上你也只看得到前端頁面，看不到後端的資料。

除非你只用 middleware 保護一個後台，而且後台的操作也都是透過這個 middleware 統一驗證的，那確實就出大事了 😅

而漏洞的利用方法也很簡單，只要傳一個 request header 就行了：
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
或是
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware

原理是 Next.js 用這個 header 來驗證 middleware 有沒有被執行過，但沒有阻止外面傳進來，所以只要自己傳進來，Next.js 會以為有執行過，就跳過不執行了 😆

總之呢，如果你沒有用到 middleware 來做權限驗證的話，那相當安全。如果有用的話，可以檢查一下繞過 middleware 會不會出事。

發現漏洞的資安研究員的 writeup 以及官方公告。

參考資料：<https://nextjs.org/blog/cve-2025-29927>
