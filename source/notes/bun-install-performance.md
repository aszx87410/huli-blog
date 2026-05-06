---
layout: note
title: "Bun安裝為何很快"
date: 2025-09-26 07:18:34
---
JavaScript 的 runtime Bun 憑藉著又快功能又多的特色，早已在圈內打響了名號。

前幾週 Bun 的技術部落格有一篇文章《Behind The Scenes of Bun [Install](https://bun.com/blog/behind-the-scenes-of-bun-install)》，深度解析了為什用 Bun 來安裝套件可以比其它程式快這麼多，足足有 pnpm 的 4 倍，npm 的 7 倍。

文章有提到 Bun 在做這個功能時的核心理念是：「把這當成是一個 systems programming 的問題」，因此用了很多相對較底層的解法，包括：

1. 減少 system calls
2. 運用 Apple 非公開的 API 做非同步 DNS 解析
3. 用 binary 格式取代 JSON pasring
4. 設計對 CPU 快取友好的資料結構
5. 善用不同的 system call 快速複製檔案

這裡面細節很多，Bun 的原始文章圖文並茂，寫得很好，因此我就只列出幾點而已。

看完之後很能理解為什麼 Bun 比別人快了這麼多，背後真的是做了很多細節上的改善。另外，Bun 是用 Zig 寫的，直接編譯成 native code 並呼叫 system call，也比用 Node.js 寫的其他套件管理程式少了許多 JavaScript overhead。

這篇 [Bun 的原文](https://bun.com/blog/behind-the-scenes-of-bun-install)很值得一看。

上面講完了 Bun 的優點跟背後的努力，接著講一下 Bun 的缺點跟我不喜歡的地方，就是 Bun 雖然宣稱自己可以直接替代 Node.js 來使用，但若是某些 spec 他們覺得不合理，就會直接不實作。

舉例來說，6 月份有個 issue 是說 Bun 在執行 fetch('localhost:6000') 時沒有報錯，可是 spec 上有所謂的「Port blocking」，發送到特定 port 的請求會直接報錯，不會建立連線。這是一種資安上的考量，避免有人用 HTTP protocol 偽造別的協定來攻擊（叫做 Cross Protocol Scripting），[Redis](https://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/) 早期就有這問題，你可以發一個 HTTP 請求當成 Redis 指令來執行。

總之，後來有人對 Bun 提了個 PR 加上這個符合 spec 的功能，而 Bun 的 creator 把 PR 關了，說他覺得這功能對使用者沒價值，如果他們就是想用這些 port 怎麼辦。

這只是其中一個案例，再查查也會發現其他 Bun 沒遵守 spec，或者是因為某些原因加進去的預設設定。久了之後說不定會成為另一種 IE？反正 spec 寫他的，我做我想做的。

不過 Bun 的出現，也確實為其他 runtime 帶來一些壓力跟競爭，其實也是件好事。在特定狀況下我可能會用 Bun（如需要 Single-file executable），但一般情形下，還是再觀望一陣子好了，繼續用我的 npm + Node.js。

補充文章：

- <https://github.com/redis/redis/commit/a81a92ca2ceba364f4bb51efde9284d939e7ff47>
- <https://github.com/oven-sh/bun/issues/20352>
- <https://github.com/oven-sh/bun/pull/6217>
