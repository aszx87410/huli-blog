---
layout: note
title: "雲端 Agent 開發時代"
date: 2026-02-26 21:45:13
---
現在業界對於 AI coding 的使用，到底是怎麼個用法呢？剛好最近看到一些可以連起來的東西，簡單寫一下。

金流服務 Stripe 最近發了一篇文章，介紹他們自己打造的內部工具 [Minions](https://stripe.dev/blog/minions-stripes-one-shot-end-to-end-coding-agents)，你可以直接從 Slack 上面 tag 他，跟他說要做什麼，他就會自己起一個環境（內部叫 devbox，一個 EC2 instance 上面已經把環境弄好 ），把任務完成之後發 PR 讓你 review。

然後他們用的 coding agent 是從開源專案 goose fork 出來改的，看來大公司還是有挺多東西需要客製化的。

在兩三年前雖然也有這種概念（AI 軟體工程師如 Devin），但在當時看來我還覺得有點遠，模型還沒這麼厲害，但是在 2026 的現在，是 100% 可以做到的東西，更是有些公司內部已經在使用的服務。

但不要看 Stripe 做得到，就以為每間公司都行，要這樣做至少要有兩個前提：
(1) 你的測試要足夠
(2) 你要能把環境建起來

Stripe 是因為本來就有很多測試，所以 AI 改壞可以自己修，直到測試通過為止，人 review 的時候可以減少很多心智負擔，因為 test coverage 夠齊全，至少不會歪到哪去。

但很多公司連測試都沒有，想這樣做要嘛工程師花些心力 review，要嘛相信 AI 足夠強，直接勇敢按下 merge。

剛好這兩天 [Cloudflare](https://blog.cloudflare.com/vinext/) 宣布他們用 AI 花了一週把 Next.js 遷移到 Vite 上面，然後只有一個工程師在負責指揮，就搞定了。

在他們的文章中也有清楚提到，這次遷移能順利的理由是完整的 AI 文件以及全面的測試案例，否則不可能這麼順利。這個再次強調了測試的重要性，當你的測試夠強，就能讓 AI 自主工作變得更有效率。

現在已經很多人直接 claude code 或其他 AI agent，跑一次就把任務完成了，而 Stripe 那種模式可以想成把你的本地環境搬一份到雲端，就可以享受隨時隨地叫 AI 工作的快感。

那如果你也想體驗這種快感該怎麼做呢？

剛好這兩天 [Cursor](https://cursor.com/blog/agent-computer-use) 的 Cloud Agent 改版，它就是一套雲端的 agent，我已經體驗過了，感覺很不錯。

把 GitHub repo 權限開給他以後，agent 會自己從 repo 中去探索怎麼把服務跑起來，然後還會錄影片給你證明它完成了。若是 agent 卡住，你可以中斷它然後幫他操作，這邊是直接有一個雲端桌面可以操控，一個 Xfce 的 Linux 環境。

比如說像我的專案需要登入，在 setup 過程中 agent 發現後就自動在 setup 區塊說他需要帳號密碼，直接多了兩個輸入框出來讓我填。

在環境配置好以後，就會存 snapshot，之後每個任務都只要出一張嘴，agent 就會自己把環境跑起來，然後完成你交代的任務，之後發 PR 等你 review，就像是 Stripe 的文章中所描述的那樣。

整體的體驗滿不錯的，專案建置上沒什麼問題，Electron 它也跑得起來。只是在操控上面因為是用 computer use 所以滿燒 token，我今天讓它試著在 desktop app 上做一個新功能，大概花了 30 分鐘，燒了 2000 萬個 token，似乎是 10 美金左右。

未來 cloud agent 我猜也會越來越普及，只是在資安以及環境建置這塊要怎麼處理會比較麻煩（例如說有些服務在公司內網），但用起來感覺不錯就是了。

總之呢，從我自己的日常開發以及這些大公司的部落格中，很明顯可以看到軟體工程師把任務交給 AI 跑已經是常態了，不要再用什麼網頁版，你用 claude code 也好 open code 也好 Codex 也好 Cursor 也好，反正有個 agent 可以幫你跑任務就對了。

我自己日常開發還是用 Cursor，下次再寫一篇我最近怎麼用 Cursor 搭配其他工具，幫助我這個外行人逆向一個 golang binary 吧。
