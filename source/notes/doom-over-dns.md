---
layout: note
title: "把 DOOM 藏進 DNS"
date: 2026-03-24 21:04:30
---
剛看到一個國外的資安工程師 Adam Rice 因為太喜歡 DNS 了，所以乾脆把 [DOOM](https://blog.rice.is/post/doom-over-dns/) 毀滅戰士放在上面，只要依序解析 DNS TXT 紀錄就可以抓下來跑 😆

先來講講 DOOM 毀滅戰士這個遊戲，如同原文所提到的，一堆神人會在各種地方試著把 DOOM 跑起來，例如說有數位螢幕的驗孕棒或者是電動飛機杯之類的。

而 DNS TXT 紀錄本質上就是個字串，每條紀錄可以放 2000 個字元左右，所以把 DOOM 的主程式壓縮一下再轉成 base64 約 3MB ，作者用了將近 2000 條 DNS 紀錄把它給放進去。

最後，只要寫個 PowerShell script 去解析 DNS 拼接成一個大字串，在記憶體裡面解碼然後解壓縮，就能直接把 DOOM 跑起來，做到檔案不落地，直接在記憶體裡面跑。

更多技術細節在原文，然後原始碼也有開源到 GitHub 上。
