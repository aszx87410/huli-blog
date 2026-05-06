---
layout: note
title: "DeepSeek資料庫裸奔"
date: 2025-02-05 20:20:10
---
今天來分享一個過年時的舊聞，應該不少人看過了，就是 [DeepSeek](https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak) 的資料庫在網路上裸奔被發現的故事。

資安公司 Wiz 的研究團隊在 1/30 的時候發佈了一篇名為《Wiz Research Uncovers Exposed DeepSeek Database Leaking Sensitive Information, Including Chat History》的文章，揭露了整段故事的細節。

基本上要入侵的第一步叫做 reconnaissance，簡稱 recon，偵查的意思，從外部的角度去搜集各種資訊，最常見的就是去找出 subdomains 或是 Google Dorking 等等，先把公開的資源搜集一波，再決定下一步。

當找到 subdomain 以後，先掃一次 port，看一下有哪些有趣的發現，接著再繼續打。

而這次 DeepSeek 的漏洞是在掃 port 這邊就被找到了，簡單來說先掃到一個 subdomain:  dev[dot]deepseek[dot].com，掃 port 發現上面開著 8123 port，結果一連進去就是一個公開的 ClickHouse，可以直接下 SQL query 並顯示結果。

整個過程就是這樣，一個裸奔的 ClickHouse 放在網路上，就算沒有被這間資安公司找到，可能過不久就被其他機器人掃到了。完全不需要驗證又直接開放在公網，暴露的又是資料庫，算是滿嚴重的。

補充文章：<https://www.ithome.com.tw/news/155392>
