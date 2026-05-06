---
layout: note
title: "Git歷史裡的祕密"
date: 2025-06-05 20:26:05
---
一定有很多人都曾經不小心把 secret commit 進去 git 裡面過，而發現之後可能就立刻把 secret 刪掉，再 commit 一次。

但是 git 畢竟是個版本管理的程式，你沒有刻意把紀錄刪除的話，紀錄是永遠都會在的。因此表面上看起來沒 secret，實際上去找的話，就能從記錄中還原出來。

而有個資安研究員 Sharon [Brizinov](https://medium.com/@sharon.brizinov/how-i-made-64k-from-deleted-files-a-bug-bounty-story-c5bd3a6f5f9b) 就寫了個工具大規模去掃，先從 bug bounty 平台上獲得公司清單，然後問 AI 這些公司的 org 叫什麼名稱，有哪些 repo，再去掃這些 repo，最後找到一堆 GCP/AWS/Slack/GitHub token，回報後總共獲得 64k 美金，折合台幣約 190 萬元。

話說作者在掃描的時候大量運用一個叫 TruffleHog 的開源工具，可以確認 git repo 裡有沒有洩漏的 secret，找到後還可以確認是否有效，非常方便。

而文章有提到 TruffleHog 其實原本就能找歷史紀錄，那為什麼作者要重新弄一套呢？這是因為有些檔案太大導致 TruffleHog 會出問題，自己把檔案從紀錄中還原之後，成功率會大大提高。

每次都很佩服這種專門找某個洞然後寫工具大規模去掃的，把程式放在背景跑，找到了就發個訊息通知自己，怎麼想都覺得滿帥的
