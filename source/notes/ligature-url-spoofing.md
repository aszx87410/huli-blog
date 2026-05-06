---
layout: note
title: "連字造成網址偽裝"
date: 2025-05-19 20:58:28
---
我知道有些工程師很愛用一種字體，會把 >= 直接顯示成一個字，像這種把多個字母合在一起顯示，有個專有名詞叫做「Ligature」，中文通常翻作連字。簡單來說，就是字體可以規定某幾個特定字母連在一起時該顯示成什麼樣子。

而近期有一位叫做 yuki yamaoto 的人回報給 Chromium 一個 bug，就是因為這個連字功能所造成的。當你在 Android Chrome 上造訪 http://googlelogoligature[.]net 這個網址的時候，就會出現我附圖這樣的狀況

這是因為 Google 自己用的字體會把 googlelogoligature 這一串字已連字的方式顯示成 Google 的 logo，所以就變成一種 URL spoofing，讓人以為是 Google 官方網站，但其實不是。

以前類似漏洞都是利用 Unicode 的一些奇怪特性，這是我第一次看到還可以用連字來攻擊，真的很有趣，這個 bug 最後也拿到了 15000 美金的賞金。

參考資料：<https://issues.chromium.org/issues/391788835>
