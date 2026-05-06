---
layout: note
title: "用 CSS 寫出 CPU"
date: 2026-02-24 20:36:33
---
有寫過網頁的人可能知道 [CSS](https://lyra.horse/x86css/) 很厲害，可以用純 CSS 來寫遊戲，無論是 2D 或 3D 的都行。

但我今天看到了個更厲害的，用 CSS 寫了個 x86 CPU 模擬器！把 C compiled 變成 machine code 之後，可以把它交給 CSS 去跑。

有點類似於有些人在 Minecraft 裡面也會搞出一台電腦或是 CPU，不過弄在 CSS 上從我的角度看來是更厲害的，因為它能用的東西更少一點。

至於原理的話，作者之後會寫個部落格談談自己用到哪些技巧，目前看起來是受兩年前另一篇文章《Expert CSS: The CPU Hack》的啟發，透過 animation + keyframe 為基礎去弄出一個 loop，剩餘的就是一堆計算跟儲存了。

補充文章：<https://garethheyes.co.uk/>
