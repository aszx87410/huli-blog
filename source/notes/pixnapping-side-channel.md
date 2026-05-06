---
layout: note
title: "Pixnapping 側信道攻擊"
date: 2025-12-02 07:41:37
---
前陣子看到一個叫做 [Pixnapping](https://www.pixnapping.com/) 的攻擊方式滿有趣的，是一種針對 Android 硬體的 side channel attack。

在理解什麼是 Pixnapping 之前，先來看另一個兩年前就被公佈的攻擊方式 [GPU](https://www.hertzbleed.com/gpu.zip/) zip。GPU 在渲染畫面的時候會做壓縮，所以在網頁上你可以用 iframe 把要攻擊的網站嵌入進來，然後利用一些 CSS 去改變它的顏色或是特別調整某個區塊。

舉例來說，可以用 CSS 獨立出某一個 pixel 然後放到很大，接著疊上一些隨機產生的點，如果畫面是白色就會難以壓縮，若畫面是黑色壓縮率就很好（背後跟 GPU 怎麼壓縮東西有關，總之結論是這樣）

再搭配 render 時間的測量，就可以反推回去原始的某個 pixel 是黑是白，重複這樣的操作就能 leak 出原本的畫面大概長什麼樣子。

而這個 Pixnapping 就是在 Android 上利用 App 可以 overlay 在別的 App 上的特性，先把 Authenticator App 開在後面，上面疊加自己的 App，然後自己的 App 變成半透明去改變顏色，就能利用類似手法，洩漏出底下 App 的某個 pixel 是黑是白。

簡單來講呢，最終結果等於是你可以對其他 App 做個 screenshot （只是需要點時間）。

針對 GPU 進行資料壓縮的特性來做 side channel attack，推斷出 pixel 顏色，進而推斷出畫面，就可以拿到上面的資料，滿有趣的。
