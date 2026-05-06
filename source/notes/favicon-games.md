---
layout: note
title: "用Favicon玩遊戲"
date: 2025-03-11 19:55:40
---
當你打開一個新的分頁時，頁籤的左邊通常會出現一個圖示，我們叫它 [favicon](https://mewtru.com/flappyfavi)，就算我們切到其他分頁，這個 favicon 也可以讓我們快速辨識出這是哪個網站。

這樣的一個小東西，利用到極致可以幹嘛呢？你可能要說可以增加網站辨識度什麼的，不是，答案是可以玩 flappy bird 跟 pong。

那要怎麼利用這個小小的 favicon 來玩遊戲呢？

網頁本身可以不斷更新 favicon，一秒大概可以切換 4 張，而 @trunarla 就利用了這個特性做了個 flappy bird 的遊戲，favicon 就是遊戲畫面，按下空白鍵就會讓鳥飛起來。我有試玩了一下，雖然畫面很小看久眼睛有點痛，不過還滿有趣的。

但這還不是最厲害的了，而是 @trunarla 的朋友 @itseieio 受到啟發後，決定用 240 個 tab 排成 8*30 的畫面，並且用這個畫面來渲染知名的遊戲 pong（就是有顆球會在左邊右邊彈來彈去的那個）。

@itseieio 自己寫的文章裡面記錄了很多有挑戰性的小地方，例如說分頁被放到背景之後就會限制 setInterval 的頻率，導致畫面切換很慢，那該怎麼辦呢？

解法是用一個 web worker，就能在背景也能快速更換 favicon。另一個挑戰是這麼多的 tab 要怎麼互相溝通？最直覺的想法是寫個 websocket 讓 server 搞定，但光是初始化就要一些時間，於是用了純前端的做法 broadcast channel，在前端讓一個主頁面處理，再把消息廣播到其他分頁。

文中有紀錄更多細節，包括整體 size 的計算以及實作「從頁面跑到 favicon 的效果」等等，都非常有趣，但文章中我最喜歡的是作者引用美國的魔術師雙人組合 Penn and Teller 中 Teller 的一段話：

> Sometimes magic is just someone spending more time on something than anyone else might reasonably expect

所謂的魔法，有時就只是某個人在某件事上花了你難以想像的時間

既然都可以拿分頁來玩遊戲了，感覺可以再進化，例如說可以 render 低畫質的 YouTube 影片之類的。

影片：<https://eieio.games/blog/running-pong-in-240-browser-tabs/>
