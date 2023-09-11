---
title: 原來 img src 也支援 mp4（Safari 限定）
date: 2023-09-11 21:10:00
catalog: true
tags: [Front-end]
categories: [Front-end]
photos: /img/mp4-in-img-src/cover.png
---

有些網站會用 GIF 來做一些圖檔，畢竟會動嘛，看起來就比一些靜態的圖片還要厲害，還要來得更吸引人。或其實不只是因為吸引人，而是有些需求本來就需要一個會動的圖，例如說貼圖，會動是很正常的。

但是 GIF 的缺點之一眾所皆知，就是檔案很大，真的很大。尤其是手機上因為解析度比較高，可能會需要用到三倍大小的圖片，就算只顯示 52 px，也要準備 156px 的圖檔，佔的空間就更多了。以網頁來說，當然是要載入的資源越少越好，越小也越好。

<!-- more -->

因此，很多網站會改用 `<video>` 標籤來呈現這些動圖，只要先轉成 mp4 格式，檔案大小就能小很多。不過轉成 `<video>` 的問題大概就是原先用 `<img>` 的一些好處會不見，像是 lazy loading 似乎就沒有原生支援，有一些麻煩。

而我在查資料的過程中，居然意外發現在 Safari 上面，`<img>` 是支援 mp4 的！也就是說，你可以這樣做：

``` html
<img src="test.mp4">
```

而且這個功能推出很久了，從 2017 的時候就有了：[Bug 176825 - [Cocoa] Add an ImageDecoder subclass backed by AVFoundation](https://bugs.webkit.org/show_bug.cgi?id=176825)

我是從這篇文章知道的：[Evolution of &lt;img>: Gif without the GIF](https://calendar.perfplanet.com/2017/animated-gif-without-the-gif/)

如果 `<img>` 裡面也可以放 mp4 的話，就可以同時利用到兩者的優點，又不用換標籤，又支援 lazy loading，然後檔案大小又一下縮減了許多。

但可惜的事情是，只有 Safari 有支援而已，就算過了六年，在 Chromium 以及 Firefox 上都沒看到這個功能，而且未來也沒什麼機會看到了。

之所以會這樣講，是因為 Chromium 已經明確表示不會支援，討論串在這邊：[Issue 791658: Support &lt;img src="*.mp4">](https://bugs.chromium.org/p/chromium/issues/detail?id=791658) ，在 2018 的時候就已經被標記為 Wont fix，理由如下：

```
Closing as WontFix per c#35, due to the following:
- The widespread adoption of WebP (addresses CDN use case)
- Forthcoming AV1 based image formats (ditto).
- Memory inefficiency with allowing arbitrary video in image.
- Most sites have already switched to &lt;video muted> now that autoplay is allowed.
```

第一點提到的是 WebP 其實也有個 Animated WebP 的格式，可以放在 `<img src>` 裡面而且也會動，檔案大小更小，其他優缺點可以參考 Google 自己寫的：[使用 WebP 動畫有什麼好處？](https://developers.google.com/speed/webp/faq?hl=zh-tw#why_should_i_use_animated_webp)

而第二點是在說比較新的圖片格式 AVIF 也有 Animated AVIF，同樣也支援動圖。

如果這些新的圖片格式都可以取代 GIF 的話，好像確實沒什麼必要一定要使用 mp4？

而 Firefox 的話雖然沒有說不會做，但是 issue 也已經很久沒動了：[Add support for video formats in &lt;img>, behaving like animated gif](https://bugzilla.mozilla.org/show_bug.cgi?id=895131)

也有人希望可以把這個功能加入規格，但也有一陣子沒有動靜：[Require img to be able to load the same video formats as video supports #7141](https://github.com/whatwg/html/issues/7141)

總而言之，看起來這個功能應該只會在 Safari 上面有了。

可惜我在用的 image service 的自動轉檔功能只支援 GIF 轉 mp4，不支援轉成 animated WebP 或是 animated AVIF，不然就超方便的。

## 總結

如果想要繼續用 `<img>` 來放動圖的話，最完整的方式應該是使用 `<picture>` 標籤搭配多種檔案格式，像這樣：

``` html
<picture>
  <source type="image/avif" srcset="test.avif">
  <source type="video/mp4" srcset="test.mp4">
  <source type="image/webp" srcset="test.webp">
  <img src="test.gif">
</picture>
```

這樣就可以確保在每個瀏覽器上面都可以呈現出結果，並且會選擇通常檔案大小較小的圖片。

我隨便試了一下，自己錄了一個簡單的 gif，原始大小是 75 KB：

![gif](/img/mp4-in-img-src/test.gif)

轉成 WebP 之後是 58 KB (-22.6%)：

![webp](/img/mp4-in-img-src/test.webp)

轉成 mp4 是 17 KB（-77.3%）：

![只有 Safari 支援 mp4，看不到正常](/img/mp4-in-img-src/test.mp4)

轉成 AVIF 是 11 KB（-85.3%）：

![AVIF 格式，有可能較新還不支援](/img/mp4-in-img-src/test.avif)

看來最新的檔案格式還是滿厲害的，一下就小了超多。
