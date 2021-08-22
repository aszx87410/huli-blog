---
title: 除了 hexo，也可以考慮用 eleventy 來寫技術部落格
catalog: true
date: 2021-08-22 15:43:37
tags: [Others]
categories: [Others]
---

## 前言

講到寫技術部落格的話，現在最多人的首選應該都還是 [hexo](https://hexo.io/zh-tw/) + GitHub Pages 這個組合，事實上，你目前看到的這個部落格也是用這個技術棧架起來的。

而最近我架了另外兩個技術部落格，卻不是使用 hexo，而是使用另外一套叫做 [eleventy](https://www.11ty.dev/) 的 static site generator，使用的滿意度極高，因此特地寫了這篇文章跟大家推薦這套。

如果你想先看是哪兩個部落格，在這邊：

1. [ErrorBaker 技術共筆部落格](https://blog.errorbaker.tw/)
2. [Cymetrics Tech Blog](https://tech-blog.cymetrics.io/)

<!-- more -->

## 為什麼是 eleventy？

我一開始知道這套，是從這篇得知的：[為什麼我離開 Medium 用 eleventy 做一個 blog](https://jason-memo.dev/posts/why-i-leave-medium-and-build-blog-with-eleventy/)，從文中可以看出 eleventy 的優勢之一就是簡單輕便，而這是我覺得部落格滿重要的一部分。

像是 hexo 這種倒是還好，大部分的 theme 效能都不會到太差，頂多是肥了一點，以我目前的 huli blog 來說，首頁的 lighthouse 跑分在效能上是 81 分，First Contentful Paint 是 3.4 秒，沒有到很差，但有進步空間，而且我這個部落格看起來明明就很簡潔卻花了這麼多時間，代表有很多地方可以改進。

但我看過一些自己建的部落格效能有夠差，跑個好幾秒才有內容出來，這種就完全無法接受。

在上面的文中有介紹了一套 Google AMP tech lead 開發的 [eleventy-high-performance-blog](https://github.com/google/eleventy-high-performance-blog)，既然標題都已經這樣取了，就代表是以效能為導向。

前陣子我剛好要幫以前的學生們架一個技術共筆部落格，就想到了這套解決方案，並且實際試了一下，結果一鳴驚人，用了之後馬上愛上這一套，整體的滿意度我給五星好評。

如果你對我講到的這個部落格有興趣，連結在這邊：[ErrorBaker 技術共筆部落格](https://blog.errorbaker.tw/)

eleventy-high-performance-blog 這個模板的好處在於效能真的很快，有幫你處理過很多東西，包括：

1. 圖片的最佳化，自動壓縮、轉換格式以及用 `<pictrue>` 載入，還有原生 lazyload
2. 幾乎沒有太多 CSS 跟 JS，所以檔案大小很小
3. 基本的 SEO 都有做
4. a11y 有考量進去
5. 版面簡潔，檔案少，要修改很容易

除了模板的好處以外，eleventy（以下簡稱 11ty）這一套 SSG 也有些好處，包括：

1. 語法簡單容易上手
2. 客製化容易
3. 文件滿詳細的

值得一提的是這些部落格其實都是給一個人用的，而我要架的部落格預設就是多人共筆，所以會有多個作者，因此本來就需要客製化修改一些東西。而這些修改我大概花了半天到一天左右就搞定了，就把單人部落格變成多人共筆部落格。

eleventy-high-performance-blog 這個模板 + 11ty 這兩套都很簡潔，所以客製化非常容易，檔案少的好處就是你不用花太多時間去找要改哪裡。

身為前端工程師，我覺得有個可以輕鬆客製化的部落格是很不錯的一件事，因為你想嘗試什麼新技術或是做效能最佳化都會容易許多，很快就可以找到要怎麼改。

原本架的那個共筆部落格搞一個段落之後，剛好公司的部落格想要搬家，因此我就拿之前弄好的來改，版面調整一下就有了一個新的部落格：[Cymetrics Tech Blog](https://tech-blog.cymetrics.io/)

總結一下，基本上我覺得 11ty 跟 eleventy-high-performance-blog 的優點是：

1. 版面簡潔，適合不喜歡太多東西的人
2. 修改容易，比較方便做客製化
3. 部落格效能不錯，載入快速

## 一些缺點與我碰過的問題

除了優點以外也來講一些缺點，平衡一下。

第一個缺點是 CSS 的部分不太好改，原本的 CSS 有些一定會被覆蓋掉的規則，但不知道為什麼沒有刪掉，而整體 CSS 看起來也寫得有點亂。

第二個缺點是圖片優化的部分因為是在 build time 直接去轉圖片，例如說把 png 轉成 webp 跟 avif，這部分只有 local cache，所以如果在 CI 上跑的話會很慢，之前有跑過 7 分鐘的 build。

解法有兩個，一個是把 cache image 一起 commit 進去，另一個是把 avif 轉換拿掉，因為這個花最多時間。

第三個是如果要串 [utterances](https://utteranc.es/) 這個評論系統的話有個小 bug，這一套登入之後會用網址列帶的 token 去做驗證，結果這模板[有個功能](https://github.com/google/eleventy-high-performance-blog/blob/60902bfdaf764f5b16b2af62cf10f63e0e74efbc/src/main.js#L27)是把 query string 弄掉，就得不到 token 就沒辦法登入。

暫時的 workaround 我目前是設成一秒後才清空 query string。

第四個是分頁，這模板的 pagination navigation 要自己做，幸好官網已經有詳細範例了：[PAGINATION NAVIGATION](https://www.11ty.dev/docs/pagination/nav/)。

第五個是有些優化似乎有一點問題，例如說 `<head>` 標籤會變不見，可能是被誤以為是可以省略的標籤了，導致的後果就是如果有用 GA 或 search console，你會沒辦法靠在 head 加東西去做驗證，我目前是先把 [removeOptionalTags](https://github.com/google/eleventy-high-performance-blog/blob/main/_11ty/optimize-html.js#L99) 給拿掉。

第六個是 SEO 有些 tag 不完整，例如說 `twitter:title`、`og:site_name`、`og:type` 這些沒有加上去，雖然說應該還是可以自動抓到一些東西，但寫清楚還是比較好的。

其實我覺得都是一些小問題啦，比較細節的地方。

## 總結

以前我就研究過寫 blog 到底要用哪一套了，那時候除了 hexo 也沒其他好選的，hugo 或是老牌 jekyll 都沒 hexo 習慣。版型的部分是看 [Askie](https://askie.today/about/) 用的版型很不錯，就也選用同個版型。

但用久了也發現一些缺點，就是網站有點太肥（我剛發現好像大部分都是 disqus 的東西，找到戰犯了，不是模板的問題而是 disqus，之後再來仔細看看），除此之外倒是沒什麼問題。

而這次因為要架新的部落格的關係開始看別套，發現 11ty 真的挺不錯的，效能確實很好，不過那個 high performance 的版型跟 hexo 比的話確實是比較陽春，如果不喜歡這麼簡潔的話，就是要自己再多花點心力去調整了。

總之呢，我用起來的整體感覺滿不錯的，而且自己動手去修 bug 或是加功能，也都會讓自己更參與在其中。

如果你喜歡簡潔快速的部落格版型，而且不排斥自己動手加新功能或是調整版面，誠心推薦你 [eleventy-high-performance-blog](https://github.com/google/eleventy-high-performance-blog)。
