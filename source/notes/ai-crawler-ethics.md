---
layout: note
title: "AI爬蟲道德爭議"
date: 2025-08-06 07:45:26
---
[Cloudflare](https://blog.cloudflare.com/perplexity-is-using-stealth-undeclared-crawlers-to-evade-website-no-crawl-directives/) 槓上 Perplexity 之 AI 爬蟲的道德問題

8/4 的時候 Cloudflare 公開發了一篇文：「Perplexity is using stealth, undeclared crawlers to evade website no-crawl directives」，指責 Perplexity 在 robots.txt 明確阻擋其 user agent 的狀況下，偷偷換成其他假裝是一般使用者的 user agent，還換個 IP 繼續爬，無視網站本身的意願。

在文中舉了另一個善良（？）的例子 OpenAI，經測試過後一旦發現 robots.txt 不允許就直接撤了，不會偷偷來。

而知名的科技媒體 [TechCrunch](https://techcrunch.com/2025/08/04/perplexity-accused-of-scraping-websites-that-explicitly-blocked-ai-scraping/) 就去問了 Perplexity，那邊的發言人給的回覆是 Cloudflare 的這篇文章是拿來行銷用的，説文中提到的爬蟲甚至不是他們家的。

所謂的「拿來行銷用的」，應該是指 Cloudflare 上個月推出的新功能，可以預設封鎖 AI 爬蟲，並且網站可以提供指定付費策略，讓 AI 爬蟲付了錢之後就能爬。

看了看 HackerNews 上的討論，有個觀點滿有趣的，就是 AI 爬蟲這個東西，究竟該視為傳統的爬蟲，還是「只是代表使用者搜尋資料」？例如說我在 Perplexity 想查一個東西，而 Perplexity 只是幫我去網路上搜集資料並且整合過後回我。並不是背後有一個 bot 會一直去爬所有網站，而是 user 有需求的時候，才幫他去爬。

雖然說無論是哪一種，造訪網站的都是機器人，但我認同它的目的確實不太一樣。如果 AI 只是幫我瀏覽網站，那 robots.txt 是針對 bot，不是針對人類的瀏覽器，是否就不適用？不過聽起來好像有點詭辯的意味在，畢竟最後去爬網站的都還是 bot 沒錯。

補充文章：<https://news.ycombinator.com/item?id=44785636>
