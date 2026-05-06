---
layout: note
title: "Vercel WAF 賞金大戰"
date: 2025-12-16 20:38:04
---
話說有關 React2Shell 的那個漏洞，Next.js 背後的公司 [Vercel](https://hackerone.com/vercel_platform_protection?type=team) 第一時間就上了 WAF，讓客戶在還來不及升級時，先幫他們擋著惡意攻擊，這是很常見的做法。

但 WAF 要做好是很難的，因此在推特上就漸漸有人找出 bypass 的方法。

而接下來 Vercel 做了件瘋狂的事情，為了表達他們對這個漏洞的重視程度，他們特別開了一個 bug bounty program 給 WAF bypass，而且獎金高達 5 萬美金！每找到一個繞過 WAF 的方法，就有 150 萬台幣可以拿！

而今天這個 program 正式告一段落，那些回報的 WAF bypass 都被修掉了，最後總共發出 85 萬美金（約 2500 萬台幣）的獎金，那些武功高強動作又快的白帽駭客們成了最大贏家。

拿到賞金的駭客有些我們以前也介紹過，如前陣子發現 Unity launcher 漏洞的 ryotak，或是最早釋出 1-day exploit 的 maple，以及打了很多個 AI 瀏覽器，在做 AI 輔助工具的 hacktron，這些都在榜上。

我以為只有幣圈會拿這麼多錢出來給 bug bounty，沒想到 Vercel 這次也這麼慷慨。
