---
layout: "about"
title: "關於我"
date: 2023-10-15 16:30:00
---

想關注部落格文章的話，除了 RSS 以外也可以考慮追蹤這個粉絲專頁：[Huli 隨意聊](https://www.facebook.com/huli.blog)

RSS 的話本站提供三個版本，可以自行選擇想要的版本：

1. 中文版：https://blog.huli.tw/atom-ch.xml
2. 英文版：https://blog.huli.tw/atom-en.xml
3. 中英雙語版：https://blog.huli.tw/atom.xml

想看更多相關文章可以參考[另一個生活部落格](https://life.huli.tw/)，想聯絡我的話可以透過 Email：aszx87410@gmail.com，網頁右上角也可以找到我的臉書。

原本是個前端工程師，2021 年 5 月開始轉做資安相關的研究，也因為這個背景，對於前端相關的資安議題（XSS、CORS 以及 XSLeaks）特別感興趣。

然而在 2023 年底又轉了回來，再次跑回去做前端。

在生活上是個重度拖延症患者，興趣是光想不做，有很多想做的事，最後都不了了之。無聊的時候喜歡寫寫文章，發現自己好像有把事情講得比其他人清楚的能力，相信分享與交流可以讓世界更美好。

喜歡把常見問題寫成文章，就不用每次被問就回答一次，就跟寫 code 的時候要順便記得重構一樣。

很多想寫的主題都擱置著，因此我把這些主題放在[這個地方](https://github.com/aszx87410/blog/discussions)，有想看到我寫哪個主題的可以按個 upvote 或是留言。

如果你對我怎麼學程式以及相關背景有興趣，可以閱讀：

1. [自學、哲學、講學：我的程式之路](https://life.huli.tw/2017/10/05/the-programming-journey-1-b9b19c0ef05b/)

如果你好奇我為什麼寫文章，每寫一篇都花多久，可以閱讀：

1. [廢文工作者的養成](https://medium.com/@hulitw/%E5%BB%A2%E6%96%87%E5%B7%A5%E4%BD%9C%E8%80%85%E7%9A%84%E9%A4%8A%E6%88%90-d05a5b7e539)
2. [我為什麼寫部落格，以及部落格帶給我的影響](https://life.huli.tw/2018/06/13/blog-e7a23a74ae2b/)
3. [我是如何完成一篇文章的？](https://life.huli.tw/2019/08/22/how-do-i-write-965328ae91fe/)

如果你想知道我對學習方面的看法，可以參考：

1. [致跟我一樣的拖延症患者：動力是需要刻意創造的](https://life.huli.tw/2018/09/26/procrastination-ba12754ada49/)
2. [當我們在學程式時，要學的到底是什麼？](https://life.huli.tw/2018/10/29/learn-coding-9c572c2fb2/)
3. [程式相關問題一網打盡：談自學、轉職、出國、職涯、教學、補習、騙錢、產業以及努力](https://life.huli.tw/2019/02/05/qa-be72946f0b23/)
4. [用對你有效的學習方法，無論那是什麼](https://life.huli.tw/2020/02/10/learning-c6656ef14cd4/)
5. [打造「正確」學習 mindset](https://life.huli.tw/2020/04/19/mindset-36c163303217/)

如果你對我的工作經歷有興趣，可以看看：

1. [一個工程師的履歷進化史](https://life.huli.tw/2017/10/09/resume-evolution-4c337ff30729/)
2. [成為前端工程師的四週年回顧](https://life.huli.tw/2019/04/13/4-years-review-7fb7edc52687/)
3. [Linkedin](http://goo.gl/ar5yhh)

## 演講與投影片

整理一下之前去過的研討會或是給過的一些 talk，避免每次要找的時候都不知道去哪裡找。

### CYBERSEC 2022 - 不需要 JS 的前端攻擊手法 - CSS injection

談到網頁前端安全，第一個想到的幾乎都是 XSS，一種利用 JavaScript 的攻擊手法。有許多人都以為只要阻止 JavaScript 執行就足夠了，但事實上還可以透過其他方式攻擊，例如說 iframe 或甚至是拿來裝飾網頁的 CSS！

在本場講題中，我會介紹 CSS injection 這個較少人提及的攻擊手法，讓攻擊者藉由 CSS 來偷取網頁上的文字以及敏感資料，例如說可以偷取 CSRF token，再用這組 token 進行 CSRF 攻擊，來繞過原本 CSRF 的防範機制。

最後我會以知名開源協作筆記軟體作為實際案例，來探討 CSS injection 的攻擊與防禦。

研討會連結：https://cyber.ithome.com.tw/2022/session-page/692  
投影片：https://speakerdeck.com/aszx87410/attacking-web-without-js-css-injection

### Sharing at TrendMicro - Front-end Security that Front-end developers don't know

這是我之前去趨勢內部分享的一個講題，主要是有關於前端資訊安全，談到了一些經典的主題像是 XSS, CSP, CSRF 以及 XSLeaks 等等

投影片：https://speakerdeck.com/aszx87410/front-end-security-that-front-end-developers-dont-know

### ModernWeb 2021 - 接觸資安才發現前端的水真深

當了五年前端工程師的我，在前陣子因緣際會轉到了資訊安全的部門，開始研究起各式各樣的攻擊手法。原本我自認為對前端以及 JS 還算熟悉，該看的都看過了，直到我接觸了資安以及 CTF，才發現我太天真了。在這場講題中，我會分享我從資安重新學習到的前端知識，跟大家一起從新的領域重新認識一些有趣好玩的前端特性。

研討會連結：https://modernweb.ithome.com.tw/session-inner#457  
投影片：https://speakerdeck.com/aszx87410/jie-chu-zi-an-cai-fa-xian-qian-duan-de-shui-zhen-shen-modern-web-2021

### MOPCON 2021 - 你懂了 JavaScript，也不懂 JavaScript

JavaScript 中有幾個主題，常出現在面試考題裡面，像是 type、hoisting、this、scope 或是 prototype 等等。有許多新手學這些是因為面試會考，但工作之後也沒有體會到除了應付考試，為何要學習這些。

儘管有些主題前輩說要學，但為何在工作上從來沒有碰過需要它的地方？那它到底是重要，還是不重要呢？

在這場演講中我希望以實際案例帶大家去探索，這些被稱為 JavaScript 核心的知識，哪些只是俗濫的面試考題，哪些又是真的有價值的。

研討會連結：https://mopcon.org/2021/schedule/2021006  
投影片：https://speakerdeck.com/aszx87410/ni-dong-liao-javascript-ye-bu-dong-javascript-mopcon-2021

### JSDC 2020 - 用 API mocking 讓前端不再苦苦等待

在開發上比較理想的狀況是後端先行，等後端 API 差不多以後前端再進來，這時候就可以直接串接 API。但現實上很常發生前後端同步開發的狀況，有時候前端就必須等後端開發完畢，才能開始進行後續動作。

為了避免這種苦苦等待的狀況，我會介紹一些好用的 API mocking library，讓大家自己先 mock API，讓前端超前部署！

研討會連結：https://2020.jsdc.tw/agenda/  
投影片：https://speakerdeck.com/aszx87410/jsdc2020-yong-api-mocking-rang-qian-duan-bu-zai-ku-deng-dai

### ModernWeb 2018 - 輕鬆應付複雜的非同步操作：RxJS + Redux Observable

Reactive Programming 近幾年在處理非同步事件上成為顯學，無論是 JavaScript、Java 或是 Swift，都能看到它的蹤影。所以演說的第一部份會介紹 RxJS 的基本概念跟常用的 operator，藉由幾個小範例讓大家看見 RxJS 在處理非同步上的厲害之處。

而 React 作為一套 UI library，在處理 API call 時往往需要依靠 Redux 來做狀態的管理，而搭配的解決方案又有好多種，像是 redux-thunk 或 redux-saga 等等。這次要介紹的 redux-observable 是一套利用 RxJS 來處理非同步 Action 的解決方案，因此第二部分會講到 redux-observable 的基本使用以及核心概念，最後講到如何用 RxJS 處理複雜的 API call。

研討會連結：https://modernweb.tw/2018/agenda.html
投影片：https://speakerdeck.com/aszx87410/modernweb-2018-qing-song-ying-fu-fu-za-de-fei-tong-bu-cao-zuo-rxjs-plus-redux-observable


## 關於部落格

經歷過無數次的搬家之後，決定在這邊定居，因為終於找到了一個喜歡的佈景主題。希望不要再搬了。

此部落格採用 [Hexo](http://hexo.io/) + [Minos theme](http://github.com/ppoffice/hexo-theme-minos) + GitHub Pages 架設而成。有改過 Minos 裡面的一些東西，例如說字體大小、文章列表以及分類頁面等等，改過的版本在這邊：[aszx87410/hexo-theme-minos](https://github.com/aszx87410/hexo-theme-minos)。

這邊是跟技術比較相關的文章，其他文章會放在我的[另一個部落格](https://life.huli.tw/)。

雖然說前面有提到「搬家」，但其實沒有把所有文章都搬過來，有稍微篩選過一下，舊的文章都還留在[Logdown](http://huli.logdown.com/)，因為早期的文章偏筆記類型，所以就沒有搬過來了。
