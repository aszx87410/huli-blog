---
title: 從歷史的角度探討多種 SSR（Server-side rendering）
date: 2023-11-27 15:40:00
catalog: true
tags: [Front-end]
categories: [Front-end]
photos: /img/server-side-rendering-ssr-and-isomorphic/cover.png
---

你知道嗎，當你跟朋友在討論 SSR 的時候，很有可能你們對 SSR 的認知其實是不一樣的。直接舉個例子，底下這幾種情境，你覺得哪些算是 SSR？

1. 由後端 PHP 產生畫面
2. 前端是 React 寫成的 SPA，但後端如果偵測到搜尋引擎，就會切換另一種 template，輸出專門針對搜尋引擎的模板，而非 React 渲染出的頁面
3. 前端是 React 寫成的 SPA，但透過 Prerender 先把頁面 render 成 HTML，再交給搜尋引擎（一般使用者依然是 SPA），跟上一個的差別是使用者跟搜尋引擎看到的畫面基本上一致
4. 前端是 React 寫成的 SPA，在後端用 `renderToString` 把 React 渲染成字串，但是沒有資料，資料會在前端拿
5. 前端是 React 寫成的 SPA，後端會針對每個 page 先呼叫 API 拿資料，拿完以後才呼叫 `renderToString` 輸出 HTML，在 client 端時會做 hydration 讓頁面可以互動

有一種人認為只要是由後端產生出畫面，就叫做 SSR，所以 1 ~ 5 全部都是 SSR。也有一種人認為前端必須先是 SPA，此時搭配的後端才能叫做 SSR，所以 2~5 都是 SSR；而另一種人則認為 SSR 的重點是 hydration，所以只有 5（或是 45）是 SSR。

<!-- more -->

下圖是我自己在推特簡單調查的結果，可以看見意見確實是有分歧的：

![推特調查結果](/img/server-side-rendering-ssr-and-isomorphic/p1.png)

## 為什麼會有這篇文章？

五年前的時候我就有寫過一篇文章在講 SPA 與 SSR：[跟著小明一起搞懂技術名詞：MVC、SPA 與 SSR](https://life.huli.tw/2018/05/04/introduction-mvc-spa-and-ssr-545c941669e9/)，那時候的我跟現在的我想法是一致的。

「現在的我」指的是還沒完全整理好想法，正在寫這段前言，底下都還沒寫好的我，等寫完以後會在結尾處再講「之後的我」的想法。但總之呢，現在的我的想法是，「並不是所有從 Server 產生出畫面的方式都『適合』稱作 SSR」。

先來看一個假想情境：

A：欸，你們公司網頁是用什麼方式 render 啊？
B：就 SSR 啊
A：是喔，那你們是用什麼框架處理 SSR？
B：就普通 PHP 而已，沒有用框架，前端就 jQuery

再看一個：

A：最近在解 SSR 的問題搞到好煩，資料好難弄
B：還好吧，我們用 PHP 都用得滿順利的啊

雖然說 server-side rendering 這個詞從字面上來看，就是指由 server 進行渲染，所以要說 PHP 是 SSR 從字面上看沒什麼問題，但我認為重點是「為什麼需要 SSR 這個詞」？

我的理解是在 SPA 還不流行的年代，根本沒什麼東西是 CSR（Client-side rendering），所以根本也不需要 SSR 這個詞。那時你只會說：「我們公司用 PHP」，而不是說：「我們公司用 PHP 做 SSR」。

有點像是我問我朋友他買的便當多少錢時，他會回我：「100 塊」，而不是「100 塊新台幣」，因為我們都預設了幣值是新台幣，所以不用特別多此一舉。同理，那時候只有從 server render 這條路，所以根本不需要特別提什麼 SSR。

但是後來 SPA 盛行，許多東西開始變成 CSR，此時就會碰到只有 CSR 才會碰到的問題如 SEO 等等，這時候為了解決這些問題，勢必有些東西要讓 server 去處理，在這種狀況下，Server-side rendering 這個詞才產生了新的意義，變成了「為了解決 CSR 的問題，產生的 server 端解決方案」

因此，將 PHP 稱之為 SSR 沒也不行，但卻是沒有意義的。

就像是如果我們把「飲料」定義為「可以喝的液體」，那你能不能說酸辣湯也是一種飲料？照定義來看沒有問題，但當有人問你「最喜歡喝的飲料是什麼？」的時候，你會說酸辣湯嗎？應該不會，而我們也不會把酸辣湯稱之為是飲料。

同理，雖然 SSR 字面上的意思是那樣，PHP 這種傳統 server 輸出內容的方案也可以稱之為 SSR，但你不會這樣叫它。SSR 更適合拿來指涉的是「用來解決 SPA 問題的 server 端解決方案」。

寫到這裡我就開始好奇了，那是不是在 SPA 與 CSR 流行以前，SSR 這個詞真的很少被使用？如果是的話，那到底從什麼時候開始的？還有，我對 SSR 的認識基本上是從 React 開始，那難道更早的框架如 Angular、Ember 或甚至是 backbone 等等，都沒有這問題嗎？如果有的話，他們的解決方案又稱之為什麼？

於是我開始了一段要花費很多時間，討論的問題或許也沒這麼重要，但我自己很樂在其中的探索之路。

## SPA 是從什麼時候開始流行的？

前面有提過我的主張是：「SSR 一詞在 SPA 盛行後開始跟著流行起來，專門指涉處理 CSR 與 SPA 問題的 server 端解決方案」

而我認為 SPA 的發展與整個網頁前端的發展其實滿有關聯的，因此先帶大家回顧一下歷史吧！

1995 年 JavaScript 正式推出，而當時雖然 JavaScript 的功能沒有這麼成熟，但已經有其他的技術可以在網頁上跑一個應用程式起來，就是 Java Applet。

而 Flash 在 1996 年發布，早期 JavaScript 還沒這麼強大時，要做比較完整的網頁應用程式，應該都是透過 Java Applet 或是 Flash。

那要到什麼時候，JavaScript 才成熟到真的可以獨當一面，用它來寫一個網頁應用程式呢？這個答案會跟技術的發展有關，作為一個需要跟後端溝通的網頁應用程式，最需要的是什麼？

是一個現在已經跟空氣和水一樣存在的東西：XMLHttpRequest。

想要不換頁就能獨立運作並且與 server 溝通，XMLHttpRequest 是必要條件，必須先有 XMLHttpRequest 這個 API，才能不換頁就能與 server 交換資料。

不過在最剛開始的時候，並不是所有的瀏覽器都用 XMLHttpRequest，最早有這個概念的微軟用的是 ActiveXObject，從 2006 年第一版的 jQuery [原始碼](https://github.com/jquery/jquery/blob/1.0/src/ajax/ajax.js#L61)就能驗證這件事：

``` js
// If IE is used, create a wrapper for the XMLHttpRequest object
if ( jQuery.browser.msie && typeof XMLHttpRequest == "undefined" )
  XMLHttpRequest = function(){
    return new ActiveXObject(
      navigator.userAgent.indexOf("MSIE 5") >= 0 ?
        "Microsoft.XMLHTTP" : "Msxml2.XMLHTTP"
      );
  };
```

講到了 XMLHttpRequest 之後，理所當然就會提到 Ajax，這個詞來自於 2005 年 2 月 18 日 Jesse James Garrett 發表的這篇文章：[Ajax: A New Approach to Web Applications](https://web.archive.org/web/20061107032631/http://www.adaptivepath.com/publications/essays/archives/000385.php)，裡面描述了一種使用 HTML + CSS + DOM + XMLHttpRequest 的新型溝通模式，我認為就是 SPA 的雛型了

![ajax](/img/server-side-rendering-ssr-and-isomorphic/p2.png)


（圖片來自於上面提到的文章）

另外，在文章裡也有提到 XMLHttpRequest 與 Ajax 的不同之處：

> Q. Is Ajax just another name for XMLHttpRequest?
> A. No. XMLHttpRequest is only part of the Ajax equation. XMLHttpRequest is the technical component that makes the asynchronous server communication possible; Ajax is our name for the overall approach described in the article, which relies not only on XMLHttpRequest, but on CSS, DOM, and other technologies.

從歷史的資料看起來，微軟的 Outlook 似乎是最早提起並運用這些技術的產品，從 2000 年就開始了，但論起大量運用並讓這個名詞廣為人知的話，就屬 2004 ~ 2005 年左右的 Google 了。


而差不多在這個時期，JavaScript 的生態系也迎來了蓬勃的發展，出現了一堆 library 如 Prototype、Dojo Toolkit 以及 MooTools 等等，還有 2006 年誕生的 YUI（Yahoo! User Interface Library）以及至今靈壓依然存在的 jQuery，都讓網頁前端得到了更進一步的發展，2007 年也出現了 Ext JS 這種專門拿來寫網頁應用的框架。

雖然說這些函式庫們都讓寫網頁變得更加容易，但 SPA 在這個時候還沒有流行起來，而是要等到兩位大前輩的誕生。

2010 年 10 月 13 日，Backbone.js 釋出了第一個版本，而一週後的 10 月 20 日，則是 AngularJS 首次發佈的日子。

而過了一年之後，別的 SPA 前端框架也出現了，分別是 2011 年 12 月 8 日發布的 Ember.js，以及 2012 年 1 月 20 出現的 Meteor.js。

一般來說一個新的框架出現以後，大概至少都要過個半年一年左右才會真正流行起來，因此我認為 2011 以及 2012 這兩年是 SPA 興起的開端，但是該用什麼資料來佐證呢？

關鍵字搜尋趨勢一定程度代表了當時某些技術名詞的流行程度，從下圖可以看出來，SPA 一詞大概是從 2011、2012 年左右開始一路攀升，與我的推測吻合（但這個數據其實不太精確就是了，可我一時想不到更好的了）：

![SPA 搜尋趨勢](/img/server-side-rendering-ssr-and-isomorphic/p3.png)

（至於 2004、2005 那個高峰是什麼，我不知道，但很想知道的。或許跟一堆 Google 服務的流行有關？有線索的可以私訊或是留言討論）

之後的故事大家就比較熟悉了，2013 年 5 月 React 正式發佈，2014 年 2 月則是 Vue，隨著前端框架的盛行，SPA 也變得越來越流行，到了今天甚至變成了前端開發的主流。

## 早期的 SPA 如何解決 CSR 的問題？

從上面的發展史中可以得知開創 SPA 盛世的元老就屬 Backbone.js 以及 AngularJS 了，那他們是怎麼解決 CSR 的問題，例如說 SEO？

先來看 AngularJS 好了，我在 GitHub 上找到一個 2013 年的專案：[angular-on-server](https://github.com/runvnc/angular-on-server/tree/b84bcea97037adaffc83cf4869fe9a008c7db3a8)，在 wiki 的前言中寫著：

> We need to pre-render pages on the server for Google to index. We don't want to have to repeat ourselves on the back end. I found a few examples of server-side rendering for Backbone applications, but none showing how to do it with AngularJS. To make this work I have modified a couple of Node modules, jsdom and xmlhttprequest. They are loaded from local subdirectories (/jsdom-with-xmlhttprequest and /xmlhttprequest).

如果他所言為真，就代表當時 AngularJS 的 SSR 解決方案並不多，大多數都是 Backbone.js 的。

從我找到的資料來看，似乎也是如此，像是這篇 2013 年的發問：[AngularJS - server-side rendering](https://stackoverflow.com/questions/16232631/angularjs-server-side-rendering)，從回答中就可以看出解法確實不多。

而 AngularJS 官方正式支援 SSR，是要一直到 2015 年 6 月底的這個演講：[Angular 2 Server Rendering](https://www.youtube.com/watch?v=0wvZ7gakqV4)，在演講結束後幾天後開源了 [Universal Angular 2](https://github.com/angular/universal/tree/e5b088ef4a59e59461fee31a21c2a81b742a7df5)，也就是現在的 Angular Universal 的前身。

在當時的 README 中，說明寫著：

> Universal (isomorphic) JavaScript support for Angular 2

看到 isomorphic 這個詞，應該勾起了不少人當年的回憶，但這個我們等等再談，先來看 Backbone.js 又是怎麼解決 SPA 問題的。

我有在 GitHub 上面找到一個 2011 年的古老範例：[Backbone-With-Server-Side-Rendering](https://github.com/runemadsen/Backbone-With-Server-Side-Rendering)，README 寫著：

> Backbone.js is a great tool for organizing your javascript code into models, collections and views, without tying your data to the DOM elements. However, most tutorials show how to render the HTML only via Backbone (client-side), which means that none of your content is crawled by search engines. This is possibly a major problem if you're not making an app hidden behind an authentication system.

比較特別的地方在於這個專案的 SSR 是透過 Ruby on Rails 實作的，但我看了一下原始碼，感覺比較像一個實驗性質的專案，透過後端把HTML 輸出，接著到了前端再由 Backbone.js 接手，是一個簡單的小範例，而非完整的 demo。

如果想要更完整的解決方案，就屬 2013 年由 Airbnb 開源出來的 [Rendr](https://github.com/rendrjs/rendr) 了。

在 2013 年 1 月 30 日，Airbnb 的技術部落格發表了一篇新的文章：[Our First Node.js App: Backbone on the Client and Server](https://web.archive.org/web/20130711035708/http://nerds.airbnb.com/weve-launched-our-first-nodejs-app-to-product/)，裡面講到了 SPA 會有的問題，以及有許多邏輯在前後端都各有一份，想要做整合。而最後的解法就是 Rendr 這個套件，能把 Backbone.js 搬到 server 去執行。

至於 Rendr 的開源則是過了三個月以後的這篇文章宣布的：[We’ve open sourced Rendr: Run your Backbone.js apps in the browser and Node.js](https://web.archive.org/web/20130623194723/http://nerds.airbnb.com/weve-open-sourced-rendr-run-your-backbonejs-a/)，裡面寫說：

> Many developers shared the same pain points with the traditional client-side MVC approach: poor pageload performance, lack of SEO, duplication of application logic, and context switching between languages. 

可見當時有大量的開發者也都意識到了 SPA 的問題，並且想要一個比較完善的解決方案。

想要把 Backbone.js 搬到 server 去執行，有個先決條件，那就是 server 要可以執行 JavaScript。

Node.js 是在 2009 年釋出的，而 Express 是在 2010 年底，NPM 則是 2011 年。2012 年中的時候 Node.js 還在 [v0.8.0](https://nodejs.org/en/blog/release/v0.8.0/)，是很早期的階段。從現在回頭看，Node.js 開始被大量使用，應該就差不多是 2012 ~ 2013 開始的。

總之呢，從我找到的資料來看，或許最早被廣泛運用於 SSR 的 library 就是 2013 推出的 Rendr 了，它能夠做到的事情是「在一開始由 server-side render，但是到了 client-side 以後由 JavaScript 接手」，如同 Airbnb 的文章中寫到的：

> Your great new product can run on both sides of the wire, serving up real HTML on first pageload, but then kicking off a client-side JavaScript app.  In other words, the Holy Grail.

底下這張圖就是所謂的 Holy Grail，取自 Airbnb 當初發表的文章：

![holy grail](/img/server-side-rendering-ssr-and-isomorphic/p4.png)

寫到這邊，整理一下時間軸以及我個人的猜測。

從 2010 年底 Backbone.js 釋出以後，SPA 開始變得逐漸流行起來，而大家也意識到了畫面在前端渲染會碰到的問題，因此開始各自實作起不同的解決方案，也就是 server-side rendering。

而 Backbone.js 一直到了 2013 年 Airbnb 開源了 Rendr 以後，才終於有了一個最理想的解法，那就是「首次渲染在 server side，而之後的話渲染都在 client side，並且 client 跟 server 是共用同一套程式碼」

「同一行程式碼既可以跑在 client 又可以跑在 server」，這個概念就是前面所提到的 isomorphic。

順帶一提，Ember.js 官方的 SSR 解法應該是要到 2014 年底的這篇：[Inside FastBoot: The Road to Server-Side Rendering](https://blog.emberjs.com/inside-fastboot-the-road-to-server-side-rendering/)

再補充一件事情，根據 [The History of React.js on a Timeline](https://blog.risingstack.com/the-history-of-react-js-on-a-timeline/) 這篇文章，[FaxJS](https://github.com/jordwalke/FaxJs/tree/5962e3a7268fc4fe0251631ec9d874f0c0f52b66) 是 React 的前身，而在 2011 年底開源的時候就有 server-side rendering 的 API，可以把元件渲染成 static HTML，並且在 client-side 把事件裝回去：https://github.com/jordwalke/FaxJs/tree/5962e3a7268fc4fe0251631ec9d874f0c0f52b66#optional-server-side-rendering

## Isomorphic JavaScript

Isomorphic JavaScript 一詞來自於 Charlie Robbins 在 2011 年 10 月 18 日發表的文章：[Scaling Isomorphic Javascript Code](https://web.archive.org/web/20170703210112/https://blog.nodejitsu.com/scaling-isomorphic-javascript-code/)

文章中有提到了 Isomorphic 的定義：

> Javascript is now an isomorphic language. By isomorphic we mean that any given line of code (with notable exceptions) can execute both on the client and the server.

而更多細節可以在 Airbnb 於 2013 年 11 月 12 日發布的這篇文章中找到：[Isomorphic JavaScript: The Future of Web Apps](https://medium.com/airbnb-engineering/isomorphic-javascript-the-future-of-web-apps-10882b7a2ebc)

在文章裡面還有附上了一個實際案例，很值得參考：[isomorphic-tutorial](https://github.com/spikebrehm/isomorphic-tutorial/tree/b54098ba61f4e766fee8c660e3d074c5eca07dfa)。

除此之外，文章裡面有提到在 Rendr 之前還有三個 Isomorphic JavaScript 的先行者，一個是 2012 年 Yahoo! 開源的 [Mojito](https://web.archive.org/web/20130722082828/https://developer.yahoo.com/blogs/ydn/yahoo-mojito-now-open-source-52490.html)，在文章中提到了一個美好的想像：

>  Imagine a framework where the first page-load was always rendered server-side, and desktop browsers subsequently just made calls to API endpoints returning JSON or XML, and the client only rendered the changed portions of the page.

基本上就是現在主流前端的運作方式。

另一個則是 Meteor.js，第三個是 Asana 的 [Luna](https://web.archive.org/web/20110211193136/https://asana.com/luna)，這個 Luna 挺有趣的，仔細看之後發現語法有點 React 的味道。

而 Isomorphic 這個詞一直到 2015 年 Michael Jackson 的這篇文章出來以後，才漸漸被「Universal」給取代：[Universal JavaScript](https://medium.com/@mjackson/universal-javascript-4761051b7ae9)。

這篇文章主要覺得比起 Isomorphic 這個詞，Universal 更能表達原本想表達的意涵，而且聽眾們會更容易理解，因此提倡用 Universal JavaScript 來替代 Isomorphic JavaScript。

## 中場總結

寫到這裡，我自己回答了我之前的幾個疑問：

> Q: 那是不是在 SPA 與 CSR 流行以前，SSR 這個詞真的很少被使用？如果是的話，那到底從什麼時候開始的？

不確定，因為沒有特別找更早以前的資料佐證，但如果是看 SSR 這個詞的搜尋趨勢的話，大概是從 2012~2013 左右開始起飛的，跟 SPA 開始流行的時間點差不多。

![SSR 搜尋趨勢](/img/server-side-rendering-ssr-and-isomorphic/p5.png)

> Q: 我對 SSR 的認識基本上是從 React 開始，那難道更早的框架如 Angular、Ember 或甚至是 backbone 等等，都沒有這問題嗎？如果有的話，他們的解決方案又稱之為什麼？

他們有相同的問題，而解法一樣稱之為 SSR。

說實在的，討論 SSR 這個名詞的明確定義確實沒什麼太大意義，反倒有點太鑽牛角尖了，而且也很難有個結論，或是說服別人：「這個定義才是對的」，只要在溝通的時候確保雙方的認知一致即可。

在談到 SSR 的時候，很多人都只關注到 SEO 的問題，但如果再更仔細想一點，其實需要利用 SSR 解決的，可不只有 SEO。

## SSR 想解決的問題

SSR 想解決的問題，就是 CSR 會造成的問題，包括：

1. SEO
2. 各種社群平台的 link preview
3. Performance
4. 使用者體驗

如果用了 CSR，由於畫面都是透過 JavaScript 所產生，搜尋引擎只會爬到空白的 HTML，就算 Google 會執行 JavaScript，其他搜尋引擎也不一定會。就算所有搜尋引擎都會執行 JavaScript，你也很難保證爬出來的結果是你要的。

舉例來說，你很難掌握它們執行完 JavaScript 以後，到底什麼時候會結束。如果抓取資料的 API 要兩秒以後才會有 response，那假設搜尋引擎執行 JavaScript 以後只等一秒就當作最終結果，那結果還是不會有資料。

社群平台的 link preview 則是另一個問題，那些 `<meta>` 標籤在 client 產生是沒有用的，通常這些社群平台的 bot 是不會去執行 JavaScript 的，只看 response，所以 CSR 的頁面的 `<meta>` 永遠只能是同一個，沒辦法根據不同頁面動態決定內容。

第三點跟第四點可以一起看，雖然現在的裝置基本上都跑得很快，能夠快速執行 JavaScript，但不排除在 JavaScript 很大一包而且裝置比較舊的情況之下，執行 JavaScript 還是需要一段時間。

CSR 的網頁要到什麼時候使用者才能看到畫面？要先下載完 JavaScript，下載完還要執行，執行結束更新 DOM 以後，使用者才能看到完整的畫面。在等待的期間，畫面就是一片空白，雖然有些網站會做個 loading，但總之使用者體驗不是很好。

如果能在一開始的 response 就拿到畫面，那使用者體驗就會變好，效能也會增加，就算是很舊的裝置，也能在一開始就看到畫面，不需要等 JavaScript 執行完畢。

## 各種不同的 SSR

其實這篇一開始只想寫這個段落的，殊不知寫著寫著就變成了前端歷史的考古文。

因應剛剛提到的 CSR 會產生的問題，就產生出了多種解法，每一種都不太一樣，而且並不一定能一次解決所有的問題。

### 第一種：針對搜尋引擎以及 bot 渲染另一個模板

這種解法只解了 SEO 跟 link preview 的問題，當 server 端收到的請求來自於搜尋引擎或是社群平台的 bot 時，就直接利用原本後端的 template 輸出結果。

像是這樣：

``` js
const express = require('express');
const app = express();

app.get('/games/:id', (req, res) => {
  const userAgent = req.headers['user-agent'];
  
  // 檢查 User Agent 是否為 Googlebot
  if (userAgent.includes('Googlebot')) {
    // 如果是 Googlebot，輸出 SEO 相關的 HTML 與 meta tags
    const game = API.getGame(req.params.id);
    res.send(`
      <html>
        <head>
          <title>${game.title}</title>
          <meta name="description" content="${game.desc}">
        </head>
          <body>
            <h1>${game.title}</h1>
            <p>${game.desc}</p>
          </body>
        </html>
    `);
  } else {
    // 如果不是 Googlebot，回傳 index.html
    res.sendFile(__dirname + '/public/index.html');
  }
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```

對於一般使用者來說，效能跟使用者體驗的問題還是沒有解決，這種解法只解了 SEO 跟 link preview，確保這些 bot 抓到的畫面是 HTML。

我自己有在工作上實作過這種方式，優點就是簡單快速，而且跟 SPA 互不干擾，缺點大概就是 Google bot 看到的頁面會跟使用者看到的不一樣，有可能影響到 SEO 分數，畢竟針對 Google bot 輸出特殊頁面是 anti-pattern，叫做 cloaking。

雖然我們的出發點是好的，但仍然是不被官方建議的行為，可以參考 Google 官方的影片：[Can we serve Googlebot a different page with no ads?](https://www.youtube.com/watch?v=wBO-1ETf_dY&ab_channel=GoogleSearchCentral)，裡面就提到了最好是 exact same page。

但比起讓 Google bot 什麼都看不到，這個解法應該還是更好一些。

### 第二種：同樣是針對搜尋引擎，但是做 pre-render

這個解法最知名的框架是 [Prerender](https://github.com/prerender/prerender)，簡單來講就是先在 server 端用 puppeteer 之類的 headless browser 去開啟你的頁面並且執行 JavaScript，然後把結果保存成 HTML。

當搜尋引擎來要資料的時候，就輸出這個 HTML，因此使用者跟 bot 看到的畫面是一樣的。

我有在 local 試了一下，用 create-react-app 簡單寫了一個頁面：

``` js
import logo from './logo.svg';
import './App.css';
import { useState, useEffect } from 'react'

function App() {
  console.log('render')
  const [data, setData] = useState([]);

  useEffect(() => {
    document.querySelector('title').textContent = 'I am new title' 
    fetch('https://cat-fact.herokuapp.com/facts/').then(res => res.json())
      .then(a => {
        setData(a);
      })
  }, [])

  function test() {
    alert('click')
  }
  
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        {data && data.map(item => (
          <div>{item.text}</div>
        ))}
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
          Can you see me now?
        </a>
        <button onClick={test}>hello</button>
      </header>
    </div>
  );
}

export default App;
```

主要想測的有幾點：

1. 頁面是不是依然可以互動
2. 動態修改的 title 是否會反映在結果
3. 是不是會輸出拿到 API response 後的結果

經過 prerender 以後，輸出的 HTML 為：

``` html

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <link rel="icon" href="http://localhost:5555/favicon.ico">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#000000">
    <meta name="description" content="Web site created using create-react-app">
    <link rel="apple-touch-icon" href="http://localhost:5555/logo192.png">
    <link rel="manifest" href="http://localhost:5555/manifest.json">
    <title>I am new title</title>
    <script defer="defer" src="http://localhost:5555/static/js/main.21981749.js"></script>
    <link href="http://localhost:5555/static/css/main.f855e6bc.css" rel="stylesheet">
  </head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root">
      <div class="App">
        <header class="App-header">
          <img src="/static/media/logo.6ce24c58023cc2f8fd88fe9d219db6c6.svg" class="App-logo" alt="logo">
          <div>When asked if her husband had any hobbies, Mary Todd Lincoln is said to have replied "cats."</div>
          <div>Cats make about 100 different sounds. Dogs make only about 10.</div>
          <div>Owning a cat can reduce the risk of stroke and heart attack by a third.</div>
          <div>Most cats are lactose intolerant, and milk can cause painful stomach cramps and diarrhea. It's best to forego the milk and just give your cat the standard: clean, cool drinking water.</div>
          <div>It was illegal to slay cats in ancient Egypt, in large part because they provided the great service of controlling the rat population.</div>
          <a class="App-link" href="https://reactjs.org" target="_blank" rel="noopener noreferrer">Learn React Can you see me now?</a>
          <button>hello</button>
        </header>
      </div>
    </div>
  </body>
</html>
```

title 有變了，內容也是 `useEffect()` 的 `fetch` 執行完並且 render 完的結果，按了按鈕以後也可以觸發事件，看起來沒什麼問題。

如果更仔細看一下，prerender 渲染出來的頁面執行流程跟正常 React app 差不多，唯一的差別在於原本的 HTML 就已經有東西了，但整個 React 還是會執行一次，並且將整個頁面重新渲染。

因此會出現底下狀況：

1. 拿到 server response，是完整並且有資料的頁面
2. React 啟動，進行初次渲染，此時 data 變成初始化狀態，頁面變成沒資料的狀態
3. React 將結果 mount 到 DOM，觸發 useEffect，再打一次 API 拿資料
4. 狀態更新，渲染出有資料的頁面

這個解法依然是只針對搜尋引擎，跟第一種的差別在於使用者跟搜尋引擎看到的頁面會更相近，但其實還是不太一樣，畢竟一般使用者看到的還是什麼都沒有的頁面。

那可以把 pre-render 的頁面也拿給一般使用者看嗎？

是可以，但如果有 API 的話會變得有點奇怪，如上所述，初始狀態 state 是沒有資料的，但是 HTML 有，因此使用者看到的頁面就會是：有資料（因為 pre-render HTML） => 沒資料（state 初始化） => 有資料（在 client 打 API），在體驗上會不太好，所以通常也不會這樣做。

這個解法的優點也是方便，不需要改到原本的 SPA，只需要在 server 那邊加一個 middleware 即可，而缺點的話則是實作起來比第一種複雜，而且有滿多細節要注意的，可以參考：[Funliday 重磅推出新的 prerender 套件 pppr](https://techblog.funliday.com/2020/05/25/Funliday-%E9%87%8D%E7%A3%85%E6%8E%A8%E5%87%BA%E6%96%B0%E7%9A%84-prerender-%E5%A5%97%E4%BB%B6-pppr/) 以及 [在 ModernWeb 2020 分享的「pppr - 解決 JavaScript 無法被搜尋引擎正確索引的問題」](https://techblog.funliday.com/2020/10/14/%E5%9C%A8-ModernWeb-2020-%E5%88%86%E4%BA%AB%E7%9A%84%E3%80%8Cpppr-%E8%A7%A3%E6%B1%BA-JavaScript-%E7%84%A1%E6%B3%95%E8%A2%AB%E6%90%9C%E5%B0%8B%E5%BC%95%E6%93%8E%E6%AD%A3%E7%A2%BA%E7%B4%A2%E5%BC%95%E7%9A%84%E5%95%8F%E9%A1%8C%E3%80%8D/)。

### 第三種：在 server render client app

這一種就是前面一直提到的：「在 server 產生第一個畫面的 HTML，而後續的操作都交給 client」，相較於前兩者，這是更理想的 SSR，也是俗稱的 Isomorphic/Universal。

因為這種的做法不只解決了 SEO 的問題，也解決了使用者體驗的問題。當使用者造訪網站時，就可以立刻看到渲染完的結果，但此時畫面因為 JavaScript 沒有執行完，可能沒有辦法操作，需要等 JavaScript 執行完畢並且把 event handler 掛上時，才能真的跟頁面互動。

另外，由於初始畫面已經在 server 渲染好了，所以在 client 端通常不需要再修改一次 DOM，只需要把 event handler 掛上去，這個流程稱為 hydration，中文通常翻作「水合」。

我覺得這個詞用得相當有畫面感，就把它想成是 SSR 輸出的頁面是被「脫水」過的，非常扁平乾燥，就只有畫面而已，沒辦法跟它互動。到了 client 以後，就需要把這個乾燥的畫面注入水，加上 event handler，讓整個頁面「活起來」，才能重現生機，變成可互動的頁面。

然而，這種解法的缺點就是實作起來更複雜一點，需要考慮到的問題是 API，例如說如果把 API call 放在 `useEffect` 裡面，那在 server render 時就不可能執行到，最後渲染出來的頁面就是沒有任何資料的狀態。

因此，可能要幫每個頁面都加上一個 function 去拿取資料，拿完之後放到 props 去，在 server side render 時才能正確輸出有資料的頁面。

也因為這個比較複雜，所以通常都交給框架來做了，像是 Next.js 就是採用我前面講的做法（Pages Router），會在頁面加上一個 `getServerSideProps` 的 function。

順帶一提，Next.js 的第一版是 2016 年 10 月 25 釋出的。

### 第四種：在 build time 就做 render

這算是針對產品情境特化的 SSR，剛剛講的第三種，是在每一個 request 都會做一次 render，產生出初始畫面。但如果你的頁面對於每一個 user 來說都長一樣（例如說官方網站的公司介紹），那其實根本不用在 run time 做這件事，在 build time 就好了。

於是，有一種做法是在 build time 的時候就會把頁面 render 好，速度會快上許多。

這種方法在 Next.js 裡面被稱之為 Static Site Generation，簡稱為 SSG。

## 該怎麼命名各種不同的 SSR？

整理一下剛剛講的四種：

1. 針對搜尋引擎以及 bot 渲染另一個模板
2. 同樣是針對搜尋引擎，但是做 pre-render
3. 在 server render client app
4. 在 build time 就做 render

不同的文件對於這幾種的稱呼都不同，接著來看幾份文件。

### web.dev

第一份是 web.dev 的：[Rendering on the Web](https://web.dev/articles/rendering-on-the-web)，在文末有一個光譜：

![SSR 光譜](/img/server-side-rendering-ssr-and-isomorphic/p6.png)

第一種沒特別提到，第二種比較像是「CSR with Prerendering」，但又好像不太像，第三種是：「SSR with (Re)hydration」，第四種是：「Static SSR」。

這篇對於 SSR 的定義為：

> Server-side rendering (SSR): rendering a client-side or universal app to HTML on the server.

所以像是第一種並沒有在 server 端去 render client-side app，應該也不會被算作 SSR。

### Next.js

第二份是 Next.js 官方的文件：https://nextjs.org/docs/pages/building-your-application/rendering

有提到的就是第三種叫做 SSR，第四種叫做 SSG。而這邊的定義其實又更不同了一點，它把「在 server 端產生 SPA 的 HTML」這件事情叫做 pre-render：

> By default, Next.js pre-renders every page. This means that Next.js generates HTML for each page in advance, instead of having it all done by client-side JavaScript. Pre-rendering can result in better performance and SEO.

而 SSR 專門指的是「每次 request 都產生 HTML」，藉此跟 SSG 做出區別。

### Nuxt.js

第三份來看 Nuxt.js：https://nuxt.com/docs/guide/concepts/rendering

文件裡面把第三種稱之為：「Universal Rendering」，其實我覺得取得還滿不錯的：

> To not lose the benefits of the client-side rendering method, such as dynamic interfaces and pages transitions, the Client (browser) loads the JavaScript code that runs on the Server in the background once the HTML document has been downloaded. The browser interprets it again (hence Universal rendering) and Vue.js takes control of the document and enables interactivity.


至於對 SSR 的定義，似乎沒有寫得太明確，不過從底下這句看起來：

> This step is similar to traditional server-side rendering performed by PHP or Ruby applications.

應該是「只要在 server render 畫面」都可以叫做 SSR。

### Angular

最後來看 Angular 的：https://angular.io/guide/ssr

它對 SSR 的定義為：

> Server-side rendering (SSR) is a process that involves rendering pages on the server, resulting in initial HTML content which contains initial page state.

這定義看起來應該跟剛那種差不多，只要是「rendering pages on the server」都可以稱之為 SSR。

## SSR 的總結

來講一下我寫到這邊以後，對於 SSR 的一些想法。

老實說我一開始好像有點把問題搞得太複雜了，SSR 就單純是指「在 server render 畫面」這件事情而已，所以確實只要符合這個前提就可以叫做 SSR。

其實這篇原本想寫的只有剛剛講的那幾種不同的 SSR 解決方案，但還沒寫之前就突然好奇起了 SSR 的定義，才有了開頭那些探索歷史的段落。

更重要的應該是對於 SSR 這個議題，是否能回答出要解決的問題是什麼，該怎麼解決，以及每種解法的優缺點等等，並不是每個網頁都需要 Next.js 才能做 SSR，要根據情境去選擇合適的技術。

接著，我們來談談現在進行式以及未來。

## 榨取更多的效能，打造更快的網頁

原本我們提到的第三種解法看起來已經很完美了對吧？既可以在 server 端渲染畫面，解決 SEO 以及 first paint 的效能問題，又可以在 client 端做 hydration，讓後續操作都有 SPA 的體驗。

但其實還有能夠持續改善的地方。

前面有稍微提到 hydration 的一個小問題，那就是在 hydration 完成以前，雖然看到畫面了，但是這個網頁是沒辦法互動的。例如說你在 input 打字，可能不會有反應，因為那時候 event handler 還沒掛上去，或是 component 還沒 render 完。

那這該怎麼辦呢？有另外一個名詞出現了，叫做：[Progressive Hydration](https://www.patterns.dev/react/progressive-hydration)，比起一次 hydration 整個頁面，不如一個一個區塊來做，還可以分優先順序，先把比較重要的區塊做完，使用者就可以馬上互動，再來做比較沒這麼重要的區塊。

除此之外，你會發現一個網頁的某幾個區塊，可能根本就不需要做 hydration，因為是不會變的，像是 footer 好了，根本沒有狀態，從頭到尾都長一樣。此時就可以運用另一種技巧叫做 [Selective Hydration](https://www.patterns.dev/react/react-selective-hydration)，提前 render 不需要 hydration 的區塊。

2019 年時，Etsy 的前端架構師 Katie Sylor-Miller 提出了 [Islands Architecture](https://jasonformat.com/islands-architecture/)，將一個網頁看作是由不同的小島組成：

![Islands Architecture](/img/server-side-rendering-ssr-and-isomorphic/p7.png)

上面這張圖就很能體現剛剛講的 selective hydration。當我們採用這樣的架構並且搭配 selective hydration 以及其他技巧之後，就能夠更快速地渲染，並且得到更好的效能。

例如說 [Astro](https://docs.astro.build/en/concepts/islands/) 就是使用了這樣的架構，整個頁面都是 static 的，只有需要互動的地方會獨立成為一個小島：

``` jsx
<MyReactComponent client:load />
```

React 目前也往這個方向在發展，server component 在這點上就滿類似的，藉由把頁面區分成 server 跟 client component，決定哪些需要狀態哪些不需要，不需要的就直接在 server render 完再送來 client，需要的就維持以前的作法。

這種方式確實會再讓網頁往上加速，但同時開發也變得越來越複雜，有更多東西需要考慮，debug 也更不方便了一些，一些心得跟細節我之後再寫篇文章分享吧。

## 總結

我自己真正接觸各種前端工具的時間其實比較晚一點，撇除最開始寫 FrontPage 或是 Dreamweaver 那種不談，大概 2012 年左右開始寫 jQuery，接著就是觀望各種前端的發展但都沒有碰過，有曾經想學過 AngularJS（那時候真的很夯）還有 Ember.js，但就是懶。

是一直到 2015 年才開始在工作上接觸到 React，那時候是 React 剛在台灣要流行起來的時候。

所以早期 Backbone.js 那個年代的東西我沒有參與到，在寫這篇文章的時候找了不少資料，其實還滿有趣的，算是幫自己補足了沒有參與到的那一段歷史。

在查資料的時候，也發現 Yahoo! 真的是網頁前端的先行者，例如說 [Atomic CSS](https://blog.huli.tw/2022/05/23/atomic-css-and-tailwind-css/) 就是 Yahoo! 開始的，而這次也發現 2012 年時 Yahoo! 就已經在使用 Universal JavaScript 的網頁框架了。

如果你對 SSR 有不同的見解，或是覺得我對歷史發展脈絡的詮釋有點誤會，可以直接寫一篇新的文章與我交流，畢竟有些概念不是三言兩語可以講清楚的，寫篇文章比較完整；或是也可以透過留言討論。

## 參考資料

1. [AJAX](https://zh.wikipedia.org/zh-tw/AJAX)
2. [A Fond Farewell to YUI](https://www.sencha.com/blog/a-fond-farewell-to-yui/)
3. [XMLHttpRequest](https://zh.wikipedia.org/zh-tw/XMLHttpRequest)
4. [Isomorphic](https://en.wikipedia.org/wiki/Isomorphic_JavaScript)
5. [The Future (and the Past) of the Web is Server Side Rendering](https://deno.com/blog/the-future-and-past-is-server-side-rendering)
6. [Rendering on the Web: Performance Implications of Application Architecture (Google I/O ’19)](https://www.youtube.com/watch?v=k-A2VfuUROg&ab_channel=ChromeforDevelopers)


