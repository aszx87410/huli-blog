---
title: 利用 Cookie 特性進行的 DoS 攻擊：Cookie 炸彈
catalog: true
date: 2021-07-10 08:51:38
tags: [Security]
categories: [Security]
---

## 前言

在網站相關的攻擊手法上，大家比較常看見的應該是 XSS、SQL injection 或是 CSRF 這些方法，而今天要介紹的是另外一種大家可能聽過但沒有這麼熟悉的：DoS，Denial-of-Service 攻擊。

講到 DoS，多數人可能都會想到是不是要送很多封包給網站，然後讓網站伺服器來不及回應或是資源耗盡才能達成目標。或也可能想到的是 DDoS（Distributed Denial-of-Service），不是一台主機而是一堆主機同時送封包給某個伺服器，然後把它打掛。

DoS 與 DDoS 其實有分不同層的攻擊，這些層對應到大家以前可能學過的 OSI Model，例如說大家記憶中的攻擊比較像是 L3 網路層與 L4 傳輸層的攻擊，詳細的攻擊手法可以參考：[什麼是 DDoS 攻擊？](https://aws.amazon.com/tw/shield/ddos-attack-protection/) 以及 [How do layer 3 DDoS attacks work? | L3 DDoS](https://www.cloudflare.com/zh-tw/learning/ddos/layer-3-ddos-attacks/)。

但這篇想跟大家分享的攻擊手法，是存在於 L7 應用層的 DoS 攻擊。

例如說某個網站有個 API 可以查詢資料，然後有設一個預設的 limit 是 100，結果我把它改成 10000 之後發現 server 大概要一分多鐘才能給我 response，於是我就每兩秒送一個 request，送著送著就發現網站越變越慢，最後整個掛掉只能回 500 Internal Server Error，這就是應用層的 DoS 攻擊。

只要能找到一個方法讓使用者無法存取網站，就是一種 DoS 的攻擊。而我們找出的方法是建立於 L7 應用層，所以是 L7 的 DoS 攻擊。

在眾多 L7 DoS 攻擊手法中有一種我覺得特別有趣，那就是 Cookie Bomb，直翻就叫做 Cookie 炸彈。

<!-- more -->

## 什麼是 Cookie？

如果對 cookie 毫無概念的話，可以參考這篇：[白話 Session 與 Cookie：從經營雜貨店開始](https://hulitw.medium.com/session-and-cookie-15e47ed838bc)。

簡單來說呢，一些網站可能會把某些資料存在瀏覽器裡面，而這些資料就稱之為 cookie。當瀏覽器對網站發送 request 的時候，會自動把之前儲存的 cookie 一併帶上去。

最常見的應用之一就是廣告追蹤，例如說我造訪 A 網站，然後 A 網站裡面有 GA（Google Analytics）的 script，因此 GA 寫了一個 id=abc 的 cookie。當使用者造訪 B 網站而且 B 網站也有裝 GA，此時瀏覽器送 request 給 GA 的時候，就會把這個 id=abc 帶上去，那 server 收到以後就會知道「又是這個人，他造訪了 A 網站跟 B 網站」，隨著使用者造訪的網站變多，就會更清楚知道他的喜好。

（附註：實際上的追蹤應該會更複雜，而且最近又有第三方 cookie 的問題，所以實作可能會不太一樣，這邊只是簡單舉例）

在寫入 cookie 的時候，有一個 domain 的選項可以設置，你只能往上寫不能往下寫。什麼意思呢，假設你在 `abc.com`，你就只能寫 cookie 到 `abc.com`。但如果你在 `a.b.abc.com`，你可以寫入 `a.b.abc.com`，也可以寫入 `b.abc.com`，就連 `abc.com` 也可以。

所以你在 subdomain `a.b.abc.com` 對 root domain `abc.com` 寫入 cookie 之後，瀏覽器送去 `abc.com` 的 request 就會帶上你寫入的 cookie。

## 那 Cookie bomb 又是什麼？

假設我的攻擊目標是 `example.com`，那我只要找到任何 subdomain 或是網站中的某個頁面可以讓我寫 cookie 的話，我就可以自由自在地寫入我想要的 cookie。

舉例來說，假設有個頁面`https://example.com/log?uid=abc`，造訪這個頁面之後，就會把 `uid=abc` 這一段寫到 cookie，那我只要把網址改成 `?uid=xxxxxxxxxx`，就可以把 `xxxxxxxxxx` 寫到 cookie 裡。

再舉個例子，假設有個部落格網站，每一個使用者都有一個獨特的 subdomain，例如說我的話就是 `huliblog.example.com`，然後部落格可以客製化自己想要的 JS，那我就可以利用 JS 在 `huliblog.example.com` 對 `examepl.com` 寫入我想要的 cookie。

好了，那可以寫入任意 cookie 之後能幹嘛呢？

開始寫一堆垃圾 cookie 進去。

例如說 `a1=o....*4000` 之類的，就是寫一堆無意義的內容進去就好，這邊要特別注意的是一個 cookie 能寫的大小大概是 4kb，而我們最少需要兩個 cookie，也就是要能寫入 8kb 的資料，才能達成攻擊。

當你寫了這些 cookie 進去之後，回到主頁 `https://example.com` 時，根據 cookie 的特性，就會一起把這些垃圾 cookie 帶上去給 server 對吧？接下來就是見證奇蹟的時刻。

Server 並沒有顯示你平常會看到的頁面，而是回給你一個錯誤：`431 Request Header Fields Too Large`。

![](/img/cookie-bomb/p1.png)

在眾多 HTTP status code 裡面，有兩個 code 都跟 request 太大有關：

1. [413 Payload Too Large](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/413)
2. [431 Request Header Fields Too Large](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/431)

假設有個表單，你填了一百萬個字送到 server 去，就很可能會收到一個 `413 Payload Too Large` 的回應，就如同錯誤訊息所說的，payload 太大了，伺服器無法處理。

而 header 也是一樣的，當你的 cookie 太多時，requset header 中的 `Cookie` 會很大，大到伺服器無法處理，就會回一個 `431 Request Header Fields Too Large`（不過根據實測，有些 server 可能會根據實作不同回覆不同的 code，像微軟就是回 400 bad request）。

因此我們只要能把使用者的 cookie 塞爆，就能讓他看到這個錯誤畫面，沒有辦法正常存取服務，這就是 cookie bomb，藉由一大堆 cookie 所引發的 DoS 攻擊。而背後的原理就是「瀏覽器造訪網頁時，會自動把相對應的 cookie 一起帶上去」。

Cookie bomb 這名詞最早的起源應該是 2014 年 1 月 18 日由 Egor Homakov 所發表的 [Cookie Bomb or let's break the Internet.](http://homakov.blogspot.com/2014/01/cookie-bomb-or-lets-break-internet.html)，但類似的攻擊手法在 2009 年就有出現過：[How to use Google Analytics to DoS a client from some website](http://sirdarckcat.blogspot.com/2009/04/how-to-use-google-analytics-to-dos.html)

## 攻擊流程

如同上面那段所說，假設我們現在發現一個網址 `https://example.com/log?uid=abc` 可以讓我們設置任意 cookie，接下來要做的事情就是：

1. 把網址改一下，讓 cookie 變很大，想辦法讓大小超過 8kb（因為似乎比較多 server 的限制都是 8kb）
2. 把這個網址傳給攻擊目標，並想辦法讓他點開
3. 目標點了網址，在瀏覽器上面設了一個很大的 cookie
4. 目標造訪網站 `https://example.com`，發現看不到內容，只能看到一片白或是錯誤訊息，攻擊成功

這時候除非使用者換個瀏覽器或是 cookie 過期，又或者是自己去把 cookie 清掉，否則一直都會是這個狀態。

綜合以上所述，這個攻擊只能攻擊特定使用者，而且必須滿足兩個前提：

1. 找到一個地方可以設置任意 cookie
2. 目標必須點擊步驟一所找到的網址

有關於實際的攻擊案例，可以參考：

1. [Overflow Trilogy](https://blog.innerht.ml/overflow-trilogy/)
2. [#777984 Denial of Service with Cookie Bomb](https://hackerone.com/reports/777984)
3. [#57356 DOM based cookie bomb](https://hackerone.com/reports/57356)
4. [#847493 Cookie Bombing cause DOS - businesses.uber.com](https://hackerone.com/reports/847493)
5. [#105363 [livechat.shopify.com] Cookie bomb at customer chats](https://hackerone.com/reports/105363)

再繼續針對攻擊面往下講以前，先來提一下防禦方式。

## 防禦方式

第一點就是不要相信使用者的輸入，例如說上面提到的那個例子：`https://example.com/log?uid=abc`，不該把 `abc` 直接寫進 cookie 裡面，而是應該做個基本檢查，例如說格式或是長度之類的，就可以避免掉這類型的攻擊。

再來的話，當我提到可以從 subdomain 往 root domain 設 cookie 時，許多人應該都會想到一件事：「那共用的 subdomain 怎麼辦？」

例如說 GitHub Pages 這功能，每個人的 domain 都是 username.github.io ，那我不就可以用 cookie 炸彈，炸到所有的 GitHub Pages 嗎？只要在我自己的 subdomain 建一個惡意的 HTML，裡面有著設定 cookie 的 JS code，再來只要把這個頁面傳給任何人，他點擊之後就沒辦法訪問任何 `*.github.io` 的資源，因為都會被 server 拒絕。

這個假說看似是成立的，但其實有個前提要先成立，那就是：「使用者可以在 `*.github.io` 對 `github.io` 設置 cookie」。如果這個前提不成立，那 cookie bomb 就無法執行了。

事實上，像是這種「不想要共同的上層 domain 可以被設置 cookie」的需求其實不少，例如說 `a.com.tw` 如果可以設置 cookie 到 `.com.tw` 或是 `.tw` 的話，是不是一大堆不相關的網站都會共享到 cookie 了？這樣顯然是不合理的。

又或者是總統府的網站 `https://www.president.gov.tw`，應該不會想被財政部的網站 `https://www.mof.gov.tw` 所影響，因此 `.gov.tw` 應該也要是一個不給設定 cookie 的 domain。

當瀏覽器在決定能不能對某個 domain 設置 cookie 時，會參照一個清單叫做 [public suffix list](https://publicsuffix.org/list/)，出現在上面的 domain，其 subdomain 都沒辦法直接設定該 domain 的 cookie。

例如說以下 domain 都在這份清單上：

1. com.tw
2. gov.tw
3. github.io

所以前面舉的例子不成立了，因為我在 `userA.github.io` 的時候，沒辦法設置 `github.io` 的 cookie，所以無法執行 cookie bomb 攻擊。

關於 public suffix list，Heroku 有一篇文特別在介紹它的一些歷史沿革：[Cookies and the Public Suffix List](https://devcenter.heroku.com/articles/cookies-and-herokuapp-com)。

## 攻擊面擴展

上面有講到兩個攻擊成立的前提：

1. 找到一個地方可以設置任意 cookie
2. 目標必須點擊步驟一所找到的網址

如果想讓攻擊變得更容易成立，就可以針對這兩個前提去想說：

1. 有沒有可能這個地方很好找？
2. 有沒有可能目標不需要點擊連結就會中招？

先針對第二點來講，如果可以利用快取污染（Cache poisoning）的話，就可以輕易達成。先簡單講一下什麼是 cache poisoning，簡單來說就是想辦法讓 cache server 存的 cache 是壞掉的那一份（例如說 431 status code 的那一份），這樣不只你，而是所有其他使用者都會因為 cache 的關係，拿到壞掉的檔案，看到同樣的錯誤訊息。

這樣的話，目標不需要點擊任何東西就會中招，而且攻擊對象就從一個人擴大成所有人。

其實第二點有個專有名詞：CPDoS（Cache Poisoned Denial of Service），而且因為是利用 cache 的關係，所以也沒有必要設置 cookie 了，用其他的 header 也行，不需要侷限在 cookie bomb。

更詳細的相關攻擊手法可以參考：https://cpdos.org/

而第一點「有沒有可能這個地方很好找？」就是我真正想提的。

在針對這點繼續往下之前，其實 cookie bomb 還有更多的攻擊面擴展，可以搭配其他的攻擊手法一起使用，相關的說明以及實際案例很推薦大家去看這個影片：[HITCON CMT 2019 - The cookie monster in your browsers](https://www.youtube.com/watch?v=njQcVWPB1is)，裡面除了 cookie bomb 以外，也提到了其他 cookie 相關的特性。

這場演講裡面利用 cookie bomb 造成的 DoS 搭配其他手法的攻擊方式，真的很漂亮。

## 找到輕易設置 cookie 的地方

有什麼地方可以讓我們輕易設置 cookie，達成 cookie bomb 呢？有，那就是像之前所提過的共用的 subdomain，像是 `*.github.io` 這一種。

可是這種的不是都在 public suffix list 裡面了嗎？沒有辦法設置 cookie。

只要找到沒有在裡面的就好啦！

不過這其實也不是件容易的事情，因為你會發現你知道的服務幾乎都已經註冊了，例如說 GitHub、AmazonS3、Heroku 以及 Netlify 等等，都已經在上面了。

不過我有找到一個沒在上面的，那就是微軟提供的 Azure CDN：azureedge.net

不知道為什麼，但這個 domain 並不屬於 public suffix，所以如果我自己去建一個 CDN，就可以執行 cookie bomb。

## 實際測試

我用來 demo 的程式碼如下，參考並改寫自[這裡](https://github.com/wrr/cookie-bomb/blob/master/bomb.html)：

``` js
const domain = 'azureedge.net'
const cookieCount = 40
const cookieLength = 3000
const expireAfterMinute = 5
setCookieBomb()

function setCookie(key, value) {
  const expires = new Date(+new Date() + expireAfterMinute * 60 * 1000);
  document.cookie = key + '=' + value + '; path=/; domain=' + domain + '; Secure; SameSite=None; expires=' + expires.toUTCString()
}

function setCookieBomb() {
  const value = 'Boring' + '_'.repeat(cookieLength)
  for (let i=0; i<cookieCount; i++) {
    setCookie('key' + i, value);
  }
}
```

接著在 Azure 上面上傳檔案然後設置一下 CDN，就可以得到一個自訂的網址：https://hulitest2.azureedge.net/cookie.html （我的 azure 過期了，所以現在點進去應該會壞掉）

點了之後就會在 `azureedge.net` 上面設置一堆垃圾 cookie：

![](/img/cookie-bomb/p2.png)

重新整理後，會發現網站真的不能存取了：

![](/img/cookie-bomb/p3.png)

這就代表 cookie bomb 成功了。

所以只要是放在 azureedge.net 的資源，都會受到影響。

其實 AzureCDN 有自訂網域的功能，所以如果是自訂網域的話就不會受到影響。但有些網站並沒有使用自訂網域，而是直接使用了 azureedge.net 當作 URL。

大多數情況下，azureedge.net 都是拿來 host 一些資源，例如說 JS 以及 CSS 或者是圖片，我們可以隨便找一個把資源放在 azureedge.net 的網站來試試看攻擊是否有效。

一開始進去一切都很好，沒什麼問題，但是先造訪過 cookie bomb 那個網址後重新整理，發現整個網頁都跑板了，就是因為 cookie bomb 造成那些資源無法載入：

![](/img/cookie-bomb/p4.png)

雖然說沒辦法讓整個網頁無法讀取，但大幅度跑版外加功能壞掉，基本上也是沒辦法使用了。

甚至連微軟自己的一些服務也會被這個攻擊影響，因為也把資源放在 azureedge.net 上面：

![](/img/cookie-bomb/p5.png)

## 防禦方式

最好的防禦方式就是改用自訂網域，不要用預設的 azureedge.net，這樣就不會有 cookie bomb 的問題。但撇開自訂網域不談，其實 azureedge.net 應該去註冊 public suffix 才對，不讓使用者在這 domain 上面設置 cookie。

除了這兩種防禦方式之外，還有一種你可能沒想到的。

我們平常在引入資源的時候不是都這樣嗎：`<script src="htps://test.azureedge.net/bundle.js"></script>`。

只要加一個屬性 `crossorigin`，變成：`<script src="htps://test.azureedge.net/bundle.js" crossorigin></script>`，就可以避免掉 cookie bomb 的攻擊。

這是因為原本的方法在發送 request 時會把 cookie 帶上去，但如果加上 `crossorigin` 改成用 cross origin 的方式去拿，預設就不會帶 cookie，所以就不會有 header too large 的狀況發生。

只是記得在 CDN 那邊也要調整一下，要確認 server 有加上 `Access-Control-Allow-Origin` 的 header，允許跨來源的資源請求。

以前我很困惑到底什麼情形需要加上 `crossorigin`，現在我知道其中一種了，如果你不想把 cookie 一起帶上去的話，就可以加上 `crossorigin`。

## 再看一個例子

曾經在特定領域紅過，但被 Automattic 收購後便轉向的 Tumblr 有個特別的功能，那就是你可以在個人頁面自訂 CSS 與 JavaScript，而這個個人頁面的 domain 會是 userA.tumblr.com，而 tumblr.com 並沒有註冊在 public suffix 上，所以一樣會受 cookie bomb 的影響：

![](/img/cookie-bomb/p6.png)

造訪這個網址：https://aszx87410.tumblr.com/ 之後重新整理或者是前往 Tumblr 首頁，就會發現無法存取（寫 cookie 的 JS 沒寫好，只在 Chrome 上有用，Firefox 不行）：

![](/img/cookie-bomb/p7.png)

## 後續回報

2021-06-16 我在 HackerOne 上面回報了 Tumblr 的 cookie bomb 問題，隔天就收到回覆，對方回說：

> this behavior does not pose a concrete and exploitable risk to the platform in and on itself, as this can be fixed by clearing the cache, and is more of a nuisance than a security vulnerability

對有些公司來說，如果只有 cookie bomb 的話造成的危害太小，而且第一受害者必須點那個網址，第二只要把 cookie 清掉就沒事，所以並不認可這是一個安全性的漏洞。

而微軟那邊則是在 2021-06-10 透過 [MSRC](https://www.microsoft.com/en-us/msrc) 回報，大約兩週後 2021-06-22 收到回覆，對方說已經回報相關的團隊進行處理，但是這個問題並沒有達到 security update 的標準，之後修好也不會有通知。

後來寫信去問那能不能把這個問題當成範例寫在 blog，2021-06-30 收到回覆說 OK。

## 結語

我以前關注的漏洞大多數都是像 SQL Injection 或是 XSS 那樣子的，能夠偷走使用者的資料，但前陣子突然發現 DoS 這類型的漏洞很多也都很有趣，尤其是應用層的 DoS，比如說這一篇提到的 cookie bomb，或者是利用 RegExp 達成的 ReDoS，還有 GraphQL 的 DoS 等等。

雖然說單純的 cookie bomb 如果沒有結合其他的攻擊手法，影響力十分有限，而且只要清掉 cookie 就沒事了，但我覺得還是一個挺有趣的攻擊，畢竟我本來就對 cookie 相關的東西都很感興趣（可能是因為[以前](https://blog.huli.tw/2017/08/27/a-cookie-problem/)有被殘害過）。

但其實這樣研究下來，除了覺得 cookie bomb 很有趣之外，還有個東西讓我收穫良多，眼界大開，就是前面貼的那個 [HITCON CMT 2019 - The cookie monster in your browsers](https://www.youtube.com/watch?v=njQcVWPB1is) 影片中提到的利用 cookie bomb 結合其他攻擊手法。

在資安的領域中怎麼把不同的，看似很小的一些問題串在一起變成大問題，一直以來都是一門藝術。只有 cookie bomb 可能做不了什麼，但跟其他東西結合之後搞不好可以昇華出一個嚴重的漏洞。目前我個人學藝不精，沒辦法達到那種程度，但我相信有朝一日可以的。

總之呢，這篇文章就是跟大家稍微介紹一下 cookie bomb 的成因以及修復方式，如果你的服務會提供 subdomain 給使用者，記得評估一下是否需要去 public suffix list 上面註冊，避免 subdomain 寫 cookie 到 root domain，進而影響到所有的 subdomain。 
