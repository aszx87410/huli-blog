---
title: CORS 完全手冊（六）：總結、後記與遺珠
catalog: true
date: 2021-02-19 00:21:13
tags: [Ajax,JavaScript,Front-end,CORS]
categories:
  - Front-end
---

## 前言

這篇技術含量比較少一點，來跟大家分享一下寫這系列文的過程以及寫完之後的一些感想。

如果你還沒看這系列文的話，傳送門如下：

* <a target="_blank" href="/2021/02/19/cors-guide-1">CORS 完全手冊（一）：為什麼會發生 CORS 錯誤？</a>
* <a target="_blank" href="/2021/02/19/cors-guide-2">CORS 完全手冊（二）：如何解決 CORS 問題？</a>
* <a target="_blank" href="/2021/02/19/cors-guide-3">CORS 完全手冊（三）：CORS 詳解</a>
* <a target="_blank" href="/2021/02/19/cors-guide-4">CORS 完全手冊（四）：一起看規範</a>
* <a target="_blank" href="/2021/02/19/cors-guide-5">CORS 完全手冊（五）：跨來源的安全性問題</a>
* <a target="_blank" href="/2021/02/19/cors-guide-6">CORS 完全手冊（六）：總結、後記與遺珠</a>

<!-- more -->

## 起源

第一篇裡面有提到過想寫這系列文的初衷，因為實在是看過太多人問 CORS 問題了，而且有些人也不管脈絡，一言不合就推薦用 proxy 或是 CORS Anywhere。如果是第三方資源沒有權限，那用這個解法合理，但如果是公司自己的服務，應該是要叫後端設定才對，而不是自己去接 proxy。

CORS 最常見的錯誤大概就那些，包括：

1. 不知道 CORS 擋的是 response 而不是 request（有 preflight 的除外）
2. 不知道為什麼要有 CORS
3. 不知道怎麼解決 CORS 問題（到處亂試，以為 `no-cors` 是解法）
4. 不知道怎麼 debug（應該要看 console 跟看 network tab）
5. 錯誤地解決 CORS 問題（該後端改的卻自己用 proxy）

在 2020 年 4 月的時候，我有了寫這個系列文的念頭，接下來就開始研究，一開始就規劃了大家看到的這五篇文章，在 2020 年 7 月開始動筆，連續寫了大概兩三天，把第一篇寫完，第二篇大概寫一半，然後就從此擱置了。

那時候會擱置大概是因為第三篇：CORS 詳解不知道該怎麼寫，然後第四篇一起看 spec 也沒太多想法，所以就拖延症一直放著了。直到 2021 年 2 月份才開始繼續寫，並且一口氣把後續文章全部寫完。會重新開始動筆的理由是，這是我心中一顆放不下的石頭，沒有把這系列寫完，我做其他事情的時候就會有些不安，想著「這系列文是不是寫不完了」。

## 後記

但幸好我有寫完。因為從寫文章的過程中我也收穫很多，花了不少時間在理解一些細節，像是 Spectre 的攻擊我就研究了一段時間，雖然最後還是沒有很懂就是了，想要完全理解要把作業系統相關的知識補齊才行。而第五篇那些 COXX 的 header 也花了許多時間，找了很多資料，把當初提案的 issue 都稍微看了一下，會更理解這些 policy 提出的原因。

在研究的過程中也發現許多安全性有關的東西其實是扣在一起的，例如說：

1. Same-origin policy
2. window.open
3. iframe
4. CSP
5. SameSite cookie

在找資料的過程中可以看到不少重疊的地方，尤其是 SameSite cookie，越想越覺得這東西真的很重要，而且可以防止滿多的攻擊。對了，在寫這篇文的時候參考資料其實大多都來自於 Google Chrome，所以文中有許多使用「瀏覽器」的地方，有可能現在其實只有 Chrome 有實作而已，其他瀏覽器還沒跟進。

不過 Chrome 確實資源最多，而且常常會 po 一些技術好文在部落格上面，都是很值得參考的資源。

我認為前後端工程師都要對 CORS 有一定的理解，碰到問題的時候才知道該怎麼解決。雖然說 CORS 是許多新手工程師都碰過的問題，但其實把脈絡理清楚之後，我覺得不是特別難，就是要花點時間把 CORS 的運作模式搞清楚。而且一旦弄懂之後，從此以後碰到這問題都不怕了。

再來有關於第五篇那些各種 COXX 的東西，我認為除非你需要用到那些被封印的功能，或是你的網站需要有高度的安全性，否則有時間再去研究就可以了，先聽過有個印象就好。

寫完這系列文之後，有些想講的東西我找不到地方放，因此底下的段落就講一些放不進去的遺珠。

## 可能不是 CORS 問題的 CORS 問題

瀏覽器的錯誤訊息是個很好的資訊來源，但是它有時候卻也不一定可靠。

有些 CORS 問題，不一定是因為 response header 沒設好，有可能是因為之前沒設定好的 response 被 cache 住，或者甚至是憑證問題！可以參考：

1. [CORS request blocked in Firefox but not other browsers #2803](https://github.com/aws-amplify/amplify-js/issues/2803)
2. [Firefox 'Cross-Origin Request Blocked' despite headers](https://stackoverflow.com/questions/24371734/firefox-cross-origin-request-blocked-despite-headers)
3. [CORS request did not succeed on Firefox but works on Chrome](https://stackoverflow.com/questions/51831652/cors-request-did-not-succeed-on-firefox-but-works-on-chrome)

## Origin Policy

在使用 CORS 的時候其實我們花了許多時間在 preflight request 上面，先假設沒有快取而且都是非簡單請求的話，那跨來源跟同來源比起來，多了一倍的 request，因為每一個 request 都會額外再附加一個 preflight request。

可是網站對於 CORS 的規則大部分都是一致的，那為什麼不先寫好一個設定檔讓瀏覽器來讀呢？這樣瀏覽器就會知道某個來源是不是被允許的，就不需要一直發送 preflight request 了。

這個想法的源頭來自：[RFC: a mechanism to bypass CORS preflight #210](https://github.com/whatwg/fetch/issues/210)，有空的話可以看一下裡面的討論。

而其實不只 CORS，其他 header 也可能有類似的狀況，例如說 CSP，大部分狀況下整個網站的 CSP 其實都是一樣的，可是現在卻是每一個 HTTP response 都要回傳一樣的 CSP header，這也可以透過寫一個設定檔的方式來讓瀏覽器讀取，就不需要再個別傳了。

上面講的這些，之後被拓展為一個叫做 [Origin Policy](https://github.com/WICG/origin-policy) 的東西，想法大概就是寫好一個檔案放在 `/.well-known/origin-policy` 並且讓瀏覽器來讀，可以節省不少 response 的 size，不過目前只是個提案而已。

## Cross origin 的圖片讀取

一般在使用 img 的時候都是 `<img src=xxx>`，就是用一般的方式去抓取資源。

但其實在 HTML 裡面有些標籤可以用「跨來源」的方式去抓取資源，例如說 `<img>` 就是一個，其他可參考：[MDN: HTML attribute: crossorigin
](https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/crossorigin)。

只要這樣就可以了：

``` html
<img src=xxx crossorigin>
```

其實 crossorigin 有三個屬性：

1. 不設定/空字串
2. anonymous
3. use-credentials

前兩種是一樣的，而後者就像是 fetch 裡面那個 `credentials: 'include'` 一樣。總之呢，只要加上 `crossorigin`，對於跨來源的檔案，後端就必須跟 CORS 一樣，加上 `Access-Control-Allow-Origin`，前端才能正確存取圖片。

那圖片好端端的，為什麼一定要用 CORS 來載入呢？兩個理由，第一個理由是上一篇我提到說：「如果把 COEP 設成 require-corp 的話，就代表告訴瀏覽器說：『頁面上所有我載入的資源，都必須有 CORP 這個 header 的存在（或是 CORS），而且是合法的』」。

假設你現在把 COEP 設成 require-corp，如果你的網站是用 `<img src=xxx>` 來載入圖片，那這個圖片一定要有 CORP 的 header 才行。那真的沒有的話怎麼辦呢？

那你可以用跨來源的方式載入圖片，也就是：`<img src=xxx crossorigin>`，在這個方式底下，圖片不需要有 CORP 的 header，只需要有 `Access-Control-Allow-Origin` 的 header 就行了，因為這是用 CORS 的模式在載入圖片。

而第二個理由，還記得我之前有說過，如果你載入一張跨來源的圖片並試著用 JS 把圖片內容讀出來，會產生錯誤嗎？如果你是用 cross origin 的模式載入，就不會有這錯誤。詳情可參考：[Allowing cross-origin use of images and canvas](https://developer.mozilla.org/en-US/docs/Web/HTML/CORS_enabled_image)。

## Chromium 處理 CORS 的程式碼

沒仔細看，筆記一下而已：[chromium/chromium/src/+/master:services/network/public/cpp/cors/cors.cc](https://source.chromium.org/chromium/chromium/src/+/master:services/network/public/cpp/cors/cors.cc?originalUrl=https:%2F%2Fcs.chromium.org%2F)

## 一個 URI 一定跟自己是同源嗎？

在 [rfc6454](https://tools.ietf.org/html/rfc6454#section-5) 給出了答案：

> NOTE: A URI is not necessarily same-origin with itself. For example, a data URI [RFC2397] is not same-origin with itself because data URIs do not use a server-based naming authority and therefore have globally unique identifiers as origins.

data URI 跟自己不同源。

不過新的 fetch spec 沒有找到這一段就是了。

## 如何讓 origin 是 "null"

前面有強調過 origin 是 null 跟 "null" 是不同的，因為 origin 確實有可能是字串的 null，例如說你開啟一個 `file:///` 開頭的網頁送出 request，或者是在 sandbox 的 iframe 裡面 AJAX：

``` js
<iframe sandbox='allow-scripts' srcdoc='
  <script>
    fetch("/test");
  </script>
'></iframe>
```

程式碼改寫自：[AppSec EU 2017 Exploiting CORS Misconfigurations For Bitcoins And Bounties by James Kettle](https://youtu.be/wgkj4ZgxI4c?t=979)

## 總結

終於寫完這系列文了。

希望大家在看完這系列之後有更理解 CORS 以及其他跨來源的相關概念，之後碰到 CORS 的錯誤都不再害怕，而且知道該怎麼解決。如同我在第一篇開頭說的，希望這系列文能成為 CORS 的寶典，每個碰到問題的人看完這個系列都可以迎刃而解。

如果有任何錯誤或是缺漏的地方，可以再私訊或是留言跟我說，感謝。
