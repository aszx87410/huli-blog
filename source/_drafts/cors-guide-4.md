---
title: CORS 完全手冊（四）：一起看規範
catalog: true
date: 2020-07-24 23:07:47
tags: [Ajax,JavaScript,Front-end,CORS]
categories:
  - Front-end
---

## 前言

當你獲得了一個知識之後，要怎樣才能知道那是正確的還是錯誤的？在程式的領域中這其實是一個相對簡單的問題，只要去確認規範是怎麼寫的就可以了（如果有規範的話）。

舉例來說，JavaScript 的各種語言特性在 ECMAScript Specification 裡面都找得到，為什麼 `[] === []` 會是 false，為什麼 `'b' + 'a' + + 'a' + 'a'` 會是 baNaNa，這些在規範裡面都有，都會詳細說明是用怎樣的規則在做轉換。

而 Web 相關的領域除了 JS 以外，HTML 或是其他相關的規範幾乎都可以在 [w3.org](https://www.w3.org) 或是 [whatwg.org](https://html.spec.whatwg.org/multipage/) 裡面找到，資源相當豐富。

雖然說瀏覽器的實作有可能跟規範寫的不一樣（像是[這篇](https://blog.huli.tw/2020/09/05/session-storage-and-html-spec-and-noopener/)），但 spec 已經是最完整而且最有權威性的一個地方了，因此來這邊找準沒錯。

如果搜尋 CORS 的 spec，可能會找到 [RFC6454 - The Web Origin Concept](https://tools.ietf.org/html/rfc6454) 以及 W3C 的 [Cross-Origin Resource Sharing](https://www.w3.org/TR/2020/SPSD-cors-20200602/)，但這兩份都叫這一份叫做 [Fetch](https://fetch.spec.whatwg.org/) 的文件給取代了。

當初我疑惑了一陣子想說是不是自己看錯，fetch 跟 CORS 有什麼關係？後來才知道原來這邊的 fetch 跟 Web API 那個 fetch 其實不同，這份規格是定義了所有跟「抓取資料（fetch）」有關的東西，就如同它的大綱所寫的：

> The Fetch standard defines requests, responses, and the process that binds them: fetching.

這一篇就讓我們一起來看一下 CORS 相關的規範，證明我前面幾篇沒有在唬爛你，講得都是有所根據的。因為規格還滿長的，所以底下就是我挑幾個我認為的重點講而已，想要理解所有的規格內容，還是需要自己去看才行。

（此文章發佈是規格的版本為：Living Standard — Last Updated 14 January 2021）

## 先來點簡單的

規格這種東西因為很完整所以內容很多也很雜，如果不先從簡單一點的開始很容易會看不下去。而最簡單的就是開頭的 Goals 跟 Preface 這兩個單元了，裡面寫到了：

> The goal is to unify fetching across the web platform and provide consistent handling of everything that involves, including:

> * URL schemes  
> * Redirects
> * Cross-origin semantics
> * CSP
> * Service workers
> * Mixed Content
> * `Referer`
>  
> To do so it also supersedes the HTTP `Origin` header  semantics originally defined in The Web Origin Concept

這份規格統整了所有「fecthing」相關的東西，例如說我們最關注的 CORS 或是其他相關的操作。然後也有提到說這份取代了原本的 [RFC6454 - The Web Origin Concept](https://tools.ietf.org/html/rfc6454)。

接著在前言中有寫到：

> At a high level, fetching a resource is a fairly simple operation. A request goes in, a response comes out. The details of that operation are however quite involved and used to not be written down carefully and differ from one API to the next.

fetch 看起來很簡單，不過就是發個 request 然後接收 response 而已，但實際上其實水很深，以前沒有規格記錄下來導致每個 API 的實作都不一樣。這也是為什麼會有這個統一的 spec 誕生。

> Numerous APIs provide the ability to fetch a resource, e.g. HTML’s img and script element, CSS' cursor and list-style-image, the navigator.sendBeacon() and self.importScripts() JavaScript APIs. The Fetch Standard provides a unified architecture for these features so they are all consistent when it comes to various aspects of fetching, such as redirects and the CORS protocol.

這邊提到了我在前面所說的，抓取資料或是跨網域抓取資源並不只侷限在 AJAX 上面，載入圖片或是 CSS 也是抓取資源的一種。而這份規格就是為了統一管理這些行為。

> The Fetch Standard also defines the fetch() JavaScript API, which exposes most of the networking functionality at a fairly low level of abstraction.

身為 Fetch 規格，定義 JS 中的 `fetch()` API 也是相當合情合理的事情。

簡單的部分就到這邊了，這邊就只是在講說為什麼會有這份規格還有它想達成的目的是什麼。

接著我們來看一下 Origin 的定義。

## Origin

Origin 的部分在 3.1. `Origin` header，裡面有附上 ABNF，用特定格式寫成的規則：

```
Origin                           = origin-or-null

origin-or-null                   = origin / %s"null" ; case-sensitive
origin                           = scheme "://" host [ ":" port ]
```

簡單來說就是 origin 的內容只會有兩種，一種是 `"null"`，注意這邊我特別用引號括住，因為那是一個字串。第二種就是前面文章中提到的 scheme + host + port 的組合。

這邊值得注意的是與舊的 rfc6454 的區別，在舊的規範中 origin 其實可以是一個 list 的：

```
7.1.  Syntax

   The Origin header field has the following syntax:

   origin              = "Origin:" OWS origin-list-or-null OWS
   origin-list-or-null = %x6E %x75 %x6C %x6C / origin-list
   origin-list         = serialized-origin *( SP serialized-origin )
   serialized-origin   = scheme "://" host [ ":" port ]
                       ; <scheme>, <host>, <port> from RFC
                       
7.2 Semantics

   In some cases, a number of origins contribute to causing the user
   agents to issue an HTTP request.  In those cases, the user agent MAY
   list all the origins in the Origin header field
```

不過在新的規範中看起來只會剩下一個。總之呢，origin 的定義就跟我之前講的一樣，是 scheme + host + port 的組合。

再來我們直接去看我們最想知道的 CORS！

## CORS

CORS 的部分在 3.2. CORS protocol 的地方。開頭的介紹非常重要。

> To allow sharing responses cross-origin and allow for more versatile fetches than possible with HTML’s form element, the CORS protocol exists. It is layered on top of HTTP and allows responses to declare they can be shared with other origins.

CORS protocol 存在是為了讓網頁可以有除了 form 元素以外，也可以抓取跨網域資源的方法。然後這個 procotol 是建立在 HTTP 之上的。

> It needs to be an opt-in mechanism to prevent leaking data from responses behind a firewall (intranets). Additionally, for requests including credentials it needs to be opt-in to prevent leaking potentially-sensitive data.

這邊提到了「prevent leaking data from responses behind a firewall (intranets)」，其實就是我第一篇文章中所提到的案例。如果沒有 same-origin policy 的保護，在內網的資訊可能就會被輕易取得。

而「for requests including credentials it needs to be opt-in」也是我們之前所提到的，如果 request 有包含 credentials（通常是 Cookie），就必須 opt-in，否則也會有資訊洩漏的風險。

接著底下 3.2.1. General 的這一段也很重要：

> The CORS protocol consists of a set of headers that indicates whether a response can be shared cross-origin.

> For requests that are more involved than what is possible with HTML’s form element, a CORS-preflight request is performed, to ensure request’s current URL supports the CORS protocol.

這邊提到了兩個重點，第一個是 CORS 是透過 header 來決定一個 response 是不是能被跨網域共享，第二個是如果一個 request 超過 HTML 的 form 元素可以表達的範圍，那就會有一個 CORS-preflight request。

那到底怎樣叫做「超過 form 元素可以表達的範圍」？這個我們稍後再看，先來看底下這兩個部分：

> 3.2.2. HTTP requests
> 
> A CORS request is an HTTP request that includes an `Origin` header. It cannot be reliably identified as participating in the CORS protocol as the `Origin` header is also included for all requests whose method is neither `GET` nor `HEAD`.

這邊滿特別的，如果我沒有理解錯誤的話，是說一個 HTTP request 如果含有 origin 這個 header，就叫做 CORS request，但這並不代表這個 request 就跟 CORS procotol 有關，因為除了 GET 跟 HEAD 之外的 request 都會帶上 origin 這個 header。

為了驗證這個行為，我建立了一個簡單的表單：

``` html
<form action="/test" method="POST">
  <input name="a" />
  <input type="submit" />
</form>
``` 

然後 method 那邊 POST 跟 GET 都試試看，發現果真是這樣沒錯。GET 的沒有帶 origin header，但是 POST 的有。所以按照規格上的說法，用表單 POST 送出資料到同一個 origin 底下，也會被叫做 CORS request，奇怪的知識又增加了。

> A CORS-preflight request is a CORS request that checks to see if the CORS protocol is understood. It uses `OPTIONS` as method and includes these headers:
> 
> `Access-Control-Request-Method`  
> Indicates which method a future CORS request to the same resource might use.
> 
> `Access-Control-Request-Headers`  
> Indicates which headers a future CORS request to the same resource might use.

而 CORS-preflight request 就是利用 OPTIONS 來確認 server 是不是理解 CORS procotol。

這邊有一點要特別提，就如同 MDN 上面寫的：

> 部分請求不會觸發 CORS 預檢。這類請求在本文中被稱作「簡單請求（simple requests）」，雖然 Fetch 規範（其定義了 CORS）中並不使用這個述語

在 Fetch 的規範中並沒有出現簡單請求這個詞，只有區分會不會觸發 CORS-preflight request 而已。

而 CORS protocol 當中的 preflight request 會帶這兩個 header：

1. Access-Control-Request-Method
2. Access-Control-Request-Headers

來說明之後的 CORS request 可能會用到的 method 跟 header。

接著有關 response 的部分：

> 3.2.3. HTTP responses
> 
> An HTTP response to a CORS request can include the following headers:
> 
> `Access-Control-Allow-Origin`  
> Indicates whether the response can be shared, via returning the literal value of the `Origin` request header (which can be `null`) or `*` in a response.
>
> `Access-Control-Allow-Credentials`  
>Indicates whether the response can be shared when request’s credentials mode is "include".

這兩個是針對 CORS request 可以返回的 response header，已經在上一篇文章裡面提到過了。

前者用來決定哪些 origin 合法，後者決定是不是允許帶上 cookie 以及設置 cookie。

> An HTTP response to a CORS-preflight request can include the following headers:
> 
> `Access-Control-Allow-Methods`  
> Indicates which methods are supported by the response’s URL for the purposes of the CORS protocol.
> 
> `Access-Control-Allow-Headers`  
> Indicates which headers are supported by the response’s URL for the purposes of the CORS protocol.
> 
> `Access-Control-Max-Age`
> Indicates the number of seconds (5 by default) the information provided by the `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` headers can be cached.

CORS-preflight request 也是 CORS request 的一種，所以上面所說的針對 CORS request 可以給的 response 也都可以給。

而除此之外還定義了另外三個：

1. Access-Control-Allow-Methods：可以使用哪些 method
2. Access-Control-Allow-Headers：可以使用哪些 header
3. Access-Control-Max-Age：前兩個 header 可以快取多久

這邊值得注意的是第三個，預設值是 5 秒，所以 5 秒內針對同一個資源的 CORS response header 是可以重用的。

> An HTTP response to a CORS request that is not a CORS-preflight request can also include the following header:
> 
> `Access-Control-Expose-Headers`  
Indicates which headers can be exposed as part of the response by listing their names.

針對不是 preflight 的 CORS request，可以提供 `Access-Control-Expose-Headers` 這個 header，用來指名有哪些 header 可以存取。

如果沒有明確指定的話，就算拿到了 response 還是沒辦法拿到 header。

接著我們回來看前面提到的那個問題：「怎樣會觸發 preflight request？」

## Preflight request

在 4.1. Main fetch 的章節中有詳細敘述了抓取資源的規則，其中我們關注的是第 5 點中的：

> request’s use-CORS-preflight flag is set  
> request’s unsafe-request flag is set and either request’s method is not a CORS-safelisted method or  CORS-unsafe request-header names with request’s header list is not empty
> 
> 1. Set request’s response tainting to "cors".
> 2. Let corsWithPreflightResponse be the result of performing an HTTP fetch using request with the CORS-preflight flag set.
> 3. If corsWithPreflightResponse is a network error, then clear cache entries using request.
> 4. Return corsWithPreflightResponse.

如果 reqeust 的 method 不是 CORS-safelisted method，或是 header 裡面有 CORS-unsafe request-header names 的話，就會設置 CORS-preflight flag 然後進行 HTTP fetch。

繼續往下追的話，在 HTTP fetch 的流程裡會判斷這個 flag 有沒有被設置，有的話就進行 CORS-preflight fetch。

上面所提的東西都可以在 spec 中找到：

> 2.2.1 Methods
> 
> A CORS-safelisted method is a method that is `GET`, `HEAD`, or `POST`.

只有這三個 method 不會觸發 preflight。

而有關於 CORS-unsafe request-header names，它會去檢查 headers 是不是都是「CORS-safelisted request-header」，這邊的定義在 2.2.2. Headers 的部分，基本上只有以下幾個會過：

1. accept
2. accept-language
3. content-language
4. content-type

但要注意的是 content-type 有額外附加條件，只能是：

1. application/x-www-form-urlencoded
2. multipart/form-data
3. text/plain

這三種。

另外，上面的 header 對應的 value 中一定都要是合法字元，至於哪些是合法字元，每個 header 的定義都不同，這邊就不細講了。

仔細想想其實會發現滿合理的，因為以 form 來說，可以填的 method 就只有 GET 跟 POST（還有一個 dialog 啦但是跟 HTTP 無關了），可以填的 enctype 也只有上面說的那三種，沒有填的話預設就是 application/x-www-form-urlencoded。

因此如果是表單的話，確實不會超過上面那樣子的定義。而如果在發出 request 的時候超過了這個範圍，就會送出 preflight request。

所以想要 POST 送出 JSON 格式的資料也會觸發，除非你 content-type 用 text/plain，就可以繞過 preflight request（但不建議這樣做就是了）

## CORS check

關於 request 的部分應該都看完了，接著來看一下 response 相關的部分。有一件我很好奇的事情，那就是該怎麼驗證 CORS 的結果是過關的？

這邊可以看到 4.9. CORS check：

（補圖）

如果 Access-Control-Allow-Origin 裡的 origin 是 null 的話，就失敗（這邊特地強調是 null 而不是 "null"，這我們之後會再提到）。

再來檢查如果 origin 是 * 而且 credentials mode 不是 include，就給過。

接著比對 request 的 origin 跟 header 裡的，不同的話就回傳失敗。

比對到這一步的時候 origin 相同了，接著再看一次 credentials mode，不是 inlcude 的話就給過。

反之則檢查 Access-Control-Allow-Credentials，如果是 true 的話就給過，否則就回傳失敗。

這一系列的檢查有種 early return 的味道在，可能是因為這樣比較好寫成條列式的，盡量把巢狀給壓平。


no-cors
