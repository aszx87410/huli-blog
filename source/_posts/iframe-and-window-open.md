---
title: iframe 與 window.open 黑魔法
catalog: true
date: 2022-04-07 22:02:57
tags: [Security, Front-end]
categories: [Security]
---

如果你想要在網頁上產生一個新的 window，大概就只有兩個選擇，一個是利用 `iframe`、`embed` 與 `object` 這些標籤將資源嵌入在同個頁面上，而另一個選擇則是使用 `window.open` 新開一個視窗。

身為前端開發者，我相信大家對這些都不陌生，可能有用過 `iframe` 嵌入第三方的網頁，或是嵌入一些 widget，也有用過 `window.open` 開啟新的視窗，並透過 `window.opener` 跟原來的視窗溝通。

但站在資安的角度來看，其實 iframe 有不少好玩的東西，無論是現實世界或是在 CTF 內都經常出現，因此我想透過這篇記錄近期學到的一些特性。

<!-- more -->

## iframe 基礎

先來看一下基本的 iframe 使用，透過 `<iframe>` 這個標籤，可以把其他人的網頁引入進來：

``` html
<iframe src="https://blog.huli.tw"></iframe>
```

但仔細想一下，如果你的網頁可以被任何人嵌入，那就可能會有點擊劫持（Clickjacking）的風險。

因此，如果你的網頁不想被嵌入或是想設定只有特定 origin 可以嵌入，可以使用 `Content-Security-Policy` 以及 `X-Frame-Options`，這些我在[不識廬山真面目：Clickjacking 點擊劫持攻擊](https://blog.huli.tw/2021/09/26/what-is-clickjacking/)裡面都有提過，這邊就不多講了。

有些可以發文或是留言的網站，通常都會開放一定程度的 HTML 元素，並不會完全封死，例如說至少粗體（`<b>`）與斜體（`<i>`）這些無害的元素會開放，而有些網站為了支援像是 YouTube 播放器之類的功能，也會支援 iframe 標籤。

做得比較好的網站，會限制讓你只能輸入 YouTube 影片的 ID，再在前端自己拼接上 YouTube 的前綴，確保 iframe 載入的 src 是來自於 YouTube。而有些網站可能要嵌入的站太多，又想開放比較多的自由度給使用者，因此可以讓使用者自定義 iframe src 的內容，想放什麼都可以。

如果攻擊者能控制 iframe 的 src，這時候會有哪些風險呢？

第一個最容易想到的風險，大概就是你可以直接嵌入一個釣魚網站在裡面，例如說寫個再次登入或是領取獎品的頁面，說不定就會有人真的輸入帳號密碼然後送出表單。

但這個的影響程度有限，而且牽涉到了一點社交工程，其實有更簡單暴力的方式，那就是這樣：

``` html
<iframe src="javascript:alert(1)"></iframe>
```

是的，iframe 的 src 可以放 `javascript:` 開頭的這種格式，就可以直接執行 JavaScript 程式碼，達成 XSS。順帶一提，`<form>` 的 action 跟 `<a>` 的 href 也都可以放，這個我在[接觸資安才發現我不懂前端](https://blog.huli.tw/2021/10/25/learn-frontend-from-security-pov/)有稍微提到。

而且不僅如此，HTML 屬性裡的東西是可以編碼的，有三種方式可以編碼，以 `&` 這個字元為例：

1. 用名稱來編碼，例如說 `&amp;`（不是每個字元都支援，這邊有列表：[https://dev.w3.org/html5/html-author/charref](https://dev.w3.org/html5/html-author/charref)）
2. 用十進位來編碼，例如說 `&#38;`
3. 用十六進位來編碼，例如說 `&#x26;`

所以 `javascript:alert(1)` 的每一個字元，你都可以自由換成上面這些編碼，例如說：

``` html
<iframe src="&#x6a;&#65;vAScrIpt&colon;alert&lpar;1&rpar;"></iframe>
```

（想要玩玩看 encode 跟 decode 的話可以到這個網站：https://mothereff.in/html-entities）

除了 `javascript:` 以外，你也可以用 `data:` 來載入任意網頁：

``` html
<iframe src="data:text/html,<h1>hello</h1>"></iframe>
```

也可以指定用 base64 編碼：

``` html
<iframe src="data:text/html;base64,PGgxPmhlbGxvPC9oMT4="></iframe>
```

不過上述兩種其實沒太大用處，因為 src 如果用 data URI 的話，origin 會變成 `"null"`，就跟原本的頁面不同源，沒辦法存取到頁面上的資料。

那這時身為防禦的一方，我們可以怎麼做呢？我們可以限制開頭一定要是 `http://` 或是 `https://`，就可以阻擋這種預期之外的 scheme。

不過，如果只有這樣的話，還有另一個潛在的風險，那就是 [open redirect](https://tech-blog.cymetrics.io/posts/huli/open-redirect/)，被嵌入的頁面可以用 `top.location = "https://huli.tw"`，把最上層的頁面導到任意地方。

通常跨 origin 的操作都會被禁止，要存取 window 上的屬性時也會噴錯誤出來：

> Uncaught DOMException: Blocked a frame with origin "null" from accessing a cross-origin frame.

但有幾個屬性除外，可參考 HTML spec 中的 [7.2.3.1 CrossOriginProperties ( O )](https://html.spec.whatwg.org/multipage/browsers.html#crossoriginproperties-(-o-))：

> If O is a Location object, then return « { [[Property]]: "href", [[NeedsGet]]: false, [[NeedsSet]]: true }, { [[Property]]: "replace" } ».
>
> A JavaScript property name P is a cross-origin accessible window property name if it is "window", "self", "location", "close", "closed", "focus", "blur", "frames", "length", "top", "opener", "parent", "postMessage", or an array index property name.

有些是可以呼叫的函式，例如說 `focus`、`blur` 跟 `postMessage`，這些都可以跨 origin 呼叫，而 `postMessage` 也是跨 origin 的 window 間傳遞資訊的首要方式。

其他大部分都是可讀的屬性，例如說 `closes`、`frames`、`length` 或是 `top`、`opener` 以及 `parent` 等等。

而少數可寫的屬性是 `location.href`，只要你能存取到 window，就能用 `location.href = 'https://huli.tw'` 把網頁導到其他地方。

順帶一提，有另外一種執行 JavaScript 的方式就是透過 location + javascript protocol，像是這樣：`location.href = 'javascript:alert(1)'`，這個我在[在做跳轉功能時應該注意的問題：Open Redirect](https://blog.huli.tw/2021/09/26/what-is-open-redirect/) 裡有提過。

這時你可能會想說，那前面提過的 iframe src + data URI，是不是就可以透過這個方法繞過 null origin 的限制，針對 parent window 做 XSS 呢？像是這樣：

``` html
<iframe src="data:text/html,<script>top.location.href = 'javascript:alert(1)'</script>"></iframe>
```

答案是不行，瀏覽器會噴這樣的錯誤給你：

> Unsafe attempt to initiate navigation for frame with URL 'file://poc.html' from frame with URL 'data:text/html,&lt;script>top.location.href = 'javascript:alert(1)'</script>'. The frame attempting navigation must be same-origin with the target if navigating to a javascript: url

如果你要跳到 javascript: 開頭的 url，那必須要 same-origin 才會讓你跳。

## iframe 的 srcdoc

除了常用的 src 屬性以外，還有另一個屬性叫做 srcdoc，裡面放的值就是 iframe 的內容，跟 src + data URI 其實有點類似：

``` html
<iframe
  srcdoc="<h1>hello</h1><script>alert(top.document.body)</script>">
</iframe>
```

但是有個決定性的差異，那就是 iframe + srcdoc 所產生的 window，它的 origin 會繼承上層，跟 data URI 會變成 null origin 不同。也就是說，上面這段程式碼可以存取到上層的 DOM 元素，因為他們是 same origin。

另外，srcdoc 並不受 CSP 的 `frame-src` 影響，就像 iframe 的 src 如果是 `javascript:` 的話，是受 `script-src` 管而不是 `frame-src` 管，細節可看這裡：[Test of CSP: iframe srcdoc='...' is not governed by frame-src](https://csplite.com/csp/test188/)

還有，由於 srcdoc 是 HTML attribute 的關係，所以內容就跟之前提過的一樣，可以是 encode 過的結果，像這樣：

``` html
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>
```

所以如果 iframe srcdoc 的屬性可控，就算內容有先 escape 過也沒有用，還是會被解析回原本的符號來執行。

## iframe 的 CSP

iframe 上有一個 csp 的屬性，可以指定 iframe 所載入的 document 的 CSP 規則，不過並不是每個瀏覽器都支援，可參考 [MDN: HTMLIFrameElement.csp](https://developer.mozilla.org/en-US/docs/Web/API/HTMLIFrameElement/csp)：

``` html
<iframe csp="default-src 'self'; script-src 'none';"
  srcdoc="<script>alert(1)</script>"></iframe>
```

加了 csp 屬性後，iframe 的內容會被它所影響，舉例來說，直接打開 test.html 會跳 alert，但是用 csp 把 inline script 擋住，就會跳出違反 CSP 的錯誤訊息：

``` html
// test.html
<script>alert(1)</script>

// csp.html
<iframe csp="default-src 'self'; script-src 'none';" src="test.html"></iframe>
```

> Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'none'". Either the 'unsafe-inline' keyword, a hash ('sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='), or a nonce ('nonce-...') is required to enable inline execution.

之前 Intigriti 有一次的 XSS 挑戰就是利用插入 CSP 的方式把 CSP 變嚴格，然後有些腳本就不會執行到，靠這樣來繞過一些限制。

## iframe 的 sandbox

前面有提過，當你利用 iframe 把其他網頁嵌入的時候，那個網頁可以用 `top.location = 'https://huli.tw'` 把上層頁面導到其他地方，而 iframe 有個叫做 sandbox 的屬性，可以限制 iframe 的各種行為，讓它不能做一些壞壞的事，基本的使用像是這樣：

``` html
<iframe srcdoc="<script>alert(1)</script>" sandbox></iframe>
```

> Blocked script execution in 'about:srcdoc' because the document's frame is sandboxed and the 'allow-scripts' permission is not set.

一旦加上了 sandbox 這個屬性，就進入了沙箱模式，這個模式有沒有加主要的差別有兩個。

第一個是，被載入的 iframe 的 origin 會變成 `null`。

第二個是，一堆功能會被關閉，而這些功能可以被主動開啟，根據目前最新的 [spec](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-element) 所述，一共有 13 種 flag，每一個都代表一個功能：

1. allow-downloads
2. allow-forms
3. allow-modals
4. allow-orientation-lock
5. allow-pointer-lock
6. allow-popups
7. allow-popups-to-escape-sandbox
8. allow-presentation
9. allow-same-origin
10. allow-scripts
11. allow-top-navigation
12. allow-top-navigation-by-user-activation
13. allow-top-navigation-to-custom-protocols

這邊其實 flag 有點多而且有些只差一點點，我們先來看最重要的一個，就是 `allow-scripts`，這個 flag 十分好懂，沒有加上的話，預設是沒辦法執行 JavaScript 的，就像上面看到的錯誤那樣，加上這個 flag 以後才能執行 JavaScript，但可以使用的功能還是有限制。

其他的 flag 我們可以分成幾類來看比較好懂。

### 重新導向類型的 flag

底下這三個都跟重新導向有關

1. allow-top-navigation
2. allow-top-navigation-by-user-activation
3. allow-top-navigation-to-custom-protocols

如果沒有加的話，預設是不能對上層重新導向的：

``` html
<iframe
  srcdoc="<script>top.location='https://blog.huli.tw'</script>"
  sandbox="allow-scripts">
</iframe>
```

錯誤：

> Unsafe attempt to initiate navigation for frame with URL 'file:///test.html' from frame with URL 'about:srcdoc'. The frame attempting navigation of the top-level window is sandboxed, but the flag of 'allow-top-navigation' or 'allow-top-navigation-by-user-activation' is not set.

想要讓 iframe 可以對上層重新導向，只要加上 `allow-top-navigation` 即可，但如果你不想讓網頁在沒有互動的狀況下就自動重新導走，可以改用 `allow-top-navigation-by-user-activation` 這個 flag：

``` html
<iframe
  srcdoc="<script>top.location='https://blog.huli.tw'</script>"
  sandbox="allow-scripts allow-top-navigation-by-user-activation">
</iframe>
```

錯誤：

> The frame attempting navigation of the top-level window is sandboxed with the 'allow-top-navigation-by-user-activation' flag, but has no user activation (aka gesture). See https://www.chromestatus.com/feature/5629582019395584.

用這個 flag 的話，使用者必須要有互動（例如說點個按鈕來觸發事件），才能把網頁重新導走。

而 `allow-top-navigation-to-custom-protocols` 這個 flag 因為 Chrome 目前還沒支援，所以也沒辦法 demo，就先跳過吧。Chrome 102 支援的 flag 可以看這邊：[third_party/blink/renderer/core/html/html_iframe_element_sandbox.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/102.0.4961.1/third_party/blink/renderer/core/html/html_iframe_element_sandbox.cc#17)

### 功能類型的 flag

1. allow-downloads
2. allow-forms
3. allow-orientation-lock
4. allow-pointer-lock
5. allow-presentation

上面這五個都是跟功能有關的，從名字就大概可以看出來是在幹嘛。

舉例來說，預設是不能送出表單的：

``` html
<iframe
  srcdoc="<form><input name=a value=a><input type=submit></form>"
  sandbox>
</iframe>
```

錯誤：

> Blocked form submission to '' because the form's frame is sandboxed and the 'allow-forms' permission is not set.

要加上 `allow-forms` 這個 flag 之後才能送出表單。其他的 flag 也都類似，這邊就不多說了。


### 彈出視窗相關的 flag

1. allow-modals
2. allow-popups
3. allow-popups-to-escape-sandbox

這邊 `allow-modals` 跟 `allow-popups` 名字很像，但定義其實差滿多的，底下幾種功能都是 `allow-modals` 會開啟的：

1. window.alert
2. window.confirm
3. window.print
4. window.prompt
5. beforeunload event

給個簡單的範例：`<iframe srcdoc="<script>alert(1)</script>" sandbox="allow-scripts">`，錯誤：

> Ignored call to 'alert()'. The document is sandboxed, and the 'allow-modals' keyword is not set.

而 `allow-popups` 則是與 `window.open` 跟 `target=_blank` 這些東西有關，預設情況下你是沒辦法開新視窗的：

``` html
<iframe
  srcdoc="<script>window.open()</script>"
  sandbox="allow-scripts">
</iframe>
```

錯誤：

> Blocked opening '' in a new window because the request was made in a sandboxed frame whose 'allow-popups' permission is not set.

要把 `allow-popups` 加上去之後才能使用 `window.open`。

而這邊還有一個神奇的特性，我覺得[舊版 spec](https://www.w3.org/TR/2010/WD-html5-20100624/the-iframe-element.html) 寫得比較清楚：

> While the sandbox attribute is specified, the iframe element's nested browsing context must have the flags given in the following list set. In addition, any browsing contexts nested within an iframe, either directly or indirectly, must have all the flags set on them as were set on the iframe's Document's browsing context when the iframe's Document was created.

[新版 spec](https://html.spec.whatwg.org/multipage/origin.html#sandboxing) 則直接把那段拿掉，要去另一個地方找，不過大意是一樣的，就是 sandbox iframe 裡面所開啟的 window，會繼承 sandbox 的屬性！

這是什麼意思呢？

舉例來說，如果我有一個 `iframe.html`，內容只有這樣：`<script>alert(1)</script>`，接著我在另一個頁面 `test.html` 這樣寫：

``` html
<iframe
  srcdoc="<script>window.open('iframe.html')</script>"
  sandbox="allow-scripts allow-popups">
</iframe>
```

你會發現新開啟的 `iframe.html` 這個頁面沒辦法執行 `alert(1)`，因為它繼承了 sandbox，而 sandbox 並沒有加上 `allow-modals` 這個屬性。

再舉個例子，我們可以在網路上隨便找一個用 JS 來 render 頁面內容的網頁，像這個計算機：`https://ahfarmer.github.io/calculator/`

直接打開是沒問題的，但如果我們用一個 sandbox iframe 打開的話：

``` html
<iframe
  srcdoc="<a href='https://ahfarmer.github.io/calculator/' target=_blank>click me</a>"
  sandbox="allow-popups">
</iframe>
```

你會看到畫面變成一片黑，打開 DevTools 可以看到錯誤：

> Blocked script execution in 'https://ahfarmer.github.io/calculator/' because the document's frame is sandboxed and the 'allow-scripts' permission is not set.

再次驗證了我們上面所說的，從 sandbox iframe 中開啟的 window 會繼承 sandbox 屬性。除此之外，還有一個特性，那就是你還記得 sandbox 裡的 origin 會變成 null 嗎？因為會繼承的緣故，所以使用 `window.open` 打開的頁面，origin 也會變成 null。

這代表著什麼？代表著我們可以用 sandbox iframe + window.open 達成：

1. 關閉任意頁面的某些功能
2. 讓任意頁面的 origin 變成 null

前面有提過兩個不同的 window 可以透過 `postMessage` 來交換訊息，而在監聽訊息時都會檢查 `event.origin`，確認是否合法：

``` js
window.onmessage = function(event) {
  if (event.origin !== 'https://example.com') return
}
```

但也有些網頁會這樣檢查：

``` js
window.onmessage = function(event) {
  if (event.origin !== window.origin) return
}
```

這時候我們就可以利用上面提到的技巧繞過檢查，用 sandbox iframe 開啟頁面，就可以讓它的 origin 變成 `"null"`，然後我們再從 sandbox iframe 本身的 window 去 postMessage，就可以讓 `event.origin` 也是 `"null"`，藉此讓條件成立。不過雖然這樣做可以繞過檢查，但就算後續拿到了 XSS，可以做的事情依然有限，因為 origin 是 `"null"` 了，所以 localStorage 跟 cookie 之類的都無法存取。

有一個 [soXSS challenge](https://github.com/terjanq/same-origin-xss) 就是用這一招去解。

如果不想讓新開的視窗繼承 `sandbox` 屬性的話，可以加上 `allow-popups-to-escape-sandbox`，這樣一來，新開的視窗就會跳出 sandbox：

``` html
<iframe
  srcdoc="<a href='https://ahfarmer.github.io/calculator/' target=_blank>click me</a>"
  sandbox="allow-popups allow-popups-to-escape-sandbox">
</iframe>
```

以前曾經發生過一個問題，就是既然 `allow-popups-to-escape-sandbox` 可以跳離 sandbox，那就可以結合 `javascript:` 去執行程式碼，像是這樣：

``` html
<iframe
  sandbox="allow-modals allow-popups allow-popups-to-escape-sandbox"
  srcdoc="<a target='_blank' href='javascript:window.opener.eval(`alert(location.href)`)'>click me</a>">
</iframe>
```

細節可參考：[ Issue 1014371: Security: iframe sandbox can be worked around via javascript: links and window.opener](https://bugs.chromium.org/p/chromium/issues/detail?id=1014371) 以及 [Gate javascript: navigation on sandboxing flags. #5083](https://github.com/whatwg/html/pull/5083) 還有當初的 [commit](https://chromium.googlesource.com/chromium/src.git/+/24134160cb7f395e2d82ddecdfe7ac0659c9477c)。

最後順便提一下另一個跟 `window.origin` 類似的東西：`location.origin`，這個就是純粹根據 location 來決定 origin，跟 `window.origin` 不太一樣。根據[規格](https://html.spec.whatwg.org/multipage/webappapis.html#dom-origin-dev)中的說法：

> Developers are strongly encouraged to use self.origin over location.origin. The former returns the origin of the environment, the latter of the URL of the environment. Imagine the following script executing in a document on https://stargate.example/:

接著底下舉了個例子說明 `window.origin` 比 `location.origin` 更可靠：

``` js
var frame = document.createElement("iframe")
frame.onload = function() {
  var frameWin = frame.contentWindow
  console.log(frameWin.location.origin) // "null"
  console.log(frameWin.origin) // "https://stargate.example"
}
document.body.appendChild(frame)
```

不過我覺得似乎還是要看場合就是了。

### allow-same-origin

終於來到了最後一個 sandbox 的 flag，前面有提到一旦加上了 sandbox，origin 就會變成 `"null"`，就算可以執行 JavaScript，也無法拿到 cookie 或是 localStorage，其實非常受限。

如果要突破這個限制，就必須加上 `allow-same-origin`。我以前對這個 flag 感到很困惑，想說：「難道加上了這個 flag，iframe 跟 parent window 就會變成 same origin 嗎？」，但根據我的理解，這個 flag 其實比較像是：「保留原本的 origin」的意思，底下直接引用一段規格上的精確描述：

> The `allow-same-origin` keyword causes the content to be treated as being from its real origin instead of forcing it into a unique origin

以底下這一段為例，假設這個頁面的網址是：http://localhost:3000

``` html
<iframe
  sandbox="allow-same-origin allow-scripts allow-modals"
  srcdoc="<script>alert(window.origin)</script>"></iframe>
```

如果沒有加上 `allow-same-origin` 的話，會跳出 `"null"`，但如果加上了 `allow-same-origin`，就會正常跳出 `http://localhost:3000`，保留原本的 origin。

另外，規格上也有特別提醒，如果你在 iframe 內嵌入一個 same origin 的網頁，然後 sandbox 設置了 `allow-same-origin allow-scripts`，那 iframe 內的網頁就可以自己把 sandbox 給移掉，變成有加跟沒加一樣，像是這樣：

``` html
<iframe
  sandbox="allow-same-origin allow-scripts"
  srcdoc="<script>top.document.querySelector('iframe').removeAttribute('sandbox');location.reload();alert(1)</script>">
</iframe>
```

## iframe 總結

我相信對大部分開發者來說，以下幾個屬性應該還是挺陌生的：

1. srcdoc
2. csp
3. sandbox

有用過或是處理過相關需求可能才會知道這些東西，而對 CTF 來說，有幾個特性是我曾經看過或是可能可以被利用的：

1. src 裡放上 `javascript:` 直接 XSS
2. 幫嵌入的頁面加上 csp 以阻擋部分功能執行
3. 利用 srcdoc 是個屬性的特性放入已經被 escaped 的字串，此時會被還原成原本內容
4. 利用 sandbox + window.open 的繼承特性，達成「就算不能用 iframe 嵌入內容，也可以改變 window.origin」

## window.open

講完 iframe 以後，我們繼續來看 `window.open` 這個方法，它有三個參數，都是可選的：`window.open(url, name, features)`，然後它會回傳所開啟的 window，你就可以對這個新的 window postMessage 之類的：

``` js
var win = window.open('https://blog.huli.tw', 'huliblog')

// 要先等 window 載入好
setTimeout(() => {
  win.postMessage("hello", '*')
}, 2000)
```

新開的 window 可以用 `window.opener` 存取到開啟它的 window，這個功能我之前在[從 SessionStorage 開始一場 spec 之旅](https://blog.huli.tw/2020/09/05/session-storage-and-html-spec-and-noopener/)中有提到過。

然後，`window.open` 傳入的第二個參數就會是這個新的 window 的 name，舉例來說，如果我在新開的 window 執行 `console.log(window.name)`，就會印出 `huliblog`。

這個 `window.name` 其實是個很好玩的特性，通常在新開連結時，我們不是會這樣嗎：`<a href="https://example.com" target="_blank">open</a>`，用 `target=_blank` 的方式去開新視窗，但其實這個 target 也可以放一個字串，而這個字串就會是新開的視窗的名稱，像這樣：

``` html
<a
  href="https://example.com"
  target="example">
  open
</a>
```

你在這個新開的視窗打開 console 然後 log 一下 `window.name`，就會看到我們設定的 `example`。

那如果這個 named window 已經存在了呢？我們來試試看：

``` html
<a href="https://blog.huli.tw" target="blog">open link</a>
<button onclick="window.open('https://example.org/','blog')">open window</button>
```

按下 `<a>` 會新開一個叫做 `blog` 的 window，並且導到我的部落格，按下按鈕則是會新開一個連去別的網頁的視窗，name 也是 `blog`。你可以試試看先按連結，再按按鈕，也可以試試看反過來操作。

總之，結果都是類似的，在新開 window 時會先確認是不是有同名的 window 存在，如果有的話，就不會新開一個，而是會直接沿用那個。所以上面的範例中，如果先按了按鈕開了一個 blog 的 window，然後再按下連結的話，並不會新開視窗，只會在原本那個 window 重新導向到 href 中的網址。

除了 a 的 target 以外，form 的 target 也可以指定 window 名稱，規格上的術語叫做：「Valid browsing context name or keyword」，keyword 就是大家所熟知的那四個：`_blank`, `_self`, `_parent`, or `_top`。

根據規格 [7.1.5 Browsing context names](https://html.spec.whatwg.org/multipage/browsers.html#browsing-context-names)，只要不要是 _ 開頭都是合法的名稱：

> A valid browsing context name is any string with at least one character that does not start with a U+005F LOW LINE character. (Names starting with an underscore are reserved for special keywords.)

### 產生 named window 以及獲取 window reference

想要產生 named window 的話有幾種方式：

1. `<a target="">`
2. `<form target="">`
3. `<iframe name="">`
4. `<object name="">`
5. `<embed name="">`
6. `window.open(url, name)`

後四種你都可以直接拿到開啟的 window 的 reference，像是這樣：

``` html
<iframe name="w1" src="https://blog.huli.tw"></iframe>
<object name="w2" data="https://blog.huli.tw"></object>
<embed name="w3" src="https://blog.huli.tw"></embed>
<script>
  var w4 = window.open('https://blog.huli.tw')
  setTimeout(() => {
    console.log('w1', w1)
    console.log('w2', w2)
    console.log('w3', w3)
    console.log('w4', w4)
  }, 2000)
</script>
```

那前兩種怎麼辦呢？可以利用 `window.open` 時如果 name 已經存在的特性來拿到，像這樣：

``` html
<a target="blog" href="https://blog.huli.tw">open</a>
<button onclick="run()">get blog window</button>
<script>
  function run() {
    var blog = window.open('https://blog.huli.tw#abc', 'blog')
    console.log(blog)
  }
</script>
```

先點 open 新開視窗，然後再按下按鈕，此時我們用 `window.open('https://blog.huli.tw#abc', 'blog')` 的方式，打開一個同名的視窗，這時根據規格上的說法：

> Opens a window to show url (defaults to "about:blank"), and returns it. target (defaults to "_blank") gives the name of the new window. If a window already exists with that name, it is reused.

因為有同名的 window 存在所以會 reuse，然後我們又只是加上 `#` 而已所以不會重新導向，此時雖然 focus 會跳去新開的 window，但是靠這樣的做法就能夠拿到用 `<a target>` 所開啟的視窗的 reference（還有另外一種方式也不會跳轉，就是給一個不存在的 scheme，像是 `xxxx://test` 之類的）。

另外，這個 named window 應該是在同一個 browsing context 底下才有用，換句話說，假如我開啟了兩個網頁 A.html 跟 B.html，在 A.html 裡面開了一個叫做 blog 的 window，然後在 B.html 執行 `window.open('', 'blog')`，此時並不會拿到 A.html 開的 blog window，而是會自己新開一個，因為 A 跟 B 處於不同的 browsing context。

但是換頁的狀況就不一樣了，這個滿好玩的，假設我現在在 `http://localhost:5555/A.html`，然後開了一個叫做 blog 的 window，開完之後導到 `http://localhost:5555/B.html`：

``` html
<button onclick="run()">run</button>
<script>
  function run() {
    window.open('https://blog.huli.tw', 'blog')
    location = 'http://localhost:5555/B.html'
  }
</script>
```

接著我在 B.html 裡面也開一個同名的 window：`window.open('', 'blog')`，此時就會拿到剛剛 A.html 開啟的 blog window，而不是新開一個。另外，如果我從 B.html 重新導向去 `https://blog.huli.tw`，接著在 console 執行 `window.open('', 'blog')`，一樣也可以拿到剛剛 A.html 開啟的 blog window。

但如果我重新導向到 `https://example.org`，就會新開分頁，拿不到 blog window。

看起來如果同一個分頁底下跳轉到了跟 opener 或是跟開啟的 window same origin 的網頁，似乎就會是同個 browsing context，這個特性滿有趣的（該找時間研究一下 browsing context 了）。

### window.name 的利用

有時候 XSS 會受長度限制，例如說 username 有 XSS 漏洞，但是只有 32 個字可以用之類的，這時候我們就會希望我們的 payload 越短越好。如果想要越短越好，自然就會需要利用其他資訊來帶入真正想執行的程式碼，才能控制長度。

舉例來說，你可以把想執行的程式碼放在網址的 `#` 後面，然後 payload 寫 `eval(location.hash.slice(1))` 之類的。

而 `window.name` 就是一個很常被利用的東西，我們可以先在 A 網頁設置 `window.name` 以後跳轉到 B 網頁，此時 B 網頁的 `window.name` 就會是我們剛剛所設定好的：

``` js
name = 'hello, world!'
location = 'https://example.org'
```

不過這招只有在 Chromium based 的瀏覽器（Chrome 跟 Edge）上有效而已，因為根據規格的說法，如果跳轉的頁面不是 same origin 的話，name 應該要被清掉才對。

Chromium 有一個 bug 就是關於這個：[Issue 706350: Clear browsing context name on cross site navigation or history traversal](https://bugs.chromium.org/p/chromium/issues/detail?id=706350&q=window.name&can=2)，從 2017 年開到現在還沒修好，中間一度有修過但引起其他 bug，就 revert 回來了。

Safari 是第一個實作的，而 2021 年 1 月時 FireFox 也實作了，於是 Chromium 就變成異類了，裡面還有附上這個很讚的網頁，可以看每個瀏覽器的測試狀況：https://wpt.fyi/results/html/browsers/windows/clear-window-name.https.html?label=master&label=experimental&aligned

### 偵測新開 window 的載入完成

iframe 有 onload 事件，可以透過這個事件得知是否載入完成。可是用 `window.open` 打開後的視窗，並沒有這個事件可以監聽（除非是 same origin），所以你不知道它什麼時候會載入完成。

但沒關係，如果你打開的是一個 cross origin 的網頁，你可以利用存取 `window.origin` 或其他屬性會出錯的特性來實做一個簡單的輪詢：

``` js
var start = new Date()
var win = window.open('https://blog.huli.tw')
run()
function run() {
  try {
    win.origin
    setTimeout(run, 60)
  } catch(err) {
    console.log('loaded', (new Date() - start), 'ms')
  }
}
```

在網頁還沒載入好的時候，`win.origin` 會是自己，載入好才會變成開啟的網頁，因此載入完成後存取 `win.origin` 會因為 cross origin 出事，被 catch 捕捉到。

### 偵測某個 name 的 window 是否存在

我們有沒有辦法偵測某個 name 的 window 是否存在呢？

前面我們有提到如果新開一個 named window 時已經有同名的 window 存在，就不會新開一個，而是會跳轉，我們可以利用這點的差異來做偵測，還可以搭配前面提過的 iframe sandbox，用這個特性阻止開新視窗。

以上概念來自 [Easter XSS by @terjanq](https://easterxss.terjanq.me/writeup.html#Dark-Arts-solution)，程式碼有稍微修改一下，只針對 Chrome：

``` html
<body>
  <a href="https://blog.huli.tw" target="blog">click</a>
  <button onclick="run()">run</button>
  <iframe
    name=f
    sandbox="allow-scripts allow-same-origin allow-popups-to-escape-sandbox allow-top-navigation">
  </iframe>
  <script>
    function run(){
      var w = f.open('xxx://abcde', 'blog')
      if (w) {
        console.log('blog window exists')
      } else {
        console.log('blog window not exists')
      }
    }
  </script>
</body>
```

## 總結

這篇簡單記錄了一些 iframe 跟 window 的有趣特性，不過有些東西還是沒有研究透徹，例如說 browsing context 的相關名詞還有怎樣算在同一個 browsing context 底下之類的，這些就要看 spec 慢慢吸收了。


參考資料：

1. https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox
2. https://cloud.google.com/blog/products/data-analytics/iframe-sandbox-tutorial
3. https://www.w3.org/TR/2010/WD-html5-20100624/the-iframe-element.html
4. https://www.html5rocks.com/en/tutorials/security/sandboxed-iframes/
5. https://googlechrome.github.io/samples/allow-popups-to-escape-sandbox/
6. https://xsleaks.dev/

