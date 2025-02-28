---
title: 從「為什麼不能用這個函式」談執行環境（runtime）
catalog: true
date: 2022-02-09 21:10:50
tags: [Front-end, JavaScript]
categories: [JavaScript]
---

我認為在理解 JavaScript 這個程式語言的時候，還需要認識到「執行環境（runtime）」這件事情，你心中的架構圖才會完整。有許多人並沒有意識到這一環，導致對於 JavaScript 或是一些技術的理解有認知上的差異；因此這一篇，就讓我們好好來談談執行環境。

附註：除了 runtime 叫做執行環境以外，execution environment 也叫做執行環境，但這兩個是完全不同的東西。為了避免歧義，底下會盡量用原文 runtime 這個詞。

另外，runtime 有許多意思，這邊的 runtime 比較像是 runtime environment 的意思。

<!-- more -->

## 存在又不存在的函式

故事的主角小明在工作上接到了一個需求，那就是要把一個字串做 base64 編碼。

在 JavaScript 裡面，我們要怎麼把一個字串轉成 base64 編碼？有一個叫做 [btoa](https://developer.mozilla.org/en-US/docs/Web/API/btoa) 的函式可以做到這件事情，你可以打開 Chrome 的 devtool console，輸入以下程式碼：

``` js
console.log(btoa('hello')) // aGVsbG8=
```

如果要把字串從 base64 轉回來，把函式名稱轉一下，變成 `atob` 即可：

``` js
console.log(atob('aGVsbG8=')) // hello
```

有些人可能會跟我一樣好奇，為什麼函式要取做 `atob` 跟 `btoa`，我自己一開始很容易誤會 `atob` 的 b 代表 base64 的意思，所以是把東西轉成 base64，但其實正好相反，`atob` 是把字串從 base64 轉回來。

根據 [Why were Javascript `atob()` and `btoa()` named like that?](https://stackoverflow.com/questions/33854103/why-were-javascript-atob-and-btoa-named-like-that) 的解答，`a` 是 ASCII 的意思，`b` 是 binary，而不是 Base64，所以 `atob` 指的是把 ASCII 的資料（也就是字串）轉成 binary，就是把 base64 編碼過的字串轉回原始的形式。

雖然說在 JavaScript 裡面無論是 `atob` 還是 `btoa`，接收的參數都是字串，沒有什麼 binary，因此上面的解釋看起來有點怪，但如果你把眼光放寬，不要侷限在 JavaScript 的話，就會變得比較合理。

舉例來說，base64 可以把任何二進位（binary）的資料轉成字串，這是它最有價值的地方。例如說你可能有用過 data URI，其中一個用法就是把圖片用 base64 編碼成字串。

因此，`btoa` 代表著 binary to ASCII，也就是把任何東西用 base64 來編碼，輸出會是一個 base64 編碼過的字串，`atob` 則相反，ASCII to binary，就是把 base64	編碼過的字串還原成原始的形式。

好，講了這麼多 base64 的東西以後，讓我們回到重點。

小明查到要用 `atob` 跟 `btoa` 以後，順利解決了工作上的需求，在網頁上完成了這個功能。過了兩個月，主管要他在一個用 Node.js 跑的伺服器上面也實作同樣的功能。

小明心想：「這有什麼難的？」，於是就一樣用了 `btoa`，可是這次卻出現了不同的結果，居然噴出了錯誤：

> Uncaught ReferenceError: btoa is not defined

小明百思不得其解，為什麼同樣的函式，之前可以用，現在卻不能用了？難道這個函式同時存在也不存在於 JavaScript 之中？

會發生這件事情，就是因為小明心中並沒有 runtime 的概念。

## 什麼是 runtime？

JavaScript 是一個程式語言，所以像 `var`、`if else`、`for` 或是 `function` 等等，這些都是 JavaScript 的一部分。但是除了語言本身以外，JavaScript 需要有地方執行，而這個地方就叫做執行環境（runtime），舉個例子，大家最常用的 runtime 就是「瀏覽器」。

所以你的 JavaScript 是在瀏覽器這個 runtime 上執行的，而這個 runtime 會提供給你一些東西使用，例如說 DOM（document）、`console.log`、`setTimeout`、`XMLHttpRequest` 或是 `fetch`，這些其實都不是 JavsScript（或是更精確地說，ECMAScript）的一部分。

這些是瀏覽器給我們使用的，所以我們只有在瀏覽器上面執行 JavaScript 時才能使用。開頭時小明所使用的 `atob` 跟 `btoa` 也是，這兩個函式並不是 ECMAScript 規格中的一部份，而是瀏覽器提供給 JavaScript 的，這也是為什麼我們在使用 Node.js 時，就突然沒辦法用了，因為 Node.js 這個 runtime 並沒有提供這兩個函式。

以下圖為例，左邊是 Node.js 這個 runtime，中間是 JS 本身的東西，右邊則是瀏覽器這個 runtime，各有各的東西：

![](/img/javascript-runtime/p1.png)

因此你可能有過類似的經驗，想說為什麼一樣的 code 搬到 Node.js 去就沒辦法執行。現在你知道了，那是因為 Node.js 並沒有提供這些東西，例如說 `document` 或是 `atob`，你沒辦法直接在 Node.js 裡面使用它（如果可以，那就代表你有用其它 library 或是 polyfill）。

相反過來也是，你用 Node.js 執行一段 JavaScript 程式碼時，你可以用 `process` 或是 `fs`，但你在瀏覽器上面就沒辦法。不同的 runtime 會提供不同的東西，你要很清楚現在是在哪個 runtime。

## 該如何分辨某個功能是 runtime 提供的，還是 JS 內建的？

靠著一個原則，就可以有大概八成的機率分辨正確，那就是：「這個功能是否跟 runtime 本身有關？」

舉例來說，DOM 跟 BOM 這兩組 API，就跟瀏覽器有很大的關係。在使用 Node.js 這個 runtime 時，我們不會有 document，因為根本沒有所謂的頁面，也不會有 localStorage，因為那是瀏覽器才有的東西，所以像是 `document` 跟 `localStorage`，都是瀏覽器給的，而不是 JavaScript 這個語言本身的東西。

又或者像是 `process`，可以讀到許多執行緒相關的資訊，瀏覽器不可能讓你做這種事情，所以顯然在瀏覽器上面無法使用，是 `Node.js` 這個 runtime 專屬的東西。

而另外兩成就是一些例外了，看起來與 runtime 無關，但其實有關。例如說 `btoa`，只是轉成 Base64 而已，跟 runtime 有什麼關係？可是好巧不巧，它就是由 runtime 所提供的。

還有 `console`，這其實也是 runtime 提供的，而且有個特性要注意，那就是有時候不同的 runtime 會提供相同的東西。例如說 `console` 跟 `setTimeout`，在瀏覽器以及 Node.js 都有，可是他們都不是 JavaScript 的一部份，而是 runtime 提供的。

但儘管他們看起來一樣，內部實作卻是完全不同，表現方法也可能不同。舉例來說，瀏覽器的 `console.log` 會輸出在 devtool 的 console，而 Node.js 則是會輸出在你的 terminal 上面。

`setTimeout` 跟 `setInterval` 也是，雖然說瀏覽器跟 Node.js 都有，可是背後的實作卻完全不同。

如果你想確認一個 API 是不是 runtime 提供的，有個簡單又正確的方式，那就是去找 ECMAScript 的規格或是 MDN 來看。以 `atob` 為例，[MDN](https://developer.mozilla.org/en-US/docs/Web/API/atob#specifications) 下方 Specifications 的段落中，你可以看見它的出處是 HTML Standard，並不是 ECMAScript，就代表它並不是 ECMAScript 的一部分：

![](/img/javascript-runtime/p2.png)

簡單來說呢，只要你在 ECMAScript 的規格上找不到它，就代表它是由 runtime 所提供的。

在 MDN 上面，這些並不是由 ECMAScript 原生提供，而是由瀏覽器所提供的 API，叫做 Web API：https://developer.mozilla.org/en-US/docs/Web/API

底下我列幾個比較常誤會是 JavaScript 的一部分，但其實是 runtime 提供的 API：

1. console
2. fetch
3. performance
4. URL
5. setTimeout
6. setInterval

## 從不同 runtime 學習 JavaScript

有許多人在學習 JavaScript 時，第一個碰到的都是瀏覽器，而且說不定會留下：「JavaScript 只能在瀏覽器上執行」這個印象。

除了瀏覽器以外，JavaScript 還有另一個 runtime 叫做 [Node.js](https://nodejs.org/en/)，官網上的介紹是：

> Node.js® is a JavaScript runtime built on Chrome's V8 JavaScript engine.

透過 Node.js 這個 runtime，我們的 JavaScript 程式碼可以脫離瀏覽器執行。我很推薦大家都去看一下 Node.js，使用一下它提供的 API，像是 `process` 或是 `fs` 之類的，寫一點小玩具出來。

當你熟悉不同的 runtime 以後，你會發現 runtime 除了會提供更多 API 以外，它同時也是個限制器。

當你的 runtime 是瀏覽器時，你可以做的功能自然而然就會受到瀏覽器限制。舉例來說，你不能「主動讀取」電腦中的檔案，因為瀏覽器基於資安上的考量，不讓你做這件事情。你也不能把電腦重新開機，因為瀏覽器不讓你這樣做。在進行網路相關操作的時候，也會受到同源政策跟 [CORS](https://blog.huli.tw/2021/02/19/cors-guide-1/) 的限制，這些都是瀏覽器這個執行環境才有的限制。

上面講的這些限制，一旦你換了個 runtime，就都沒問題了。使用 Node.js 來執行程式碼時，你可以讀取檔案，可以把電腦重開機，也沒有什麼同源政策跟 CORS 這些限制，你想幹嘛就幹嘛，想發送 request 給誰就給誰，response 都不會被攔截住。

之所以建議大家去學習 Node.js，是為了讓大家清楚意識到自己在執行程式碼時，所受的限制是誰給的限制。是 JavaScript 本身的限制，還是 runtime 給的限制？

意識到這點以後，就會對 JavaScript 的認知更為全面。

## 結語

當你在使用 JavaScript 時，有些 API 是這個語言本身內建的，例如說 `JSON.parse` 或是 `Promise`，你可以在 ECMAScript 的規格書中找到他們的說明。

而有些 API 則是 runtime 提供的，例如說 `atob`、`localStorage` 或是 `document`，就是瀏覽器所提供的 API，一旦脫離了瀏覽器這個 runtime，你就沒有這些 API 可以用。

但這並不代表在瀏覽器跟在 Node.js 這兩個 runtime 上面都可以使用的 API，就是語言內建的 API。舉例來說，`console` 以及 `setTimeout` 還有最近 [Node.js 也要原生支援的 fetch](https://github.com/nodejs/node/pull/41749)，在瀏覽器以及 Node.js 上面都可以使用，可是它們都是 runtime 提供的，

也就是說，瀏覽器實作了 `console` 與 `setTimeout` 的 API，時做了計時器的機制，並且提供給 JavaScript 使用，而 Node.js 也實作了同樣的 API，也提供給 JavaScript 使用。雖然說表面上看起來是同一個 function，但背後的實作卻不同，這就好像你去全家可以買到鮪魚飯糰，你去 711 也可以買到鮪魚飯糰，雖然說都是鮪魚飯糰，但背後的供應商其實不一樣，製作方法也不同。

有了 runtime 的概念之後，以後如果碰到某個 function 在瀏覽器可以用，但是在 Node.js 上不能用，你就知道是為什麼了。