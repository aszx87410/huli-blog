---
title: 你需要注意的 console.log 問題
catalog: true
header-img: /img/header_img/article-bg.png
date: 2020-03-23 23:08:32
tags: [Web]
categories:
  - Web
---

## 前言

會寫這篇是因為我相信一定很多人都碰到過這個問題，簡單一句話總結就是：「用console.log 印出物件時，印出的值跟想像中不一樣」，我們來看看底下的程式碼：

<!-- more -->


```js
var obj = {value: 'before'}
console.log('before:', obj) // 應該要是 {value: 'before'}
obj.value = 'after'
console.log('after:', obj)
```


這是一段很簡單的程式碼，log 出一個 object，改變某個屬性，然後再 log 一次。理所當然地，預期第一個 log 的結果會是：`before: {value: 'before'}`，第二個 log 應該要是：`after: {value: 'after'}`。

可是呢，現實與你想像的不太一樣。實際情況是：

1. 如果你先執行這段程式碼才打開 console，很有可能看到第一個 log 出來的結果是`{value: 'after'}`，而不是`{value: 'before'}`
2. 如果先把 console 打開才執行，儘管乍看之下是對的，但如果你點開 console 裡面 object 的詳細資料，你會看到 `{value: 'after'}`，如下圖，接著開始懷疑人生，不知道該相信誰。


![](/img/console/bug.png)

不相信的話可以自己試試看：[Demo 連結](https://aszx87410.github.io/demo/console_log_bug/)

在查看 log 的時候，開發者應該會預期看到 log 當時的狀態，但是點開物件詳細資料的時候，看到的卻會是最新的狀態，而非印出當時的狀態。所以才會有上面附圖的狀況，preview 顯示的是 log 當下的狀態，展開則是最新的狀態，所以兩者不一致。

有些人可能會認為如果 preview 都是對的，那就看 preview 就好。不過 preview 是有限制的，當你的物件太多屬性的時候，沒有辦法全部顯示出來，一定要把物件展開才能看到所有屬性。一旦這種情況發生，就沒辦法只看 preview，一定要把物件展開，可是就沒辦法看到 log 當下的值了。

這只是一個簡單的範例而已，或許你會覺得沒什麼，但是這問題可怕的點就在於第一次碰到它時，往往都是在實際的開發情境而不是像這樣簡單的範例。而開發者們會因為不知道有這個情形，導致自己不斷思考到底程式是哪裡出了錯，怎麼印出來的東西跟自己想像中不一樣，殊不知是 console 這東西跟自己想的不一樣。

這個問題基本上「不會被修掉」，所以對待它最好的方法就是：

1. 知道有這個問題的存在，以後才能多注意
2. 知道如何暫時應付這個問題
3. 知道為什麼這問題不會被修掉

## 再次觀察問題

前面開頭有提到過可能會出現的兩個問題，接著我們來試試看各個瀏覽器對於兩個不同場景底下的結果到底如何。

先附上拿來測試的範例程式碼：

``` js
var obj = {value: 'before'}
console.log('before:', obj) // 應該要是 {value: 'before'}
obj.value = 'after'
console.log('after:', obj)
```

1. 場景一：先執行這一段程式碼，再打開 console 看結果
2. 場景二：先打開 console，再執行程式碼看結果

底下是在 macOS Mojave 10.14.4 的各個瀏覽器的執行結果：

### Chrome 80.0.3987.149

#### 場景一：先執行程式再開 console

只顯示 Object 字樣，不顯示 preview：

![](/img/console/chrome-1.png)


#### 場景二：先開 console 再執行程式

console preview 印出來的內容是對的，把 object 展開之後則印出物件最新的內容。

![](/img/console/bug.png)

### Firefox 74.0

#### 場景一：先執行程式再開 console

顯示錯誤的 preview，兩個都是 `{value: 'after'}`：

![](/img/console/ff-1.png)


#### 場景二：先開 console 再執行程式

console preview 印出來的內容是對的，把 object 展開之後則印出物件最新的內容。

![](/img/console/ff-2.png)

### Safari 12.1（14607.1.40.1.4）

#### 場景一：先執行程式再開 console

只顯示 Object 字樣，不顯示 preview：

![](/img/console/safari-1.png)


#### 場景二：先開 console 再執行程式

console preview 印出來的內容是對的，把 object 展開之後則印出物件最新的內容。

附註：因為物件如果太短的話不能展開，所以我新增了幾個屬性

![](/img/console/safari-2.png)

-----

從以上實驗可以得到幾個結論：

1. 對於場景一：「先執行程式再開 console」，Chrome 與 Safari 都不會有 preview，而 Firefox 會顯示錯誤的 preview。
2. 對於場景二：「先開 console 再執行程式」，三個瀏覽器的行爲是一致的，preview 都是對的，把物件展開看詳細內容則會是物件最新的狀態。

## 問題發生的原因

這個問題其實很久以前就存在了，在好幾年前就已經有 Stackoverflow 的討論串了：

1. [Google Chrome console.log() inconsistency with objects and arrays](https://stackoverflow.com/questions/24175017/google-chrome-console-log-inconsistency-with-objects-and-arrays)
2. [console.log() shows the changed value of a variable before the value actually changes](https://stackoverflow.com/questions/11284663/console-log-shows-the-changed-value-of-a-variable-before-the-value-actually-ch)
3. [Is Chrome's JavaScript console lazy about evaluating arrays?](https://stackoverflow.com/questions/4057440/is-chromes-javascript-console-lazy-about-evaluating-arrays)

在各個瀏覽器的 issue tracker 也可以找到相關紀錄：

1. [Webkit: Bug 35801 - Web Inspector: generate preview for the objects dumped into the console upon logging.](https://bugs.webkit.org/show_bug.cgi?id=35801)
2. [Mozilla: console.log doesn't show objects at the time of logging if console is closed](https://bugzilla.mozilla.org/show_bug.cgi?id=754861)
3. [Chromium: Issue 1041063: console.log() does not log the correct fields of an object at the instant it is called](https://bugs.chromium.org/p/chromium/issues/detail?id=1041063&q=console%20preview&can=1)
4. [Chromium: Issue 760776: Console Array data updates after console.log](https://bugs.chromium.org/p/chromium/issues/detail?id=760776&q=console.log%20preview&can=1)

連 MDN 對於 `console.log` 的[文件](https://developer.mozilla.org/en-US/docs/Web/API/Console/log)，都有一塊特別講這個問題：

> Don't use console.log(obj), use console.log(JSON.parse(JSON.stringify(obj))).

> This way you are sure you are seeing the value of obj at the moment you log it. Otherwise, many browsers provide a live view that constantly updates as values change. This may not be what you want.

在上面的連結裡面也都有人出來解釋為什麼會有這個問題，還有為什麼沒辦法修掉。

首先呢，在 devtool 打開的情形下，preview 的內容基本上都是對的，所以這一點完全沒問題。但是把 object 展開以後，顯示的並不是 log 當下的值，而是物件最新的狀態，就是這點造成大家混淆，因為開發者會預期儘管把 object 展開，應該也要是 log 當下的狀態才對。

但如果要達成這個功能，每一次 `console.log`，瀏覽器就要把當下的值都複製一份起來，才能保證使用者在展開 object 時能看到 log 當時的內容。

套用上面 Issue 其他人的話，他們是這麼說的：

> We can't get a copy of the heap every time you console.log...

> I don't think we are ever going to fix this one. We can't clone object upon dumping it into the console and we also can't listen to the object properties' changes in order to make it always actual.

所以在實作上有困難，沒辦法做這件事。既然沒辦法修好，那就只能多留意這種情形了，一定要記得使用`console.log`印出物件的時候：

1. Preview 基本上是正確的（如果你 log 的時候 devtool 就有開著）
2. 展開後所看到的完整資料會是物件最新的狀態，而不是 log 當時的狀態。

Chrome 在 console 裡面其實有加上一個貼心的小 icon 提醒你這件事：

![](/img/console/chrome-notice.png)

## 對付問題的方法

解決方法上面 MDN 其實就有寫到了，就是在印出物件時利用 `JSON.parse(JSON.stringify(obj))` 把物件當下的狀態複製起來，然後重新產生一個物件（就是俗稱的深拷貝啦），就能確保印出來的是當前的狀態了，像是這樣：

``` js
function log() {
  var obj = {value: 'before'}
  console.log('before:', cp(obj))
  obj.value = 'after'
  console.log('after:', cp(obj))
}

function cp(obj) {
  return JSON.parse(JSON.stringify(obj))
}
```

或者還有一個方法，那就是盡量不要把整個物件給印出來。與其印出整個物件，不如印出你真正想要觀察的值。

或是乾脆直接用 `debugger` 把程式給暫停再來看當前的值是多少，這也是一種方法。


## 總結

許多新手在接觸 `console.log` 時一不小心就會踩到這個坑，然後過了許久才發現根本不是自己程式碼的問題，是 log 出來的內容跟想像中不同。所以希望這篇可以讓大家都知道有這個問題存在，以後在使用 `console.log` 印出物件時，就可以多留意一下這個狀況。

話說，基本上我個人在印物件時還是會直接使用 `console.log` 而不是採用上面提到的方法，因為直接印還是比較方便一點。但因為我知道`console.log`有這個問題，所以一旦我發現我印出來的物件跟想像中不一樣，就會改用上面提到的深拷貝來複製值，確認到底是哪裡有問題。

最後，請大家記得 array 也是物件的一種，所以陣列也會有同樣的情形發生。