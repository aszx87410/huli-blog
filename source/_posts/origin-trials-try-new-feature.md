---
title: 透過 Chrome Origin Trials 搶先試用新功能
catalog: true
date: 2022-02-02 19:27:06
tags: [Front-end]
categories: [Front-end]
---

如果你的網站想要搶先體驗瀏覽器還沒有正式上線的新功能，該怎麼做呢？

通常這些功能已經做好了，只是沒有開放而已，因此瀏覽器都會提供一些可以開關的 flag，只要把開關打開，就能夠搶先體驗到新功能，但我們通常不太可能叫使用者自己把開關打開。

因此，Chrome 提供了一個機制叫做 [origin trials](https://developer.chrome.com/blog/origin-trials/)，你可以在網站上註冊，取得一組 token，接著只要設置好以後，如果使用者是用 Chrome 造訪你的網站，那就會開啟新功能，讓你的網站可以使用。

這篇就來簡單介紹一下這個機制該如何使用。

<!-- more -->

## 挑選功能

這個頁面有目前 Chrome Origin Trials 提供的所有功能：https://developer.chrome.com/origintrials/#/trials/active

![feature list](/img/origin-trial/p1-all.png)

每個功能點進去以後都會有詳細的說明，舉例來說，我們可以點進去：「App History API」，就會看到詳細的說明：

![detail](/img/origin-trial/p2-detail.png)

上面會簡單介紹一下這個功能在幹嘛，以及開放的版本跟結束日期，通常還會再搭配兩個資源，例如說「Learn More」按下去以後可能會連到一篇介紹這個功能的文章，像這篇：[Modern client-side routing: the App History API](https://web.dev/app-history-api/)，就是在介紹 App History API 的基本使用。

而另一個資源則是 Chrome Platform Status，點下去之後會出現更詳細的頁面，頁面裡面給出目前的狀況跟預計的發佈時間，還有 spec 的連結，以及其他瀏覽器對於這個功能是否會跟進：

![status](/img/origin-trial/p3-spec.png)

會開放給 origin trials 的功能大部分是新功能，不過有少部分會是已經被淘汰或是快要被淘汰的功能。

這是為什麼呢？因為有些網站可能還需要多一點時間更新，就可以來這邊申請 origin trials，瀏覽器就會先把舊功能留著，讓網站有更多時間可以更新。因此，origin trials 提供的不只是新功能，也會有已經被淘汰的功能。

總之呢，如果你好奇有哪些新功能可以試用，可以來這個網站尋寶。

## 試用功能

接著我們實際來試用看看 App History API 這個功能，這個新功能是設計給 SPA 用的，因為現有的 History API 誕生時 SPA 還沒有開始流行，所以有很多需求都不太符合，需要一組新的 API。

詳細的介紹可以參考：[Modern client-side routing: the App History API](https://web.dev/app-history-api/)

總之呢，如果這個功能可以用的話，我們應該要可以存取 `appHistory` 這個東西，現在因為功能還沒開放，所以存取只會出現：`Uncaught ReferenceError: appHistory is not defined` 的錯誤。

在 Chrome Origin Trials 的頁面挑好想用的功能以後，點進去之後再點 REGISTER，就會進到註冊頁面，接著要輸入想試用的網站的 origin，畢竟都叫做 origin trials 了，就是「指定哪些 origin 可以試用」的意思，像這樣：

![form](/img/origin-trial/p4-form.png)


申請完成以後，就會給你一組 token 還有過期時間，會跟你說可以用到什麼時候，像這樣：

![token](/img/origin-trial/p5-token.png)

接下來很簡單，只要在你想試用的頁面上加上一個 meta tag 就好：

``` html
<meta http-equiv="origin-trial" content="TOKEN">
```

也可以用 HTTP header：`Origin-Trial: TOKEN `

為了方便 demo，我準備了一個頁面，內容如下：

``` html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <meta http-equiv="origin-trial" content="AnmLpSv09ah5QRsTiszCUGI8WzgiH5OByD2I/kQjnbSSmN2DMnuvRsbPWfqN7QmDJbNH6cUBvsay+UlJBwQyXwcAAABXeyJvcmlnaW4iOiJodHRwczovL2Fzeng4NzQxMC5naXRodWIuaW86NDQzIiwiZmVhdHVyZSI6IkFwcEhpc3RvcnkiLCJleHBpcnkiOjE2NDc5OTM1OTl9">
</head>
<body>
  origin trial demo
  <script>
    if (window.appHistory) {
      document.writeln('appHistory exists!')
    } else {
      document.writeln('appHistory is not defined')
    }
  </script>
</body>
</html>
```

會偵測有沒有 appHistory，並將結果顯示在畫面上。

設置完成以後，造訪這個頁面：https://aszx87410.github.io/demo/misc/origin-trial.html

如果你用 Chrome 以外的瀏覽器開，會看到：「appHistory is not defined」，用 Chrome 的話，應該會看到：「appHistory exists!」。

打開 devtool -> Application -> Frames -> top，可以看到我們順利啟用了 origin trials：

![devtool](/img/origin-trial/p6-devtool.png)

沒錯，這整個流程就是這麼簡單。

## 結語

這篇簡單介紹了一下 Origin Trials 這個機制，可以透過這個機制去申請一組 token，將其放到網站上以後，就能讓 Chrome 的使用者們搶先試用新功能。

像是 three.js 的範例頁面，就有用到 origin trial 來開啟 WebGPU 相關功能：[three.js/examples/webgpu_skinning.html](https://github.com/mrdoob/three.js/blob/r137/examples/webgpu_skinning.html#L9)

除此之外，就算沒有想要體驗新功能，也可以偶爾來這邊看看，光是看看就能夠收穫不少，例如說我從列表中就看到了「App History API」、「Private Network Access from non-secure contexts」以及「User Agent Reduction」這幾個從來沒聽過的東西。