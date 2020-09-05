---
title: 從 SessionStorage 開始一場 spec 之旅
date: 2020-09-05 10:27:57
tags: [Web, Front-end]
categories:
  - Web
---

## 前言

如果你想把東西存在網頁前端，也就是存在瀏覽器裡面，基本上就是以下這幾個選項：

1. Cookie
2. LocalStorage
3. SessionStorage
4. IndexedDB
5. Web SQL

後兩者應該滿少用到的，而最後一個 Web SQL 也早在幾年前就被[宣告](https://www.w3.org/TR/webdatabase/)已經不再維護了。因此在談到儲存資料的時候，大部分的人提的還是前三種，其中又以前兩種最多人使用。

畢竟在前端儲存資料時，大部分資料都希望能儲存一段時間，而 cookie 跟 localStorage 就是被設計在這種情形下用的，可是 sessionStorage 不是，它只適合儲存非常短期的資料。

不知道大家對 sessionStorage 的理解是不是跟我一樣，先說說我的理解好了：

> sessionStorage 跟 localStorage 最大的差別在於前者只會存在於一個分頁當中，你分頁關掉之後資料就清除了，所以新開分頁，就會有新的 sessionStorage，在不同分頁不會共用。但後者如果是相同的網站，可以共用同一個 localStorage

但我想問大家的是：有沒有可能有一種情況，我在分頁 A 的 sessionStorage 存了一些東西，然後有一個新的分頁 B，也可以讀到分頁 A 的 sessionStorage？

你可能以為沒有，我以前也以為沒有，我同事也這樣認為。

但偏偏就是有。

<!-- more -->

## 我不懂 sessionStorage

如同前言所說的，我對 sessionStorage 的理解就是它只會存在於一個 tab 當中，tab 關掉就沒了，然後開新 tab 也不會共享到原本的資料，所以可以很安心地假設 tab 裡的 sessionStorage 只有他自己讀得到。

但之前在公司內部的技術分享上，我主管 howard 分享了一個案例：

> 假設有一個頁面 A，用了 sessionStorage 儲存了一些資料，然後網站裡有個 a 的超連結，點了連到同個 origin 下的頁面 B，應該很多人會預期頁面 B 的 sessionStorage 是空的。但沒有，它會沿用頁面 A 的。

沒錯，就是這個案例打破了我對 sessionStorage 的天真幻想，原來兩個不同的分頁是有可能共用同一份 sessionStorage 的。

或是嚴格來講，其實不是共用，而是原本的 sessionStorage 會「複製」一份到新開的 tab 去，如果在頁面 A 改變了值，頁面 B 拿不到更新後的值。頁面 B 只是把「點開連結那一刻的 sessionStorage」複製過去而已。

我準備了一個 demo 讓大家玩，就是兩個簡單的頁面而已，先附上網址：[sessionStorage demo](https://aszx87410.github.io/demo/session_storage/index.html)。

頁面長這個樣子：

![p1-demo](/img/session_storage/p1-demo.png)


這頁面的程式碼很簡單，基本上就是設置一個 `name=guest` 的 sessionStorage，然後把它顯示在螢幕上。然後有一個 a 可以連到新的 tab，另一個按鈕隨機更新 sessionStorage 裡的值：

``` html
<!DOCTYPE html>

<html>
<head>
  <title>SessionStorage 範例</title>
  <meta charset="utf-8">
  <script>
    sessionStorage.setItem('name', 'guest')
  </script>
</head>

<body>
  <div>
    進來這網站之後，會自動幫你設置一個 sessionStorage，name="guest" <br>
    你可以打開 devtool -> applications 或是打開 console，或檢查下面內容確認
  </div>
  <div>
    sessionStorage 內容：<b></b>
  </div>
  <button id="btn">改變 sessionStorage 內容</button><br>
  <a href="new_tab.html" target="_blank">Click me to see magic(?)</a>
  <script>
    document.querySelector('b').innerText = sessionStorage.getItem('name')
    console.log('sessionStorage', sessionStorage)
    console.log('sessionStorage.name', sessionStorage.name)

    btn.addEventListener('click',() => {
      sessionStorage.setItem('name', (Math.random()).toString(16))
      document.querySelector('b').innerText = sessionStorage.getItem('name')
      console.log('updated sessionStorage', sessionStorage)
      console.log('updated sessionStorage.name', sessionStorage.name)
    })
  </script>
</body>
</html>
```

如果你點了那個 a 到了新的頁面以後，就會看到 sessionStorage 被複製過來了：

![p2-demo2](/img/session_storage/p2-demo2.png)


這個新頁面的程式碼如下，裡面沒有一行是在設置 sessionStorage：

``` html
<!DOCTYPE html>

<html>
<head>
  <title>SessionStorage 範例</title>
  <meta charset="utf-8">
</head>

<body>
  <div>
    這網站沒有任何設置 sessionStorage 的程式碼<br>
    但如果你是從 index.html 的 a 連結點來的，你可以存取得到
  </div>
  <div>
    sessionStorage 內容：<b></b>
  </div>
  <button id='btn'>重新抓取</button><br>
  <a href="index.html">Back to index.html</a>
  <script>
    document.querySelector('b').innerText = sessionStorage.getItem('name')
    console.log('sessionStorage', sessionStorage)
    console.log('sessionStorage.name', sessionStorage.name)
    btn.addEventListener('click', () => {
      document.querySelector('b').innerText = sessionStorage.getItem('name')
    console.log('latest sessionStorage', sessionStorage)
    console.log('latest sessionStorage.name', sessionStorage.name)
    })
  </script>
</body>
</html>
```

因為是新開分頁的關係，所以現在你有兩個分頁，一個是原本的 index.html，另一個是這個新開的 new_tab.html，你可以在 index.html 按下「改變 sessionStorage 內容」，就會看到畫面更新，接著再去 new_tab.html，按下重新抓取，會發現值並沒有改變。

這就是我前面所說的，其實是「複製」，並不是「共用」。因為共用的話一個地方變了，另一個地方會跟著變，但複製的話原本的內容跟複製後的內容，是不會互相干擾的。

當初聽到這個行為之後嚇了一跳，畢竟跟自己認知的不一樣。震驚完之後第一件想到的事情是：「那有辦法可以不要這樣嗎？」，同事有試過幾個方法但是都不行，而我腦中瞬間就聯想到會不會 a 上面有一些屬性可以調整，例如說 noopener, noreferrer 或是 nofollow 之類的，但實際去試以後都沒有效。

後來找了一下資料，終於發現了一個正解，也因為想把相關知識補足，來去看了 sessionStorage 的 spec，發現寫得其實滿不錯的，就想跟大家分享一下。所以呢，接著我們會一起簡單看過 Web storage 的 spec，如果你只是想知道問題的解答，可以直接跳到最後一段。

## Web Storage spec

LocalStorage 跟 sessionStorage 都屬於 Web Storage 的一種，Web Storage 的 spec 在這裡：https://html.spec.whatwg.org/multipage/webstorage.html#introduction-16

我覺得最前面 introduction 那個段落寫得簡單明瞭：

> This specification introduces two related mechanisms, similar to HTTP session cookies, for storing name-value pairs on the client side

開門見山就跟你說了這兩個東西是在幹嘛，是跟 cookie 類似的兩個機制，拿來在 client side 儲存 name-value pairs 用的。

> The first is designed for scenarios where the user is carrying out a single transaction, but could be carrying out multiple transactions in different windows at the same time.

接著則是先講會需要用到 sessionStorage 的情境，這一段要接下面的範例才比較清楚：

> Cookies don't really handle this case well. For example, a user could be buying plane tickets in two different windows, using the same site. If the site used cookies to keep track of which ticket the user was buying, then as the user clicked from page to page in both windows, the ticket currently being purchased would "leak" from one window to the other, potentially causing the user to buy two tickets for the same flight without really noticing.

這個例子大概是這樣的，假設現在我們只有 cookie 可以用，然後小明在買機票，因為他想買兩張「不同」的機票，所以他開了兩個分頁。但如果網站沒寫好，是用 cookie 來記錄他要買哪張機票，就有可能發生以下情形：

1. 小明在分頁 A 點了一張台北到日本的機票，網站把這資訊存在 cookie 裡
2. 小明在分頁 B 點了一張台北到紐約的機票，網站把這資訊存在 cookie 裡
3. 由於 cookie 在分頁 AB 是共用的，而且 key 又一樣，所以 cookie 現在存的是台北到紐約的機票
4. 小明在分頁 A 按下結帳，買了台北到紐約的機票
5. 小明在分頁 B 按下結帳，又買了一張台北到紐約的機票
6. 於是小明就買到重複的機票了

這就是把資訊存在 cookie 有可能發生的潛在問題。因此 sessionStorage 就是為了解決這個問題而生，可以把資訊侷限在「一個 session」，以瀏覽器的角度來說基本上就是一個分頁，不會干擾到其他分頁。

再往下看，會講到 localStorage 的使用情境：

> The second storage mechanism is designed for storage that spans multiple windows, and lasts beyond the current session. In particular, web applications might wish to store megabytes of user data, such as entire user-authored documents or a user's mailbox, on the client side for performance reasons.
>   
> Again, cookies do not handle this case well, because they are transmitted with every request.

有些網站可能會因為效能相關的原因，想要在瀏覽器存大量的資料，例如說把使用者的信件都存進去之類的，其實就有點像是自己做 cache，把這些東西存起來，就可以優先從快取去拿，加快載入速度。

但 cookie 不適合這種情境，因為 cookie 會隨著 request 發出去。你想想看，如果你在 cookie 存了 1MB 的資料，這網站底下每個 request 就至少都是 1MB 的大小了，而且那些又是 server 用不到的資料，會造成很多不必要的流量。

因此，localStorage 就這樣誕生了，可以讓你存大量的資料，而且不會被帶去 server。

接著下面還有一段紅字的警告：

> The localStorage getter provides access to shared state. This specification does not define the interaction with other browsing contexts in a multiprocess user agent, and authors are encouraged to assume that there is no locking mechanism. A site could, for instance, try to read the value of a key, increment its value, then write it back out, using the new value as a unique identifier for the session; if the site does this twice in two different browser windows at the same time, it might end up using the same "unique" identifier for both sessions, with potentially disastrous effects.

大意就是說因為 localStorage 是可以跨頁面被分享的，所以就跟其他那種被共享的資源一樣，要注意 race condition，舉例來說如果有個網站會去 localStorage 讀一個叫做 id 的 key，取出來之後 +1 放回去，把 id 當作頁面的唯一 id，若是兩個頁面同時做這件事，有可能會得到同樣的 id，例如說：

1. 頁面 A 取得 id，id 是 1
2. 頁面 A 把 id + 1
3. 與此同時，頁面 B 也取得 id，也拿到 1
4. 頁面 A 把 id 寫回去，現在 id 是 2
5. 頁面 B 把 id + 1 寫回去，id 還是 2

連續的動作不保證不被其他的 process 給中斷，所以才會寫說：「authors are encouraged to assume that there is no locking mechanism」，要小心這種狀況出現。

再來可以看到 Web Stroage 的 interface：

![p3-web-storage](/img/session_storage/p3-web-storage.png)

這邊值得注意的是雖然常見用法是 `storage.setItem` 或是 `storage.getItem`，但其實直接 `storage[key] = value` 以及 `storage[key]` 也都行得通，刪除的話直接 `delete storage[key]` 也可以。

然後如果寫不進去的話，會丟一個 `QuotaExceededError` 出來，Chrome 的這份文件：[chrome.storage](https://developer.chrome.com/apps/storage) 有提到相關的一些數字。

再來還有一段很常出現：

> Dispatches a storage event on Window objects holding an equivalent Storage object.

這是因為在 storage 裡的內容有變動時，其實都會發出一個事件，而你可以去監聽這個事件做出反應。舉例來說，你可以用這招在不同分頁去偵測 localStorage 的變化並且即時反應，相關說明請看：[Window: storage event](https://developer.mozilla.org/en-US/docs/Web/API/Window/storage_event)。

順帶一提，storage 的 key 可以是 emoji，所以打開[這個網頁](https://aszx87410.github.io/demo/session_storage/emoji.html)之後，可以看到：

![p3-web-storage](/img/session_storage/p4-emoji.png)


再來底下的 spec 都是在描述各個方法的細節，我這邊就不再重複了。接著一直往下看到 sessionStorage 的部分，會看到這一段：

![p5-session-storage](/img/session_storage/p5-session-storage.png)


有看到重點了嗎？

> While creating a new auxiliary browsing context, the session storage is copied over.

當建立一個 `auxiliary browsing context` 的時候，sessionStorage 就會被複製過去。從文章開頭給的那個範例看來，我們可以猜測我們點了 a 標籤新開一個分頁的行為，可能就是「creating a auxiliary browsing context」。

接著我們點進去，看看 creating a auxiliary browsing context 的流程是什麼：

![p6-auxiliary](/img/session_storage/p6-auxiliary.png)


重點是第六步，有提到了會把 sessionStorage 複製過去。

所以呢，現在問題就被重新定義了。

原本我們好奇的是「sessionStorage 什麼時候會被複製」，得到的答案是：「建立 auxiliary browsing context 的時候」，因此現在好奇的問題轉成：「什麼時候會建立 auxiliary browsing context？」

再者，從結果看來，開頭的範例中是透過 a link 外連一個網站達成的，因此可以猜測答案可能就在 link 的 spec 當中。

## Links spec

Links 相關的 spec 在這裡：https://html.spec.whatwg.org/multipage/links.html

先來看一下 link 的定義：

> Links are a conceptual construct, created by a, area, form, and link elements, that represent a connection between two resources, one of which is the current Document. There are two kinds of links in HTML:

有四種 elements 可以 create link：`<a>`、`<area>`、`<form>`還有`<link>`，其中`<area>`這個我還是第一次聽到。

接著文件中定義了連結有兩種，第一種是：Links to external resources

> These are links to resources that are to be used to augment the current document, generally automatically processed by the user agent. All external resource links have a fetch and process the linked resource algorithm which describes how the resource is obtained.

可以先簡單想成就是你用 `<link>` 這個 element 時會用的東西，例如說 CSS 就是一種 external resources，再來第二種是 Hyperlinks：

> These are links to other resources that are generally exposed to the user by the user agent so that the user can cause the user agent to navigate to those resources, e.g. to visit them in a browser or download them.

就是我們所熟知的超連結，指引瀏覽器（user agent）前往其他資源。

再來我們持續往下看，可以看到 [4.6.4 Following hyperlinks](https://html.spec.whatwg.org/multipage/links.html#following-hyperlinks) 有提到說當使用者按下超連結以後，瀏覽器應該要做什麼：

![p7-follow-hyperlink](/img/session_storage/p7-follow-hyperlink.png)


重點是第六步跟第七步：

> 6.Let noopener be the result of getting an element's noopener with subject and targetAttributeValue.

> 7.Let target and windowType be the result of applying the rules for choosing a browsing context given targetAttributeValue, source, and noopener.

這邊會透過在 spec 上面的流程決定 `noopener` 的值：

![p8-noopener](/img/session_storage/p8-noopener.png)


我們一開始的範例符合第二種情況，沒有 opener 屬性，而且 target 是 `_blank`，所以 noopener 會是 true。

再來我們看第七步，他有一個 [the rules for choosing a browsing context](https://html.spec.whatwg.org/multipage/browsers.html#the-rules-for-choosing-a-browsing-context-given-a-browsing-context-name) 可以點，點下去之後就又回到了 browsing context 的 spec。

在選擇 browsering context 的時候會有一些流程，去判斷應該要選擇哪一個。我們想要找的情況（name 是 `_blank`）都不符合前面的狀況，所以會直接到第八步：

> Otherwise, a new browsing context is being requested, and what happens depends on the user agent's configuration and abilities — it is determined by the rules given for the first applicable option from the following list:

接著下面又有幾條規則，來決定最後應該要做出怎樣的行為，而我們的範例會是這一條規則：

![p9-rules](/img/session_storage/p9-rules.png)


從流程中可以看出來，在第三個步驟中判斷 noopener 是不是 true，是的話就建立一個新的 top-level browsing context，不是的話就建一個 auxiliary browsing context。

這樣看下來，整個流程都清楚了，只要我們進到這邊而且 noopener 是 false，就會建立一個 auxiliary browsing context，進而把 sessionStorage 複製過去。

等等...可是我們的 noopener 不是 true 嗎？在上面決定 noopener 的值的時候，根據我們的狀況，spec 很明顯是 true，那就應該會建立一個新的 top-level browsing context，sessionStorage 也不會被複製過去。

難道我看漏了什麼？

## 第一次被 spec 搞混就上手

原本自信滿滿想寫這篇文章，結果寫一寫的時候就發現到上面的狀況：「咦，怎麼實際的行為跟 spec 對不起來？」，一直覺得自己看漏了什麼，就又再檢查了幾遍，發現沒錯啊，noopener 的確是 true 才對，那應該就不會建立 auxiliary browsing context 了，sessionStorage 也不應該被複製。

可是在 Chrome 上觀察到的就不是這樣，於是我突然想到了一個可能性，那就是 Chrome 沒有照著 spec 做。這邊要特別留意一件事，那就是我們看的 spec 是最新的 spec，但通常瀏覽器都不會跟到這麼新，再加上有些東西可能是 breaking changes，就會更緩慢一點。

因此我猜測是 spec 有改過，Chrome 所遵照的是以前的行為。有了這個猜測之後，就去搜相關的字眼，真的讓我找到了一個 commit：[Make target=_blank imply noopener; support opener](https://github.com/whatwg/html/commit/5c68ab3ee22bff367baf72c59e0af836868c2f95)。

這是 2019 年 2 月 7 號的一個 commit，在 diff 中可以看到這段改動：

![p10-diff](/img/session_storage/p10-diff.png)


在舊的 spec 中，如果 noopener 或是 noreferrer 屬性是 true 才會讓 noopener 是 true，否則就都是 false。

所以我們開頭觀測到的行為是符合舊的 spec 的，我們用 a 連結新開了一個分頁，沒有設置 noopener 跟 noreferrer，所以新開的分頁建立了一個 auxiliary browsing context，sessionStorage 就跟著被複製過去了。

寫到這邊，我們終於得到了一個合理而且權威的解釋，再來只剩下最後幾個問題要處理了：

> noopener 跟 noreferrer 是什麼？為什麼 spec 要做這個改動？

## noopener 與 noreferrer

我最早看到這兩個屬性是在 2016 年 5 月，沒記錯的話應該是從這篇[臉書貼文](https://www.facebook.com/Orange.8361/posts/1309695172378612)中看到的，那時候我好像還有跟同事分享這個東西，因為覺得這招滿帥的。

想知道問題是什麼，可以直接看這篇文章：[About rel=noopener, what problems does it solve?](https://mathiasbynens.github.io/rel-noopener/)。

簡單來說呢，當你從網站 A 使用 `<a target="_blank">` 連結到網站 B 的時候，網站 B 可以拿到 `window.opener`，這就等於是網站 A 的 `window`，因此我只要在網站 B 執行 `window.opener.location = 'phishing_site_url'`，就可以把網站 A 導到其他地方，如果導去的地方是刻意設置的釣魚網站，那使用者就很有可能中招，因為他根本沒有預期到點了連結之後，網站 A 會跳去其他地方。

而解法呢，就是加上 `rel="noopener"` 這個屬性。

另外一個屬性 noreferrer 則是跟 [Referer](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Referer) 這個 HTTP request header 有關，例如說我從網站 A 連到網站 B，網站 B 的 `Referer` 就會是網站的 A 的 URL，所以它會知道你從哪邊來的。

而帶上了這個屬性就是告訴瀏覽器說：「不要幫我帶 Referer 這個 header」。

接著我們回到 spec，看一下 spec 怎麼說。

[4.6.6.13 Link type "noopener"](https://html.spec.whatwg.org/multipage/links.html#link-type-noopener)：

> The keyword indicates that any newly created top-level browsing context which results from following the hyperlink will not be an auxiliary browsing context. E.g., its window.opener attribute will be null.

[4.6.6.14 Link type "noreferrer"](https://html.spec.whatwg.org/multipage/links.html#link-type-noreferrer)：

> It indicates that no referrer information is to be leaked when following the link and also implies the noopener keyword behavior under the same conditions.

這邊的定義是「no referrer information is to be leaked」，而這個 referrer information 除了我上面講的 Referer header 之外，其實也包含了其他相關的資訊，不過實際上到底還有什麼，就要去看其他 spec 或是瀏覽器的相關實作了。

然後還有一點要注意的是：「also implies the noopener keyword」，所以用了 noreferrer 之後就蘊含著 noopener 的效果了。

有在寫 React 並且使用 eslint 的朋友們應該都看過一條規則，那就是在用 a link 而且 target 是 `_blank` 的時候，必須要搭配使用 `rel="noreferrer noopener"`，這個規則其實已經被改掉了，現在只要求放上 `noreferrer` 就好，原因就是我上面講的。

想看更多細節可以看這個 issue：[target=_blank rel=noreferrer implies noopener](https://github.com/yannickcr/eslint-plugin-react/issues/2022)，原本怕一些舊的 browser 會出問題所以沒有要改，後來是有人提供了一堆瀏覽器的測試資料，確認沒問題之後才改的。

讓我們把主題再拉回 opener 這個問題，當初這個問題被揭露之後我記得受到滿大的關注，在 spec 的 repo 上也可以找到一大堆相關的討論，其實很多人都滿驚訝原來預設的行為是這樣。

相關的討論可以看這一串：[Windows opened via a target=_blank should not have an opener by default](https://github.com/whatwg/html/issues/4078) 還有這個 PR：[Make target=_blank imply noopener; support opener](https://github.com/whatwg/html/pull/4330)。

總之呢，後來 [Safari](https://trac.webkit.org/changeset/237144/webkit/) 跟 [Firefox](https://bugzilla.mozilla.org/show_bug.cgi?id=1522083) 都針對這點做出改動，使用 `target=_blank`，預設的 opener 就會是 noopener。

那 Chrome 呢？抱歉，還沒。可以參考：[Issue 898942: Anchor target=_blank should imply rel=noopener](https://bugs.chromium.org/p/chromium/issues/detail?id=898942)。

## 回到 sessionStorage

繞了一大圈，看了一大堆 spec 跟 bug tracker 之後，最後我們回到一開始的主題：sessionStorage。

在 spec 裡面說了，如果建立的是 auxiliary browsing context 就會把 sessionSotrage 複製過去。而如果我們加上了 `rel="noopener"`，就不會有這個行為。

所以這就是開頭問題的正解：「加上 `rel="noopener"`」。

可是我開頭已經講過了，我試過這些都沒有用，這是為什麼呢？這是因為 Chrome 還沒支援這個行為：[Issue 771959: Do not copy sessionStorage when a window is created with noopener](https://bugs.chromium.org/p/chromium/issues/detail?id=771959)，而 Safari 雖然說 `target=_blank` 會蘊含 `rel="noopener"`，但是也沒有支援 `noopener` 不會複製 sessionStorage。

唯一符合最新標準的是 Firefox，你加上 `rel="noopener"`，就真的不會把 sessionStorage 一起帶過去了。

由於這些都是瀏覽器還沒修正的行為，所以我們在開發的時候也無能為力。就現階段來說，在 Chrome 跟 Safari 上面，用 `<a target="_blank">` 開啟同個 origin 下的新分頁，就是會把 sessionStorage 複製一份過去。

再提醒最後一個小細節，「點擊連結」跟「右鍵 -> 開新分頁」的行為是不同的。前者會把 sessionStorage 複製過去，但後者不會。因為瀏覽器（至少是 Chrome 跟 Safari）認為「右鍵 -> 開新分頁」就像是你新開一個 tab，然後把網址複製貼上，而不是直接從現有的分頁連過去，所以不會幫你複製 sessionStorage。

再次附上開頭的 demo，你自己試試看就知道了：https://aszx87410.github.io/demo/session_storage/index.html

相關討論可以看：[Issue 165452: sessionStorage variables not being copied to new tab](https://bugs.chromium.org/p/chromium/issues/detail?id=165452)。

## 結語

以 sessionStorage 為起點向外延伸，我們探索到了很多新的東西，而且連結到了我幾年前看到的 noopener 安全性的文章，也連結到了之前寫 code 時碰到的 eslint warning，如果還想再繼續連結，甚至也可以連到 Chrome 最近對 Referer 做出的[改動](https://developers.google.com/web/updates/2020/07/referrer-policy-new-chrome-default)。所以儘管只是一個看起來很小的知識點，背後都蘊含著一整張超大的知識圖譜。

在發現 spec 跟實作不一樣的時候，我瞬間體會到了「盡信書不如無書」的感覺，我原本一直都以為 spec 就是唯一的權威，卻忽略了 spec 會不斷變動、更新，但實作不一定會跟上的這個事實。還有一點，那就是瀏覽器的實作有時候會因為一些考量，不會完全跟著 spec 走，這一點也是往後需要特別注意的。

經歷過這麼一段旅程之後，對 sessionStorage 的理解又更深入了一些。以後有機會的話把 HTML 的 spec 都翻一翻好了，應該能看到更多有趣的東西。

參考資料：

1. [HTML spec](https://html.spec.whatwg.org/multipage/webstorage.html#introduction-16)
2. [About rel=noopener, what problems does it solve?](https://mathiasbynens.github.io/rel-noopener/)
3. [target=_blank rel=noreferrer implies noopener](https://github.com/yannickcr/eslint-plugin-react/issues/2022)
4. [Windows opened via a target=_blank should not have an opener by default](https://github.com/whatwg/html/issues/4078)
5. [Issue 898942: Anchor target=_blank should imply rel=noopener](https://bugs.chromium.org/p/chromium/issues/detail?id=898942)
6. [Issue 771959: Do not copy sessionStorage when a window is created with noopener](https://bugs.chromium.org/p/chromium/issues/detail?id=771959)
7. [Issue 165452: sessionStorage variables not being copied to new tab](https://bugs.chromium.org/p/chromium/issues/detail?id=165452)
