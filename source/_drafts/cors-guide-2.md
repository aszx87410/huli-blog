---
title: CORS 完全手冊（二）：如何解決 CORS 問題？
catalog: true
date: 2020-07-24 23:07:47
tags: [Ajax,JavaScript,Front-end,CORS]
categories:
  - Front-end
---

## 前言

在上一篇 [CORS 完全手冊（一）：為什麼會發生 CORS 錯誤？]()裡面，我們理解了為什麼瀏覽器要有 same-origin policy，以及跨來源請求擋的其實是 response 而不是 request。在釐清了一些錯誤的觀念以及對 CORS 有基本的認知以後，就可以先來講講怎麼樣解決 CORS 的問題。

先跟大家預告一下，這篇會提到的解決問題的方法並不完整。事實上，跨來源請求分成兩種，簡單請求跟非簡單請求，這一篇只會針對「簡單請求」，至於到底怎麼分簡單還是非簡單，以及非簡單的要如何處理，這些都會在下一篇提到。

想要解決基本的 CORS 錯誤，其實有滿多種方法，先來介紹幾個「治標不治本」的：

1. 關掉瀏覽器的安全性設置
2. 把 fetch mode 設成 no-cors
3. 不要用 AJAX 拿資料

以下就會先針對這三個方法再進一步講解，講完以後我們會來講最後一個也是最正確的做法：「請後端加上 CORS header」。

<!-- more -->

## 解法一：關掉瀏覽器的安全性設置

在上一篇裡面有再三跟大家提過，跨來源請求會被擋住，是因為瀏覽器的限制。所以只要瀏覽器沒有這個限制，就能平平安安快快樂樂拿到 response。

因此解決 CORS 問題的方法之一，就是直接把瀏覽器的安全性設置關掉，簡單暴力又有用。

至於怎麼關閉，如果是 Chrome 的話可以參考：[Run Chrome browser without CORS](https://alfilatov.com/posts/run-chrome-without-cors/)，其他瀏覽器的話就要自己查一下相關資料了。

把安全機制關掉以後，就可以順利拿到 response，瀏覽器也會跳一個提示出來：

（補圖）

問題是解決了，但為什麼我說這是治標不治本呢？因為只有在你電腦上沒問題而已，在其他人的電腦上面還是有問題。有些人會在開發時圖個方便把這個設置關起來，就不會碰到任何 CORS 的問題，但我認為這是比較不好的做法，因為你關掉的不只是 CORS，你連其他安全機制也一起關掉了。

總之呢，只是跟大家介紹有這個解法，但不推薦使用。

## 解法二：把 fetch mode 設成 no-cors

如果你是使用 fetch 去抓取資料，例如說這樣（這個網頁的 origin 是 `http://localhost:8081`，跟 `http://localhost:3000` 不同源）：

``` js
fetch('http://localhost:3000').then(res => {
  console.log('response', res)
  return res.text()
}).then(body => {
  console.log('body', body)
})
```

你就會看到 console 上面跳出顯眼的紅字：

> Access to fetch at 'http://localhost:3000/' from origin 'http://localhost:8081' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.

前半段很熟悉，後半段可能就比較陌生一點。但沒關係，我們看到了關鍵字：` set the request's mode to 'no-cors'`，喔喔喔，難道說這樣就可以不管 CORS 嗎？馬上來試試看：

``` js
fetch('http://localhost:3000', {
  mode: 'no-cors'
}).then(res => {
  console.log('response', res)
  return res.text()
}).then(body => {
  console.log('body', body)
})
```

改了程式碼之後重新執行，果真不會跳錯誤出來了！console 一片乾淨，只是印出來的值似乎怪怪的：

（補圖）

Response 的 status 是 0，body 的內容是空的，type 是一個叫做 `opaque` 的東西，看起來很奇怪。但如果我們打開 devtool 並且切到 Network 的那一個 tab 去看，會發現其實後端是有回傳 response 的：

（補圖）

為什麼會這樣呢？

當你傳進 `mode: no-cors` 的時候就代表「我就是要發 request 到一個沒有 CORS header 的 url」，既然是這樣的話，那自然也就不會出現 `No 'Access-Control-Allow-Origin' header is present on the requested resource` 這個錯誤，因為你本來就預期到這件事了。

但這樣設置並不代表你就拿得到 response，事實上正好相反，用 `mode: no-cors` 的話，你**一定**拿不到 response。沒錯，一定拿不到，就算後端幫你把 `Access-Control-Allow-Origin` 這個 header 加上去了，你也拿不到 response。

所以，如果你發現你用了 `mode: no-cors` 這東西，那有 99% 的機率是你用錯了，你根本不該用這個。用了的話你反而會很困惑，因為：

1. 你在 network tab 可以看到 response
2. 而且你的程式沒有產生任何錯誤

但是你就是拿不到 response，它就是空的，這都是因為 no-cors 這個 mode。用了以後你可能就會跟[這個 issue](https://github.com/lexich/redux-api/issues/151) 裡面的人一樣感到困惑。

總結一下，設置這個 mode 以後，並不會神奇地就讓你可以突破限制拿到東西，正好相反，這個模式是在跟瀏覽器說：「我就是要發 request 給一個沒有 cors header 的資源，我知道我拿不到 response，所以你絕對不要給我 response」。

至於在什麼場合會用到這個 mode，我還要再研究一下，大家可以先參考：

1. [Trying to use fetch and pass in mode: no-cors](https://stackoverflow.com/questions/43262121/trying-to-use-fetch-and-pass-in-mode-no-cors/43268098)
2. [What limitations apply to opaque responses?](https://stackoverflow.com/questions/39109789/what-limitations-apply-to-opaque-responses)

## 解法三：不要用 AJAX 拿資料

既然用 AJAX 會被擋跨來源的請求，那如果可以不用 AJAX 拿資料，不就沒有問題了嗎？在上一篇我們有提過，有一些 tag 是不會受到 same-origin policy 的限制的，例如說 img 或者是 script...對，script！

script 一般來說都是引入其他人寫好的程式碼，例如說 jQuery 或是其它套件之類的。但在那個 CORS 規範還不完整的年代，就有一些人想出了用 script 標籤來傳遞資料的妙招，我到現在都覺得很厲害。

簡單來說是這樣的，用 script 可以引入別人的 script 對吧？假設我們要引入的 script 長這樣：

``` js
var data = {
  username: 'huli'
};
```

那我們引入以後，是不是就可以直接存取 data 這個變數，而裡面就是我們想要跨來源拿到的資料。上面的例子算比較簡單的，來舉一個複雜一點點的好了，假設現在我們要傳一個 userId 到 server，然後需要拿到這個 userId 的資料，那我們的 server 可以這樣寫：

``` js
var express = require('express');
var app = express();

// 事先準備好的資料
const users = {
  1: { name: 'user1' },
  2: { name: 'user2' },
  3: { name: 'user3' },
}

// 根據傳入的 id 回傳資料
app.get('/users/:userId', function (req, res) {
  const userId = req.params.userId;
  res.end(`var data = ${JSON.stringify(users[userId])}`);
});

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});
```

如果我們造訪 `http://localhost:3000/users/1`，response 就會是：`var data = {"name":"user1"}`。

接著呢，我們的前端可以這樣寫：

``` html
<!DOCTYPE html>

<html>
<head>
  <meta charset="utf-8">
  <script src="http://localhost:3000/users/1"></script>
  <script>
    console.log(data)
  </script>
</head>

<body>
</body>
</html>
```

就只是引入這個 script 然後把 data 印出來，就可以發現我們順利拿到資料了！所以這個方法的重點在於 server 端動態產生資料，然後以 JS 的形式輸出。

不過在實務上，我們其實事先不會知道要拿誰的資料，而是使用者做出一些動作之後，我們才去拿相對應 id 的資料，因此這個 script 就會是動態新增的，像是這樣：

``` html
<!DOCTYPE html>

<html>
<head>
  <meta charset="utf-8">
  <script>
    function getUser(userId) {
      // 新增 script 元素
      const script = document.createElement('script')

      // 加上 src
      script.src = 'http://localhost:3000/users/' + userId

      // 插入到 body 中
      document.body.appendChild(script);

      // 印出資料
      console.log(data)
    }
  </script>
</head>

<body>
  <button onclick="getUser(1)">user1</button>
  <button onclick="getUser(2)">user2</button>
</body>
</html>
```

前端放了兩顆按鈕，按第一顆就去抓 user1 的資料，第二顆就去抓 user2。按了之後我們動態產生 script 然後放到 body 上，這樣等腳本載入完成，就能拿到資料了！

不過如果你執行上面這段程式碼，會回給你一個 `Uncaught ReferenceError: data is not defined` 的錯誤，這是因為載入 script 是需要時間的，而我們在還沒載入完成前，就拿不到資料。

像是這種非同步的東西，解法都是一樣的，就是加上一個 callback。與其用變數來儲存資料，不如用 callback 的方式把資料帶過來。後端可以改成這樣：

``` js
app.get('/users/:userId', function (req, res) {
  const userId = req.params.userId;
  res.end(`setData(${JSON.stringify(users[userId])})`);
});
```

你拿到的 response 就會長得像這樣：

``` js
setData({"name":"user1"})
```

其實就是把之前的變數宣告換成傳入 function 而已。而這個 `setData` 就是你要寫在前端來接收資料的 function：

``` html
<!DOCTYPE html>

<html>
<head>
  <meta charset="utf-8">
  <script>
    function setData(data) {
      console.log(data)
    }
    function getUser(userId) {
      const script = document.createElement('script')
      script.src = 'http://localhost:3000/users/' + userId
      document.body.appendChild(script);
    }
  </script>
</head>

<body>
  <button onclick="getUser(1)">user1</button>
  <button onclick="getUser(2)">user2</button>
</body>
</html>
``` 

如此一來，當 script 載入完成以後，就會呼叫 setData 這個 function 並且把資料帶進去，我們就可以拿到資料了。

最後我們要做一個小改善，那就是不把 function 名稱寫死，而是可以讓 client 自己傳想要的名稱進來：

``` js
app.get('/users/:userId', function (req, res) {
  const userId = req.params.userId;
  const callback = req.query.callback;
  res.end(`${callback}(${JSON.stringify(users[userId])})`);
});

```

而前端就可以自己帶上一個 query string，指定 callback function 的名稱：

``` js
function setUser(data) {
  console.log(data)
}
function getUser(userId) {
  const script = document.createElement('script')
  script.src = 'http://localhost:3000/users/' + userId +
    '?callback=setUser';
  document.body.appendChild(script);
}
```

總結一下這個方法，這個方法利用 script 標籤不會擋跨來源請求的特性，讓 server 動態產生檔案的內容，並且利用呼叫 JS 函式的方式傳遞 JSON 格式的資料。這個方法就是大名鼎鼎的 JSONP，JSON with Padding（padding 是填充的意思，可以想成就是前面填的那個 function 名稱）。

這個方法在早期 CORS 的規範還不完全時挺常用的，巧秒地跨過了瀏覽器的安全性限制。不過它的缺點是因為你只能用 script 的方式去呼叫，所以你只能用 GET 這個 method，其他 POST、PATCH、DELETE 什麼的都不能用。

以前在使用 jQuery 提供的 `$.ajax` 的時候，就知道裡面有一個 JSONP 的參數可以調整，害我一直以為他們是同樣的東西，但其實只是 jQuery 把他們包起來而已。

JSONP 的原理是透過 script 標籤傳遞資料跨過限制，而一般我們使用的 AJAX 都是用 XMLHttpRequest 或是 fetch，這兩種方法的原理相去甚遠，完全不一樣。

儘管 JSONP 這東西我講過很多次了，但每次再提都還是會覺得很神奇很厲害，怎麼想到用 script 來傳遞資料的。

最後做個總結，JSONP 是一種用 script 標籤傳遞資料藉此避開 CORS policy 的方法，必須要透過 server 配合才能使用（因為它回傳的東西其實是一段 JavaScript，而不是只有資料），目前有些網站的 API 還有支援 JSONP，例如說 [Twitch API](https://dev.twitch.tv/docs/v5)。

## 中場休息

講到這邊，前端可以嘗試的解法應該就差不多了，而你也會發現，上面提到的這三個解法：

1. 關掉瀏覽器的安全性設置
2. 把 fetch mode 設成 no-cors
3. 不要用 AJAX 拿資料

都沒有辦法真正解決問題。

這就是為什麼我在上一篇裡面說了：「大部分情形下，CORS 都不是前端的問題，純前端是解決不了的」。瀏覽器因為安全性的考量所以會把東西給擋住，因此，你必須要讓瀏覽器知道：「這其實是安全的」，它才會放行。

舉個例子，你發了一個跨來源的請求給 `google.com`，瀏覽器因為之前講的安全性問題擋住了。是誰可以決定不要把這個請求給擋住？不會是前端，因為前端是發出請求的那一方。所以，答案就理所當然是後端了，也就是 `google.com`，只要 `google.com` 跟瀏覽器說：「欸欸我相信這個 origin，他不會做壞事，把我的 response 給他吧！」，瀏覽器就會照做。

就像是如果你去餐廳打工，聽到客人說：「我認識老闆喔」，你會立刻就相信他嗎？不會，因為每個人都可以說他認識老闆，但你沒辦法判斷是不是真的。要判斷真偽，你只能去問老闆，如果老闆說：「對，我真的認識」，那就是真的認識。

所以擁有決定權的並不是客人，而是老闆。送出跨來源請求也是這樣，每個 origin 一定都會說自己有權限，但問那些發出請求的人不準，而是要問接收到請求的那一邊，問說你是不是願意給這個 origin 權限，如果願意的話才放行。

那要怎麼跟瀏覽器說：「我願意」呢？方法可能比你想像中簡單很多，加一個 header 就行了！

## 真正的解法：請後端設置 CORS header

還記得一開始用 fetch 時出現的那個錯誤嗎？

> Access to fetch at 'http://localhost:3000/' from origin 'http://localhost:8081' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.

這點是這一句：No 'Access-Control-Allow-Origin' header is present on the requested resource

剛剛有提到說後端才是擁有權限，可以告訴瀏覽器說：「我允許這個 origin 跨來源存取我的資源」的一方，而告訴瀏覽器的方法，就是在 response 加上一個 header。

這個 header 的名稱叫做 `Access-Control-Allow-Origin`，內容就是你想要放行的 origin，例如說：`Access-Control-Allow-Origin: http://localhost:8081`，這樣就是允許 `http://localhost:8081` 的跨來源請求。

那如果想要允許多個來源呢？抱歉，你沒辦法在 header 內放入多個 origin，你只能放一個，或是你可以選擇放 `*`，就代表允許任何 origin 的意思。如果想要針對多個 origin，server 那邊必須做一點額外處理。

這邊我們先來看放 * 的情形：

``` js
var express = require('express');
var app = express();

app.get('/', function (req, res) {
  res.set('Access-Control-Allow-Origin', '*');
  res.end('hello world');
});

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});
```

這樣就是在跟瀏覽器說：「任何 origin 都可以拿到我的 response，所以你不需要擋下來」。所以當你前端在用 AJAX 去送 request 的時候，就可以拿到 response，也不會出現任何錯誤。

這邊有一個常見的錯誤，就是有些人以為 `Access-Control-Allow-Origin` 這個 header 是前端在發送 request 時要加的。不，這完全是錯的，前端加這個完全沒有用，因為這個 header 只存在 response 裡面，是後端才需要加的，前端加了跟沒加一模一樣。

所以如果你在前端有加這個，麻煩把它拿掉。

如果只想針對特定的 origin 開放權限，只要傳入要開放的 origin 就行了：

``` js
app.get('/', function (req, res) {
  res.set('Access-Control-Allow-Origin', 'http://localhost:8081');
  res.end('hello world');
});
```

就是這麼的簡單，只要加了一個 header，就可以告訴瀏覽器說：「我同意這個 origin 拿到我的 response」，就這樣就好了。

這才是從根本去解決跨來源請求的問題。如果你跟你想存取的資源有合作關係的話，通常直接請他們設定這個 header 就行了。例如說你在串接公司後端的 API，發現碰到 CORS 問題，這時候請去找後端工程師幫你把這個 header 加上去。

不要想著靠自己來解決，因為這不是前端該解決的問題。這是後端該解決的，只是你要幫助他，告訴他應該怎麼解。

上面我有強調一件事，那就是「你跟你想存取的資源有合作關係」，但有時候，你可能就是會想要在前端拿一些「跟你沒有合作關係」的資料，例如說你想呼叫別人家的非公開 API，或是去抓 google.com 的內容之類的，這些資源絕對不會給你 `Access-Control-Allow-Origin` 這個 header。

這時候怎麼辦呢？

讓我們歡迎 proxy server 登場！

## 使用 proxy server

這幾篇文章中不斷提醒大家，同源政策什麼的都只是「瀏覽器的限制」，一旦脫離了瀏覽器，就沒有任何限制了，proxy server 就是如此。

Proxy server 的翻譯叫做代理伺服器，在不同的場合下用這個詞，代表的意思會有一點點不同，但是大方向都是一樣的，就是原本你是從 A 傳資料到 B，就在變成你從 A 傳到 P，P 再傳到 B，然後再回傳回來，中間那個 P 就擔任著「代理」的角色。

這就像是藝人與經紀人一樣，對外的工作都是經紀人負責接洽，談完以後才告知藝人。而藝人如果想找誰合作，也是讓經紀人去問，問完再跟藝人說。所以經紀人其實就是藝人明星的「代理」人。

那要如何把這個概念應用在 CORS 相關的問題上面呢？

如果你想拿 A 網站的資料，但是他沒有提供 `Access-Control-Allow-Origin` 這個 header，你就自己寫個 server，從後端去拿 A 網站的資料，再把資料丟回給自己的前端就行了。因為自己的後端可以自己控制，所以你想加什麼 header 就加什麼 header，想拿什麼資料就拿什麼。

（圖片待補）

圖片中的數字代表以下流程：

1. 瀏覽器發 request 到 proxy，說要拿 huli.tw 的資料
2. proxy server 去跟 huli.tw 拿資料（後端，沒有跨來源限制）
3. huli.tw 回傳資料給 proxy（後端，沒有跨來源限制）
4. proxy 回傳資料給瀏覽器，並加上 CORS header（所以前端不會被擋）

大家應該都有聽過的 [CORS Anywhere](https://github.com/Rob--W/cors-anywhere/)，開頭就直接寫了：

> CORS Anywhere is a NodeJS proxy which adds CORS headers to the proxied request.

就是一個 proxy server，幫你把你想存取的資源加上 CORS 的 header。或是如果你有在用 Chrome 上幫你解決 CORS 問題的 [plugin](https://github.com/vitvad/Access-Control-Allow-Origin/blob/master/background.js#L33)，背後原理其實也只是用 plugin 幫你把 response 加上 `Access-Control-Allow-Origin` 這個 header 而已。

所以，要解決 CORS 沒有什麼魔法，無論你是裝了 plugin 還是用了 proxy server，背後原理都是一樣的，都還是那個 `Access-Control-Allow-Origin` 的 header。

不過講到 proxy 這個做法，有些人可能會有個疑問：

> 開頭的時候不是說如果可以拿任意網站的資料會有安全性問題嗎？那 proxy server 呢？為什麼用了 proxy 就沒有這限制？

來，我們來看這張對照圖，上面是走 proxy 的流程，下面是沒有走的：

（補圖）

不經過 proxy 的就會有之前提過的安全性問題，網站可以去拿你 localhost 或是其他網站的資料，所以瀏覽器要把它擋住。

而 proxy 的話則不同，這邊有一點很重要，那就是如果走 proxy 的話，跟 localhost:3000 溝通的是誰？是 proxy server，所以網頁去抓的並不是「本機的 localhost:3000」，而是「proxy server 的 localhost:3000」，那這樣對你的電腦來說，就沒有安全性的問題（但是對 proxy server 可能有）。

## 總結

在這一篇裡面我們看了很多種不同的解法，你應該會最常用的應該是「請後端加上 CORS header」這一種，因為這通常是最正確的解法。但如果你對後端沒有掌控權，例如說你就是想要抓其他不認識的網域的資料，那大概會自己架一個 proxy server 或者是找現成的，讓 proxy 幫你加上 CORS header。

若是後端 API 只提供 JSONP 形式的方式，那也可以用 JSONP 來做；只是在自己電腦上想測試東西又覺得 CORS 很煩的話，裝個擴充套件來解決這問題也是可以的，但要注意的是這只有在自己電腦上有用，換一台電腦就失效了。

其實沒有說哪一種做法一定是對，哪一種一定是錯，畢竟不同的場合之下會有不同作法。但我之所以會說「請後端加上 CORS header 通常是最正確的解法」，是因為大部分人碰到跨來源請求問題可能都是在工作上。這時如果前後端都有經驗，其實加個 header 就沒事了，但如果兩方都經驗不足，可能就會繞遠路，讓前端自己去架個 proxy server，這就是對這個主題不夠熟造成的後果。

這篇文章只處理到「最簡單的情況」，還有兩個狀況我們沒有講到：

1. 非簡單請求（像是其他 HTTP method 與自定義 header）
2. 傳送 Cookie（如何讓跨來源請求也支援 cookie）

這些都會在下一篇：[CORS 完全手冊（三）：CORS 詳解]()裡面跟大家說明。