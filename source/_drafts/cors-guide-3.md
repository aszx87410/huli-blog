---
title: CORS 完全手冊（三）：CORS 詳解
catalog: true
date: 2020-07-24 23:07:47
tags: [Ajax,JavaScript,Front-end,CORS]
categories:
  - Front-end
---

## 前言

在上一篇裡面我們提到了常見的 CORS 錯誤解法，以及大多數狀況下應該要選擇的解法：「請後端加上 response header」。

但其實「跨網域請求」這個東西又可以再細分成兩種，簡單請求跟非簡單請求，簡單請求的話可以透過上一篇的解法來解，但非簡單請求的話就比較複雜一些了。

除此之外，跨網域請求預設是不會把 cookie 帶上去的，需要在使用 xhr 或是 fetch 的時候多加一個設定，而後端也需要加一個額外的 header 才行。

與 CORS 相關的 header 其實不少，有些你可能聽都沒聽過。原本這篇我想要把這些東西一一列出來講解，但仔細想了一下發覺這樣的話有點太無趣，而且大家應該看過就忘記了。

那怎樣的方法會比較好呢？大家都喜歡聽故事，因此這篇讓我們從故事的角度下手，為大家講述一段愛與 CORS 的故事。

主角的名字大家都知道了，對，就是毫無新意的小明。

<!-- more -->

## Day1：簡單的 CORS

小明任職於某科技公司，擔任菜鳥前端工程師。

而他的第一個任務，就是要做一個「聯絡我們」的表單，讓看到官網，對他們服務有興趣的潛在使用者能夠聯絡到公司的人，再讓業務去跟他們聯絡，洽談後續的合作事項。

而表單長這樣（雖然長得很像 Goolge 表單但是是小明自己做的）：

![](/img/cors/story/01-form.png)

小明花了半天不到的時間，把頁面都刻好了，功能也差不多做完了，只剩下最後一步而已。小明的主管跟他說公司常常會對外舉辦一些活動，而在活動尾聲都會提供這個表單給大家，希望大家統一透過表單留下聯絡資料。

因此表單上的「怎麼知道我們公司的？」就會希望能夠動態調整欄位，在活動期間加一個「透過在 1/10 舉辦的技術分享會」的選項，而活動結束後大概兩個禮拜把這個選項撤掉。之所以要能動態調整，主管說是因為不想讓後續維護的工再回到開發這端，如果一開始就能做成動態的，那未來只要他們自己維護就行了，讓他們能夠透過後台自己去控制。

所以後端開了一個 API 出來，要小明去接這個 API 然後把內容 render 出來變成選項，為了方便測試，後端工程師先把整個 API service 打包成 docker image，然後讓小明跑在自己電腦上，網址是：`http://localhost:3000`。

小明接到這個任務之後，想說先把 API 內容抓下來看看好了，於是就寫了這樣一段程式碼：

``` js
fetch('http://localhost:3000')
```

然後發現 console 出現了錯誤訊息：

![](/img/cors/story/02-cors-error.png)

小明沒有看得很懂那是什麼意思，只注意到了最後一段：

> If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.

於是幫 fetch 加上了 no-cors 的 mode：	

``` js
fetch('http://localhost:3000', {
  mode: 'no-cors'
}).then(res => console.log(res))
```

改完之後重新整理，發現沒有錯誤了，可是印出來的 response 長得特別奇怪：

![](/img/cors/story/03-opaque.png)

沒有任何資料，而且 status 居然是 0。小明在這之後 debug 很久，找不出原因，不知道為什麼就是拿不到資料。眼看死線將近，小明鼓起勇氣去求助了前輩小華，小華跟他說：

> 這是當然的啊，`no-cors` 是個很容易誤導初學者的參數，他的意思並不是「繞過 cors 拿到資料」，而是「我知道它過不了 cors，但我沒差，所以不要給我錯誤也不要給我 response」
> 
> 你這問題一定要透過後端去解，我幫你跟後端說一聲吧

小華前輩不愧資深，三兩下就解決了小明的問題。而後端那邊也幫忙加上了一個 header：`Access-Control-Allow-Origin: *`，代表來自任何 origin 的網站都可以用 AJAX 存取這個資源。

後端程式碼：

``` js
app.get('/', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.json({
    data: db.getFormOptions(),
  })
})
```


小明把原本的 mode 拿掉，改成：

``` js
fetch('http://localhost:3000')
  .then(res => res.json())
  .then(res => console.log(res))
```

打開了瀏覽器，發現可以成功拿到選項了，也從 network tab 裡面看到了新增加的 header：

![](/img/cors/story/04-acao.png)

拿到資料以後，就只剩下把選項放上去畫面而已，大概又半天的時間，小明就把這個功能做完並且測試完了，感謝小華前輩的幫助。

### Day1 總結

`mode: 'no-cors'` 跟你想的不一樣，這個沒有辦法解決 CORS 問題。

碰到 CORS 問題的時候，先確認後端有沒有給你 `Access-Control-Allow-Origin` 這個 header，沒有的話請後端給你，否則你怎麼試都不會過。

`Access-Control-Allow-Origin` 的值可以帶 `*`，代表 wildcard，任何 origin 都合法，也可以帶 origin 像是 `http://huli.tw`，代表只有這個 origin 是合法的。

如果想帶多個的話呢？抱歉，沒有辦法，就是只能全部都給過或者是給一個 origin。因此也有後端會根據 request 的 origin 來決定 response 的 `Access-Control-Allow-Origin` 值會是多少，這個我們之後會提到。

## Day2：不簡單的 CORS

隔了一天之後，主管跟小明說更上層的人不滿意這個使用者體驗，送出表單之後要等個一兩秒才能看到成功的畫面，而且這中間也沒有 loading 什麼的，體驗不好，希望能改成 AJAX 的做法送出表單而不是換頁，就可以改善使用者體驗。

為了因應這個改變，後端又多出了一個 API：`POST /form`，而且這次後端已經很自動地把 `Access-Control-Allow-Origin` 的 header 加上去了：

``` js
app.post('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*')
  // 省略寫到 db 的程式碼
  res.json({
    success: true
  })
})
```

小明之前已經做過類似的事情，因此很快就把程式碼寫好了：

``` js
document.querySelector('.contact-us-form')
  .addEventListener('submit', (e) => {
    // 阻止表單送出
    e.preventDefault()

    // 設置參數
    var data = new URLSearchParams();
    data.append('email', 'test@test.com')
    data.append('source', 'search')

    // 送出 request
    fetch('http://localhost:3000/form', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: data
    }).then(res => res.json())
      .then(res => console.log(res))
  })
```

測試之後也沒有問題，正當小明要跟主管報告做好的時候，後端走過來跟小明說：「不好意思，我們後端最近做了一些改動，未來要統一改成用 JSON 當作資料格式，所以你那邊也要改一下，要送 JSON 過來而不是 urlencoded 的資料」

小明聽了之後心想：「這簡單嘛，不就是改一下資料格式嗎？」，於是改成這樣：

``` js
document.querySelector('.contact-us-form')
  .addEventListener('submit', (e) => {
    // 阻止表單送出
    e.preventDefault()

    // 設置參數
    var data = {
      email: 'test@test.com',
      soruce: 'search'
    }

    // 送出 request
    fetch('http://localhost:3000/form', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    }).then(res => res.json())
      .then(res => console.log(res))
  })
```

就只是換一下資料格式而已，改成用 JSON 的方式傳資料到後端。改完之後小明再測試了一遍，發現這一次居然掛掉了，而且出現錯誤訊息：

![](/img/cors/story/05-preflight-error.png)

> Access to fetch at 'http://localhost:3000/form' from origin 'null' has been blocked by CORS policy: Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin' header is present on the requested resource. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.

切到 network tab 去看 request 的狀況，發現除了原本預期的 POST 以外，還多了一個 OPTIONS 的 request：

![](/img/cors/story/06-preflight-tab.png)

小明上網用錯誤訊息給的關鍵字：`preflight request` 找了一下資料，發現 CORS 沒有他想像中的簡單。

原來之前發送的那些請求都叫做「簡單請求」，只要 method 是 GET、POST 或是 HEAD 然後不要帶自訂的 header，Content-Type 也不要超出：`application/x-www-form-urlencoded`、`multipart/form-data` 或是 `text/plain` 這三種，基本上就可以被視為是「簡單請求」（更詳細的定義下一篇會說）。

一開始串 API 的時候沒有碰到錯誤，是因為 Content-Type 是 `application/x-www-form-urlencoded`，所以被視為是簡單請求。後來改成 `application/json` 就不符合簡單請求的定義了，就變成是「非簡單請求」。

那非簡單請求會怎麼樣呢？會多送出一個東西，叫做 preflight request，中文翻作「預檢請求」。這個請求就是小明在 network tab 看到的那個 OPTIONS 的 request，針對這個 request，瀏覽器會幫忙帶上兩個 header：

1. Access-Control-Request-Headers
2. Access-Control-Request-Method

以剛剛我們看到的 `/form` 的 preflight request 來說，內容是：

1. Access-Control-Request-Headers: content-type
2. Access-Control-Request-Method: POST

前者會帶上不屬於簡單請求的 header，後者會帶上 HTTP Method，讓後端對前端想送出的 request 有更多的資訊。

如果後端願意放行，就跟之前一樣，回一個 `Access-Control-Allow-Origin` 就好了。知道這點以後，小明馬上請後端同事補了一下，後端程式碼變成：

``` js

app.post('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.json({
    success: true
  })
})

// 多加這個，讓 preflight 通過
app.options('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.end()
})
```

改好以後小明重新試了一下，發現居然還是有錯誤：

> Access to fetch at 'http://localhost:3000/form' from origin 'null' has been blocked by CORS policy: Request header field content-type is not allowed by Access-Control-Allow-Headers in preflight response.

當你的 CORS request 含有自訂的 header 的時候，preflight response 需要明確用 `Access-Control-Allow-Headers` 來表明：「我願意接受這個 header」，瀏覽器才會判斷預檢通過。

而在這個案例中，`content-type` 就屬於自訂 header，所以後端必須明確表示願意接受這個 header：

``` js
app.options('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Headers', 'content-type')
  res.end()
})
```

如此一來，小明那邊就可以順利通過 preflight request，只有在通過 preflight 之後，真正的那個 request 才會發出。

流程會像是這樣：

1. 我們要送出 POST 的 request 到 http://localhost:3000/form
2. 瀏覽器發現是非簡單請求，因此先發出一個 preflight request
3. 檢查 response，preflight 通過
4. 送出 POST 的 request 到 http://localhost:3000/form

所以如果 preflight 沒有過，第一個步驟的 request 是不會被送出的。

經歷過一番波折之後，這個改動總算也順利完成了。現在我們可以成功在前端用 AJAX 的方式送出表單資料了。

### Day2 總結

CORS request 分成兩種：簡單請求與非簡單請求，無論是哪一種，後端都需要給 `Access-Control-Allow-Origin` 這個 header。而最大的差別在於非簡單請求在發送正式的 request 之前，會先發送一個 preflight request，如果 preflight 沒有通過，是不會發出正式的 request 的。

針對 preflight request，我們也必須給  `Access-Control-Allow-Origin` 這個 header 才能通過。

除此之外，有些產品可能會想要送一些自訂的 header，例如說`X-App-Version` 好了，帶上目前網站的版本，這樣後端可以做個紀錄：

``` js
fetch('http://localhost:3000/form', {
      method: 'POST',
      headers: {
        'X-App-Version': "v0.1",
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    }).then(res => res.json())
      .then(res => console.log(res))
```

當你這樣做以後，後端也必須要新增 `Access-Control-Allow-Headers`，才能通過 preflight：

``` js
app.options('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Headers', 'X-App-Version, content-type')
  res.end()
})
```

簡單來說，preflight 就是一個驗證機制，確保後端知道前端要送出的 request 是預期的，瀏覽器才會放行。

那為什麼會需要 preflight request 呢？這邊可以從兩個角度去思考：

1. 相容性
2. 安全性

針對第一點，你可能有發現如果一個請求是非簡單請求，那你絕對不可能用 HTML 的 form 元素做出一樣的 request，反之亦然。舉例來說，`<form>` 的 enctype 不支援 `application/json`，所以這個 content type 是非簡單請求；enctype 支援 `multipart/form`，所以這個 content type 屬於簡單請求。

對於那些古老的網站，甚至於是在 XMLHttpRequest 出現之前就存在的網站，他們的後端沒有預期到瀏覽器能夠發出 method 是 `DELETE` 或是 `PATCH` 的 request，也沒有預期到瀏覽器會發出 content-type 是 `application/json` 的 request，因為在那個時代 `<form>` 跟 `<img>` 等等的元素是唯一能發出 request 的方法。

那時候根本沒有 fetch，甚至連 XMLHttpRequest 都沒有。所以為了不讓這些後端接收到預期外的 request，就先發一個 preflight request 出去，古老的後端沒有針對這個 preflight 做處理，因此就不會通過，瀏覽器就不會把真正的 request 給送出去。

這就是我所說的相容性，通過預檢請求，讓早期的網站不受到傷害，不接收到預期外的 request。

而第二點安全性的話，還記得在第一篇問過大家的問題嗎？送出 POST request 刪除文章的那個問題。刪除的 API 一般來說會用 DELETE 這個 HTTP method，如果沒有 preflight request 先擋住的話，瀏覽器就會真的直接送這個 request 出去，就有可能對後端造成未預期的行為（沒有想到瀏覽器會送這個出來）。

所以才需要 preflight request，確保後端知道待會要送的這個 request 是合法的，才把真正的 request 送出去。

## Day3：帶上 Cookie

昨天改的那版受到上層的激勵讚賞，主管也請小明跟小華喝了手搖飲來慶祝。只是正當他們開心之時，行銷部門的人跑來了，問說：「為什麼這些 request 都沒有 cookie？我們需要使用者的 cookie 來做分析，請把這些 cookie 帶上」。

此時小明才突然想起來：「對欸，跨來源的請求，預設是不會帶 cookie 的」，查了一下 MDN 之後，發現只要帶：`credentials: 'include'` 應該就行了：

``` js
fetch('http://localhost:3000/form', {
  method: 'POST',
  credentials: 'include', // 新增這個
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(data)
}).then(res => res.json())
  .then(res => console.log(res))
```

可是沒想到前端卻出現了錯誤訊息：

![](/img/cors/story/07-cookie-error.png)

> Access to fetch at 'http://localhost:3000/form' from origin 'http://localhost:8080' has been blocked by CORS policy: Response to preflight request doesn't pass access control check: The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.

錯誤訊息其實已經解釋得很清楚了，如果要帶上 cookie 的話，那 `Access-Control-Allow-Origin` 不能是 `*`，一定要明確指定 origin。

為什麼會這樣呢？因為如果沒有這個限制的話，那代表任何網站（任何 origin）都可以發 request 到這個 API，並且帶上使用者的 cookie，這樣就會有安全性的問題產生，大概就跟 CSRF 有異曲同工之妙。

所以因為安全性的關係，強制你如果要帶上 cookie，後端一定要明確指定是哪個 origin 有權限。除此之外，後端還要額外帶上 `Access-Control-Allow-Credentials: true` 這個 header。

於是小明再度請小華改一下後端：

``` js
const VALID_ORIGIN = 'http://localhost:8080'
app.post('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', VALID_ORIGIN) // 明確指定
  res.header('Access-Control-Allow-Credentials', true) // 新增這個
  res.json({
    success: true
  })
})

app.options('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', VALID_ORIGIN) // 明確指定
  res.header('Access-Control-Allow-Credentials', true) // 新增這個
  res.header('Access-Control-Allow-Headers', 'content-type, X-App-Version')
  res.end()
})
```

改完之後的版本明確指定 `http://localhost:8080` 才有權限存取 CORS Response，也加上了 `Access-Control-Allow-Credentials` 這個 header。

如此一來就大功告成了，在發送 request 的時候可以成功帶上 Cookie，行銷部門那邊的需求也搞定了，耶依。

### Day3 總結

如果你需要在發送 request 的時候帶上 cookie，那必須滿足三個條件：

1. 後端 Response header 有 `Access-Control-Allow-Credentials: true`
2. 後端 Response header 的 `Access-Control-Allow-Origin` 不能是 `*`，要明確指定
3. 前端 fetch 加上 `credentials: 'include'`

這三個條件任何一個不滿足的話，都是沒辦法帶上 cookie 的。

除了這個之外還有一件事情要特別注意，那就是不只帶上 cookie，連設置 cookie 也是一樣的。後端可以用 `Set-Cookie` 這個 header 讓瀏覽器設置 cookie，但一樣要滿足上面這三個條件。如果這三個條件沒有同時滿足，那儘管有 `Set-Cookie` 這個 header，瀏覽器也不會幫你設置，這點要特別注意。

事實上呢，無論有沒有想要存取 Cookie，都會建議  `Access-Control-Allow-Origin` 不要設定成 `*` 而是明確指定 origin，避免預期之外的 origin 跨站存取資源。若是你有多個 origin 的話，建議在後端有一個 origin 的清單，判斷 request header 內的 origin 有沒有在清單中，有的話就設定 `Access-Control-Allow-Origin`，沒有的話就不管它。

## Day4：存取自訂 header

還記得我們一開始串的那一個 API 嗎？跟後端拿選項的 API。雖然之前已經順利完成，但沒想到有隕石砸下來了。今天早上上面說要加一個新的需求。

這個需要是要對這個 API 的內容做版本控制，後端會在 response header 裡面多帶上一個 header：`X-List-Version`，來讓前端知道這個選項的清單是哪一個版本。

而前端則是要拿到這個版本，並且把值放到表單裡面一起送出。

後端會像是這樣：

``` js
app.get('/', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('X-List-Version', '1.3')
  res.json({
    data: [
      {name: '1/10 活動', id: 1},
      {name: '2/14 特別活動', id: 2}
    ]
  })
})
```

由於這一個 API 的內容本來就是公開的，所以沒有允許特定的 origin 也沒有關係，可以安心使用 wildcard。

小明把之前的程式碼改了一下，試著把 header 先列出來看看：

``` js
fetch('http://localhost:3000')
  .then(res => {
    console.log(res.headers.get('X-List-Version'))
    return res.json()
  })
  .then(res => console.log(res))
```

此時，神奇的事情發生了。明明從 network tab 去看，確實有我們要的 response header，但是在程式裡面卻拿不到，輸出 null。小明檢查了幾遍，確定字沒打錯，而且沒有任何錯誤訊息，但就是拿不到。

![](/img/cors/story/08-custom-header-error.png)

卡了一個小時之後，小明決定再次求助前輩小華。小華身為資深前輩，一看到這個狀況之後就說了：

> 如果你要存取 CORS response 的 header，尤其是這種自定義的 header 的話，後端要多帶一個 `Access-Control-Expose-Headers` 的 header 喔，這樣前端才拿得到

「原來是這樣嗎！」小明恍然大悟，去找了後端的同事，讓他加上這個 header：

``` js
app.get('/', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Expose-Headers', 'X-List-Version')
  res.header('X-List-Version', '1.3')
  res.json({
    data: [
      {name: '1/10 活動', id: 1},
      {name: '2/14 特別活動', id: 2}
    ]
  })
})
```

改完之後小明再測試一遍，發現果真可以正確拿到 header 了！感恩小華，讚嘆小華，平安的一天又度過了。

### Day4 總結

當你拿到跨來源的 response 的時候，基本上都可以拿到 response body，也就是內容。但是 header 就不一樣了，只有幾個基本的 header 可以直接拿到，例如說 `Content-Type` 就是一個。

除此之外，如果你想拿其他 header，尤其是自定義的 header 的話，後端就需要帶上 `Access-Control-Expose-Headers`，讓瀏覽器知道說：「我願意把這個 header 開放出去讓 JS 看到」，這樣子前端才能順利抓到 header。

如果沒有加的話就會拿到 null，就跟這個 header 不存在一樣。

## Day5：編輯資料

原本以為一切都很順利的小明又再次踢到了鐵板。這次是老闆那邊提出的需求，現在一送出表單之後就沒機會再更改了，若是使用者意識到哪邊有填錯，就只能重新再填一遍。而老闆覺得這樣的體驗不好，希望在使用者送出表單以後還有一次機會能夠挽回，可以編輯剛剛送出的表單。

跟後端討論過後，在送出表單之後後端會給一個 token，前端只要帶著這個 token 去打 `PATCH /form` 這個 API，就能夠編輯剛剛表單的內容。

後端長得像這樣，一樣有把該加的 header 都加好：

``` js
const VALID_ORIGIN = 'http://localhost:8080'
app.patch('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', VALID_ORIGIN)
  res.header('Access-Control-Allow-Credentials', true)
  // 省略編輯的部分
  res.json({
    success: true
  })
})

app.options('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', VALID_ORIGIN)
  res.header('Access-Control-Allow-Credentials', true)
  res.header('Access-Control-Allow-Headers', 'content-type, X-App-Version')
  res.end()
})
```

而小明立刻開始著手前端的部分，大概像是這樣：

``` js
fetch('http://localhost:3000/form', {
  method: 'PATCH',
  credentials: 'include',
  headers: {
    'X-App-Version': "v0.1",
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    token: 'test_token',
    content: 'new content'
  })
}).then(res => res.json())
  .then(res => console.log(res))
```

其實跟之前送出表單的程式碼八七分像，差別大概只在 body 跟 method 的部分。然而，小明在測試的時候，瀏覽器又跳出錯誤了：

> Access to fetch at 'http://localhost:3000/form' from origin 'http://localhost:8080' has been blocked by CORS policy: Method PATCH is not allowed by Access-Control-Allow-Methods in preflight response.

跨來源的請求只接受三種 HTTP Method：`GET`、`HEAD` 以及 `POST`，除了這三種之外，都必須由後端回傳一個 `Access-Control-Allow-Methods`，讓後端決定有哪些 method 可以用。

因此後端要改成這樣：

``` js
// preflight
app.options('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', VALID_ORIGIN)
  res.header('Access-Control-Allow-Credentials', true)
  res.header('Access-Control-Allow-Methods', 'PATCH') // 多這個
  res.header('Access-Control-Allow-Headers', 'content-type, X-App-Version')
  res.end()
})
```

如此一來，瀏覽器就知道前端能夠使用 PATCH 這個 method，就不會把後續的 request 給擋下來了。

### Day5 總結

如果前端要使用 `GET`、`HEAD` 以及 `POST` 以外的 HTTP method 發送請求的話，後端的 preflight response header 必須有 `Access-Control-Allow-Methods` 並且指定合法的 method，preflight 才會通過，瀏覽器才會把真正的 request 發送出去。

這個就跟前面提過的 `Access-Control-Allow-Headers` 有點像，只是一個是在規範可以用哪些 method，一個是在規範可以用哪些 request headers。

## Day6：快取 preflight request

好不容易滿足了公司各個大頭的需求，沒想到在上線前夕，技術這端出問題了。小明原本以為解掉了所有跨來源的問題就行了，可是卻忽略了一個地方。在 QA 對網站做壓測的時候，發現 preflight request 的數量實在是太多了，而且就算同一個使用者已經預檢過了，每次都還是需要再檢查，其實滿浪費效能的。

於是 QA 那邊希望後端可以把這個東西快取住，這樣如果同一個瀏覽器重複發送 request，就不用再做預檢。

雖然說小明是做前端的，但他其實想成為 CORS 大師，於是就跟後端一起研究該怎麼解決這個問題。最後他們找到了一個 header：`Access-Control-Max-Age`，可以跟瀏覽器說這個 preflight response 能夠快取幾秒。

接著後端把這個 header 加上去：

``` js
app.options('/form', (req, res) => {
  res.header('Access-Control-Allow-Origin', VALID_ORIGIN)
  res.header('Access-Control-Allow-Credentials', true)
  res.header('Access-Control-Allow-Headers', 'content-type, X-App-Version')
  res.header('Access-Control-Max-Age', 300)
  res.end()
})
```

這樣 preflight response 就會被瀏覽器快取 300 秒，在 300 秒內對同一個資源都不會再打到後端去做 preflight，而是會直接沿用快取的資料。

## 總結

讓我們一個一個來回憶故事中出現的各個 header。

一開始小明需要存取跨來源請求的 response，因此需要後端協助提供 `Access-Control-Allow-Origin`，證明這個 origin 是有權限的。

再來因為要帶自訂的 header，所以後端要提供 `Access-Control-Allow-Headers`，寫明 client 可以帶哪些 header 上去。同時也因為多了 preflight requset，後端要特別處理 `OPTIONS` 的 request。

然後我們需要用到 cookie，所以 `Access-Control-Allow-Origin` 不能是 `*`，要改成單一的 origin。而後端也要多提供 `Access-Control-Allow-Credentials: true`。

接著前端需要存取 header，所以後端必須提供 `Access-Control-Expose-Headers`，跟瀏覽器說前端可以拿到哪些 header。而前端如果要使用 HEAD、GET 跟 POST 之外的 method，後端要加上 `Access-Control-Allow-Methods`。

關於快取的部分，則是用 `Access-Control-Max-Age`。

整串故事看下來，其實你會發現根本沒什麼前端的事情。前端在整個故事中擔任的角色就是：寫 code => 發現錯誤 => 回報後端 => 後端修正 => 完成功能。這也呼應了我之前一再強調的：「CORS 的問題，通常都不是前端能解決的」。

說穿了，CORS 就是藉由一堆的 response header 來跟瀏覽器講說哪些東西是前端有權限存取的。如果沒有後端給的這些 header，那前端根本什麼也做不了。因此無論是前端還是後端，都有必要知道這些 header，未來碰到相關問題的時候才知道怎麼解決。

順帶一提，我覺得 Chrome 的錯誤提示好像愈做愈棒了，印象中以前好像沒有講得那麼詳細，現在詳細到爆，甚至可以直接看錯誤訊息而不 Google 就知道該怎麼修。

希望透過這一篇，能讓大家理解 CORS 有哪些 response header，以及什麼是 preflight request，在哪些情形之下會觸發。理解這些以後，你對整個 CORS protocol 的理解大概就有八成了。

在下一篇 [CORS 完全手冊（四）：一起看規範]()中，我們會一起來看看規格，更進一步理解 CORS protocol。